"""Check a Circle Wallets (developer-controlled) request before it is sent to Circle's API.

With Circle Wallets, an agent does not sign anything itself: it asks Circle's API to transfer tokens, call a
contract, or sign a transaction or EIP-712 typed data from a wallet Circle holds the keys for. Once Circle
accepts the request, it is signed. So the check has to run on the request body, before it is sent:

* ``check_circle_request(operation, body, ...)`` checks one request body (a dict, or a request model from the
  official ``circle-developer-controlled-wallets`` SDK) and returns the same ``RiskAssessment`` as every other
  check. Fails closed: anything it cannot read is HOLD.
* ``guard_circle_wallets(api, ...)`` wraps the SDK's ``TransactionsApi`` or ``SigningApi`` so that every
  request that moves money or signs is checked first, and only sent on APPROVE (otherwise
  ``CircleRequestBlocked`` is raised and nothing reaches Circle).

Supported operations (Circle API paths under ``/v1/w3s/developer/``):

=========================  =======================================================================
``transactions/transfer``  token transfer: USDC (by contract address, or a Circle token id you list
                           in ``usdc_token_ids``) goes through ``check_payment``; native USDC sends on
                           Arc too. Other tokens, NFTs and native sends elsewhere are held.
``transactions/contractExecution``  contract call: rebuilt into a transaction and checked with
                           ``check_transaction`` (so ``approve`` is TOKEN_APPROVAL, and only a USDC
                           ``transfer`` is approved).
``sign/typedData``         EIP-712 signature: ``check_authorization`` (x402, Circle Gateway, Permit).
``sign/transaction``       EVM transaction signature: ``check_transaction``.
anything else that signs   held: ``sign/message`` (a raw message can authorise anything),
                           ``transactions/walletUpgrade``, ``sign/delegateAction``.
=========================  =======================================================================

A request that names the wallet by ``walletId`` does not say which address it is or which chain, so pass
``wallets={wallet_id: address}`` (and ``chain=`` when the body has no ``blockchain``). These come from your
own configuration, never from the agent.
"""
from __future__ import annotations

import json
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any, Callable, Mapping, Optional, Union

from sra_riskgate.authorization import check_authorization
from sra_riskgate.chains import NATIVE_USDC_CHAINS, USDC_ADDRESSES, USDC_DECIMALS, is_usdc
from sra_riskgate.check import _verdict, check_payment
from sra_riskgate.models import ActionDecision, RiskAssessment
from sra_riskgate.transaction import _POLICY_KEYS, _same, check_transaction

# Circle's blockchain identifiers for the chains sra-riskgate checks. "EVM" / "EVM-TESTNET" are Circle's
# chain-agnostic EVM wallets: the chain then comes from the payload itself (typed data or transaction).
CIRCLE_BLOCKCHAINS: dict[str, int] = {
    "ETH": 1,
    "BASE": 8453,
    "BASE-SEPOLIA": 84532,
    "ARC": 5042,
    "ARC-TESTNET": 5042002,
}
_GENERIC_EVM = {"EVM", "EVM-TESTNET"}
_AUTH_KEYS = {"max_validity_seconds", "max_gateway_validity_seconds"}

# The known ERC-20 functions a contract call can be rebuilt from, by Circle's abiFunctionSignature.
_SELECTORS = {
    "transfer(address,uint256)": "a9059cbb",
    "approve(address,uint256)": "095ea7b3",
    "increaseAllowance(address,uint256)": "39509351",
    "transferFrom(address,address,uint256)": "23b872dd",
}

_OPERATIONS = {
    "transfer": "transfer", "transactions/transfer": "transfer",
    "create_developer_transaction_transfer": "transfer",
    "contractexecution": "contractExecution", "transactions/contractexecution": "contractExecution",
    "create_developer_transaction_contract_execution": "contractExecution",
    "typeddata": "signTypedData", "sign/typeddata": "signTypedData", "signtypeddata": "signTypedData",
    "sign_typed_data": "signTypedData",
    "transaction": "signTransaction", "sign/transaction": "signTransaction", "signtransaction": "signTransaction",
    "sign_transaction": "signTransaction",
    "message": "signMessage", "sign/message": "signMessage", "signmessage": "signMessage",
    "sign_message": "signMessage",
    "walletupgrade": "walletUpgrade", "transactions/walletupgrade": "walletUpgrade",
    "create_developer_transaction_wallet_upgrade": "walletUpgrade",
    "delegateaction": "signDelegateAction", "sign/delegateaction": "signDelegateAction",
    "sign_delegate_action": "signDelegateAction",
}

# SDK methods that move money or sign, and are therefore checked by guard_circle_wallets. Everything else
# on the API object (get_, list_, estimate fee, validate address, accelerate, cancel) passes through.
_GUARDED_METHODS = {
    "create_developer_transaction_transfer", "create_developer_transaction_contract_execution",
    "create_developer_transaction_wallet_upgrade", "sign_typed_data", "sign_transaction", "sign_message",
    "sign_delegate_action",
}


class CircleRequestBlocked(Exception):
    """Raised by a guarded Circle Wallets API object when a request is held or rejected. Nothing was sent."""

    def __init__(self, operation: str, assessment: RiskAssessment):
        self.operation = operation
        self.assessment = assessment
        verb = "BLOCKED" if assessment.decision == ActionDecision.REJECT else "HELD for human review"
        super().__init__(f"{verb}: Circle Wallets {operation} request not sent. {assessment.explanation} "
                         f"Flags: {', '.join(assessment.flags)}.")


def _hold(flags: list, why: str) -> RiskAssessment:
    return _verdict(ActionDecision.HOLD, flags, f"SRA-RiskGate cannot approve this Circle Wallets request: {why}",
                    ["manual_review"])


def _body(request: Any) -> Mapping[str, Any]:
    """A request body as a camelCase mapping: a dict as given, or an SDK request model via to_dict()."""
    if isinstance(request, Mapping):
        return request
    to_dict = getattr(request, "to_dict", None)
    if callable(to_dict):
        out = to_dict()
        if isinstance(out, Mapping):
            return out
    raise TypeError("the request is neither a mapping nor an SDK request model")


def _text(value: Any) -> Optional[str]:
    """Enum members (the SDK's TransferBlockchain etc.) become their value; None stays None."""
    if value is None:
        return None
    return str(getattr(value, "value", value)).strip()


def _operation(operation: str) -> Optional[str]:
    key = str(operation).strip().lower()
    for prefix in ("/v1/w3s/developer/", "v1/w3s/developer/", "/"):
        if key.startswith(prefix):
            key = key[len(prefix):]
    return _OPERATIONS.get(key)


def _chain(blockchain: Any, chain: Union[int, str, None]) -> tuple[Optional[int], Optional[str]]:
    """(chain id, error). The body's ``blockchain`` wins; ``chain`` (an id or a Circle name) fills the gap."""
    name = _text(blockchain)
    if name:
        if name.upper() in _GENERIC_EVM:
            return None, None  # chain comes from the payload
        if name.upper() not in CIRCLE_BLOCKCHAINS:
            return None, (f"blockchain {name} is not checked; supported: "
                          f"{', '.join(CIRCLE_BLOCKCHAINS)}.")
        cid = CIRCLE_BLOCKCHAINS[name.upper()]
        if chain is not None:
            other, err = _chain(chain, None) if isinstance(chain, str) else (chain, None)
            if err is None and other is not None and other != cid:
                return None, f"the request is for {name} (chain {cid}), but the wallet is configured for chain {other}."
        return cid, None
    if chain is None:
        return None, None
    if isinstance(chain, bool):
        return None, f"chain {chain!r} is not a chain id."
    if isinstance(chain, int):
        return chain, None
    return _chain(chain, None)


def _sender(body: Mapping[str, Any], sender: Optional[str], wallets: Optional[Mapping[str, str]]):
    """(address, error) of the wallet the request spends from."""
    address = _text(body.get("walletAddress"))
    wallet_id = _text(body.get("walletId"))
    configured = None
    if wallet_id:
        configured = (wallets or {}).get(wallet_id)
        if wallets is not None and configured is None:
            return None, (f"it spends from wallet {wallet_id}, which is not one of the configured wallets; an "
                          f"agent may only use the wallets you listed in wallets=.")
        if configured is None and sender is None and address is None:
            return None, (f"it names wallet {wallet_id} by id, and its address is not configured; pass "
                          f"wallets={{wallet_id: address}} from your own Circle configuration.")
    known = [a for a in (address, configured, sender) if a]
    for a in known[1:]:
        if not _same(a, known[0]):
            return None, f"the wallet address in the request ({known[0]}) does not match the configured one ({a})."
    return (known[0] if known else None), None


def _micro_usdc(amount: Any) -> Decimal:
    """A decimal USDC amount, rounded up to a whole micro-USDC so no limit can be passed by dust."""
    d = Decimal(str(amount).strip())
    if not d.is_finite():
        raise InvalidOperation
    return d.quantize(Decimal(1).scaleb(-USDC_DECIMALS), rounding=ROUND_CEILING)


def _word(x: int) -> str:
    return format(x, "064x")


def _address_word(a: Any) -> str:
    s = str(a).strip().lower()
    if not (s.startswith("0x") and len(s) == 42):
        raise ValueError(f"{a!r} is not an address")
    int(s[2:], 16)
    return s[2:].zfill(64)


def _uint_word(v: Any) -> str:
    n = int(str(v).strip(), 0)
    if n < 0 or n >= 2**256:
        raise ValueError(f"{v!r} is not a uint256")
    return _word(n)


def _calldata(signature: str, params: Any) -> Optional[str]:
    """Calldata for a known ERC-20 function signature, or None if the signature is not one of them."""
    sig = "".join(str(signature).split())
    selector = _SELECTORS.get(sig)
    if selector is None:
        return None
    types = sig[sig.index("(") + 1:-1].split(",")
    if not isinstance(params, (list, tuple)) or len(params) != len(types):
        raise ValueError(f"{sig} takes {len(types)} parameters, got {params!r}")
    words = [_address_word(p) if t == "address" else _uint_word(p) for t, p in zip(types, params)]
    return "0x" + selector + "".join(words)


def check_circle_request(
    operation: str,
    request: Any,
    *,
    sender: Optional[str] = None,
    chain: Union[int, str, None] = None,
    wallets: Optional[Mapping[str, str]] = None,
    usdc_token_ids: Optional[Union[set, list, tuple, frozenset]] = None,
    **policy: Any,
) -> RiskAssessment:
    """Check a Circle Wallets request body before sending it. Never raises; anything unexpected becomes HOLD.

    ``operation`` is the API path (``"transactions/transfer"``, ``"/v1/w3s/developer/sign/typedData"``), its
    short name (``"transfer"``, ``"contractExecution"``, ``"signTypedData"``, ``"signTransaction"``) or the
    SDK method name. ``request`` is the JSON body as a dict, or the SDK's request model.

    ``sender`` (or ``wallets``, mapping Circle wallet ids to addresses) says which address the wallet is;
    ``chain`` (a chain id or Circle name such as ``"ARC-TESTNET"``) is needed when the body names the wallet
    by ``walletId`` and has no ``blockchain``. ``usdc_token_ids`` lists the Circle token ids you have
    confirmed are USDC on that chain (a transfer by ``tokenId`` of anything else is held). Every other
    keyword is the usual policy (``known_recipients``, ``blocked_addresses``, ``max_amount``,
    ``untrusted_request``, ``peg_deviation_pct``, and for typed data ``max_validity_seconds`` and
    ``max_gateway_validity_seconds``).

    Flags beyond those of the underlying checks: ``UNSUPPORTED_OPERATION`` (a signing request that cannot be
    checked, such as ``sign/message``), ``WALLET_MISMATCH`` (the request's wallet is not the configured one),
    ``UNKNOWN_WALLET`` (the wallet's address or chain is not known), ``INVALID_REQUEST`` (missing or
    malformed fields).
    """
    auth_policy = {k: policy.pop(k) for k in list(policy) if k in _AUTH_KEYS}
    unknown = sorted(set(policy) - _POLICY_KEYS)
    if unknown:
        return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                        f"The risk gate is misconfigured: unknown argument(s) {', '.join(unknown)}.",
                        ["fix_configuration"])
    try:
        op = _operation(operation)
        if op is None:
            return _hold(["UNSUPPORTED_OPERATION"], f"{operation} is not a Circle Wallets operation this checks.")
        if op == "signMessage":
            return _hold(["UNSUPPORTED_OPERATION"],
                         "a raw message signature can authorise anything (a login, an off-chain order, a "
                         "permit encoded as text), and its meaning cannot be checked; a person must approve it.")
        if op == "walletUpgrade":
            return _hold(["CODE_DELEGATION"],
                         "upgrading the wallet changes the code that controls everything it holds; a person "
                         "must approve it.")
        if op == "signDelegateAction":
            return _hold(["UNSUPPORTED_OPERATION"], "NEAR delegate actions are not checked.")

        try:
            body = _body(request)
        except TypeError as e:
            return _hold(["INVALID_REQUEST"], f"{e}.")
        chain_id, err = _chain(body.get("blockchain"), chain)
        if err:
            flag = "WALLET_MISMATCH" if "configured" in err else "UNSUPPORTED_CHAIN"
            return _hold([flag], err)
        frm, err = _sender(body, sender, wallets)
        if err:
            return _hold(["WALLET_MISMATCH" if "match" in err else "UNKNOWN_WALLET"], err)

        if op == "signTypedData":
            data = body.get("data")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except ValueError:
                    return _hold(["INVALID_REQUEST"], "data is not valid JSON typed data.")
            return check_authorization(data, sender=frm, chain_id=chain_id, **auth_policy, **policy)

        if op == "signTransaction":
            if body.get("rawTransaction") and not body.get("transaction"):
                return _hold(["UNSUPPORTED_OPERATION"],
                             "a raw (serialised) transaction is not decoded; send the transaction as JSON in "
                             "`transaction` so it can be checked.")
            tx = body.get("transaction")
            if isinstance(tx, str):
                try:
                    tx = json.loads(tx)
                except ValueError:
                    return _hold(["INVALID_REQUEST"], "transaction is not valid JSON.")
            if not isinstance(tx, Mapping):
                return _hold(["INVALID_REQUEST"], "transaction is missing.")
            return check_transaction(tx, chain_id=chain_id, sender=frm, **policy)

        # transfers and contract calls need a chain and a sender
        if chain_id is None:
            return _hold(["UNKNOWN_WALLET"], "the request does not say which chain it is on; pass chain=.")
        if chain_id not in USDC_ADDRESSES:
            return _hold(["UNSUPPORTED_CHAIN"], f"chain {chain_id} is not checked.")
        if frm is None:
            return _hold(["UNKNOWN_WALLET"], "the request does not say which wallet address it spends from; "
                                             "pass sender= or wallets=.")

        if op == "contractExecution":
            contract = _text(body.get("contractAddress"))
            if not contract:
                return _hold(["INVALID_REQUEST"], "contractAddress is required.")
            amount = body.get("amount")
            native = None
            if amount not in (None, ""):
                try:
                    native = Decimal(str(amount).strip())
                except InvalidOperation:
                    return _hold(["INVALID_REQUEST"], f"amount {amount!r} is not a number.")
                if native < 0 or not native.is_finite():
                    return _hold(["INVALID_REQUEST"], f"amount {amount!r} is not a valid amount.")
                if native > 0:
                    return _hold(["NATIVE_VALUE_TRANSFER"],
                                 f"the contract call also sends {amount} of the chain's native token; native "
                                 f"value sent with a contract call is not checked.")
            call_data = _text(body.get("callData"))
            signature = _text(body.get("abiFunctionSignature"))
            if call_data and signature:
                return _hold(["INVALID_REQUEST"], "callData and abiFunctionSignature cannot both be set.")
            if signature:
                try:
                    call_data = _calldata(signature, body.get("abiParameters") or [])
                except (ValueError, TypeError) as e:
                    return _hold(["INVALID_REQUEST"], f"the ABI parameters cannot be read ({e}).")
                if call_data is None:
                    return _hold(["UNSUPPORTED_FUNCTION"],
                                 f"only USDC transfer(address,uint256) is approved; this calls {signature} on "
                                 f"{contract}.")
            if not call_data:
                return _hold(["INVALID_REQUEST"], "callData or abiFunctionSignature is required.")
            return check_transaction({"to": contract, "data": call_data, "value": 0},
                                     chain_id=chain_id, sender=frm, **policy)

        # op == "transfer"
        if body.get("nftTokenIds"):
            return _hold(["UNSUPPORTED_ASSET"], "NFT transfers are not checked.")
        token_id, token_address = _text(body.get("tokenId")), _text(body.get("tokenAddress"))
        if token_id and token_address:
            return _hold(["INVALID_REQUEST"], "tokenId and tokenAddress cannot both be set.")
        if token_id:
            listed = {str(t).strip().lower() for t in (usdc_token_ids or ())}
            if token_id.lower() not in listed:
                return _hold(["UNSUPPORTED_ASSET"],
                             f"Circle token {token_id} is not one of the USDC token ids you configured "
                             f"(usdc_token_ids).")
        elif token_address:
            if not is_usdc(chain_id, token_address):
                return _hold(["UNSUPPORTED_ASSET"],
                             f"token {token_address} is not USDC on chain {chain_id} ({USDC_ADDRESSES[chain_id]}).")
        elif chain_id not in NATIVE_USDC_CHAINS:
            return _hold(["NATIVE_VALUE_TRANSFER"],
                         f"this is a native-token transfer on chain {chain_id}, which is not USDC.")
        amounts = body.get("amounts")
        if not isinstance(amounts, (list, tuple)) or len(amounts) != 1:
            return _hold(["INVALID_REQUEST"], "a transfer must have exactly one amount.")
        try:
            usdc = _micro_usdc(amounts[0])
        except (InvalidOperation, ValueError):
            return _hold(["INVALID_REQUEST"], f"amount {amounts[0]!r} is not a number.")
        recipient = _text(body.get("destinationAddress"))
        if not recipient:
            return _hold(["INVALID_REQUEST"], "destinationAddress is required.")
        return check_payment(chain_id=chain_id, sender=frm, recipient=recipient, amount=float(usdc), **policy)
    except Exception as e:  # fail closed: no error path may approve
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The Circle Wallets request check failed ({type(e).__name__}), so it is held.",
                        ["manual_review"])


class _GuardedApi:
    """A Circle Wallets SDK API object whose money-moving and signing methods are checked first."""

    def __init__(self, api: Any, options: dict, on_decision: Optional[Callable[..., None]]):
        self._api, self._options, self._on_decision = api, options, on_decision

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._api, name)
        if name not in _GUARDED_METHODS or not callable(value):
            return value

        def guarded(request: Any = None, *args: Any, **kwargs: Any) -> Any:
            if request is None and kwargs:
                # the SDK's own keyword, e.g. create_transfer_transaction_for_developer_request=...
                key = next((k for k in kwargs if k.endswith("_request")), None)
                request = kwargs.get(key) if key else None
            assessment = check_circle_request(name, request, **self._options)
            if self._on_decision is not None:
                self._on_decision(operation=name, request=request, assessment=assessment)
            if assessment.decision != ActionDecision.APPROVE:
                raise CircleRequestBlocked(name, assessment)
            if request is not None and not any(k.endswith("_request") for k in kwargs):
                return value(request, *args, **kwargs)
            return value(*args, **kwargs)

        return guarded


def guard_circle_wallets(
    api: Any,
    *,
    on_decision: Optional[Callable[..., None]] = None,
    **options: Any,
) -> Any:
    """Wrap a ``TransactionsApi`` or ``SigningApi`` from ``circle-developer-controlled-wallets``.

    Every transfer, contract execution, wallet upgrade and signing request is checked with
    ``check_circle_request`` (with ``options``: ``wallets``, ``chain``, ``usdc_token_ids`` and the usual
    policy) and sent only on APPROVE; otherwise ``CircleRequestBlocked`` is raised and nothing reaches
    Circle. Read-only methods pass through. ``on_decision(operation=, request=, assessment=)`` is called with
    every decision, for logging. Give the agent only the wrapped object.
    """
    probe = check_circle_request("transfer", {}, **options)  # surfaces a misconfigured policy at wrap time
    if "CONFIGURATION_ERROR" in probe.flags:
        raise ValueError(probe.explanation)
    return _GuardedApi(api, dict(options), on_decision)
