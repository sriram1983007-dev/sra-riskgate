"""Check an ERC-4337 UserOperation before a smart account's owner signs it.

Many agents on Base do not sign plain transactions: they use a smart account (Coinbase Smart Wallet, CDP smart
accounts, Safe, Kernel, Nexus, SimpleAccount), and what the owner key signs is a UserOperation whose ``callData``
tells the account what to execute, often several calls at once. A transaction-level check never sees those
inner calls, so an unlimited ``approve()`` can ride along inside a batch with an ordinary payment.

``check_user_operation`` decodes the ``callData`` of the common account interfaces into the calls the account will
make, runs every call through ``check_transaction`` (so a USDC transfer gets the full payment check and anything
else is held), sums payments to the same payee across the batch so a payment cannot be split under the amount
limit, and holds anything it cannot read. Decoding was tested against callData produced by viem 2.57 and
permissionless 0.5 for each account type (tests/data/smart_account_calldata.json).

Supported ``callData`` (the account's execute function):

* ``execute(address,uint256,bytes)`` and ``executeBatch((address,uint256,bytes)[])``: Coinbase Smart Wallet,
  Solady, viem's Simple7702 account.
* ``executeBatch(address[],uint256[],bytes[])`` and ``executeBatch(address[],bytes[])``: eth-infinitism
  SimpleAccount (v0.7 and v0.6).
* ``execute(bytes32,bytes)``: ERC-7579 accounts (Kernel v3, Biconomy Nexus, Safe7579), single and batch calls.
* ``executeUserOp`` / ``executeUserOpWithErrorString(address,uint256,bytes,uint8)``: the Safe 4337 module. A
  batch is a delegatecall to Safe's MultiSendCallOnly contract, which is decoded; any other delegatecall is held.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Iterable, Mapping, Optional

from sra_riskgate.chains import NATIVE_USDC_CHAINS, NATIVE_USDC_DECIMALS, USDC_ADDRESSES, USDC_DECIMALS
from sra_riskgate.check import _verdict, check_payment
from sra_riskgate.counterparty import _normalise, parse_address_list
from sra_riskgate.models import ActionDecision, RiskAssessment
from sra_riskgate.transaction import _POLICY_KEYS, _hex, _int, _same, check_transaction, decode_erc20_transfer

EXECUTE = "b61d27f6"                    # execute(address,uint256,bytes)
EXECUTE_BATCH_TUPLES = "34fcd5be"       # executeBatch((address,uint256,bytes)[])
EXECUTE_BATCH_ARRAYS = "47e1da2a"       # executeBatch(address[],uint256[],bytes[])
EXECUTE_BATCH_NO_VALUE = "18dfb3c7"     # executeBatch(address[],bytes[])
EXECUTE_7579 = "e9ae5c53"               # execute(bytes32,bytes)
SAFE_EXECUTE = "7bb37428"               # executeUserOp(address,uint256,bytes,uint8)
SAFE_EXECUTE_ERR = "541d63c8"           # executeUserOpWithErrorString(address,uint256,bytes,uint8)
MULTI_SEND = "8d80ff0a"                 # multiSend(bytes)

# Safe's MultiSendCallOnly (it refuses delegatecalls inside the batch): v1.4.1 and v1.3.0 canonical deployments.
SAFE_MULTISEND_CALL_ONLY = frozenset({
    "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
    "0x40a2accbd92bca938b02010e17a5b8929b49130d",
})

_PAYMENT_KEYS = frozenset(_POLICY_KEYS)
_CAMEL = {"call_data": "callData", "init_code": "initCode", "paymaster_and_data": "paymasterAndData",
          "factory_data": "factoryData", "paymaster_data": "paymasterData", "eip7702_auth": "eip7702Auth"}


class _Unreadable(ValueError):
    """callData that does not decode as a supported account call."""


class _Delegatecall(ValueError):
    """A delegatecall the account would make: it runs another contract's code as the account itself."""


def _word(h: str, i: int) -> str:
    w = h[i * 64:(i + 1) * 64]
    if len(w) != 64:
        raise _Unreadable("calldata ends early")
    return w


def _uint(h: str, i: int) -> int:
    return int(_word(h, i), 16)


def _addr(h: str, i: int) -> str:
    w = _word(h, i)
    if w[:24] != "0" * 24:
        raise _Unreadable("an address word has non-zero padding")
    return "0x" + w[24:]


def _offset(h: str, i: int) -> int:
    off = _uint(h, i)
    if off % 32 or off // 32 > len(h) // 64:
        raise _Unreadable("a bad ABI offset")
    return off // 32


def _bytes_at(h: str, word: int) -> str:
    n = _uint(h, word)
    data = h[(word + 1) * 64:(word + 1) * 64 + 2 * n]
    if len(data) != 2 * n:
        raise _Unreadable("a bytes value runs past the end")
    return data


def _array_len(h: str, word: int) -> int:
    n = _uint(h, word)
    if n > 256:
        raise _Unreadable("more than 256 calls in one operation")
    return n


def _call(target: str, value: int, data: str) -> dict:
    return {"to": target, "value": value, "data": "0x" + data}


def _tuples(h: str, base: int) -> list:
    """abi-encoded (address,uint256,bytes)[] whose array starts at word ``base``."""
    n, calls = _array_len(h, base), []
    for k in range(n):
        t = base + 1 + _uint(h, base + 1 + k) // 32
        calls.append(_call(_addr(h, t), _uint(h, t + 1), _bytes_at(h, t + _uint(h, t + 2) // 32)))
    return calls


def _multisend(packed: str) -> list:
    """Safe MultiSend packing: operation(1) to(20) value(32) dataLength(32) data, repeated."""
    calls, i = [], 0
    while i < len(packed):
        if len(packed) - i < 2 * (1 + 20 + 32 + 32):
            raise _Unreadable("a truncated MultiSend entry")
        op = int(packed[i:i + 2], 16)
        to = "0x" + packed[i + 2:i + 42]
        value = int(packed[i + 42:i + 106], 16)
        n = int(packed[i + 106:i + 170], 16)
        data = packed[i + 170:i + 170 + 2 * n]
        if len(data) != 2 * n:
            raise _Unreadable("a MultiSend entry runs past the end")
        if op != 0:
            raise _Delegatecall(f"a MultiSend entry delegatecalls {to}")
        calls.append(_call(to, value, data))
        i += 170 + 2 * n
    if len(calls) > 256:
        raise _Unreadable("more than 256 calls in one operation")
    return calls


def decode_account_calls(call_data: Any) -> list:
    """The calls a smart account will make for this UserOperation ``callData``, as ``{to, value, data}`` dicts.

    Raises ValueError for callData that is not one of the supported account interfaces, and for any delegatecall
    other than a batch through Safe's MultiSendCallOnly.
    """
    h = _hex(call_data)
    if h is None or len(h) < 8:
        raise _Unreadable("the callData is empty or not hex")
    sel, a = h[:8], h[8:]
    if sel == EXECUTE:
        return [_call(_addr(a, 0), _uint(a, 1), _bytes_at(a, _offset(a, 2)))]
    if sel == EXECUTE_BATCH_TUPLES:
        return _tuples(a, _offset(a, 0))
    if sel in (EXECUTE_BATCH_ARRAYS, EXECUTE_BATCH_NO_VALUE):
        with_value = sel == EXECUTE_BATCH_ARRAYS
        t = _offset(a, 0)
        v = _offset(a, 1) if with_value else None
        d = _offset(a, 2 if with_value else 1)
        n = _array_len(a, t)
        if _array_len(a, d) != n or (with_value and _array_len(a, v) not in (0, n)):
            raise _Unreadable("the batch arrays have different lengths")
        values = [_uint(a, v + 1 + k) for k in range(n)] if with_value and _uint(a, v) else [0] * n
        return [_call(_addr(a, t + 1 + k), values[k], _bytes_at(a, d + 1 + _uint(a, d + 1 + k) // 32))
                for k in range(n)]
    if sel == EXECUTE_7579:
        mode = _word(a, 0)
        call_type, exec_type = mode[0:2], mode[2:4]
        payload = _bytes_at(a, _offset(a, 1))
        if exec_type not in ("00", "01"):
            raise _Unreadable(f"unknown ERC-7579 exec type 0x{exec_type}")
        if call_type == "00":       # single: target(20) value(32) callData
            if len(payload) < 104:
                raise _Unreadable("a truncated ERC-7579 single call")
            return [_call("0x" + payload[:40], int(payload[40:104], 16), payload[104:])]
        if call_type == "01":       # batch: abi.encode(Execution[])
            return _tuples(payload, _offset(payload, 0))
        if call_type == "ff":
            raise _Delegatecall("an ERC-7579 delegatecall")
        raise _Unreadable(f"unsupported ERC-7579 call type 0x{call_type}")
    if sel in (SAFE_EXECUTE, SAFE_EXECUTE_ERR):
        to, value, data, op = _addr(a, 0), _uint(a, 1), _bytes_at(a, _offset(a, 2)), _uint(a, 3)
        if op == 0:
            return [_call(to, value, data)]
        if op == 1 and to in SAFE_MULTISEND_CALL_ONLY and value == 0 and data[:8] == MULTI_SEND:
            inner = data[8:]
            return _multisend(_bytes_at(inner, _offset(inner, 0)))
        raise _Delegatecall(f"a delegatecall to {to}")
    raise _Unreadable(f"0x{sel} is not a supported smart-account execute function")


def _hold(flags: list, why: str) -> RiskAssessment:
    return _verdict(ActionDecision.HOLD, flags, f"SRA-RiskGate cannot approve this UserOperation: {why}",
                    ["manual_review"])


def _paymaster(op: Mapping) -> Optional[str]:
    if op.get("paymaster") not in (None, "", "0x"):
        return _normalise(op.get("paymaster")) or str(op.get("paymaster"))
    pad = _hex(op.get("paymasterAndData") or "")
    if pad:
        return "0x" + pad[:40]
    return None


def _usdc_micro(chain_id: int, call: dict) -> Optional[tuple]:
    """(recipient, micro-USDC) if the call is a USDC payment, else None."""
    data = _hex(call["data"]) or ""
    if _same(call["to"], USDC_ADDRESSES.get(chain_id)) and data[:8] == "a9059cbb" and not call["value"]:
        decoded = decode_erc20_transfer(data)
        return (decoded[0].lower(), decoded[1]) if decoded else None
    if chain_id in NATIVE_USDC_CHAINS and not data and call["value"] > 0:
        scale = 10 ** (NATIVE_USDC_DECIMALS - USDC_DECIMALS)
        return (call["to"].lower(), -(-call["value"] // scale))
    return None


def check_user_operation(
    user_op: Mapping[str, Any],
    *,
    chain_id: int,
    sender: Optional[str] = None,
    expected_paymasters: Optional[Iterable[str]] = None,
    allow_account_deployment: bool = False,
    **policy: Any,
) -> RiskAssessment:
    """Check an ERC-4337 UserOperation before the owner signs it. Never raises; anything unexpected is HOLD.

    ``user_op`` is the UserOperation as your bundler client builds it (v0.6 ``initCode`` / ``paymasterAndData``,
    or v0.7 / v0.8 ``factory`` / ``paymaster``). ``chain_id`` is required; ``sender``, if given, must match
    ``user_op["sender"]`` (the smart account). Every keyword in ``policy`` (``known_recipients``, ``max_amount``,
    ``untrusted_request``, ``account_code``, ...) applies to each call.

    * Each call the account would make goes through ``check_transaction``: a USDC ``transfer`` gets the full
      payment check; approvals, permits, other contracts and native ETH are held. The first call that is not
      approved decides, and its index is named.
    * Payments to the same payee are summed across the batch and checked again as one payment, so splitting a
      payment does not bring it under ``max_amount``.
    * A call from the account to itself is held (``ACCOUNT_SELF_CALL``): it can change the account's owners,
      modules or implementation.
    * A delegatecall is held (``DELEGATECALL``), except a Safe batch through MultiSendCallOnly, which is decoded.
    * Unreadable callData is held (``UNSUPPORTED_ACCOUNT_CALL``).
    * Deploying the account in the same operation (``initCode`` or ``factory``) is held
      (``ACCOUNT_DEPLOYMENT``) unless ``allow_account_deployment=True``.
    * An EIP-7702 authorization in the operation (``eip7702Auth``) is held (``CODE_DELEGATION``).
    * If ``expected_paymasters`` is given, any other paymaster is held (``UNKNOWN_PAYMASTER``).

    Only sign if ``result.decision`` is ``ActionDecision.APPROVE``.
    """
    unknown = sorted(set(policy) - _PAYMENT_KEYS)
    if unknown:
        return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                        f"The risk gate is misconfigured: unknown argument(s) {', '.join(unknown)}.",
                        ["fix_configuration"])
    try:
        try:
            paymasters = parse_address_list("expected_paymasters", expected_paymasters)
        except ValueError as e:
            return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                            f"The risk gate is misconfigured: {e}", ["fix_configuration"])
        if not isinstance(user_op, Mapping):
            return _hold(["INVALID_USER_OPERATION"], "it is not a mapping.")
        user_op = {_CAMEL.get(k, k): v for k, v in user_op.items()}  # snake_case clients (Python SDKs) too
        try:
            chain_id = _int(chain_id)
        except (TypeError, ValueError):
            return _hold(["INVALID_USER_OPERATION"], f"chain id {chain_id!r} is not a number.")
        if chain_id not in USDC_ADDRESSES:
            return _hold(["UNSUPPORTED_CHAIN"], f"chain {chain_id} is not checked.")
        account = _normalise(user_op.get("sender"))
        if account is None:
            return _hold(["INVALID_USER_OPERATION"], "its sender (the smart account) is missing or not an address.")
        if sender is not None and not _same(sender, account):
            return _hold(["USER_OPERATION_MISMATCH"], f"it is for account {account}, not {sender}.")
        if user_op.get("eip7702Auth") or user_op.get("authorization"):
            return _hold(["CODE_DELEGATION"], "it carries an EIP-7702 authorization that delegates the owner's "
                                              "account to contract code; a person must approve it.")
        deploys = (_hex(user_op.get("initCode") or "") or "") or user_op.get("factory") not in (None, "", "0x")
        if deploys and not allow_account_deployment:
            return _hold(["ACCOUNT_DEPLOYMENT"], "it also deploys the smart account (initCode / factory). Deploy "
                                                 "it once on purpose, or pass allow_account_deployment=True.")
        pm = _paymaster(user_op)
        if pm is not None and paymasters is not None and pm not in paymasters:
            return _hold(["UNKNOWN_PAYMASTER"], f"its paymaster {pm} is not one of your expected_paymasters.")

        try:
            calls = decode_account_calls(user_op.get("callData"))
        except _Delegatecall as e:
            return _hold(["DELEGATECALL"], f"it makes {e}, which runs another contract's code as the account "
                                           f"itself and can do anything the account can.")
        except (_Unreadable, ValueError) as e:
            return _hold(["UNSUPPORTED_ACCOUNT_CALL"], f"its callData cannot be read ({e}).")
        if not calls:
            return _hold(["UNSUPPORTED_ACCOUNT_CALL"], "it makes no calls.")

        n, approved, totals, counts = len(calls), [], {}, {}
        for i, call in enumerate(calls, 1):
            where = f"call {i} of {n}" if n > 1 else "its call"
            if _same(call["to"], account):
                return _hold(["ACCOUNT_SELF_CALL"], f"{where} is to the account itself, which can change its "
                                                    f"owners, modules or implementation.")
            r = check_transaction({**call, "from": account, "chainId": chain_id}, **policy)
            if r.decision != ActionDecision.APPROVE:
                why = r.explanation.replace("SRA-RiskGate cannot approve this transaction: ", "")
                return RiskAssessment(decision=r.decision, risk_score=r.risk_score, flags=r.flags,
                                      explanation=f"In this UserOperation, {where}: {why}"[:500],
                                      required_actions=r.required_actions)
            approved.append(r)
            paid = _usdc_micro(chain_id, call)
            if paid:
                totals[paid[0]] = totals.get(paid[0], 0) + paid[1]
                counts[paid[0]] = counts.get(paid[0], 0) + 1

        for payee, micro in totals.items():
            if counts[payee] < 2:
                continue
            amount = float(Decimal(micro) / (Decimal(10) ** USDC_DECIMALS))
            r = check_payment(chain_id=chain_id, sender=account, recipient=payee, amount=amount, **policy)
            if r.decision != ActionDecision.APPROVE:
                return RiskAssessment(
                    decision=r.decision, risk_score=r.risk_score, flags=sorted(set(r.flags) | {"BATCH_TOTAL"}),
                    explanation=(f"Together, the {counts[payee]} payments to {payee} in this UserOperation total "
                                 f"{amount} USDC: {r.explanation}")[:500],
                    required_actions=r.required_actions)

        flags = sorted({f for r in approved for f in r.flags})
        return RiskAssessment(decision=ActionDecision.APPROVE, risk_score=max(r.risk_score for r in approved),
                              flags=flags, explanation=f"All {n} call(s) in this UserOperation passed the checks.",
                              required_actions=[])
    except Exception as e:  # fail closed
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The UserOperation check failed ({type(e).__name__}), so it is held.", ["manual_review"])
