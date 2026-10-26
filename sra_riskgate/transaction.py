"""Check the exact transaction an agent is about to sign, not just its description of the payment.

``check_payment`` checks a payment described in fields (chain, sender, recipient, amount). An agent
actually signs a transaction: a contract address, calldata and a native value. ``check_transaction``
decodes that transaction and only lets a plain USDC ``transfer`` through to the full payment check.
Everything else (token approvals, ``transferFrom``, other contracts, native ETH) is held. Fails closed.
"""
from __future__ import annotations

import inspect
from decimal import Decimal
from typing import Any, Mapping, Optional

from sra_riskgate.chains import (NATIVE_USDC_CHAINS, NATIVE_USDC_DECIMALS, USDC_ADDRESSES, USDC_DECIMALS,
                                  is_usdc)
from sra_riskgate.check import _verdict, check_payment
from sra_riskgate.models import ActionDecision, RiskAssessment

TRANSFER = "a9059cbb"          # transfer(address,uint256)
_APPROVALS = {
    "095ea7b3": "approve(address,uint256)",
    "39509351": "increaseAllowance(address,uint256)",
    "d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
}
_OTHER = {
    "23b872dd": "transferFrom(address,address,uint256)",
    "e3ee160e": "transferWithAuthorization(...)",
    "ef55bec6": "receiveWithAuthorization(...)",
}
_UNLIMITED = 2**255  # any allowance this large is effectively unlimited


def _hex(data: object) -> Optional[str]:
    """Lower-case hex without 0x, or None if it is not hex. Accepts str or bytes."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).hex()
    if not isinstance(data, str):
        return None
    h = data.strip().lower()
    h = h[2:] if h.startswith("0x") else h
    if len(h) % 2 or any(c not in "0123456789abcdef" for c in h):
        return None
    return h


def _address_word(word: str) -> Optional[str]:
    return "0x" + word[24:] if word[:24] == "0" * 24 else None


def decode_erc20_transfer(data: object) -> Optional[tuple[str, int]]:
    """``(recipient, atomic_amount)`` from ERC-20 ``transfer`` calldata, or None if it is anything else.

    Strict: exactly the selector plus two 32-byte words, and a clean address word."""
    h = _hex(data)
    if h is None or len(h) != 8 + 64 + 64 or h[:8] != TRANSFER:
        return None
    to = _address_word(h[8:72])
    return (to, int(h[72:], 16)) if to else None


def _int(value: object) -> int:
    """A transaction's native value: int, decimal string or 0x-hex string. Raises on anything else."""
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ValueError("value must be a number")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        return int(s, 16) if s.startswith("0x") else int(s)
    raise ValueError("value must be an integer")


def _same(a: object, b: object) -> bool:
    return isinstance(a, str) and isinstance(b, str) and a.strip().lower() == b.strip().lower()


_POLICY_KEYS = frozenset(inspect.signature(check_payment).parameters) - {
    "chain_id", "sender", "recipient", "amount", "token"}


_DELEGATION_KEYS = ("authorizationList", "authorization_list", "authorizations")


def _describe_delegation(auth: object) -> str:
    """'to <address> on chain <n>' for one EIP-7702 authorization, as far as it can be read."""
    if isinstance(auth, Mapping):
        target = auth.get("address", auth.get("contractAddress"))
        chain = auth.get("chainId", auth.get("chain_id"))
    else:  # a signed authorization object, e.g. eth-account's SignedSetCodeAuthorization
        target = getattr(auth, "address", None)
        chain = getattr(auth, "chain_id", getattr(auth, "chainId", None))
        if isinstance(target, (bytes, bytearray)):
            target = "0x" + bytes(target).hex()
    if target is None and chain is None:
        return "(the authorization could not be read)"
    try:
        every = chain is not None and not isinstance(chain, bool) and _int(chain) == 0
    except (TypeError, ValueError):
        every = False
    where = "on every chain (chain id 0)" if every else f"on chain {chain}"
    return f"to {target} {where}"


def check_delegation(authorization: object = None) -> RiskAssessment:
    """Check an EIP-7702 authorization before the agent signs it. Always HOLD (``CODE_DELEGATION``).

    An EIP-7702 authorization is not a transaction and not EIP-712 typed data: it is a signature over
    (chain id, contract address, nonce) that makes the wallet's own account run that contract's code, so
    the contract can move everything the account holds, in every token, without further signatures. A
    chain id of 0 makes it valid on every chain. No payment check can make that safe, so an agent must never
    sign one on its own. Route your wallet library's authorization signing (viem ``signAuthorization``,
    eth-account ``sign_authorization``) through this function and stop on anything but approve."""
    try:
        what = _describe_delegation(authorization) if authorization is not None else "of unknown target"
    except Exception:
        what = "of unknown target"
    return _hold(["CODE_DELEGATION"],
                 f"it is an EIP-7702 delegation of this wallet's account {what}, which gives that contract "
                 f"control of everything the wallet holds; a person must approve it.")


def _hold(flags: list, why: str) -> RiskAssessment:
    return _verdict(ActionDecision.HOLD, flags, f"SRA-RiskGate cannot approve this transaction: {why}",
                    ["manual_review"])


def check_transaction(
    tx: Mapping[str, Any],
    *,
    chain_id: Optional[int] = None,
    sender: Optional[str] = None,
    **policy: Any,
) -> RiskAssessment:
    """Check a transaction before the agent signs it. Never raises; anything unexpected becomes HOLD.

    ``tx`` is the transaction as you would pass it to your wallet or web3.py: ``to``, ``data``
    (or ``input``), optional ``value``, ``from`` and ``chainId``. ``chain_id`` and ``sender``
    default to ``tx["chainId"]`` and ``tx["from"]``; if both are given they must agree.

    Only a USDC ``transfer`` with no native value is decoded and passed to ``check_payment``, with
    every keyword in ``policy`` (``known_recipients``, ``blocked_addresses``, ``max_amount``,
    ``untrusted_request``, ``peg_deviation_pct``, ...). Everything else is HOLD:

    * ``TOKEN_APPROVAL`` for ``approve``, ``increaseAllowance`` and ``permit`` (plus
      ``UNLIMITED_APPROVAL`` for an effectively unlimited amount): an allowance lets someone else
      move the wallet's USDC later, the usual way agent wallets are drained.
    * ``UNSUPPORTED_FUNCTION`` for any other USDC function (``transferFrom``,
      ``transferWithAuthorization``, ...).
    * ``UNSUPPORTED_ASSET`` when ``to`` is not the USDC contract on that chain.
    * ``NATIVE_VALUE_TRANSFER`` when the transaction moves native ETH.
    * ``CODE_DELEGATION`` for an EIP-7702 (type 4) transaction, or any transaction carrying an
      ``authorizationList``: it delegates the whole account to contract code. Checked first, so a clean
      transfer cannot carry a delegation through. Standalone authorizations: ``check_delegation``.

    On Arc (5042, testnet 5042002) USDC is the native asset, so a plain native send (value, no
    calldata) to an address is a USDC payment: its value is read with 18 decimals, rounded up to a whole
    micro-USDC, and passed to ``check_payment`` like a ``transfer``. Native value sent together with a contract call is held.
    * ``UNSUPPORTED_CHAIN``, ``INVALID_TRANSACTION`` (missing or malformed fields) and
      ``TRANSACTION_MISMATCH`` (``from`` or ``chainId`` disagree with the arguments).

    Only sign the transaction if ``result.decision`` is ``ActionDecision.APPROVE``.
    """
    unknown = sorted(set(policy) - _POLICY_KEYS)
    if unknown:
        return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                        f"The risk gate is misconfigured: unknown argument(s) {', '.join(unknown)}.",
                        ["fix_configuration"])
    try:
        if not isinstance(tx, Mapping):
            return _hold(["INVALID_TRANSACTION"], "the transaction is not a mapping.")
        # EIP-7702 (type 4): the authorization list delegates the account to contract code. It is checked
        # before anything else, because the rest of the transaction can be a perfectly clean transfer.
        tx_type = tx.get("type")
        auths = next((tx.get(k) for k in _DELEGATION_KEYS if tx.get(k) is not None), None)
        is_type_4 = str(tx_type).strip().lower() in ("4", "0x4", "0x04")
        if isinstance(auths, (list, tuple)) and not auths and not is_type_4:
            auths = None  # an empty list on an ordinary transaction delegates nothing
        if auths is not None or is_type_4:
            listed = auths if isinstance(auths, (list, tuple)) else ([auths] if auths else [])
            what = "; ".join(_describe_delegation(a) for a in listed) or "with an unreadable authorization list"
            return _hold(["CODE_DELEGATION"],
                         f"it carries an EIP-7702 authorization that delegates this wallet's account {what}. "
                         f"That gives the contract control of everything the wallet holds, which is worse than "
                         f"any token approval; a person must approve it.")
        tx_from, tx_chain = tx.get("from"), tx.get("chainId", tx.get("chain_id"))
        if tx_chain is not None and not isinstance(tx_chain, bool):
            try:
                tx_chain = _int(tx_chain)
            except (TypeError, ValueError):
                return _hold(["INVALID_TRANSACTION"], f"chainId {tx_chain!r} is not a number.")
        if chain_id is not None and tx_chain is not None and chain_id != tx_chain:
            return _hold(["TRANSACTION_MISMATCH"], f"the transaction is for chain {tx_chain}, not {chain_id}.")
        if sender is not None and tx_from is not None and not _same(sender, tx_from):
            return _hold(["TRANSACTION_MISMATCH"], f"the transaction is from {tx_from}, not {sender}.")
        chain_id = chain_id if chain_id is not None else tx_chain
        sender = sender if sender is not None else tx_from
        if chain_id is None or sender is None:
            return _hold(["INVALID_TRANSACTION"], "the chain id and the sender are both required.")
        if isinstance(chain_id, bool) or chain_id not in USDC_ADDRESSES:
            return _hold(["UNSUPPORTED_CHAIN"], f"chain {chain_id!r} is not checked.")

        try:
            value = _int(tx.get("value"))
        except (TypeError, ValueError):
            return _hold(["INVALID_TRANSACTION"], f"value {tx.get('value')!r} is not an integer.")
        to = tx.get("to")
        raw = tx.get("data", tx.get("input"))
        if value != 0:
            if chain_id in NATIVE_USDC_CHAINS:
                # On Arc the native asset is USDC: a plain send to an address is a USDC payment.
                h = _hex(raw if raw is not None else "")
                if h is None:
                    return _hold(["INVALID_TRANSACTION"], "the calldata is not hex.")
                if h:
                    return _hold(["NATIVE_VALUE_TRANSFER"],
                                 "it sends native USDC together with a contract call, which is not checked.")
                if not to:
                    return _hold(["INVALID_TRANSACTION"], "it has no 'to' address (a contract deployment?).")
                if is_usdc(chain_id, to):
                    return _hold(["INVALID_TRANSACTION"],
                                 "it sends native USDC to the USDC contract itself, which is not a payment.")
                if value < 0:
                    return _hold(["INVALID_TRANSACTION"], "the value is negative.")
                # Round up to a whole micro-USDC (the ERC-20 interface's smallest unit), so no limit can
                # be passed by an amount that differs from it only below that precision.
                scale = 10 ** (NATIVE_USDC_DECIMALS - USDC_DECIMALS)
                micro = -(-value // scale)
                amount = float(Decimal(micro) / (Decimal(10) ** USDC_DECIMALS))
                return check_payment(chain_id=chain_id, sender=sender, recipient=to, amount=amount, **policy)
            return _hold(["NATIVE_VALUE_TRANSFER"], f"it sends {value} wei of native ETH, which is not checked.")

        if not to:
            return _hold(["INVALID_TRANSACTION"], "it has no 'to' address (a contract deployment?).")
        if not is_usdc(chain_id, to):
            return _hold(["UNSUPPORTED_ASSET"],
                         f"it calls {to}, which is not the USDC contract on chain {chain_id} "
                         f"({USDC_ADDRESSES[chain_id]}).")

        h = _hex(raw if raw is not None else "")
        if h is None or len(h) < 8:
            return _hold(["INVALID_TRANSACTION"], "the calldata is empty or not hex.")
        selector = h[:8]
        if selector in _APPROVALS:
            flags = ["TOKEN_APPROVAL"]
            why = f"it is {_APPROVALS[selector]}, which lets another address spend this wallet's USDC later."
            if selector != "d505accf" and len(h) == 8 + 128:
                spender, amount = _address_word(h[8:72]), int(h[72:136], 16)
                if amount >= _UNLIMITED:
                    flags.append("UNLIMITED_APPROVAL")
                    why += " The amount is effectively unlimited."
                if spender:
                    why += f" Spender: {spender}."
            return _hold(flags, why)
        if selector != TRANSFER:
            name = _OTHER.get(selector, f"function 0x{selector}")
            return _hold(["UNSUPPORTED_FUNCTION"], f"only USDC transfer() is checked; this is {name}.")

        decoded = decode_erc20_transfer(h)
        if decoded is None:
            return _hold(["INVALID_TRANSACTION"], "the transfer calldata is malformed or the wrong length.")
        recipient, atomic = decoded
        amount = float(Decimal(atomic) / (Decimal(10) ** USDC_DECIMALS))
        return check_payment(chain_id=chain_id, sender=sender, recipient=recipient, amount=amount, **policy)
    except Exception as e:  # fail closed: no error path may approve
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The transaction check failed ({type(e).__name__}), so it is held.", ["manual_review"])
