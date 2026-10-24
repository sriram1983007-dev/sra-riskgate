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

from sra_riskgate.chains import USDC_ADDRESSES, USDC_DECIMALS, is_usdc
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
        if value != 0:
            return _hold(["NATIVE_VALUE_TRANSFER"], f"it sends {value} wei of native ETH, which is not checked.")

        to = tx.get("to")
        if not to:
            return _hold(["INVALID_TRANSACTION"], "it has no 'to' address (a contract deployment?).")
        if not is_usdc(chain_id, to):
            return _hold(["UNSUPPORTED_ASSET"],
                         f"it calls {to}, which is not the USDC contract on chain {chain_id} "
                         f"({USDC_ADDRESSES[chain_id]}).")

        raw = tx.get("data", tx.get("input"))
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
