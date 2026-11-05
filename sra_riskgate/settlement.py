"""Check what actually settled: a payment the gate approved is not a receipt until the chain says so.

The other checks run before signing. These run after settlement, on data you already fetched, and say whether
exactly the approved payment arrived:

- ``verify_settlement(receipt, ...)`` reads a mined transaction receipt (``eth_getTransactionReceipt``): it must
  have succeeded and contain exactly one USDC ``Transfer`` from the payer to the payee for exactly the approved
  amount, and, for an EIP-3009 / x402 payment, the ``AuthorizationUsed`` event for the authorization's nonce.
  Works for a plain transfer, an x402 settlement, a facilitator's batch and an ERC-4337 bundle alike, because
  only the payer's own USDC events are read.
- ``verify_gateway_balances(...)`` checks a Circle Gateway payment, which settles off the payer's transaction
  in a batch: the payer's Gateway balance must have gone down, and the payee's up, by at least the amount.

Neither function calls an RPC or an API: you pass in the receipt or the balances. Both fail closed: anything
missing, malformed or unexpected is reported as not verified, with a flag saying why.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, List, Mapping, Optional

from pydantic import BaseModel, Field

from sra_riskgate.chains import STABLECOINS, USDC_ADDRESSES, USDC_DECIMALS, stablecoin

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
AUTHORIZATION_USED_TOPIC = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
_MICRO = Decimal(10) ** USDC_DECIMALS


class SettlementCheck(BaseModel):
    """The result of a post-settlement check. ``verified`` is True only when every condition held."""
    verified: bool
    flags: List[str] = Field(default_factory=list)
    explanation: str
    block_number: Optional[int] = None
    transfers: List[dict] = Field(default_factory=list)


def _fail(flag: str, why: str, **extra: Any) -> SettlementCheck:
    return SettlementCheck(verified=False, flags=[flag], explanation=f"Not verified: {why}", **extra)


def _hex(v: Any) -> str:
    """A hex string, lowercase, with 0x, from a str, bytes or HexBytes value."""
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    if hasattr(v, "hex") and not isinstance(v, str):
        h = v.hex()
        return (h if h.startswith("0x") else "0x" + h).lower()
    s = str(v).strip().lower()
    return s if s.startswith("0x") else "0x" + s


def _int(v: Any) -> int:
    if isinstance(v, bool):
        raise ValueError("boolean is not a number")
    if isinstance(v, int):
        return v
    s = _hex(v) if isinstance(v, (bytes, bytearray)) else str(v).strip().lower()
    return int(s, 16) if s.startswith("0x") else int(s)


def _address(v: Any) -> str:
    s = _hex(v)
    if len(s) != 42:
        raise ValueError(f"{v!r} is not a 20-byte address")
    int(s, 16)
    return s


def _topic_address(topic: Any) -> str:
    return "0x" + _hex(topic)[-40:]


def _trim(s: str) -> str:
    """Drop trailing zeros after the decimal point only: "100" stays "100", "0.0100" becomes "0.01"."""
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def _micro(amount: Any) -> int:
    try:
        d = Decimal(str(amount)) * _MICRO
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"amount {amount!r} is not a number")
    if not d.is_finite() or d <= 0 or d != d.to_integral_value():
        raise ValueError(f"amount {amount!r} must be a positive USDC amount with at most 6 decimals")
    return int(d)


def _usdc(micro: int) -> str:
    return _trim(f"{Decimal(micro) / _MICRO:f}")


def _units(amount: Any, decimals: int, symbol: str) -> int:
    try:
        d = Decimal(str(amount)) * (Decimal(10) ** decimals)
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"amount {amount!r} is not a number")
    if not d.is_finite() or d <= 0 or d != d.to_integral_value():
        raise ValueError(f"amount {amount!r} must be a positive {symbol} amount with at most {decimals} decimals")
    return int(d)


def _fmt(units: int, decimals: int) -> str:
    return _trim(f"{Decimal(units) / (Decimal(10) ** decimals):f}")


def verify_settlement(
    receipt: Any,
    *,
    chain_id: int,
    payer: str,
    payee: str,
    amount: Any,
    authorization_nonce: Optional[str] = None,
    allow_other_transfers: bool = False,
    token: Optional[str] = None,
    decimals: Optional[int] = None,
    symbol: Optional[str] = None,
) -> SettlementCheck:
    """Check a mined receipt for exactly the approved payment: USDC by default, or any ERC-20 you name.

    Args:
        receipt: The ``eth_getTransactionReceipt`` result, as JSON (hex strings) or as web3.py returns it.
        chain_id: The chain the payment was made on. For USDC: Base, Base Sepolia, Ethereum or Arc.
        payer, payee: The addresses the gate approved.
        amount: The approved amount in whole tokens (``0.01``, ``"25"`` or a ``Decimal``).
        authorization_nonce: For an EIP-3009 / x402 payment, the authorization's nonce: its
            ``AuthorizationUsed`` event must be in the receipt too.
        allow_other_transfers: Accept other transfers of the token out of the payer in the same transaction, such
            as a facilitator fee taken alongside the payment. Off by default: anything else the payer sent is reported.
        token, decimals: Check another token instead of USDC. Either a named stablecoin listed for that chain
            (``"USDT"``, ``"USDB"``, ``"USDG"``, ``"USDC"``: contract and decimals filled in, see
            ``chains.STABLECOINS``), or any ERC-20 by contract address together with its ``decimals()``, which you
            read from the token contract yourself. ``symbol`` only names the token in explanations.

    Flags when not verified: ``INVALID_RECEIPT``, ``UNSUPPORTED_CHAIN``, ``CONFIGURATION_ERROR``,
    ``SETTLEMENT_FAILED`` (the transaction reverted), ``SETTLEMENT_NOT_FOUND``, ``SETTLEMENT_AMOUNT_MISMATCH``,
    ``SETTLEMENT_PAYEE_MISMATCH``, ``DUPLICATE_SETTLEMENT``, ``UNEXPECTED_TRANSFER``, ``AUTHORIZATION_NOT_USED``.
    """
    try:
        try:
            payer_a, payee_a = _address(payer), _address(payee)
            if isinstance(token, str) and not token.strip().lower().startswith("0x"):
                named = token.strip().upper()
                addr, dec_known = stablecoin(named, chain_id)
                if decimals is not None and decimals != dec_known:
                    raise ValueError(f"{named} on chain {chain_id} has {dec_known} decimals, not {decimals}")
                token, decimals, symbol = addr, dec_known, symbol or named
            elif token is not None and decimals is None:
                listed = [(sym, d) for sym, by_chain in STABLECOINS.items() for cid, (a, d) in by_chain.items()
                          if cid == chain_id and a.lower() == str(token).strip().lower()]
                if listed:
                    symbol, decimals = symbol or listed[0][0], listed[0][1]
            if (token is None) != (decimals is None):
                raise ValueError("token and decimals must be given together")
            if token is not None:
                if isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 36:
                    raise ValueError(f"decimals {decimals!r} must be a whole number from 0 to 36")
                contract, dec, sym = _address(token), decimals, str(symbol or "tokens")
            else:
                contract, dec, sym = None, USDC_DECIMALS, "USDC"
            units = _units(amount, dec, sym)
            nonce = _hex(authorization_nonce) if authorization_nonce is not None else None
            if nonce is not None and len(nonce) != 66:
                raise ValueError("authorization_nonce must be 32 bytes of hex")
            if isinstance(chain_id, bool) or not isinstance(chain_id, int):
                raise ValueError(f"chain_id {chain_id!r} must be a number")
        except ValueError as e:
            return _fail("CONFIGURATION_ERROR", f"{e}.")
        if contract is None:
            if chain_id not in USDC_ADDRESSES:
                return _fail("UNSUPPORTED_CHAIN", f"chain {chain_id} has no known USDC contract; pass token= and "
                                                  f"decimals= to check another token.")
            contract = USDC_ADDRESSES[chain_id].lower()

        if not isinstance(receipt, Mapping) and not hasattr(receipt, "get"):
            return _fail("INVALID_RECEIPT", "the receipt is not a mapping.")
        status, logs = receipt.get("status"), receipt.get("logs")
        if status is None or not isinstance(logs, (list, tuple)):
            return _fail("INVALID_RECEIPT", "the receipt has no status or no logs.")
        try:
            block = _int(receipt.get("blockNumber")) if receipt.get("blockNumber") is not None else None
            ok = _int(status) == 1
        except ValueError:
            return _fail("INVALID_RECEIPT", "status or blockNumber is not a number.")
        if not ok:
            return _fail("SETTLEMENT_FAILED", "the transaction reverted, so nothing was paid.", block_number=block)

        sent: list = []
        nonce_used = False
        for lg in logs:
            try:
                if _hex(lg.get("address")) != contract:
                    continue
                topics = [_hex(t) for t in (lg.get("topics") or [])]
                if len(topics) == 3 and topics[0] == TRANSFER_TOPIC and _topic_address(topics[1]) == payer_a:
                    data = lg.get("data")
                    raw = _int(_hex(data) if data not in (None, "") else "0x0")
                    entry = {"from": payer_a, "to": _topic_address(topics[2]), "amount": _fmt(raw, dec),
                             "units": raw}
                    if sym == "USDC" and dec == USDC_DECIMALS:
                        entry["amount_usdc"] = entry["amount"]
                    sent.append(entry)
                elif (nonce is not None and len(topics) == 3 and topics[0] == AUTHORIZATION_USED_TOPIC
                      and _topic_address(topics[1]) == payer_a and topics[2] == nonce):
                    nonce_used = True
            except (AttributeError, TypeError, ValueError):
                return _fail("INVALID_RECEIPT", f"a {sym} log in the receipt could not be read.", block_number=block)

        public = [{k: v for k, v in t.items() if k != "units"} for t in sent]
        common = {"block_number": block, "transfers": public}
        want = _fmt(units, dec)
        to_payee = [t for t in sent if t["to"] == payee_a]
        exact = [t for t in to_payee if t["units"] == units]
        if not exact:
            if to_payee:
                got = ", ".join(t["amount"] for t in to_payee)
                return _fail("SETTLEMENT_AMOUNT_MISMATCH",
                             f"the payee received {got} {sym} from the payer, not the approved {want}.", **common)
            if sent:
                where = ", ".join(f"{t['amount']} {sym} to {t['to']}" for t in sent)
                return _fail("SETTLEMENT_PAYEE_MISMATCH",
                             f"the payer's {sym} went elsewhere ({where}), not to {payee_a}.", **common)
            return _fail("SETTLEMENT_NOT_FOUND",
                         f"the receipt has no {sym} transfer from {payer_a} at all.", **common)
        if len(exact) > 1:
            return _fail("DUPLICATE_SETTLEMENT",
                         f"the payee was paid {want} {sym} {len(exact)} times in this transaction.", **common)
        others = [t for t in sent if t is not exact[0]]
        if others and not allow_other_transfers:
            where = ", ".join(f"{t['amount']} {sym} to {t['to']}" for t in others)
            return _fail("UNEXPECTED_TRANSFER",
                         f"besides the approved payment the payer also sent {where} in the same transaction "
                         f"(pass allow_other_transfers=True if that is an expected fee).", **common)
        if nonce is not None and not nonce_used:
            return _fail("AUTHORIZATION_NOT_USED",
                         f"the payment is there, but not by the approved authorization: no AuthorizationUsed "
                         f"event for nonce {nonce}.", **common)
        where = f" in block {block}" if block is not None else ""
        return SettlementCheck(
            verified=True, flags=[], **common,
            explanation=(f"Verified: the transaction succeeded{where} and moved exactly {want} {sym} "
                         f"from {payer_a} to {payee_a}"
                         + (", by the approved authorization." if nonce is not None else ".")))
    except Exception as e:  # fail closed
        return _fail("INVALID_RECEIPT", f"the check failed ({type(e).__name__}).")


def verify_gateway_balances(
    *,
    amount: Any,
    payer_before: Any,
    payer_after: Any,
    payee_before: Any,
    payee_after: Any,
) -> SettlementCheck:
    """Check a Circle Gateway payment from Gateway balances read before and after it.

    Gateway settles batched payments later and together, so there is no single transaction to read. Read both
    balances from Gateway's ``/balances`` API before submitting the payment and again after it settles, and
    pass them here as USDC amounts (Gateway returns strings such as ``"0.080000"``). Verified when the payer's
    balance went down by at least ``amount`` and the payee's went up by at least ``amount``; other activity on
    either balance in between can only make the change larger, so "at least" is the safe test.

    Flags when not verified: ``CONFIGURATION_ERROR``, ``GATEWAY_PAYER_NOT_DEBITED``,
    ``GATEWAY_PAYEE_NOT_CREDITED`` (often just not settled yet: check again later).
    """
    try:
        try:
            micro = _micro(amount)
            pb, pa, qb, qa = (_micro_balance(x) for x in (payer_before, payer_after, payee_before, payee_after))
        except ValueError as e:
            return _fail("CONFIGURATION_ERROR", f"{e}.")
        debited, credited = pb - pa, qa - qb
        if debited < micro:
            return _fail("GATEWAY_PAYER_NOT_DEBITED",
                         f"the payer's Gateway balance went from {_usdc(pb)} to {_usdc(pa)} USDC, down by "
                         f"{_usdc(max(debited, 0))}, less than the {_usdc(micro)} paid.")
        if credited < micro:
            return _fail("GATEWAY_PAYEE_NOT_CREDITED",
                         f"the payee's Gateway balance went from {_usdc(qb)} to {_usdc(qa)} USDC, up by "
                         f"{_usdc(max(credited, 0))}, less than the {_usdc(micro)} paid. If the payer was "
                         f"debited, Gateway has probably not settled the batch yet: check again later.")
        return SettlementCheck(
            verified=True, flags=[],
            explanation=(f"Verified: payer {_usdc(pb)} to {_usdc(pa)} USDC, payee {_usdc(qb)} to {_usdc(qa)} USDC, "
                         f"both moved by at least the {_usdc(micro)} USDC paid."))
    except Exception as e:  # fail closed
        return _fail("CONFIGURATION_ERROR", f"the check failed ({type(e).__name__}).")


def _micro_balance(v: Any) -> int:
    try:
        d = Decimal(str(v).split()[0]) * _MICRO
    except (InvalidOperation, ValueError, TypeError, IndexError):
        raise ValueError(f"balance {v!r} is not a number")
    if not d.is_finite() or d < 0 or d != d.to_integral_value():
        raise ValueError(f"balance {v!r} must be a non-negative USDC amount with at most 6 decimals")
    return int(d)
