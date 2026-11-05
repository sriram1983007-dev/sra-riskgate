"""Check the approvals an agent has already granted: the risk in a pull payment lives there.

A subscription charge, a loan repayment or any other pull payment is taken by the spender's contract with
``transferFrom``. The agent signs nothing at that moment, so there is nothing for a pre-sign gate to stop. What the
agent signed earlier is the approval, and the allowance it left behind is what the spender can still take.

``check_allowances(owner, {spender: allowance, ...})`` checks those standing allowances. Read each one yourself
with the token's ``allowance(owner, spender)`` (the SDK stays offline) and pass the raw values. Run it on a
schedule, and after every approval the agent signs.

Holds (``HOLD``): an effectively unlimited allowance (``UNLIMITED_ALLOWANCE``), one above your ``max_allowance``
(``ALLOWANCE_ABOVE_LIMIT``), and, when you list ``expected_spenders``, any allowance to another address
(``UNKNOWN_SPENDER``). Rejects: a spender on the OFAC SDN snapshot or your ``blocked_addresses``
(``SANCTIONED_SPENDER``, ``BLOCKLISTED_SPENDER``): revoke those now. A zero allowance is never a finding.
Anything malformed is held, never approved.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping, Optional

from sra_riskgate.chains import stablecoin
from sra_riskgate.check import _verdict
from sra_riskgate.models import ActionDecision, RiskAssessment
from sra_riskgate.sanctions import SanctionsList, _normalise

UNLIMITED_FROM = 2**255  # an allowance this large is effectively unlimited (max uint256 is 2**256 - 1)


def _raw(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean")
    if isinstance(value, int):
        n = value
    else:
        s = str(value).strip().lower()
        n = int(s, 16) if s.startswith("0x") else int(s)
    if n < 0 or n >= 2**256:
        raise ValueError("out of uint256 range")
    return n


def _trim(s: str) -> str:
    """Drop trailing zeros after the decimal point only: "100" stays "100", "0.0100" becomes "0.01"."""
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def _fmt(units: int, decimals: int) -> str:
    return _trim(f"{Decimal(units) / (Decimal(10) ** decimals):f}")


def check_allowances(
    owner: str,
    allowances: Mapping[str, Any],
    *,
    decimals: int = 6,
    symbol: str = "USDC",
    token: Optional[str] = None,
    chain_id: Optional[int] = None,
    max_allowance: Optional[Any] = None,
    expected_spenders: Optional[Iterable[str]] = None,
    blocked_addresses: Optional[Iterable[str]] = None,
    sanctions_list: Optional[SanctionsList] = None,
) -> RiskAssessment:
    """Check the standing allowances ``owner`` has granted, as ``{spender: raw allowance}``.

    Args:
        owner: The agent's wallet.
        allowances: Each spender with the raw value its ``allowance(owner, spender)`` returned now (an int, a
            decimal string or a 0x hex string, as an RPC returns it).
        decimals, symbol: The token's ``decimals()`` (USDC and USDG use 6) and a name for the explanation.
        token, chain_id: Instead, a named stablecoin and its chain (``token="USDT", chain_id=1``): decimals and
            symbol come from ``chains.STABLECOINS``.
        max_allowance: The most any single spender may be allowed, in whole tokens (for example ``"50"``).
        expected_spenders: The contracts the agent is meant to have approved (a lender, a subscription
            contract). Any allowance to another address is held.
        blocked_addresses: Spenders that must never hold an allowance.

    Returns APPROVE when nothing needs attention, HOLD when an allowance should be reduced or reviewed, and REJECT
    when a sanctioned or blocked spender can pull funds; the explanation names each spender and what to do.
    """
    try:
        try:
            if token is not None:
                _, decimals = stablecoin(token, chain_id)
                symbol = str(token).strip().upper()
            if isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 36:
                raise ValueError(f"decimals {decimals!r} must be a whole number from 0 to 36")
            if _normalise(owner) is None:
                raise ValueError(f"owner {owner!r} is not an address")
            if not isinstance(allowances, Mapping) or not allowances:
                raise ValueError("allowances must be a non-empty mapping of spender to allowance")
            limit = None
            if max_allowance is not None:
                d = Decimal(str(max_allowance)) * (Decimal(10) ** decimals)
                if not d.is_finite() or d < 0 or d != d.to_integral_value():
                    raise ValueError(f"max_allowance {max_allowance!r} must be a non-negative {symbol} amount")
                limit = int(d)
            expected = None
            if expected_spenders is not None:
                expected = {_normalise(a) for a in expected_spenders}
                if None in expected:
                    raise ValueError("expected_spenders must all be addresses")
            blocked = set()
            if blocked_addresses is not None:
                blocked = {_normalise(a) for a in blocked_addresses}
                if None in blocked:
                    raise ValueError("blocked_addresses must all be addresses")
            rows = []
            for spender, value in allowances.items():
                s = _normalise(spender)
                if s is None:
                    raise ValueError(f"spender {spender!r} is not an address")
                rows.append((s, _raw(value)))
        except (ValueError, TypeError, InvalidOperation) as e:
            return _verdict(ActionDecision.HOLD, ["CONFIGURATION_ERROR"],
                            f"The allowances could not be checked: {e}.", ["manual_review"])

        sanctions = sanctions_list or SanctionsList.bundled()
        flags: list = []
        rejects, holds = [], []
        for s, n in rows:
            if n == 0:
                continue
            shown = "unlimited" if n >= UNLIMITED_FROM else f"{_fmt(n, decimals)} {symbol}"
            if s in sanctions:
                flags.append("SANCTIONED_SPENDER")
                rejects.append(f"{s} (allowed {shown}) is on the OFAC SDN list")
            if s in blocked:
                flags.append("BLOCKLISTED_SPENDER")
                rejects.append(f"{s} (allowed {shown}) is on your blocklist")
            if n >= UNLIMITED_FROM:
                flags.append("UNLIMITED_ALLOWANCE")
                holds.append(f"{s} may take the whole {symbol} balance at any time (unlimited allowance)")
            elif limit is not None and n > limit:
                flags.append("ALLOWANCE_ABOVE_LIMIT")
                holds.append(f"{s} may take {shown}, above your {_fmt(limit, decimals)} {symbol} limit")
            if expected is not None and s not in expected:
                flags.append("UNKNOWN_SPENDER")
                holds.append(f"{s} may take {shown} but is not one of your expected spenders")
        flags = list(dict.fromkeys(flags))
        if rejects:
            return _verdict(ActionDecision.REJECT, flags,
                            "Revoke now: " + "; ".join(rejects) + ". Set the allowance to 0 with approve(spender, 0).",
                            ["revoke_allowance"])
        if holds:
            return _verdict(ActionDecision.HOLD, flags,
                            "Review these standing allowances: " + "; ".join(holds) + ". A pull payment needs no new "
                            "signature, so reduce each one to what is actually due, or to 0.", ["reduce_allowance"])
        live = sum(1 for _, n in rows if n)
        return _verdict(ActionDecision.APPROVE, [],
                        f"{live} of {len(rows)} spender(s) hold an allowance, all within your limits.", [])
    except Exception as e:  # fail closed
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The allowance check failed ({type(e).__name__}), so it is held.", ["manual_review"])
