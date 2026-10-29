import math
from datetime import date
from decimal import Decimal
from typing import Iterable, Optional

from sra_riskgate.models import ActionDecision, RiskAssessment, TransactionPayload
from sra_riskgate.counterparty import (BLOCKLIST_FLAG, LOOKALIKE_FLAG, NEW_COUNTERPARTY_FLAG, find_lookalike, merge,
                                       parse_address_list)
from sra_riskgate.sanctions import FLAG as SANCTIONS_FLAG, NOT_CHECKED_FLAG, SanctionsList, _normalise

ROUND_AMOUNT_FLAG = "ROUND_AMOUNT"
DEFAULT_ROUND_AMOUNT_THRESHOLD = 10_000.0
STALE_SANCTIONS_FLAG = "SANCTIONS_LIST_STALE"
DEFAULT_SANCTIONS_MAX_AGE_DAYS = 90


def _today() -> date:
    """Today's date. A separate function so tests can replace it."""
    return date.today()


def _parse_as_of(as_of: object) -> Optional[date]:
    try:
        return date.fromisoformat(str(as_of))
    except ValueError:
        return None


def _is_whole(amount: float) -> bool:
    d = Decimal(str(amount))
    return d.is_finite() and d == d.to_integral_value()

# Legacy keyword names accepted for backwards compatibility.
# In 0.1.x, `max_allowed_deviation_pct` was the HOLD threshold (reject was fixed at 5%).
_LEGACY_KWARGS = {
    "max_amount_usdc",              # 0.1.x / 0.2.0  -> max_amount
    "max_allowed_deviation_pct",    # 0.1.x / 0.2.0  -> depeg_hold_pct
    "depeg_hold_threshold_pct",     # 0.2.3 (signed) -> depeg_hold_pct
    "depeg_reject_threshold_pct",   # 0.2.3 (signed) -> depeg_reject_pct
}


class RulePreFilter:
    """Deterministic rule-based pre-filter for stablecoin transactions.

    This is NOT the SRA-RiskGate-4B model. It is a fast, zero-dependency first pass
    (OFAC SDN address match, depeg bounds, amount ceiling, payload validation) to run before the model.

    Sanctions: by default sender and recipient are matched against the bundled OFAC SDN snapshot
    (see ``sra_riskgate.sanctions``); a match is a REJECT. Pass ``sanctions_list`` to use a fresher
    list, or ``check_sanctions=False`` to turn the match off (results then carry SANCTIONS_NOT_CHECKED).

    Round amounts: a whole-number amount at or above ``round_amount_threshold`` (default 10,000 USDC)
    adds the informational flag ROUND_AMOUNT. It never changes the decision. Pass
    ``round_amount_threshold=None`` to turn it off.

    Counterparty policy (see ``sra_riskgate.counterparty``): ``blocked_addresses`` makes any payment
    from or to a listed address a REJECT (BLOCKLISTED_ADDRESS). ``known_recipients``, when given,
    makes a payment to any other recipient a HOLD (NEW_COUNTERPARTY). Both default to None (off);
    an empty ``known_recipients`` holds every payment. A recipient that is not known but shares the first and
    last characters of a known payee is a REJECT (LOOKALIKE_RECIPIENT): address poisoning.

    Sanctions-list age: if the list's ``as_of`` date is more than ``sanctions_max_age_days`` (default
    90) days old, results carry the informational flag SANCTIONS_LIST_STALE. It never changes the
    decision. Lists with no parseable ``as_of`` date are not flagged. Pass None to turn it off.
    """

    def __init__(
        self,
        max_amount: float = 50_000.0,
        depeg_hold_pct: float = 1.0,
        depeg_reject_pct: float = 5.0,
        *,
        check_sanctions: bool = True,
        sanctions_list: Optional[SanctionsList] = None,
        round_amount_threshold: Optional[float] = DEFAULT_ROUND_AMOUNT_THRESHOLD,
        blocked_addresses: Optional[Iterable[str]] = None,
        known_recipients: Optional[Iterable[str]] = None,
        sanctions_max_age_days: Optional[int] = DEFAULT_SANCTIONS_MAX_AGE_DAYS,
        **kwargs,
    ):
        unknown = set(kwargs) - _LEGACY_KWARGS
        if unknown:
            raise TypeError(
                f"Unknown argument(s): {', '.join(sorted(unknown))}. "
                "Valid arguments: max_amount, depeg_hold_pct, depeg_reject_pct, check_sanctions, sanctions_list, "
                "round_amount_threshold, blocked_addresses, known_recipients, sanctions_max_age_days."
            )

        if "max_amount_usdc" in kwargs:
            max_amount = kwargs["max_amount_usdc"]
        if "max_allowed_deviation_pct" in kwargs:
            depeg_hold_pct = abs(kwargs["max_allowed_deviation_pct"])
        if "depeg_hold_threshold_pct" in kwargs:
            depeg_hold_pct = abs(kwargs["depeg_hold_threshold_pct"])
        if "depeg_reject_threshold_pct" in kwargs:
            depeg_reject_pct = abs(kwargs["depeg_reject_threshold_pct"])

        for name, val in (("max_amount", max_amount),
                          ("depeg_hold_pct", depeg_hold_pct),
                          ("depeg_reject_pct", depeg_reject_pct)):
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
                raise ValueError(f"{name} must be a finite number, got {val!r}.")
        if max_amount <= 0:
            raise ValueError("max_amount must be strictly greater than 0.")
        if not (0 < depeg_hold_pct < depeg_reject_pct):
            raise ValueError("Thresholds must satisfy 0 < depeg_hold_pct < depeg_reject_pct.")

        if not isinstance(check_sanctions, bool):
            raise ValueError(f"check_sanctions must be True or False, got {check_sanctions!r}.")
        if sanctions_list is not None and not isinstance(sanctions_list, SanctionsList):
            raise ValueError("sanctions_list must be a SanctionsList (see SanctionsList.from_file).")
        if round_amount_threshold is not None and (
                isinstance(round_amount_threshold, bool) or not isinstance(round_amount_threshold, (int, float))
                or not math.isfinite(round_amount_threshold) or round_amount_threshold <= 0):
            raise ValueError("round_amount_threshold must be a positive finite number or None, "
                             f"got {round_amount_threshold!r}.")
        self.round_amount_threshold = None if round_amount_threshold is None else float(round_amount_threshold)
        if sanctions_max_age_days is not None and (
                isinstance(sanctions_max_age_days, bool) or not isinstance(sanctions_max_age_days, int)
                or sanctions_max_age_days <= 0):
            raise ValueError("sanctions_max_age_days must be a positive whole number of days or None, "
                             f"got {sanctions_max_age_days!r}.")
        self.sanctions_max_age_days = sanctions_max_age_days
        self.blocked_addresses = parse_address_list("blocked_addresses", blocked_addresses)
        self.known_recipients = parse_address_list("known_recipients", known_recipients)
        self.check_sanctions = check_sanctions
        self._sanctions_list = sanctions_list

        self.max_amount = float(max_amount)
        self.depeg_hold_pct = float(depeg_hold_pct)
        self.depeg_reject_pct = float(depeg_reject_pct)

    @property
    def sanctions_list(self) -> Optional[SanctionsList]:
        """The list used for matching (the bundled snapshot unless one was supplied); None if disabled."""
        if not self.check_sanctions:
            return None
        return self._sanctions_list or SanctionsList.bundled()

    def screen_sanctions(self, sender: object, recipient: object) -> Optional[RiskAssessment]:
        """A REJECT if sender or recipient is on the sanctions list, else None. Raises if the list cannot load."""
        lst = self.sanctions_list
        if lst is None:
            return None
        hits = lst.screen(sender, recipient)
        if not hits:
            return None
        who = " and ".join(f"{party} {addr}" for party, addr in hits)
        return RiskAssessment(
            decision=ActionDecision.REJECT,
            risk_score=1.0,
            flags=[SANCTIONS_FLAG] + [f"SANCTIONED_{party.upper()}" for party, _ in hits],
            explanation=(f"The {who} is on the OFAC SDN list ({lst.describe()}). Do not pay. "
                         "This is an exact address match, not a compliance determination; "
                         "refer it to your compliance process."),
            required_actions=["reject_payment", "refer_to_compliance"],
        )

    def screen_blocklist(self, sender: object, recipient: object,
                         blocked_addresses: Optional[Iterable[str]] = None) -> Optional[RiskAssessment]:
        """A REJECT if sender or recipient is on this gate's or the given blocklist, else None."""
        blocked = merge(self.blocked_addresses, parse_address_list("blocked_addresses", blocked_addresses))
        if not blocked:
            return None
        hits = []
        for party, addr in (("recipient", recipient), ("sender", sender)):
            n = _normalise(addr)
            if n is not None and n in blocked:
                hits.append((party, n))
        if not hits:
            return None
        who = " and ".join(f"{party} {addr}" for party, addr in hits)
        return RiskAssessment(
            decision=ActionDecision.REJECT,
            risk_score=1.0,
            flags=[BLOCKLIST_FLAG] + [f"BLOCKLISTED_{party.upper()}" for party, _ in hits],
            explanation=f"The {who} is on your blocked_addresses list. Do not pay.",
            required_actions=["reject_payment"],
        )

    def sanctions_list_age_days(self) -> Optional[int]:
        """Days since the sanctions list's as_of date, or None if matching is off or the date is unknown."""
        lst = self.sanctions_list
        as_of = _parse_as_of(lst.as_of) if lst is not None else None
        return None if as_of is None else (_today() - as_of).days

    def inspect(self, payload: TransactionPayload, *,
                known_recipients: Optional[Iterable[str]] = None,
                blocked_addresses: Optional[Iterable[str]] = None) -> RiskAssessment:
        """Apply the rules. ``known_recipients`` and ``blocked_addresses`` add to this gate's own lists."""
        sanctioned = self.screen_sanctions(payload.sender, payload.recipient)
        if sanctioned is not None:
            return sanctioned
        blocked = self.screen_blocklist(payload.sender, payload.recipient, blocked_addresses)
        if blocked is not None:
            return blocked
        known = merge(self.known_recipients, parse_address_list("known_recipients", known_recipients))
        lookalike = find_lookalike(payload.recipient, known)
        if lookalike is not None:
            imitated, prefix, suffix = lookalike
            r = payload.recipient.lower()
            return RiskAssessment(
                decision=ActionDecision.REJECT,
                risk_score=0.95,
                flags=[LOOKALIKE_FLAG],
                explanation=(f"The recipient {payload.recipient} is not one of your known payees, but it imitates "
                             f"{imitated}: both start 0x{r[2:2 + prefix]} and end {r[-suffix:]}. This is the pattern "
                             f"of address poisoning, where an attacker plants a look-alike address in the wallet's "
                             f"history. Do not pay; take the payee's address from your own records."),
                required_actions=["reject_payment", "verify_recipient"],
            )

        peg_dev = payload.peg_deviation_pct if payload.peg_deviation_pct is not None else 0.0

        if not math.isfinite(peg_dev):
            return RiskAssessment(
                decision=ActionDecision.REJECT,
                risk_score=1.0,
                flags=["INVALID_PEG_VALUE"],
                explanation="Peg deviation percentage is NaN or infinite.",
                required_actions=["reject_payment"],
            )

        dev_mag = abs(peg_dev)

        if dev_mag >= self.depeg_reject_pct:
            return RiskAssessment(
                decision=ActionDecision.REJECT,
                risk_score=0.95,
                flags=["CRITICAL_DEPEG_EVENT"],
                explanation=f"Peg deviation magnitude {dev_mag}% meets or exceeds rejection ceiling {self.depeg_reject_pct}%.",
                required_actions=["reject_payment", "halt_clearing"],
            )

        flags, reasons = [], []
        if dev_mag >= self.depeg_hold_pct:
            flags.append("MODERATE_DEPEG")
            reasons.append(f"Peg deviation magnitude {dev_mag}% meets or exceeds hold threshold {self.depeg_hold_pct}%.")
        if payload.amount > self.max_amount:
            flags.append("HIGH_VALUE_TRANSFER")
            reasons.append(f"Transfer amount {payload.amount} exceeds single-transaction ceiling {self.max_amount}.")
        round_note = ""
        if (self.round_amount_threshold is not None and payload.amount >= self.round_amount_threshold
                and _is_whole(payload.amount)):
            # Informational only: it never changes the decision (see `notes` below).
            flags.append(ROUND_AMOUNT_FLAG)
            round_note = (f"Round amount of {payload.amount:g} USDC (a whole number at or above "
                          f"{self.round_amount_threshold:g}): large round-number transfers are a common "
                          "transaction-monitoring signal. Informational only; many such payments, such as "
                          "payroll or settlements, are legitimate.")
            reasons.append(round_note)

        if known is not None and payload.recipient.lower() not in known:
            flags.append(NEW_COUNTERPARTY_FLAG)
            reasons.append(f"First payment to {payload.recipient}: it is not in known_recipients. Confirm the "
                           "payee through a channel you control, not the payment request, before adding it.")
        age = self.sanctions_list_age_days() if self.sanctions_max_age_days is not None else None
        stale_note = ""
        if age is not None and age > self.sanctions_max_age_days:
            # Informational only: it never changes the decision (see `notes` below).
            flags.append(STALE_SANCTIONS_FLAG)
            stale_note = (f"The sanctions list is {age} days old (as of {self.sanctions_list.as_of}); "
                          "addresses designated since then are not matched. Load a fresher list.")
            reasons.append(stale_note)

        if not payload.peg_observed:
            # No peg data is not the same as a perfect peg: say so explicitly.
            flags.append("PEG_NOT_CHECKED")
            reasons.append("No peg deviation supplied, so the depeg check was skipped.")
        if not self.check_sanctions:
            flags.append(NOT_CHECKED_FLAG)
            reasons.append("Sanctions matching is turned off for this gate.")

        notes = ("PEG_NOT_CHECKED", NOT_CHECKED_FLAG, ROUND_AMOUNT_FLAG, STALE_SANCTIONS_FLAG)
        if any(f not in notes for f in flags):
            return RiskAssessment(
                decision=ActionDecision.HOLD,
                risk_score=0.65,
                flags=flags,
                explanation="; ".join(reasons),
                required_actions=["manual_review"],
            )

        return RiskAssessment(
            decision=ActionDecision.APPROVE,
            risk_score=0.05,
            flags=flags,
            explanation="Transaction conforms to standard deterministic pre-filter policies."
                        + ("" if payload.peg_observed else " Depeg check skipped: no peg data supplied.")
                        + ("" if self.check_sanctions else " Sanctions matching is turned off.")
                        + (f" {round_note}" if round_note else "")
                        + (f" {stale_note}" if stale_note else ""),
            required_actions=[],
        )


class RiskGate(RulePreFilter):
    """Alias kept for backwards compatibility. Same as RulePreFilter."""
