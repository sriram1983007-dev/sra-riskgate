import math
from typing import Optional

from sra_riskgate.models import ActionDecision, RiskAssessment, TransactionPayload
from sra_riskgate.sanctions import FLAG as SANCTIONS_FLAG, NOT_CHECKED_FLAG, SanctionsList

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
    """

    def __init__(
        self,
        max_amount: float = 50_000.0,
        depeg_hold_pct: float = 1.0,
        depeg_reject_pct: float = 5.0,
        *,
        check_sanctions: bool = True,
        sanctions_list: Optional[SanctionsList] = None,
        **kwargs,
    ):
        unknown = set(kwargs) - _LEGACY_KWARGS
        if unknown:
            raise TypeError(
                f"Unknown argument(s): {', '.join(sorted(unknown))}. "
                "Valid arguments: max_amount, depeg_hold_pct, depeg_reject_pct, check_sanctions, sanctions_list."
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

    def inspect(self, payload: TransactionPayload) -> RiskAssessment:
        sanctioned = self.screen_sanctions(payload.sender, payload.recipient)
        if sanctioned is not None:
            return sanctioned

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

        if not payload.peg_observed:
            # No peg data is not the same as a perfect peg: say so explicitly.
            flags.append("PEG_NOT_CHECKED")
            reasons.append("No peg deviation supplied, so the depeg check was skipped.")
        if not self.check_sanctions:
            flags.append(NOT_CHECKED_FLAG)
            reasons.append("Sanctions matching is turned off for this gate.")

        notes = ("PEG_NOT_CHECKED", NOT_CHECKED_FLAG)
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
                        + ("" if self.check_sanctions else " Sanctions matching is turned off."),
            required_actions=[],
        )


class RiskGate(RulePreFilter):
    """Alias kept for backwards compatibility. Same as RulePreFilter."""
