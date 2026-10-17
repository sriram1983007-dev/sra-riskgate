"""One-call, fail-closed payment check: validation, rules and the self-asserted claims scan together."""
from __future__ import annotations

from typing import Any, Optional

from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.client import RulePreFilter
from sra_riskgate.models import ActionDecision, RiskAssessment, TransactionPayload
from sra_riskgate.payload_claims import FLAG as CLAIMS_FLAG
from sra_riskgate.payload_claims import scan_payload_claims
from sra_riskgate.sanctions import SanctionsList

_SUPPORTED_CHAINS = ", ".join(f"{c}" for c in sorted(USDC_ADDRESSES))


def _verdict(decision: ActionDecision, flags: list, explanation: str, actions: list) -> RiskAssessment:
    score = {ActionDecision.APPROVE: 0.05, ActionDecision.HOLD: 0.65, ActionDecision.REJECT: 1.0}[decision]
    return RiskAssessment(decision=decision, risk_score=score, flags=flags,
                          explanation=explanation[:500], required_actions=actions)


def _first_error(e: Exception) -> str:
    errors = getattr(e, "errors", None)
    if callable(errors):
        try:
            return str(errors()[0]["msg"])
        except Exception:
            pass
    return str(e).splitlines()[0] if str(e) else type(e).__name__


def check_payment(
    *,
    chain_id: int,
    sender: str,
    recipient: str,
    amount: float,
    token: str = "USDC",
    untrusted_request: Any = None,
    peg_deviation_pct: Optional[float] = None,
    max_amount: float = 1_000.0,
    depeg_hold_pct: float = 1.0,
    depeg_reject_pct: float = 5.0,
    check_sanctions: bool = True,
    sanctions_list: Optional[SanctionsList] = None,
    gate: Optional[RulePreFilter] = None,
) -> RiskAssessment:
    """Check a USDC payment before sending it. Never raises on bad payment data; anything unexpected becomes HOLD.

    Runs, in order:
      1. Sanctions: sender or recipient on the OFAC SDN list gives REJECT (flag OFAC_SDN_MATCH).
         Uses the bundled snapshot unless ``sanctions_list`` is given; ``check_sanctions=False``
         turns it off. It is an exact address match against a dated snapshot, not a screening service.
      2. Supported asset and chain: USDC on Ethereum (1), Base (8453) or Base Sepolia (84532),
         otherwise HOLD.
      3. Validation: malformed, zero or self address, or a non-positive amount, gives REJECT.
      4. Rules (``RulePreFilter``): per-payment ceiling and, if ``peg_deviation_pct`` is given,
         depeg thresholds.
      5. Self-asserted claims in ``untrusted_request`` (the payment request, memo or description
         exactly as received), such as "risk level: low (verified offline)", give HOLD.
         Never pass your own verification results here: those legitimately say "verified".

    Only send the payment if ``result.decision`` is ``ActionDecision.APPROVE``.
    Pass ``gate`` to reuse a configured ``RulePreFilter``; the threshold and sanctions arguments are
    then ignored.
    """
    try:
        if gate is None:
            try:
                gate = RulePreFilter(max_amount=max_amount, depeg_hold_pct=depeg_hold_pct,
                                     depeg_reject_pct=depeg_reject_pct, check_sanctions=check_sanctions,
                                     sanctions_list=sanctions_list)
            except (TypeError, ValueError) as e:
                return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                                f"The risk gate is misconfigured: {_first_error(e)}", ["fix_configuration"])

        sanctioned = gate.screen_sanctions(sender, recipient)
        if sanctioned is not None:
            return sanctioned

        if not isinstance(token, str) or token.strip().upper() != "USDC":
            return _verdict(ActionDecision.HOLD, ["UNSUPPORTED_ASSET"],
                            f"Only USDC is checked; got {token!r}.", ["manual_review"])
        if isinstance(chain_id, bool) or chain_id not in USDC_ADDRESSES:
            return _verdict(ActionDecision.HOLD, ["UNSUPPORTED_CHAIN"],
                            f"Chain {chain_id!r} is not checked; supported chain ids: {_SUPPORTED_CHAINS}.",
                            ["manual_review"])

        if isinstance(amount, bool):  # True would otherwise be read as 1.0 USDC
            return _verdict(ActionDecision.REJECT, ["INVALID_PAYMENT"],
                            "Payment failed validation: amount must be a number, not a boolean.", ["reject_payment"])
        try:
            payload = TransactionPayload(chain_id=chain_id, token="USDC", sender=sender, recipient=recipient,
                                         amount=amount, peg_deviation_pct=peg_deviation_pct)
        except (TypeError, ValueError) as e:
            return _verdict(ActionDecision.REJECT, ["INVALID_PAYMENT"],
                            f"Payment failed validation: {_first_error(e)}", ["reject_payment"])

        result = gate.inspect(payload)
        if result.decision == ActionDecision.REJECT or untrusted_request is None:
            return result

        claims = scan_payload_claims(untrusted_request)
        if not claims:
            return result
        found = "; ".join(f"{c.rule}: {c.match!r}" for c in claims[:3])
        flags = [CLAIMS_FLAG] + [c.rule for c in claims] + [f for f in result.flags if f != CLAIMS_FLAG]
        why = f"The payment request claims its own verification ({found}). Real checks must come from your own tools."
        if result.decision == ActionDecision.HOLD:
            why += " Also: " + result.explanation
        return _verdict(ActionDecision.HOLD, flags, why, ["manual_review"])
    except Exception as e:  # fail closed: no error path may approve
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The payment check failed ({type(e).__name__}), so the payment is held.",
                        ["manual_review"])
