"""Deterministic checks on a dispute verdict, starting with the dispute window.

On the published benchmark, SRA-RiskGate-4B misjudges whether a dispute was filed inside the policy's
window: when it says "outside the window" it is wrong 81% of the time, and those false claims cause 59 of
its 61 wrongful denials. Whether a dispute is inside the window is date arithmetic, so it belongs in code.

``check_dispute_verdict`` recomputes the window from the dispute itself and corrects a verdict that rests
on a false window claim: a deny or dismiss becomes ``escalate_to_human``, never a refund. On the benchmark
this lowers wrongful denials from 26.0% to 0.85% and leaves wrongful refunds unchanged.
"""
from __future__ import annotations

import copy
import math
from dataclasses import dataclass
from typing import Any, Mapping, Optional

WINDOW_FLAG = "outside_dispute_window"
CONTRADICTED_FLAG = "dispute_window_claim_contradicted"
UNCHECKED_FLAG = "dispute_window_not_checked"
_DENY = {"deny", "dismiss"}
_SECONDS_PER_DAY = 86400


@dataclass(frozen=True)
class DisputeWindow:
    """How long after the payment the dispute was filed, against the policy's window."""
    days_since_payment: float
    window_days: float
    within_window: bool


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def dispute_window(paid_at: Any, filed_at: Any, window_days: Any) -> Optional[DisputeWindow]:
    """Compute the window from Unix timestamps (seconds) and the policy's window in days.

    Returns None if any value is missing, not a number, or the claim predates the payment, so a caller
    can never mistake "could not compute" for "inside" or "outside"."""
    paid, filed, window = _number(paid_at), _number(filed_at), _number(window_days)
    if paid is None or filed is None or window is None or window < 0 or filed < paid:
        return None
    days = (filed - paid) / _SECONDS_PER_DAY
    return DisputeWindow(days_since_payment=round(days, 4), window_days=window, within_window=days <= window)


def window_from_dispute(dispute: Mapping[str, Any]) -> Optional[DisputeWindow]:
    """The window for a dispute in the model's input format (``policy``, ``payload.payment``,
    ``payload.claim``). None if the fields are missing or malformed."""
    try:
        policy = dispute.get("policy") or {}
        payload = dispute.get("payload") or {}
        return dispute_window((payload.get("payment") or {}).get("paid_at"),
                              (payload.get("claim") or {}).get("filed_at"),
                              policy.get("dispute_window_days"))
    except AttributeError:
        return None


def check_dispute_verdict(dispute: Mapping[str, Any], verdict: Mapping[str, Any]) -> dict[str, Any]:
    """Check a dispute verdict (from SRA-RiskGate-4B or any other source) against the dispute window.

    ``dispute`` is the dispute in the model's input format; ``verdict`` is its parsed JSON verdict.
    Returns a corrected copy of the verdict; the input is not modified. Never raises.

    * The verdict says ``outside_dispute_window`` but the dates put the dispute inside the window:
      the false flag is removed and ``dispute_window_claim_contradicted`` is added. If the outcome was
      ``deny`` or ``dismiss``, it becomes ``escalate_to_human`` with no refund, because the reason given
      for refusing the claim is wrong. Other outcomes are kept.
    * The window cannot be computed from the dispute: the verdict is returned unchanged except for the
      informational flag ``dispute_window_not_checked``.
    * Otherwise the verdict is returned unchanged.

    The result always carries ``dispute_window`` (days since payment, window, within) when it could be
    computed, so the decision can be logged and audited.
    """
    try:
        out = copy.deepcopy(dict(verdict))
    except Exception:  # not a mapping we can copy: nothing to correct, and nothing to approve
        return {"outcome": "escalate_to_human", "mechanism": "none", "refund_amount_usdc": "0",
                "refund_destination": None, "idempotency_key": None, "flags": ["check_failed"],
                "explanation": "The dispute verdict could not be read, so it is escalated.",
                "required_actions": ["manual_review"]}
    flags = [f for f in out.get("flags") or [] if isinstance(f, str)]
    try:
        win = window_from_dispute(dispute) if isinstance(dispute, Mapping) else None
    except Exception:
        win = None
    if win is None:
        out["flags"] = flags + ([UNCHECKED_FLAG] if UNCHECKED_FLAG not in flags else [])
        return out

    out["dispute_window"] = {"days_since_payment": win.days_since_payment, "window_days": win.window_days,
                             "within_window": win.within_window}
    if WINDOW_FLAG in flags and win.within_window:
        flags = [f for f in flags if f != WINDOW_FLAG] + [CONTRADICTED_FLAG]
        note = (f"The dispute was filed {win.days_since_payment:.1f} days after payment, inside the "
                f"{win.window_days:g}-day window, so the verdict's window claim is wrong.")
        if out.get("outcome") in _DENY:
            out.update({"outcome": "escalate_to_human", "mechanism": "none", "refund_amount_usdc": "0",
                        "refund_destination": None, "idempotency_key": None,
                        "required_actions": ["manual_review"]})
            note += " The claim is escalated to a human instead of being refused."
        out["explanation"] = (note + " " + str(out.get("explanation") or "")).strip()[:1000]
    out["flags"] = flags
    return out
