"""0.10.0: deterministic dispute-window check on dispute verdicts."""
import copy
import json

import pytest

from sra_riskgate import DisputeWindow, check_dispute_verdict, dispute_window

DAY = 86400


def dispute(days_after=26.5, window=60):
    return {"now": 1_800_000_000, "policy": {"dispute_window_days": window},
            "payload": {"payment": {"paid_at": 1_700_000_000, "amount_usdc": "10"},
                        "claim": {"reason": "not_delivered", "filed_at": 1_700_000_000 + int(days_after * DAY)}}}


def verdict(outcome="dismiss", flags=("outside_dispute_window",), **kw):
    v = {"outcome": outcome, "mechanism": "none", "settlement_state": "final", "refund_amount_usdc": "0",
         "refund_destination": None, "idempotency_key": None, "flags": list(flags),
         "explanation": "The dispute was filed 26.5 days after payment, outside the 60-day window.",
         "required_actions": ["close_dispute"]}
    v.update(kw)
    return v


# ------------------------------------------------------------------ the arithmetic
@pytest.mark.parametrize("days,window,inside", [(26.5, 60, True), (60, 60, True), (60.01, 60, False),
                                                (0, 30, True), (91, 90, False)])
def test_dispute_window(days, window, inside):
    w = dispute_window(1000, 1000 + days * DAY, window)
    assert isinstance(w, DisputeWindow) and w.within_window is inside and w.window_days == window


@pytest.mark.parametrize("args", [(None, 1, 30), (1, None, 30), (1, 2, None), ("1", 2, 30), (True, 2, 30),
                                  (10, 5, 30), (1, 2, -1), (1, float("nan"), 30), (1, float("inf"), 30)])
def test_window_cannot_be_computed(args):
    assert dispute_window(*args) is None


# ------------------------------------------------------------------ the correction
def test_false_window_dismissal_is_escalated_not_refunded():
    out = check_dispute_verdict(dispute(26.5, 60), verdict("dismiss"))
    assert out["outcome"] == "escalate_to_human" and out["mechanism"] == "none"
    assert out["refund_amount_usdc"] == "0" and out["refund_destination"] is None
    assert "outside_dispute_window" not in out["flags"] and "dispute_window_claim_contradicted" in out["flags"]
    assert out["required_actions"] == ["manual_review"]
    assert out["dispute_window"] == {"days_since_payment": 26.5, "window_days": 60, "within_window": True}
    assert out["explanation"].startswith("The dispute was filed 26.5 days after payment, inside the 60-day window")


def test_false_window_deny_is_escalated_too():
    assert check_dispute_verdict(dispute(10.5, 60), verdict("deny"))["outcome"] == "escalate_to_human"


def test_false_flag_on_another_outcome_keeps_the_outcome():
    out = check_dispute_verdict(dispute(5, 30), verdict("await_merchant_response"))
    assert out["outcome"] == "await_merchant_response"
    assert out["flags"] == ["dispute_window_claim_contradicted"]


def test_true_window_claim_is_left_alone():
    v = verdict("dismiss")
    out = check_dispute_verdict(dispute(75, 60), v)
    assert out["outcome"] == "dismiss" and out["flags"] == ["outside_dispute_window"]
    assert out["dispute_window"]["within_window"] is False


@pytest.mark.parametrize("outcome", ["voluntary_refund", "forced_refund", "escalate_to_human", "dismiss"])
def test_verdict_without_a_window_claim_is_unchanged(outcome):
    v = verdict(outcome, flags=["duplicate_dispute"])
    out = check_dispute_verdict(dispute(5, 30), v)
    assert {k: out[k] for k in v} == v


def test_never_turns_anything_into_a_refund():
    for outcome in ("deny", "dismiss", "escalate_to_human", "await_merchant_response", "no_enforceable_remedy"):
        for days in (1, 29, 31, 400):
            out = check_dispute_verdict(dispute(days, 30), verdict(outcome))
            assert out["outcome"] in (outcome, "escalate_to_human")
            assert out["refund_amount_usdc"] == "0"


def test_input_verdict_is_not_modified():
    v = verdict("dismiss")
    before = copy.deepcopy(v)
    check_dispute_verdict(dispute(), v)
    assert v == before


@pytest.mark.parametrize("bad", [{}, {"policy": {}}, {"payload": "x"}, None, "a string", 5,
                                 {"policy": {"dispute_window_days": 30}, "payload": {"payment": {}, "claim": {}}}])
def test_uncomputable_window_is_reported_not_guessed(bad):
    out = check_dispute_verdict(bad, verdict("dismiss"))
    assert out["outcome"] == "dismiss" and "dispute_window_not_checked" in out["flags"]
    assert "dispute_window" not in out


def test_unreadable_verdict_is_escalated():
    out = check_dispute_verdict(dispute(), None)
    assert out["outcome"] == "escalate_to_human" and out["flags"] == ["check_failed"]


def test_result_is_json_serialisable():
    json.dumps(check_dispute_verdict(dispute(), verdict()))
