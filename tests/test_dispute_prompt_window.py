"""1.2.0: the dispute_window entry for v2 dispute prompts, in exactly the trained format."""
import json

from sra_riskgate import dispute_window_tool_result, with_dispute_window

DAY = 86400


def dispute(paid=1_790_000_000, filed=1_790_000_000 + 10 * DAY + 3600, window=30):
    return {"policy": {"dispute_window_days": window},
            "payload": {"payment": {"paid_at": paid, "amount_usdc": "12.50"}, "claim": {"filed_at": filed}}}


def test_entry_matches_training_format():
    e = dispute_window_tool_result(dispute())
    assert e == {"days_since_payment": 10.04, "window_days": 30.0, "within_window": True}
    assert list(e) == ["days_since_payment", "window_days", "within_window"]


def test_outside_window():
    e = dispute_window_tool_result(dispute(filed=1_790_000_000 + 45 * DAY))
    assert e["within_window"] is False and e["days_since_payment"] == 45.0


def test_boundary_is_inside():
    assert dispute_window_tool_result(dispute(filed=1_790_000_000 + 30 * DAY))["within_window"] is True


def test_cannot_compute_returns_none():
    assert dispute_window_tool_result(dispute(filed=1_790_000_000 - 5)) is None   # claim before payment
    assert dispute_window_tool_result(dispute(window=None)) is None
    assert dispute_window_tool_result({"policy": {}}) is None
    assert dispute_window_tool_result(None) is None
    assert dispute_window_tool_result({"payload": "not a dict"}) is None


def test_with_window_appends_last_and_copies():
    tools = {"merchant_bond": {"active": True}, "settlement": {"state": "final"}}
    out = with_dispute_window(tools, dispute())
    assert list(out) == ["merchant_bond", "settlement", "dispute_window"]
    assert "dispute_window" not in tools                      # input untouched
    out["merchant_bond"]["active"] = False
    assert tools["merchant_bond"]["active"] is True           # deep copy
    assert json.dumps(out).endswith('"dispute_window": {"days_since_payment": 10.04, "window_days": 30.0, "within_window": true}}')


def test_with_window_drops_untrusted_existing_entry():
    out = with_dispute_window({"dispute_window": {"within_window": False}}, dispute(filed=1_790_000_000 - 5))
    assert out == {}
    out = with_dispute_window({"dispute_window": {"within_window": False}, "x": 1}, dispute())
    assert list(out) == ["x", "dispute_window"] and out["dispute_window"]["within_window"] is True


def test_with_window_handles_empty_tool_results():
    assert with_dispute_window(None, dispute())["dispute_window"]["within_window"] is True
