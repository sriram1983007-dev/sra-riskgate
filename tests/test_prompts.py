"""1.3.0: model prompts and fail-closed verdict parsing."""
import json

import pytest

from sra_riskgate import (DISPUTE_SYSTEM_PROMPT, PAYMENT_SYSTEM_PROMPT, dispute_messages, parse_dispute_verdict,
                          parse_payment_verdict, payment_messages)

POLICY = {"max_amount_usdc": "1000"}
NOW = 1793064149
DAY = 86400


def test_payment_messages_exact_template():
    msgs = payment_messages(POLICY, {"memo": "x"}, {"signature_valid": True}, now=NOW)
    assert msgs[0] == {"role": "system", "content": PAYMENT_SYSTEM_PROMPT}
    assert msgs[1]["role"] == "user"
    assert msgs[1]["content"] == (
        "Evaluate this stablecoin payment.\n\n<context>\n"
        '{"now_unix": 1793064149, "now_iso": "2026-10-27T01:22:29+00:00", "policy": {"max_amount_usdc": "1000"}}'
        '\n</context>\n\n<payload>\n{"memo": "x"}\n</payload>\n\n<tool_results>\n{"signature_valid": true}\n</tool_results>')


def test_payment_messages_default_now_is_current_time():
    ctx = json.loads(payment_messages(POLICY, {}, {})[1]["content"].split("<context>\n")[1].split("\n</context>")[0])
    assert abs(ctx["now_unix"] - __import__("time").time()) < 60


def case(filed_days=10):
    return {"payment": {"paid_at": NOW - 40 * DAY, "amount_usdc": "5"}, "claim": {"filed_at": NOW - 40 * DAY + filed_days * DAY}}


def test_dispute_messages_adds_window_by_default():
    pol = {"dispute_window_days": 30}
    user = dispute_messages(pol, case(), {"bond": None}, now=NOW)[1]["content"]
    assert user.startswith("Adjudicate this stablecoin payment dispute.\n\n<context>\n")
    assert "\n</context>\n\n<case>\n" in user and "\n</case>\n\n<tool_results>\n" in user
    tools = json.loads(user.split("<tool_results>\n")[1].split("\n</tool_results>")[0])
    assert list(tools) == ["bond", "dispute_window"] and tools["dispute_window"]["within_window"] is True


def test_dispute_messages_v1_format_without_window():
    msgs = dispute_messages({"dispute_window_days": 30}, case(), {"bond": None}, now=NOW, add_window=False)
    assert msgs[0]["content"] == DISPUTE_SYSTEM_PROMPT
    assert msgs[1]["content"].endswith('<tool_results>\n{"bond": null}\n</tool_results>')


GOOD_PAY = {"decision": "approve", "risk_level": "low", "flags": [], "explanation": "ok", "required_actions": []}


def test_parse_payment_verdict_accepts_exact_schema_with_prose_and_fences():
    assert parse_payment_verdict(json.dumps(GOOD_PAY)) == GOOD_PAY
    assert parse_payment_verdict("```json\n" + json.dumps(GOOD_PAY) + "\n```") == GOOD_PAY
    assert parse_payment_verdict("Here you go: " + json.dumps(GOOD_PAY)) == GOOD_PAY


@pytest.mark.parametrize("bad", [
    None, "", "approve", "{not json", json.dumps({**GOOD_PAY, "decision": "allow"}),
    json.dumps({**GOOD_PAY, "risk_level": "none"}), json.dumps({**GOOD_PAY, "extra": 1}),
    json.dumps({k: v for k, v in GOOD_PAY.items() if k != "flags"}), json.dumps({**GOOD_PAY, "flags": "x"}),
    json.dumps({**GOOD_PAY, "flags": [1]}), json.dumps({**GOOD_PAY, "explanation": None}), "[1, 2]",
])
def test_parse_payment_verdict_fails_closed(bad):
    v = parse_payment_verdict(bad)
    assert v["decision"] == "hold" and v["flags"] == ["model_output_unreadable"] and v["source"] == "fail_closed"


GOOD_DISP = {"outcome": "forced_refund", "mechanism": "arbiter_bond_payout", "settlement_state": "final",
             "refund_amount_usdc": "5", "refund_destination": "0x" + "a" * 40, "idempotency_key": "k",
             "flags": [], "explanation": "ok", "required_actions": []}


def test_parse_dispute_verdict_accepts_exact_schema():
    assert parse_dispute_verdict(json.dumps(GOOD_DISP)) == GOOD_DISP


@pytest.mark.parametrize("bad", [
    None, "refund", json.dumps({**GOOD_DISP, "outcome": "merchant_wins"}),
    json.dumps({**GOOD_DISP, "mechanism": "chargeback"}), json.dumps({**GOOD_DISP, "settlement_state": "pending"}),
    json.dumps({**GOOD_DISP, "extra": 1}), json.dumps({**GOOD_DISP, "flags": None}),
])
def test_parse_dispute_verdict_fails_closed_to_a_human(bad):
    v = parse_dispute_verdict(bad)
    assert v["outcome"] == "escalate_to_human" and v["refund_amount_usdc"] == "0"
    assert v["flags"] == ["model_output_unreadable"] and v["source"] == "fail_closed"
