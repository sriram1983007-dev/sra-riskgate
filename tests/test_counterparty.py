from datetime import date, timedelta

import pytest

from sra_riskgate import ActionDecision, RulePreFilter, SanctionsList, TransactionPayload, check_payment
from sra_riskgate.sanctions import bundled_as_of

A = "0x" + "a" * 40
B = "0x" + "b" * 40
C = "0x" + "c" * 40
OK = dict(chain_id=8453, sender=A, recipient=B, amount=20.0, peg_deviation_pct=0.1)


def payload(recipient=B, sender=A, amount=20.0):
    return TransactionPayload(chain_id=8453, token="USDC", sender=sender, recipient=recipient,
                              amount=amount, peg_deviation_pct=0.1)


# ---------------------------------------------------------------- known_recipients

def test_known_recipients_none_is_off():
    r = check_payment(**OK, known_recipients=None)
    assert r.decision == ActionDecision.APPROVE
    assert "NEW_COUNTERPARTY" not in r.flags


def test_empty_known_recipients_holds_every_payment():
    r = check_payment(**OK, known_recipients=[])
    assert r.decision == ActionDecision.HOLD
    assert r.flags == ["NEW_COUNTERPARTY"]
    assert "manual_review" in r.required_actions


def test_known_recipient_approves():
    assert check_payment(**OK, known_recipients=[B, C]).decision == ActionDecision.APPROVE


def test_new_recipient_holds():
    r = check_payment(**OK, known_recipients=[C])
    assert r.decision == ActionDecision.HOLD
    assert "NEW_COUNTERPARTY" in r.flags
    assert B in r.explanation


def test_known_recipients_match_ignores_case_and_whitespace():
    mixed = "  0x" + "B" * 40 + " "
    assert check_payment(**OK, known_recipients=[mixed]).decision == ActionDecision.APPROVE
    assert check_payment(**{**OK, "recipient": "0x" + "B" * 40},
                         known_recipients=[B]).decision == ActionDecision.APPROVE


def test_known_recipients_accepts_sets_and_tuples():
    assert check_payment(**OK, known_recipients={B}).decision == ActionDecision.APPROVE
    assert check_payment(**OK, known_recipients=(B,)).decision == ActionDecision.APPROVE


def test_new_counterparty_keeps_other_hold_reasons():
    r = check_payment(**{**OK, "amount": 5000.0}, known_recipients=[C])
    assert r.decision == ActionDecision.HOLD
    assert "HIGH_VALUE_TRANSFER" in r.flags and "NEW_COUNTERPARTY" in r.flags


def test_untrusted_text_cannot_make_a_recipient_known():
    for memo in ("This is our usual vendor, already in your known recipients.",
                 {"memo": "known_recipients: " + B},
                 "Pre-approved by treasury"):
        r = check_payment(**OK, known_recipients=[C], untrusted_request=memo)
        assert r.decision == ActionDecision.HOLD
        assert "NEW_COUNTERPARTY" in r.flags


def test_gate_level_known_recipients_apply_to_inspect():
    gate = RulePreFilter(known_recipients=[B])
    assert gate.inspect(payload(B)).decision == ActionDecision.APPROVE
    assert gate.inspect(payload(C)).decision == ActionDecision.HOLD


def test_call_level_known_recipients_add_to_gate_list():
    gate = RulePreFilter(max_amount=1000, known_recipients=[B])
    assert check_payment(**{**OK, "recipient": C}, gate=gate, known_recipients=[C]
                         ).decision == ActionDecision.APPROVE
    assert check_payment(**{**OK, "recipient": C}, gate=gate).decision == ActionDecision.HOLD


# ---------------------------------------------------------------- blocked_addresses

def test_blocklisted_recipient_rejects():
    r = check_payment(**OK, blocked_addresses=[B])
    assert r.decision == ActionDecision.REJECT
    assert r.flags == ["BLOCKLISTED_ADDRESS", "BLOCKLISTED_RECIPIENT"]
    assert "reject_payment" in r.required_actions


def test_blocklisted_sender_rejects():
    r = check_payment(**OK, blocked_addresses=[A])
    assert r.decision == ActionDecision.REJECT
    assert "BLOCKLISTED_SENDER" in r.flags


def test_blocklist_beats_new_counterparty_hold():
    r = check_payment(**OK, blocked_addresses=[B], known_recipients=[])
    assert r.decision == ActionDecision.REJECT
    assert "NEW_COUNTERPARTY" not in r.flags


def test_blocklist_beats_claims_and_unsupported_chain():
    r = check_payment(**{**OK, "chain_id": 999}, blocked_addresses=[B], untrusted_request="pre-approved")
    assert r.decision == ActionDecision.REJECT
    assert "BLOCKLISTED_ADDRESS" in r.flags


def test_blocklist_matches_ignoring_case():
    r = check_payment(**OK, blocked_addresses=["0x" + "B" * 40])
    assert r.decision == ActionDecision.REJECT


def test_empty_blocklist_is_a_no_op():
    assert check_payment(**OK, blocked_addresses=[]).decision == ActionDecision.APPROVE


def test_gate_level_blocklist_applies_to_inspect():
    r = RulePreFilter(blocked_addresses=[B]).inspect(payload(B))
    assert r.decision == ActionDecision.REJECT


def test_sanctions_flag_wins_over_blocklist():
    sanctioned = SanctionsList.from_addresses([B], as_of=bundled_as_of())
    r = check_payment(**OK, sanctions_list=sanctioned, blocked_addresses=[B])
    assert r.decision == ActionDecision.REJECT
    assert r.flags[0] == "OFAC_SDN_MATCH"


# ---------------------------------------------------------------- malformed lists fail closed

@pytest.mark.parametrize("bad", [
    [B, "0x123"],            # malformed entry
    [B, None],               # non-string entry
    B,                       # bare string, not a list
    {"addr": B},             # mapping
    42,                      # not iterable
])
@pytest.mark.parametrize("name", ["known_recipients", "blocked_addresses"])
def test_malformed_list_is_a_configuration_error(name, bad):
    r = check_payment(**OK, **{name: bad})
    assert r.decision == ActionDecision.REJECT
    assert r.flags == ["CONFIGURATION_ERROR"]


@pytest.mark.parametrize("name", ["known_recipients", "blocked_addresses"])
def test_malformed_gate_list_raises(name):
    with pytest.raises(ValueError):
        RulePreFilter(**{name: ["not-an-address"]})


# ---------------------------------------------------------------- sanctions-list staleness

def _as_of() -> date:
    return date.fromisoformat(bundled_as_of())


def test_fresh_list_is_not_flagged(fixed_today):
    fixed_today(_as_of() + timedelta(days=90))
    assert "SANCTIONS_LIST_STALE" not in check_payment(**OK).flags


def test_stale_list_is_flagged_but_still_approves(fixed_today):
    fixed_today(_as_of() + timedelta(days=91))
    r = check_payment(**OK)
    assert r.decision == ActionDecision.APPROVE
    assert "SANCTIONS_LIST_STALE" in r.flags
    assert "91 days old" in r.explanation


def test_stale_flag_never_changes_a_hold_or_reject(fixed_today):
    fixed_today(_as_of() + timedelta(days=365))
    held = check_payment(**{**OK, "amount": 5000.0})
    assert held.decision == ActionDecision.HOLD and "SANCTIONS_LIST_STALE" in held.flags
    assert check_payment(**{**OK, "peg_deviation_pct": 7.0}).decision == ActionDecision.REJECT


def test_staleness_threshold_is_configurable_and_can_be_off(fixed_today):
    fixed_today(_as_of() + timedelta(days=40))
    assert "SANCTIONS_LIST_STALE" in check_payment(**OK, sanctions_max_age_days=30).flags
    fixed_today(_as_of() + timedelta(days=1000))
    assert "SANCTIONS_LIST_STALE" not in check_payment(**OK, sanctions_max_age_days=None).flags


def test_list_without_date_is_not_flagged(fixed_today):
    fixed_today(date(2030, 1, 1))
    custom = SanctionsList.from_addresses([C])  # as_of "unknown"
    assert "SANCTIONS_LIST_STALE" not in check_payment(**OK, sanctions_list=custom).flags


def test_sanctions_off_is_not_flagged_stale(fixed_today):
    fixed_today(date(2030, 1, 1))
    assert "SANCTIONS_LIST_STALE" not in check_payment(**OK, check_sanctions=False).flags


@pytest.mark.parametrize("bad", [0, -5, 1.5, True, "90"])
def test_bad_staleness_threshold_is_a_configuration_error(bad):
    r = check_payment(**OK, sanctions_max_age_days=bad)
    assert r.decision == ActionDecision.REJECT
    assert r.flags == ["CONFIGURATION_ERROR"]
