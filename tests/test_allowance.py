"""0.20.0: check_allowances finds the standing approvals a pull payment can draw on."""
import pytest

from sra_riskgate import ActionDecision, check_allowances

AGENT = "0x33d6112f2f3bcd2a476bd9c13208e4c632be2d0a"
PRIORS = "0x281210097f0de7a8fb6f87310af0f089c9c8de21"   # the lender in the 2026-11-04 Robinhood Chain repayment
OTHER = "0x" + "77" * 20
SANCTIONED = "0x0330070fd38ec3bb94f58fa55d40368271e9e54a"  # first address in the bundled OFAC SDN snapshot
MAX = 2**256 - 1


def check(allowances, **kw):
    kw.setdefault("symbol", "USDG")
    return check_allowances(AGENT, allowances, **kw)


def test_spent_exact_approval_is_clean():
    # The Robinhood Chain case: the approval was exactly the amount due and is now spent.
    r = check({PRIORS: 0}, expected_spenders=[PRIORS])
    assert r.decision == ActionDecision.APPROVE and r.flags == []


def test_open_exact_approval_within_limit_passes():
    assert check({PRIORS: 25_075_000}, max_allowance="30", expected_spenders=[PRIORS]).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("value", [MAX, hex(MAX), str(MAX), 2**255])
def test_unlimited_allowance_is_held(value):
    r = check({PRIORS: value})
    assert r.decision == ActionDecision.HOLD and r.flags == ["UNLIMITED_ALLOWANCE"]
    assert "whole USDG balance" in r.explanation and r.required_actions == ["reduce_allowance"]


def test_above_limit_is_held_with_amounts():
    r = check({PRIORS: 100_000_000}, max_allowance="30")
    assert r.flags == ["ALLOWANCE_ABOVE_LIMIT"] and "100 USDG" in r.explanation and "30 USDG" in r.explanation


def test_unknown_spender_is_held():
    r = check({PRIORS: 0, OTHER: 5_000_000}, expected_spenders=[PRIORS])
    assert r.flags == ["UNKNOWN_SPENDER"] and OTHER in r.explanation


def test_zero_allowance_to_unknown_spender_is_not_a_finding():
    assert check({OTHER: 0}, expected_spenders=[PRIORS]).decision == ActionDecision.APPROVE


def test_several_findings_are_all_named():
    r = check({PRIORS: MAX, OTHER: 1}, expected_spenders=[PRIORS])
    assert r.flags == ["UNLIMITED_ALLOWANCE", "UNKNOWN_SPENDER"]


def test_sanctioned_spender_is_rejected():
    r = check({SANCTIONED: 1})
    assert r.decision == ActionDecision.REJECT and "SANCTIONED_SPENDER" in r.flags
    assert r.required_actions == ["revoke_allowance"]


def test_blocked_spender_is_rejected_even_if_small():
    r = check({OTHER: 1}, blocked_addresses=[OTHER])
    assert r.decision == ActionDecision.REJECT and r.flags == ["BLOCKLISTED_SPENDER"]


@pytest.mark.parametrize("allowances,kw", [({}, {}), ({"0x123": 1}, {}), ({PRIORS: -1}, {}), ({PRIORS: 2**256}, {}),
                                          ({PRIORS: "lots"}, {}), ({PRIORS: True}, {}), ({PRIORS: 1}, {"decimals": 99}),
                                          ({PRIORS: 1}, {"max_allowance": "-5"}),
                                          ({PRIORS: 1}, {"expected_spenders": ["nope"]}), ("not a mapping", {})])
def test_bad_input_is_held(allowances, kw):
    r = check(allowances, **kw)
    assert r.decision == ActionDecision.HOLD and r.flags == ["CONFIGURATION_ERROR"]


def test_bad_owner_is_held():
    assert check_allowances("me", {PRIORS: 0}).flags == ["CONFIGURATION_ERROR"]


def test_named_token_allowances():
    r = check_allowances(AGENT, {PRIORS: 100_000_000}, token="USDT", chain_id=1, max_allowance="50")
    assert r.flags == ["ALLOWANCE_ABOVE_LIMIT"] and "100 USDT" in r.explanation and "50 USDT" in r.explanation
    assert check_allowances(AGENT, {PRIORS: 1}, token="USDT", chain_id=8453).flags == ["CONFIGURATION_ERROR"]
