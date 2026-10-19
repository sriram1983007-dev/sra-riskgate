import pytest

from sra_riskgate import ActionDecision, RulePreFilter, TransactionPayload, check_payment
from sra_riskgate.client import ROUND_AMOUNT_FLAG

A, B = "0x" + "a" * 40, "0x" + "b" * 40


def pay(amount, **kw):
    return TransactionPayload(chain_id=8453, token="USDC", sender=A, recipient=B, amount=amount,
                              peg_deviation_pct=0.0, **kw)


GATE = RulePreFilter(max_amount=100_000)


@pytest.mark.parametrize("amount", [10_000.0, 25_000.0, 50_000.0])
def test_round_amount_is_flagged_but_still_approved(amount):
    v = GATE.inspect(pay(amount))
    assert v.decision == ActionDecision.APPROVE          # informational only
    assert v.flags == [ROUND_AMOUNT_FLAG]
    assert "Informational only" in v.explanation and "legitimate" in v.explanation


@pytest.mark.parametrize("amount", [9_999.99, 9_999.0, 10_500.50, 25_000.01, 5_000.0, 20.0])
def test_non_round_or_small_amounts_are_quiet(amount):
    v = GATE.inspect(pay(amount))
    assert v.decision == ActionDecision.APPROVE
    assert ROUND_AMOUNT_FLAG not in v.flags


def test_round_amount_never_loosens_a_hold():
    v = RulePreFilter(max_amount=20_000).inspect(pay(25_000.0))
    assert v.decision == ActionDecision.HOLD
    assert v.flags == ["HIGH_VALUE_TRANSFER", ROUND_AMOUNT_FLAG]


def test_round_amount_with_check_payment_default_ceiling_still_holds():
    r = check_payment(chain_id=8453, sender=A, recipient=B, amount=25_000.0, peg_deviation_pct=0.1)
    assert r.decision == ActionDecision.HOLD                  # default ceiling is 1,000
    assert ROUND_AMOUNT_FLAG in r.flags


def test_round_amount_with_raised_ceiling_approves_with_flag():
    r = check_payment(chain_id=8453, sender=A, recipient=B, amount=25_000.0, peg_deviation_pct=0.1,
                      max_amount=50_000)
    assert r.decision == ActionDecision.APPROVE
    assert r.flags == [ROUND_AMOUNT_FLAG]


def test_threshold_is_configurable_and_can_be_turned_off():
    assert ROUND_AMOUNT_FLAG in RulePreFilter(round_amount_threshold=500).inspect(pay(600.0)).flags
    assert RulePreFilter(max_amount=100_000, round_amount_threshold=None).inspect(pay(25_000.0)).flags == []


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True, "10000"])
def test_bad_threshold_raises(bad):
    with pytest.raises(ValueError):
        RulePreFilter(round_amount_threshold=bad)
