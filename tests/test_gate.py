import math
import pytest
from sra_riskgate import RiskGate, RulePreFilter, TransactionPayload

A, B = "0x" + "a" * 40, "0x" + "b" * 40


def tx(amount=5000.0, peg=0.0, **kw):
    return TransactionPayload(chain_id=1, token="USDC", sender=kw.get("sender", A),
                              recipient=kw.get("recipient", B), amount=amount, peg_deviation_pct=peg)


@pytest.mark.parametrize("peg,amount,expected", [
    (0.0, 5000, "approve"),
    (0.5, 5000, "approve"),
    (-0.5, 5000, "approve"),
    (-1.5, 5000, "hold"),
    (1.5, 5000, "hold"),          # upward depeg (regressed in 0.2.3)
    (-6.0, 5000, "reject"),
    (6.0, 5000, "reject"),        # upward depeg (regressed in 0.2.3)
    (50.0, 5000, "reject"),
    (float("nan"), 5000, "reject"),
    (float("inf"), 5000, "reject"),
    (0.0, 50000, "approve"),      # ceiling is exclusive
    (0.0, 50001, "hold"),
    (-1.5, 60000, "hold"),
])
def test_every_decision_path(peg, amount, expected):
    v = RulePreFilter().inspect(tx(amount, peg))
    assert v.decision.value == expected
    assert isinstance(v.required_actions, list)   # 0.2.1/0.2.2 crashed here
    assert 0.0 <= v.risk_score <= 1.0


def test_none_peg_treated_as_zero():
    assert RulePreFilter().inspect(tx(peg=None)).decision.value == "approve"


@pytest.mark.parametrize("bad", [
    dict(amount=float("nan")), dict(amount=-1), dict(amount=0),
    dict(sender="x"), dict(recipient="0x" + "0" * 40), dict(recipient=A),
])
def test_invalid_payloads_rejected_at_validation(bad):
    args = dict(chain_id=1, token="USDC", sender=A, recipient=B, amount=10.0)
    args.update(bad)
    with pytest.raises(Exception):
        TransactionPayload(**args)


def test_typo_kwarg_raises():
    with pytest.raises(TypeError, match="max_amout"):
        RulePreFilter(max_amout=1000)


@pytest.mark.parametrize("kw", [
    dict(depeg_hold_pct=5, depeg_reject_pct=1), dict(max_amount=0),
    dict(max_amount=float("nan")), dict(depeg_reject_pct=float("inf")), dict(max_amount=True),
])
def test_bad_thresholds_raise(kw):
    with pytest.raises(ValueError):
        RulePreFilter(**kw)


def test_legacy_max_allowed_deviation_is_hold_threshold():
    g = RulePreFilter(max_allowed_deviation_pct=2.0)
    assert (g.depeg_hold_pct, g.depeg_reject_pct) == (2.0, 5.0)
    assert g.inspect(tx(peg=-3)).decision.value == "hold"      # 0.1.x behaviour
    RulePreFilter(max_allowed_deviation_pct=1.0)               # old default must not raise


def test_legacy_signed_names_and_amount():
    g = RulePreFilter(depeg_hold_threshold_pct=-1, depeg_reject_threshold_pct=-5, max_amount_usdc=1000)
    assert (g.depeg_hold_pct, g.depeg_reject_pct, g.max_amount) == (1.0, 5.0, 1000.0)


def test_riskgate_alias():
    assert RiskGate().inspect(tx()).decision.value == "approve"


def test_version_matches_pyproject():
    import pathlib, re
    import sra_riskgate
    pyproject = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject.exists():
        declared = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.M).group(1)
        assert sra_riskgate.__version__ == declared
