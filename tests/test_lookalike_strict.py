"""1.10.0: lookalike_check="strict" also rejects a look-alike sharing only 3 characters at each end."""
import json

import pytest

from sra_riskgate import ActionDecision, check_payment, check_transaction, load_policy
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.cli import main
from sra_riskgate.counterparty import find_lookalike, parse_lookalike_check

A = "0x" + "1" * 40
REAL = "0x2ffb" + "8" * 32 + "b7ee"
FAKE_33 = "0x2ff" + "9" * 34 + "7ee"     # 3 + 3: missed by standard
FAKE_44 = "0x2ffb" + "9" * 32 + "b7ee"   # 4 + 4: caught by both
FAKE_32 = "0x2ff" + "9" * 35 + "ee"      # 3 + 2: never a look-alike
KW = dict(chain_id=8453, sender=A, amount=5, peg_deviation_pct=0.0, known_recipients=[REAL])


def test_standard_is_unchanged_and_the_default():
    assert check_payment(recipient=FAKE_44, **KW).flags == ["LOOKALIKE_RECIPIENT"]
    r = check_payment(recipient=FAKE_33, **KW)
    assert r.decision == ActionDecision.HOLD and "NEW_COUNTERPARTY" in r.flags   # held, not rejected
    assert check_payment(recipient=FAKE_33, lookalike_check="standard", **KW).decision == ActionDecision.HOLD


def test_strict_rejects_three_plus_three():
    r = check_payment(recipient=FAKE_33, lookalike_check="strict", **KW)
    assert r.decision == ActionDecision.REJECT and r.flags == ["LOOKALIKE_RECIPIENT"]
    assert REAL in r.explanation and "0x2ff" in r.explanation
    assert check_payment(recipient=FAKE_44, lookalike_check="strict", **KW).decision == ActionDecision.REJECT


def test_strict_never_lowers_the_three_at_each_end_floor():
    assert check_payment(recipient=FAKE_32, lookalike_check="strict", **KW).decision == ActionDecision.HOLD
    assert find_lookalike(FAKE_32, frozenset([REAL]), 6) is None
    assert check_payment(recipient=REAL, lookalike_check="strict", **KW).decision == ActionDecision.APPROVE


def test_strict_needs_known_recipients():
    kw = {k: v for k, v in KW.items() if k != "known_recipients"}
    assert check_payment(recipient=FAKE_33, lookalike_check="strict", **kw).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("bad", ["Strict", "loose", "", None, 6, True])
def test_bad_setting_is_a_configuration_error(bad):
    r = check_payment(recipient=REAL, lookalike_check=bad, **KW)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]
    with pytest.raises(ValueError):
        parse_lookalike_check(bad)


def test_flows_through_check_transaction():
    data = "0xa9059cbb" + FAKE_33[2:].rjust(64, "0") + format(5_000_000, "x").rjust(64, "0")
    tx = {"from": A, "to": USDC_ADDRESSES[8453], "chainId": 8453, "data": data}
    assert check_transaction(tx, peg_deviation_pct=0.0, known_recipients=[REAL]).decision == ActionDecision.HOLD
    assert check_transaction(tx, peg_deviation_pct=0.0, known_recipients=[REAL],
                             lookalike_check="strict").decision == ActionDecision.REJECT


def test_policy_file():
    p = load_policy({"version": 1, "known_recipients": [REAL], "lookalike_check": "strict"})
    assert check_payment(recipient=FAKE_33, chain_id=8453, sender=A, amount=5, peg_deviation_pct=0.0,
                         **p.check_kwargs()).decision == ActionDecision.REJECT
    with pytest.raises(ValueError, match="lookalike_check"):
        load_policy({"version": 1, "lookalike_check": "paranoid"})


def test_cli(tmp_path, capsys):
    base = ["check", "--chain", "8453", "--sender", A, "--to", FAKE_33, "--amount", "5", "--peg", "0", "--known", REAL]
    assert main(base) == 10
    assert main(base + ["--lookalike", "strict"]) == 20
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"version": 1, "lookalike_check": "strict"}))
    assert main(base + ["--policy", str(pol)]) == 20
    assert main(base + ["--policy", str(pol), "--lookalike", "standard"]) == 3
    capsys.readouterr()
