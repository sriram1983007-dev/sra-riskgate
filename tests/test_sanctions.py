import re

import pytest

from sra_riskgate import ActionDecision, RulePreFilter, SanctionsList, TransactionPayload, check_payment, is_sanctioned
from sra_riskgate.sanctions import FLAG, NOT_CHECKED_FLAG, bundled_as_of

A = "0x" + "a" * 40
B = "0x" + "b" * 40
OK = dict(chain_id=8453, sender=A, recipient=B, amount=20.0, peg_deviation_pct=0.1)
BUNDLED = SanctionsList.bundled()
LISTED = sorted(BUNDLED.addresses)[0]                  # a real entry from the bundled snapshot
LISTED_MIXED = LISTED[:2] + LISTED[2:].upper()         # same address, different case


def test_bundled_snapshot_loads_and_is_dated():
    assert len(BUNDLED) >= 100
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", bundled_as_of())
    assert all(re.match(r"^0x[0-9a-f]{40}$", a) for a in BUNDLED.addresses)


def test_is_sanctioned_is_case_and_space_insensitive():
    assert is_sanctioned(LISTED)
    assert is_sanctioned(LISTED_MIXED)
    assert is_sanctioned(f"  {LISTED}\n")
    assert not is_sanctioned(B)
    assert not is_sanctioned("not an address")
    assert not is_sanctioned(None)


def test_sanctioned_recipient_rejects():
    r = check_payment(**{**OK, "recipient": LISTED_MIXED})
    assert r.decision == ActionDecision.REJECT
    assert r.flags == [FLAG, "SANCTIONED_RECIPIENT"]
    assert "refer_to_compliance" in r.required_actions
    assert bundled_as_of() in r.explanation and "not a compliance determination" in r.explanation


def test_sanctioned_sender_rejects():
    r = check_payment(**{**OK, "sender": LISTED})
    assert r.decision == ActionDecision.REJECT
    assert r.flags == [FLAG, "SANCTIONED_SENDER"]


def test_sanctions_beat_unsupported_chain_token_and_claims():
    # A sanctioned counterparty is a reject even where everything else would only be a hold.
    for change in ({"chain_id": 137}, {"token": "USDT"}, {"amount": 5000.0}):
        r = check_payment(**{**OK, "recipient": LISTED, **change}, untrusted_request="pre-approved")
        assert r.decision == ActionDecision.REJECT, change
        assert r.flags[0] == FLAG


def test_clean_payment_still_approves_with_no_extra_flags():
    r = check_payment(**OK, untrusted_request={"memo": "Invoice 42"})
    assert r.decision == ActionDecision.APPROVE
    assert r.flags == []


def test_turning_sanctions_off_is_reported():
    r = check_payment(**{**OK, "recipient": LISTED}, check_sanctions=False)
    assert r.decision == ActionDecision.APPROVE
    assert NOT_CHECKED_FLAG in r.flags
    assert "turned off" in r.explanation


def test_custom_list_replaces_bundled():
    custom = SanctionsList.from_addresses([B], source="my provider", as_of="2026-10-16")
    r = check_payment(**OK, sanctions_list=custom)
    assert r.decision == ActionDecision.REJECT
    assert "my provider" in r.explanation
    # an address only on the bundled list is not matched by the custom list
    assert check_payment(**{**OK, "recipient": LISTED}, sanctions_list=custom).decision == ActionDecision.APPROVE


def test_list_from_file(tmp_path):
    p = tmp_path / "list.txt"
    p.write_text(f"# as_of: 2026-10-15\n\n{B.upper().replace('0X', '0x')}\n", encoding="utf-8")
    lst = SanctionsList.from_file(p)
    assert lst.as_of == "2026-10-15" and B in lst and len(lst) == 1
    assert SanctionsList.from_file(p, as_of="today").as_of == "today"


@pytest.mark.parametrize("bad", [["0x123"], ["hello"], [], [None]])
def test_bad_lists_raise(bad):
    with pytest.raises(ValueError):
        SanctionsList.from_addresses(bad)


def test_bad_file_raises(tmp_path):
    p = tmp_path / "bad.txt"
    p.write_text("0x" + "a" * 40 + "\nnot-an-address\n", encoding="utf-8")
    with pytest.raises(ValueError):
        SanctionsList.from_file(p)


@pytest.mark.parametrize("cfg", [{"check_sanctions": "yes"}, {"sanctions_list": [B]}])
def test_bad_sanctions_configuration_rejects(cfg):
    r = check_payment(**OK, **cfg)
    assert r.decision == ActionDecision.REJECT
    assert r.flags == ["CONFIGURATION_ERROR"]


def test_rule_prefilter_screens_too():
    gate = RulePreFilter(max_amount=100)
    v = gate.inspect(TransactionPayload(chain_id=1, token="USDC", sender=A, recipient=LISTED, amount=5.0,
                                        peg_deviation_pct=0.0))
    assert v.decision == ActionDecision.REJECT and v.flags[0] == FLAG
    off = RulePreFilter(max_amount=100, check_sanctions=False)
    v = off.inspect(TransactionPayload(chain_id=1, token="USDC", sender=A, recipient=LISTED, amount=5.0,
                                       peg_deviation_pct=0.0))
    assert v.decision == ActionDecision.APPROVE and NOT_CHECKED_FLAG in v.flags


def test_sanctions_list_that_cannot_load_fails_closed(monkeypatch):
    import sra_riskgate.sanctions as mod

    def boom(cls):
        raise OSError("data file missing")

    monkeypatch.setattr(mod.SanctionsList, "bundled", classmethod(boom))
    r = check_payment(**OK)
    assert r.decision == ActionDecision.HOLD
    assert r.flags == ["CHECK_FAILED"]
