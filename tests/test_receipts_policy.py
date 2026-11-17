"""1.8.0: signed decision receipts and the policy file."""
import copy
import datetime as dt
import json

import pytest

from sra_riskgate import (ActionDecision, Policy, ReceiptSigner, check_payment, check_transaction, issue_receipt,
                          load_policy, verify_receipt)
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.receipts import canonical_json, policy_hash

A, B, C = "0x" + "1" * 39 + "a", "0x" + "2" * 39 + "b", "0x" + "3" * 39 + "c"
KEY = b"k" * 32
PAYMENT = {"chain_id": 8453, "sender": A, "recipient": B, "amount": 5.0, "token": "USDC"}


def result():
    return check_payment(**PAYMENT, peg_deviation_pct=0.0)


# ---------------------------------------------------------------- receipts

def test_hmac_receipt_round_trip_and_contents():
    r = result()
    rc = issue_receipt(r, ReceiptSigner.hmac(KEY, key_id="ops-1"), payment=PAYMENT,
                       now=dt.datetime(2026, 11, 16, 18, 0, 5, 123, tzinfo=dt.timezone.utc))
    assert verify_receipt(rc, key=KEY)
    assert rc["decision"] == "approve" and rc["alg"] == "hmac-sha256" and rc["signer"] == "ops-1"
    assert rc["issued_at"] == "2026-11-16T18:00:05Z" and rc["library"] == f"sra-riskgate {__import__('sra_riskgate').__version__}"
    assert rc["payment"] == PAYMENT and len(rc["id"]) == 32 and rc["policy_sha256"] is None
    json.dumps(rc)  # plain JSON
    assert type(rc["decision"]) is str  # not the ActionDecision enum


def test_receipts_for_a_mapping_with_an_enum_decision():
    from sra_riskgate import ActionDecision
    rc = issue_receipt({"decision": ActionDecision.HOLD, "risk_score": 0.65, "flags": [], "explanation": ""},
                       ReceiptSigner.hmac(KEY))
    assert type(rc["decision"]) is str and rc["decision"] == "hold" and verify_receipt(rc, key=KEY)


@pytest.mark.parametrize("field,value", [("decision", "reject"), ("risk_score", 0.0), ("flags", ["X"]),
                                         ("explanation", "edited"), ("issued_at", "2020-01-01T00:00:00Z"),
                                         ("signer", "someone-else"), ("id", "0" * 32), ("policy_sha256", "ab")])
def test_any_edit_breaks_the_receipt(field, value):
    rc = issue_receipt(result(), ReceiptSigner.hmac(KEY), payment=PAYMENT)
    bad = copy.deepcopy(rc)
    bad[field] = value
    assert not verify_receipt(bad, key=KEY)


def test_editing_the_payment_breaks_it_even_with_a_matching_hash():
    rc = issue_receipt(result(), ReceiptSigner.hmac(KEY), payment=PAYMENT)
    bad = copy.deepcopy(rc)
    bad["payment"]["amount"] = 500.0
    assert not verify_receipt(bad, key=KEY)
    import hashlib
    bad["payment_sha256"] = hashlib.sha256(canonical_json(bad["payment"]).encode()).hexdigest()
    assert not verify_receipt(bad, key=KEY)  # the signature still covers the original


@pytest.mark.parametrize("bad", [None, {}, [], "x", {"v": 2, "sig": "a"}, {"v": 1}, {"v": 1, "sig": "a", "alg": "none"}])
def test_garbage_never_verifies(bad):
    assert verify_receipt(bad, key=KEY) is False


def test_wrong_key_or_missing_key_fails():
    rc = issue_receipt(result(), ReceiptSigner.hmac(KEY), payment=PAYMENT)
    assert not verify_receipt(rc, key=b"z" * 32)
    assert not verify_receipt(rc)


def test_ethereum_receipts_verify_by_address_and_resist_forgery():
    pytest.importorskip("eth_account")
    from eth_account import Account
    k1, k2 = Account.create(), Account.create()
    rc = issue_receipt(result(), ReceiptSigner.ethereum(k1.key), payment=PAYMENT)
    assert rc["alg"] == "eip191" and rc["signer"] == k1.address
    assert verify_receipt(rc, expected_signer=k1.address)
    assert verify_receipt(rc, expected_signer=k1.address.lower())
    assert not verify_receipt(rc, expected_signer=k2.address)
    forged = issue_receipt(result(), ReceiptSigner.ethereum(k2.key), payment=PAYMENT)
    forged["signer"] = k1.address  # claims to be k1
    assert not verify_receipt(forged, expected_signer=k1.address)
    bad = dict(rc, decision="reject")
    assert not verify_receipt(bad, expected_signer=k1.address)


@pytest.mark.parametrize("key", [b"short", "a string key" * 3, None])
def test_bad_hmac_key(key):
    with pytest.raises(ValueError):
        ReceiptSigner.hmac(key)


def test_unserialisable_payment_is_refused():
    with pytest.raises(ValueError):
        issue_receipt(result(), ReceiptSigner.hmac(KEY), payment={"amount": float("nan")})
    with pytest.raises(ValueError):
        issue_receipt(result(), ReceiptSigner.hmac(KEY), payment={"when": dt.datetime.now()})


# ---------------------------------------------------------------- policy

POLICY = {
    "version": 1, "name": "test",
    "max_amount": 50, "allowed_tokens": ["USDC"],
    "known_recipients": [B], "blocked_addresses": [C],
    "budgets": {"window_hours": 24, "total": 60},
    "anomalies": {"max_payments_per_hour": 100},
}


def test_policy_drives_every_check():
    p = load_policy(POLICY)
    kw = p.check_kwargs()
    ok = check_payment(chain_id=8453, sender=A, recipient=B, amount=40, peg_deviation_pct=0.0, **kw)
    assert ok.decision == ActionDecision.APPROVE
    assert check_payment(chain_id=8453, sender=A, recipient=B, amount=60, peg_deviation_pct=0.0,
                         **kw).decision == ActionDecision.HOLD        # over max_amount
    assert check_payment(chain_id=8453, sender=A, recipient=C, amount=1, peg_deviation_pct=0.0,
                         **kw).decision == ActionDecision.REJECT      # blocked
    tx = {"from": A, "to": USDC_ADDRESSES[8453], "chainId": 8453,
          "data": "0xa9059cbb" + B[2:].rjust(64, "0") + format(30_000_000, "x").rjust(64, "0")}
    r = check_transaction(tx, peg_deviation_pct=0.0, **p.check_kwargs())  # same guard, same ledger
    assert r.decision == ActionDecision.HOLD and "BUDGET_EXCEEDED" in r.flags


def test_policy_from_json_and_yaml_files(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(POLICY))
    p = load_policy(str(f))
    assert p.name == "test" and p.source == str(f) and p.sha256 == policy_hash(POLICY)
    yaml = pytest.importorskip("yaml")
    y = tmp_path / "p.yaml"
    y.write_text(yaml.safe_dump(POLICY))
    assert load_policy(y).sha256 == p.sha256


def test_policy_hash_binds_into_receipts():
    p = load_policy(POLICY)
    rc = issue_receipt(result(), ReceiptSigner.hmac(KEY), payment=PAYMENT, policy=p)
    assert rc["policy_sha256"] == p.sha256 and verify_receipt(rc, key=KEY)


def test_screening_keys_come_only_from_named_environment_variables():
    pol = {"version": 1, "screening": {"providers": [
        {"type": "chainalysis", "api_key_env": "MY_CHAIN_KEY"}, {"type": "trm"},
        {"type": "elliptic", "api_key_env": "EK", "api_secret_env": "ES", "high_risk_score": 4}],
        "hold_at": "medium"}}
    p = load_policy(pol)
    import base64
    kw = p.check_kwargs(env={"MY_CHAIN_KEY": "abc", "EK": "k", "ES": base64.b64encode(b"s" * 16).decode()})
    names = [x.name for x in kw["screening_providers"]]
    assert names == ["chainalysis", "trm", "elliptic"] and kw["screening_hold_at"] == "medium"
    with pytest.raises(ValueError, match="MY_CHAIN_KEY"):
        p.check_kwargs(env={})


@pytest.mark.parametrize("bad", [
    {}, {"version": 2}, {"version": 1, "max_ammount": 5}, {"version": 1, "max_amount": -1},
    {"version": 1, "max_amount": True}, {"version": 1, "allowed_tokens": "USDC"},
    {"version": 1, "known_recipients": [1]}, {"version": 1, "ledger": ""},
    {"version": 1, "screening": {"providers": []}},
    {"version": 1, "screening": {"providers": [{"type": "unknown"}]}},
    {"version": 1, "screening": {"providers": [{"type": "chainalysis"}]}},
    {"version": 1, "screening": {"providers": [{"type": "chainalysis", "api_key": "sk_live_123"}]}},
    {"version": 1, "screening": {"providers": [{"type": "elliptic", "api_key_env": "EK"}]}},
    {"version": 1, "screening": {"providers": [{"type": "trm"}], "hold_at": "loud"}},
    {"version": 1, "screening": {"providers": [{"type": "trm"}], "hold_at": "severe", "reject_at": "high"}},
    {"version": 1, "budgets": {}}, {"version": 1, "budgets": {"total": 0}},
    {"version": 1, "budgets": {"total": 10, "per_day": 5}},
    {"version": 1, "anomalies": {"min_history": 3}}, {"version": 1, "anomalies": {"amount_spike_factor": 1}},
    [1, 2], "text",
])
def test_invalid_policies_are_refused(bad):
    with pytest.raises((ValueError, TypeError)):
        load_policy(bad) if isinstance(bad, dict) else Policy(bad)


def test_a_literal_api_key_gets_a_helpful_message():
    with pytest.raises(ValueError, match="environment variables"):
        load_policy({"version": 1, "screening": {"providers": [{"type": "chainalysis", "api_key": "x"}]}})


def test_policy_copy_is_independent():
    src = copy.deepcopy(POLICY)
    p = load_policy(src)
    src["max_amount"] = 1
    assert p.as_dict()["max_amount"] == 50
