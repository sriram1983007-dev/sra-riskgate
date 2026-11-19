"""1.11.0: new_counterparty="allow", payee-change requests, chained receipts and the guard benchmark."""
import json
import sys

import pytest

from sra_riskgate import (ActionDecision, ReceiptSigner, check_payment, issue_receipt, load_policy, receipt_sha256,
                          verify_receipt_chain)
from sra_riskgate.bench import GUARDS, generate_cases, public_view, run_benchmark
from sra_riskgate.cli import main
from sra_riskgate.payload_claims import scan_payee_change

A, B, NEW = "0x" + "1" * 40, "0x" + "2" * 40, "0x" + "4" * 40
FAKE = "0x2222" + "9" * 32 + "2222"
KW = dict(chain_id=8453, sender=A, amount=5, peg_deviation_pct=0.0, known_recipients=[B])
KEY = b"k" * 32


# ---------------------------------------------------------------- new_counterparty

def test_new_counterparty_allow_keeps_the_lookalike_check():
    assert check_payment(recipient=NEW, **KW).decision == ActionDecision.HOLD           # default unchanged
    assert check_payment(recipient=NEW, new_counterparty="allow", **KW).decision == ActionDecision.APPROVE
    r = check_payment(recipient=FAKE, new_counterparty="allow", **KW)
    assert r.decision == ActionDecision.REJECT and r.flags == ["LOOKALIKE_RECIPIENT"]


@pytest.mark.parametrize("bad", ["Allow", "skip", "", None, True])
def test_bad_new_counterparty_is_a_configuration_error(bad):
    assert check_payment(recipient=B, new_counterparty=bad, **KW).flags == ["CONFIGURATION_ERROR"]


def test_new_counterparty_in_policy_and_cli(tmp_path, capsys):
    p = load_policy({"version": 1, "known_recipients": [B], "new_counterparty": "allow"})
    assert check_payment(recipient=NEW, chain_id=8453, sender=A, amount=5, peg_deviation_pct=0.0,
                         **p.check_kwargs()).decision == ActionDecision.APPROVE
    with pytest.raises(ValueError, match="new_counterparty"):
        load_policy({"version": 1, "new_counterparty": "maybe"})
    base = ["check", "--chain", "8453", "--sender", A, "--to", NEW, "--amount", "5", "--peg", "0", "--known", B]
    assert main(base) == 10 and main(base + ["--new-payee", "allow"]) == 0
    capsys.readouterr()


# ---------------------------------------------------------------- payee-change requests

@pytest.mark.parametrize("text", [
    "Our wallet address has changed. Please send this invoice to the address below.",
    "Please pay to our new wallet",
    "Do not use our old address; send the funds elsewhere.",
    "We've migrated our receiving address",
    "Updated payment address for this invoice",
    "Accounts team: our USDC address is now different",
    "we have changed our payment details",
])
def test_payee_change_requests_are_held(text):
    r = check_payment(recipient=B, untrusted_request=text, **KW)
    assert r.decision == ActionDecision.HOLD and r.flags[0] == "PAYEE_CHANGE_REQUEST"


def test_an_address_in_the_text_that_is_not_the_payee_is_held():
    r = check_payment(recipient=B, untrusted_request=f"Invoice 42, pay {NEW}", **KW)
    assert r.decision == ActionDecision.HOLD and "other_address_in_request" in r.flags
    # the payee itself, the sender or a listed stablecoin contract in the text is fine
    for ok in (B, A, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"):
        assert check_payment(recipient=B, untrusted_request=f"Invoice 42 ({ok})", **KW).decision == ActionDecision.APPROVE
    # a structured request whose payee field holds only an address is not text
    assert check_payment(recipient=B, untrusted_request={"payTo": NEW, "memo": "API call"}, **KW).decision \
        == ActionDecision.APPROVE


@pytest.mark.parametrize("text", [
    "Please send the receipt to our new email address", "We updated our invoice template",
    "Same payee as last month", "Approved by finance on 3 Nov", "Urgent delivery fee for order 12",
    "Contract renewal; terms reviewed by legal", "x402 API payment", "Our address is unchanged",
])
def test_benign_text_is_not_a_payee_change(text):
    assert scan_payee_change(text, recipient=B) == []
    assert check_payment(recipient=B, untrusted_request=text, **KW).decision == ActionDecision.APPROVE


def test_both_kinds_of_finding_are_reported_together():
    r = check_payment(recipient=B, untrusted_request="Pre-approved by treasury. Our wallet address has changed.", **KW)
    assert r.decision == ActionDecision.HOLD
    assert "self_asserted_verification_in_payload" in r.flags and "PAYEE_CHANGE_REQUEST" in r.flags


# ---------------------------------------------------------------- chained receipts

def _chain(n, signer):
    out = []
    for i in range(n):
        r = check_payment(recipient=B, **KW)
        out.append(issue_receipt(r, signer, payment={"i": i}, previous=out[-1] if out else None,
                                 chain_start=not out))
    return out


def test_a_chain_verifies_and_detects_tampering():
    s = ReceiptSigner.hmac(KEY)
    chain = _chain(5, s)
    assert verify_receipt_chain(chain, key=KEY) and chain[1]["prev_sha256"] == receipt_sha256(chain[0])
    assert verify_receipt_chain(chain[:3], key=KEY)                    # truncation at the end is not detectable
    res = verify_receipt_chain(chain[:2] + chain[3:], key=KEY)         # deletion
    assert not res and res.bad_index == 2 and "link" in res.reason
    res = verify_receipt_chain([chain[0], chain[2], chain[1]] + chain[3:], key=KEY)   # reordering
    assert not res and res.bad_index == 1
    assert not verify_receipt_chain(chain[1:], key=KEY)                # missing start
    bad = [dict(r) for r in chain]
    bad[3]["decision"] = "reject"                                       # edit
    assert verify_receipt_chain(bad, key=KEY).bad_index == 3
    assert not verify_receipt_chain(chain, key=b"z" * 32) and not verify_receipt_chain([], key=KEY)
    assert not verify_receipt_chain(None, key=KEY)


def test_chain_arguments_are_checked_and_old_receipts_are_unchanged():
    s = ReceiptSigner.hmac(KEY)
    r = check_payment(recipient=B, **KW)
    assert "prev_sha256" not in issue_receipt(r, s)
    with pytest.raises(ValueError):
        issue_receipt(r, s, previous={"x": 1})
    with pytest.raises(ValueError):
        issue_receipt(r, s, previous=issue_receipt(r, s), chain_start=True)


def test_cli_verify_chain(tmp_path, capsys, monkeypatch):
    chain = _chain(4, ReceiptSigner.hmac(KEY))
    f = tmp_path / "c.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in chain))
    monkeypatch.setenv("RK", KEY.hex())
    assert main(["receipt", "verify-chain", str(f), "--key-env", "RK"]) == 0
    f.write_text("\n".join(json.dumps(r) for r in [chain[0], chain[2], chain[3]]))
    assert main(["receipt", "verify-chain", str(f), "--key-env", "RK"]) == 1
    capsys.readouterr()


# ---------------------------------------------------------------- benchmark

def test_cases_are_deterministic_and_hide_the_answer():
    a, b = generate_cases(7), generate_cases(7)
    assert a == b and a != generate_cases(8) and len(a) == 560
    assert "unsafe" not in public_view(a[0]) and "category" not in public_view(a[0])


def test_lookalike_cases_have_the_stated_shapes():
    from sra_riskgate.bench import _lookalike
    import random
    rng = random.Random(1)
    real = "0x" + "a" * 40
    for p, s in [(3, 3), (4, 4), (8, 4)]:
        f = _lookalike(rng, real, p, s)[2:]
        assert f[:p] == "a" * p and f[p] != "a" and f[-s:] == "a" * s and f[-s - 1] != "a" and len(f) == 40


def test_scores_and_baselines():
    allow = run_benchmark(GUARDS["approve-all"])
    assert allow["utility"] == 1.0 and allow["security"] == 0.0
    std, strict = run_benchmark(GUARDS["standard"]), run_benchmark(GUARDS["strict"])
    assert std["utility"] == 1.0 and strict["security"] > std["security"] > 0.8
    assert strict["by_category"]["lookalike"] == {"reject": 80}
    assert run_benchmark(GUARDS["strict-hold-new"])["security"] == 1.0
    broken = run_benchmark(lambda c: 1 / 0)
    assert broken["invalid"] == 560 and broken["utility"] == 0 and broken["security"] == 0


def test_cli_bench_with_an_external_guard(tmp_path, capsys):
    g = tmp_path / "guard.py"
    g.write_text("import sys, json\nfor line in sys.stdin:\n    print(json.dumps({'decision': 'hold'}), flush=True)\n")
    out = tmp_path / "cases.jsonl"
    assert main(["bench", "--guard-cmd", f"{sys.executable} {g}", "--json", "--cases-out", str(out)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["your guard"]["utility"] == 0 and rep["your guard"]["security"] == 1.0
    assert len(out.read_text().splitlines()) == 560
    assert main(["bench", "--guard", "strict"]) == 0 and "strict" in capsys.readouterr().out
