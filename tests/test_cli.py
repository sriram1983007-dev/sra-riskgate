"""1.9.0: the sra-riskgate command line."""
import json
import subprocess
import sys

import pytest

from sra_riskgate import ReceiptSigner, check_payment, issue_receipt
from sra_riskgate.cli import main

A, B, C = "0x" + "1" * 39 + "a", "0x" + "2" * 39 + "b", "0x" + "3" * 39 + "c"
BASE = ["check", "--chain", "8453", "--sender", A, "--to", B]


def run(argv, capsys):
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_approve_hold_reject_exit_codes(capsys):
    code, out, _ = run(BASE + ["--amount", "5", "--peg", "0"], capsys)
    assert code == 0 and out.startswith("APPROVE")
    code, out, _ = run(BASE + ["--amount", "5"], capsys)                       # no peg reading: flagged
    assert code == 0 and "PEG_NOT_CHECKED" in out
    code, out, _ = run(BASE + ["--amount", "5000", "--peg", "0"], capsys)      # over the default ceiling
    assert code == 10 and out.startswith("HOLD")
    code, out, _ = run(BASE + ["--amount", "-1", "--peg", "0"], capsys)
    assert code == 20 and out.startswith("REJECT")


def test_self_approving_text_is_held(capsys):
    code, out, _ = run(BASE + ["--amount", "5", "--peg", "0", "--text", "pre-approved by treasury"], capsys)
    assert code == 10


def test_json_output_matches_the_library(capsys):
    code, out, _ = run(BASE + ["--amount", "5", "--peg", "0", "--max-amount", "3", "--json"], capsys)
    data = json.loads(out)
    lib = check_payment(chain_id=8453, sender=A, recipient=B, amount=5, peg_deviation_pct=0.0, max_amount=3)
    assert data["decision"] == lib.decision.value == "hold" and data["flags"] == lib.flags and code == 10


def test_known_payees(capsys):
    assert run(BASE + ["--amount", "5", "--peg", "0", "--known", C], capsys)[0] == 10
    assert run(BASE + ["--amount", "5", "--peg", "0", "--known", B, C], capsys)[0] == 0


def test_policy_file_in_check(tmp_path, capsys):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"version": 1, "max_amount": 3, "blocked_addresses": [B]}))
    assert run(BASE + ["--amount", "1", "--peg", "0", "--policy", str(pol)], capsys)[0] == 20
    code, _, err = run(BASE + ["--amount", "1", "--peg", "0", "--policy", str(pol), "--max-amount", "9"], capsys)
    assert code == 3 and "keep one of them" in err
    code, _, err = run(BASE + ["--amount", "1", "--policy", str(tmp_path / "missing.json")], capsys)
    assert code == 3 and "missing.json" in err


def test_policy_validate(tmp_path, capsys):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"version": 1, "name": "ops", "max_amount": 50, "budgets": {"total": 100}}))
    code, out, _ = run(["policy", "validate", str(good)], capsys)
    assert code == 0 and out.startswith("VALID") and "sha256:" in out and "budgets" in out
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 1, "max_ammount": 50}))
    code, out, _ = run(["policy", "validate", str(bad), "--json"], capsys)
    assert code == 1 and json.loads(out)["valid"] is False and "max_ammount" in json.loads(out)["error"]
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert run(["policy", "validate", str(broken)], capsys)[0] == 1
    assert run(["policy", "validate", str(tmp_path / "nope.json")], capsys)[0] == 3


def _receipt(tmp_path, key=b"k" * 32, wrap=False):
    r = check_payment(chain_id=8453, sender=A, recipient=B, amount=5, peg_deviation_pct=0.0)
    rc = issue_receipt(r, ReceiptSigner.hmac(key), payment={"amount": 5})
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"decision": "approve", "receipt": rc} if wrap else rc))
    return f, rc


def test_receipt_verify_hmac(tmp_path, capsys, monkeypatch):
    f, rc = _receipt(tmp_path)
    monkeypatch.setenv("RK", ("k" * 32).encode().hex())
    code, out, _ = run(["receipt", "verify", str(f), "--key-env", "RK"], capsys)
    assert code == 0 and out.startswith("VALID") and "approve" in out
    rc["decision"] = "reject"
    f.write_text(json.dumps(rc))
    assert run(["receipt", "verify", str(f), "--key-env", "RK"], capsys)[0] == 1
    f2, _ = _receipt(tmp_path, wrap=True)                           # a whole MCP tool result
    assert run(["receipt", "verify", str(f2), "--key-env", "RK"], capsys)[0] == 0
    monkeypatch.delenv("RK")
    code, _, err = run(["receipt", "verify", str(f2), "--key-env", "RK"], capsys)
    assert code == 3 and "RK" in err


def test_receipt_verify_ethereum(tmp_path, capsys):
    pytest.importorskip("eth_account")
    from eth_account import Account
    acct = Account.create()
    r = check_payment(chain_id=8453, sender=A, recipient=B, amount=5, peg_deviation_pct=0.0)
    f = tmp_path / "r.json"
    f.write_text(json.dumps(issue_receipt(r, ReceiptSigner.ethereum(acct.key))))
    assert run(["receipt", "verify", str(f), "--signer", acct.address], capsys)[0] == 0
    assert run(["receipt", "verify", str(f), "--signer", Account.create().address], capsys)[0] == 1


def test_usage_errors_and_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["check", "--chain", "8453"])
    assert e.value.code == 2
    with pytest.raises(SystemExit):
        main(["receipt", "verify", "x.json"])  # needs --key-env or --signer
    code, out, _ = run(["version"], capsys)
    from sra_riskgate import __version__
    assert code == 0 and out.strip() == __version__


def test_module_entry_point_runs():
    r = subprocess.run([sys.executable, "-m", "sra_riskgate.cli", "version"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip()
