"""Evidence packs (1.13.0): build, reproduce, verify, and refuse to vouch for bad input."""
import json
import zipfile

import pytest

from sra_riskgate import ReceiptSigner, check_payment, issue_receipt
from sra_riskgate.bench import run_benchmark, GUARDS
from sra_riskgate.cli import main
from sra_riskgate.evidence import DEMO_RECEIPT_KEY, build_evidence_pack, self_check, verify_evidence_pack

KEY = b"k" * 32
EXPECTED_FILES = {"README.md", "MANIFEST.json", "selfcheck.json", "bench.json", "bench.md", "bench_cases.jsonl",
                  "threats.json", "threats.md", "audit_report.json", "audit_report.md", "demo_receipts.jsonl",
                  "environment.json"}


def _receipts(n=3):
    signer, out = ReceiptSigner.hmac(KEY), []
    for i in range(n):
        p = {"chain_id": 8453, "sender": "0x" + "1" * 40, "recipient": "0x" + "2" * 40, "amount": 10 + i}
        r = check_payment(chain_id=8453, sender=p["sender"], recipient=p["recipient"], amount=p["amount"],
                          peg_deviation_pct=0.0)
        out.append(issue_receipt(r, signer, payment=p, **({"previous": out[-1]} if out else {"chain_start": True})))
    return out


def test_self_check_passes():
    sc = self_check()
    assert sc["passed"] and sc["failed"] == 0 and sc["total"] >= 8
    assert {c["expected"] for c in sc["cases"]} == {"approve", "hold", "reject"}


def test_default_pack(tmp_path):
    m = build_evidence_pack(tmp_path / "ev")
    assert m["ok"] and m["demo_audit_report"]
    assert set(m["files"]) == EXPECTED_FILES - {"MANIFEST.json"}
    assert {p.name for p in (tmp_path / "ev").iterdir()} == EXPECTED_FILES
    assert verify_evidence_pack(tmp_path / "ev")["ok"]
    readme = (tmp_path / "ev" / "README.md").read_text()
    assert "demo" in readme.lower() and "not independent accuracy" in readme
    assert (tmp_path / "ev" / "audit_report.md").read_text().startswith("> **DEMO.**")


def test_bench_in_pack_matches_a_fresh_run(tmp_path):
    build_evidence_pack(tmp_path / "ev", seed=3)
    saved = json.loads((tmp_path / "ev" / "bench.json").read_text())["guards"]["strict"]
    fresh = run_benchmark(GUARDS["strict"], seed=3)
    fresh.pop("ms_per_case")
    assert saved == fresh


def test_demo_report_reproduces_from_the_published_key(tmp_path, monkeypatch, capsys):
    build_evidence_pack(tmp_path / "ev")
    want = json.loads((tmp_path / "ev" / "audit_report.json").read_text())["report_sha256"]
    monkeypatch.setenv("K", DEMO_RECEIPT_KEY.hex())
    assert main(["receipt", "report", str(tmp_path / "ev" / "demo_receipts.jsonl"), "--key-env", "K", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["report_sha256"] == want


def test_tampering_is_detected(tmp_path):
    build_evidence_pack(tmp_path / "ev", make_zip=True)
    ev = tmp_path / "ev"
    assert verify_evidence_pack(tmp_path / "ev.zip")["ok"]
    (ev / "bench.md").write_text("better numbers")
    (ev / "extra.txt").write_text("x")
    (ev / "threats.md").unlink()
    probs = " ".join(verify_evidence_pack(ev)["problems"])
    assert "bench.md: changed" in probs and "extra.txt: not in the manifest" in probs and "threats.md: missing" in probs
    m = json.loads((ev / "MANIFEST.json").read_text())
    m["files"]["bench.md"] = "0" * 64  # editing the manifest's hashes breaks pack_sha256
    (ev / "MANIFEST.json").write_text(json.dumps(m))
    assert "pack_sha256 does not match" in " ".join(verify_evidence_pack(ev)["problems"])


def test_unreadable_paths(tmp_path):
    assert verify_evidence_pack(tmp_path / "nope")["problems"] == [f"{tmp_path / 'nope'} not found"]
    (tmp_path / "empty").mkdir()
    assert verify_evidence_pack(tmp_path / "empty")["problems"] == ["MANIFEST.json is missing or unreadable"]
    with zipfile.ZipFile(tmp_path / "bad.zip", "w") as z:
        z.writestr("x/a.txt", "a")
    assert not verify_evidence_pack(tmp_path / "bad.zip")["ok"]


def test_own_receipts(tmp_path):
    m = build_evidence_pack(tmp_path / "ev", receipts=_receipts(), key=KEY)
    assert m["ok"] and not m["demo_audit_report"]
    assert m["summary"]["audit"] == {**m["summary"]["audit"], "receipts": 3, "verified": 3, "chain_intact": True}
    assert not (tmp_path / "ev" / "demo_receipts.jsonl").exists()
    assert "demo" not in (tmp_path / "ev" / "README.md").read_text().lower().split("## limits")[1]


def test_bad_receipts_make_the_pack_not_ok(tmp_path):
    rows = _receipts()
    rows[1] = {**rows[1], "amount_note": "edited"}
    m = build_evidence_pack(tmp_path / "ev", receipts=rows, key=KEY)
    assert not m["ok"] and m["summary"]["audit"]["invalid"] == 1
    assert "did not verify" in (tmp_path / "ev" / "README.md").read_text()
    assert not build_evidence_pack(tmp_path / "ev2", receipts=[], key=KEY)["ok"]


def test_refuses_unverifiable_receipts_and_non_empty_folders(tmp_path):
    with pytest.raises(ValueError, match="key="):
        build_evidence_pack(tmp_path / "ev", receipts=_receipts())
    (tmp_path / "full").mkdir()
    (tmp_path / "full" / "x").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        build_evidence_pack(tmp_path / "full")


def test_policy_summary_has_no_addresses(tmp_path):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"version": 1, "name": "agents", "max_amount": 50, "known_recipients": ["0x" + "2" * 40]}))
    build_evidence_pack(tmp_path / "ev", policy=str(pol))
    text = (tmp_path / "ev" / "policy.json").read_text()
    d = json.loads(text)
    assert d["name"] == "agents" and "known_recipients" in d["sets"] and "0x2222" not in text


def test_failing_tests_are_recorded(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "test_x.py").write_text("def test_ok():\n    pass\n\ndef test_bad():\n    assert False\n")
    m = build_evidence_pack(tmp_path / "ev", tests=str(t))
    res = m["summary"]["tests"]
    assert not m["ok"] and res["ran"] and res["counts"] == {"passed": 1, "failed": 1}


def test_cli(tmp_path, capsys, monkeypatch):
    out = tmp_path / "ev"
    assert main(["evidence", "build", "--out", str(out)]) == 0
    assert "READY" in capsys.readouterr().out
    assert main(["evidence", "verify", str(out)]) == 0
    (out / "bench.md").write_text("x")
    assert main(["evidence", "verify", str(out)]) == 1
    assert main(["evidence", "build", "--out", str(out)]) == 3  # not empty
    capsys.readouterr()
    f = tmp_path / "r.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in _receipts()))
    monkeypatch.setenv("RK", KEY.hex())
    assert main(["evidence", "build", "--out", str(tmp_path / "ev2"), "--receipts", str(f), "--key-env", "RK",
                 "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["audit"]["verified"] == 3
    assert main(["evidence", "build", "--out", str(tmp_path / "ev3"), "--receipts", str(f)]) == 3
    assert main(["evidence", "build", "--out", str(tmp_path / "ev4"), "--key-env", "RK"]) == 3


def test_bench_cli_reports_the_seed_it_used(capsys):
    assert main(["bench", "--guard", "strict", "--seed", "3", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["strict"]["seed"] == 3


def test_zip_name_keeps_dots_in_the_folder_name(tmp_path):
    m = build_evidence_pack(tmp_path / "pack-1.13.0", make_zip=True)
    assert m["zip"].endswith("pack-1.13.0.zip") and verify_evidence_pack(m["zip"])["ok"]
