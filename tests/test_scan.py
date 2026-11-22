"""Poisoning scan (1.14.0): find look-alikes planted in a wallet's history, from standard JSON-RPC logs."""
import json
import random

import pytest

from sra_riskgate import load_policy
from sra_riskgate.cli import main
from sra_riskgate.scan import TRANSFER_TOPIC, ScanError, scan_policy, scan_wallet

USDC_ETH = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"
FAKE_TOKEN = "0x" + "fa" * 20
WALLET = "0x" + "a1" * 20
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"

# Every (shared prefix, shared suffix) shape among the 179 real attacks in
# huggingface.co/datasets/sriram1983007/sra-real-world-poisoning (attacks.csv).
REAL_SHAPES = [(4, 4), (4, 3), (3, 3), (8, 4), (4, 6), (3, 6), (9, 29), (4, 5), (5, 4), (16, 23), (3, 7), (3, 5)]


def lookalike(real, prefix, suffix, seed=0):
    """An address sharing exactly ``prefix`` leading and ``suffix`` trailing hex characters with ``real``."""
    rng = random.Random(seed)
    h = real[2:]
    mid = []
    for i in range(prefix, 40 - suffix):
        mid.append(rng.choice([c for c in "0123456789abcdef" if c != h[i]]))
    return "0x" + h[:prefix] + "".join(mid) + h[40 - suffix:]


def topic(a):
    return "0x" + "0" * 24 + a[2:]


class FakeRPC:
    def __init__(self, chain_id=1, latest=1_000_000, max_range=None, fail=None):
        self.chain_id, self.latest, self.max_range, self.fail = chain_id, latest, max_range, fail
        self.logs, self.calls, self.n = [], [], 0

    def transfer(self, token, frm, to, value, block, tx=None):
        self.n += 1
        self.logs.append({"address": token, "blockNumber": hex(block), "transactionHash": tx or f"0x{self.n:064x}",
                          "topics": [TRANSFER_TOPIC, topic(frm), topic(to)], "data": hex(value)})

    def __call__(self, method, params):
        self.calls.append(method)
        if self.fail:
            raise ScanError(self.fail)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.latest)
        assert method == "eth_getLogs"
        f = params[0]
        lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
        if self.max_range and hi - lo + 1 > self.max_range:
            raise ScanError("query exceeds max block range 1000")
        want = f["topics"]
        out = []
        for lg in self.logs:
            if not lo <= int(lg["blockNumber"], 16) <= hi:
                continue
            if all(w is None or (i < len(lg["topics"]) and lg["topics"][i] == w) for i, w in enumerate(want)):
                out.append(lg)
        return out


def poisoned_wallet(prefix=4, suffix=4, kind="zero"):
    rpc = FakeRPC()
    rpc.transfer(USDC_ETH, WALLET, PAYEE, 250_000_000, 990_000)                 # a real payment
    fake = lookalike(PAYEE, prefix, suffix)
    if kind == "zero":
        rpc.transfer(USDC_ETH, WALLET, fake, 0, 990_100)                        # zero-value transferFrom "from" you
    elif kind == "fake_token":
        rpc.transfer(FAKE_TOKEN, WALLET, fake, 250_000_000, 990_100)            # fake token mimicking the payment
    else:
        rpc.transfer(USDC_ETH, fake, WALLET, 1, 990_100)                        # dust to you
    return rpc, fake


@pytest.mark.parametrize("prefix,suffix", REAL_SHAPES)
def test_every_real_attack_shape_is_found_with_strict(prefix, suffix):
    rpc, fake = poisoned_wallet(prefix, suffix)
    r = scan_wallet(WALLET, rpc=rpc)
    assert r["blocked_addresses"] == [fake]
    f = r["findings"][0]
    assert (f["imitates"], f["shared_prefix"], f["shared_suffix"]) == (PAYEE, prefix, suffix)


def test_standard_rule_misses_three_and_three_strict_does_not():
    rpc, fake = poisoned_wallet(3, 3)
    assert scan_wallet(WALLET, rpc=rpc, lookalike_check="standard")["findings"] == []
    assert scan_wallet(WALLET, rpc=rpc)["blocked_addresses"] == [fake]


@pytest.mark.parametrize("kind,label", [("zero", "zero_value_transfer"), ("fake_token", "fake_token"),
                                        ("dust", "dust_received")])
def test_how_it_was_planted(kind, label):
    rpc, fake = poisoned_wallet(kind=kind)
    f = scan_wallet(WALLET, rpc=rpc)["findings"][0]
    assert f["kinds"] == [label] and f["transactions"][0]["url"].startswith("https://etherscan.io/tx/0x")


def test_clean_wallet_has_no_findings():
    rpc = FakeRPC()
    rng = random.Random(7)
    payees = ["0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40)) for _ in range(40)]
    for i, p in enumerate(payees):
        rpc.transfer(USDC_ETH if i % 2 else USDT_ETH, WALLET, p, 10_000_000 + i, 900_000 + i)
        rpc.transfer(USDC_ETH, p, WALLET, 5_000_000, 950_000 + i)               # ordinary incoming payments
    r = scan_wallet(WALLET, rpc=rpc)
    assert r["findings"] == [] and r["suspicious_payees"] == [] and r["payees"] == 40 and r["complete"]


def test_payee_paid_twice_by_mistake_is_flagged_as_suspicious():
    rpc, fake = poisoned_wallet()
    rpc.transfer(USDC_ETH, WALLET, fake, 9_000_000_000, 990_500)                 # the loss: paid the copy
    r = scan_wallet(WALLET, rpc=rpc)
    assert r["findings"] == []                                                   # it is a payee now, not a finding
    s = r["suspicious_payees"][0]
    assert set(s["addresses"]) == {PAYEE, fake} and s["payments"][fake] == 1


def test_known_payees_you_pass_in_count_too():
    rpc = FakeRPC()
    fake = lookalike(PAYEE, 4, 4)
    rpc.transfer(USDC_ETH, fake, WALLET, 1, 990_000)
    assert scan_wallet(WALLET, rpc=rpc)["findings"] == []                        # no payee known: nothing to imitate
    assert scan_wallet(WALLET, rpc=rpc, known_payees=[PAYEE])["blocked_addresses"] == [fake]


def test_block_range_and_range_limited_rpcs():
    rpc, fake = poisoned_wallet()
    rpc.max_range = 1000
    r = scan_wallet(WALLET, rpc=rpc, blocks=20_000, chunk=10_000)
    assert r["blocked_addresses"] == [fake] and r["complete"]
    assert (r["from_block"], r["to_block"]) == (980_001, 1_000_000)
    assert scan_wallet(WALLET, rpc=FakeRPC(), from_block=5, to_block=10)["from_block"] == 5
    old, _ = poisoned_wallet()
    assert scan_wallet(WALLET, rpc=old, blocks=5_000)["findings"] == []          # planted before the range


def test_request_budget_marks_the_scan_incomplete():
    rpc, _ = poisoned_wallet()
    r = scan_wallet(WALLET, rpc=rpc, blocks=100_000, chunk=1_000, max_requests=5)
    assert r["complete"] is False and r["stopped_at_block"] and r["requests_used"] == 5


def test_rpc_errors_are_raised_not_hidden():
    with pytest.raises(ScanError):
        scan_wallet(WALLET, rpc=FakeRPC(fail="unauthorized"))
    rpc = FakeRPC()
    rpc.max_range = 1
    rpc.transfer(USDC_ETH, WALLET, PAYEE, 1, 999_999)

    def broken(method, params):
        if method == "eth_getLogs":
            raise ScanError("method not allowed")
        return rpc(method, params)
    with pytest.raises(ScanError, match="not allowed"):
        scan_wallet(WALLET, rpc=broken)


def test_bad_arguments():
    for kw in ({"blocks": 0}, {"chunk": -1}, {"max_requests": True}, {"lookalike_check": "loose"},
               {"known_payees": "0xabc"}):
        with pytest.raises(ValueError):
            scan_wallet(WALLET, rpc=FakeRPC(), **kw)
    with pytest.raises(ValueError):
        scan_wallet("not-an-address", rpc=FakeRPC())
    with pytest.raises(ValueError):
        scan_wallet(WALLET)
    with pytest.raises(ScanError):
        scan_wallet(WALLET, rpc_url="file:///etc/passwd")


def test_malformed_logs_are_skipped():
    rpc, fake = poisoned_wallet()
    rpc.logs.append({"address": USDC_ETH, "blockNumber": hex(990_200), "topics": [TRANSFER_TOPIC, topic(WALLET)],
                     "data": "0x"})
    rpc.logs.append({"address": USDC_ETH, "blockNumber": hex(990_201), "transactionHash": "0x1",
                     "topics": [TRANSFER_TOPIC, topic(WALLET), "0xnothex"], "data": "zz"})
    assert scan_wallet(WALLET, rpc=rpc)["blocked_addresses"] == [fake]


def test_policy_from_a_scan_validates(tmp_path):
    rpc, fake = poisoned_wallet()
    r = scan_wallet(WALLET, rpc=rpc)
    pol = scan_policy(r, include_payees=True)
    path = tmp_path / "p.json"
    path.write_text(json.dumps(pol))
    p = load_policy(str(path))
    d = p.as_dict()
    assert d["blocked_addresses"] == [fake] and d["known_recipients"] == [PAYEE] and d["lookalike_check"] == "strict"
    assert "known_recipients" not in scan_policy(r)


def test_cli(tmp_path, capsys, monkeypatch):
    rpc, fake = poisoned_wallet()
    monkeypatch.setattr("sra_riskgate.scan._http_rpc", lambda url, timeout=30.0: rpc)
    out = tmp_path / "policy.json"
    assert main(["scan", WALLET, "--rpc", "https://rpc.example", "--write-policy", str(out)]) == 10
    text = capsys.readouterr().out
    assert "FOUND 1" in text and fake in text and PAYEE in text
    assert load_policy(str(out)).as_dict()["blocked_addresses"] == [fake]
    monkeypatch.setenv("SRA_RPC_URL", "https://rpc.example")
    assert main(["scan", WALLET, "--json"]) == 10
    assert json.loads(capsys.readouterr().out)["blocked_addresses"] == [fake]
    clean = FakeRPC()
    monkeypatch.setattr("sra_riskgate.scan._http_rpc", lambda url, timeout=30.0: clean)
    assert main(["scan", WALLET]) == 0 and "CLEAN" in capsys.readouterr().out
    monkeypatch.delenv("SRA_RPC_URL")
    assert main(["scan", WALLET]) == 3
    monkeypatch.setattr("sra_riskgate.scan._http_rpc", lambda url, timeout=30.0: FakeRPC(fail="boom"))
    assert main(["scan", WALLET, "--rpc", "https://x"]) == 3
    assert main(["scan", "0x123", "--rpc", "https://x"]) == 3


def test_cli_incomplete_clean_scan_is_not_reported_clean(capsys, monkeypatch):
    monkeypatch.setattr("sra_riskgate.scan._http_rpc", lambda url, timeout=30.0: FakeRPC())
    assert main(["scan", WALLET, "--rpc", "https://x", "--blocks", "100000", "--max-requests", "3"]) == 1
    assert "INCOMPLETE" in capsys.readouterr().out


def test_learned_range_is_reused_for_the_second_query():
    rpc, fake = poisoned_wallet()
    rpc.max_range = 1000
    r = scan_wallet(WALLET, rpc=rpc, blocks=20_000, chunk=8_000)
    # first query: 8000, 4000, 2000 refused, then 20 x 1000; second query starts at 1000: 20 more
    assert r["requests_used"] == 3 + 20 + 20 and r["blocked_addresses"] == [fake]
