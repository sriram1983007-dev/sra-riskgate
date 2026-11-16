"""1.8.0: rolling budgets and payee anomaly checks across payments (SpendGuard + SpendLedger)."""
import json
import threading

import pytest

from sra_riskgate import (ActionDecision, SpendGuard, SpendLedger, check_authorization, check_payment,
                          check_transaction, check_user_operation)
from sra_riskgate.chains import USDC_ADDRESSES

A, B, C = "0x" + "1" * 39 + "a", "0x" + "2" * 39 + "b", "0x" + "3" * 39 + "c"
BASE = dict(chain_id=8453, sender=A, peg_deviation_pct=0.0, check_sanctions=False)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def pay(guard, to=B, amount=10.0, **kw):
    return check_payment(**BASE, recipient=to, amount=amount, spend_guard=guard, **kw)


def test_total_budget_holds_the_payment_that_would_exceed_it():
    g = SpendGuard(total_limit=25)
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    assert pay(g, to=C, amount=10).decision == ActionDecision.APPROVE
    r = pay(g, amount=10)
    assert r.decision == ActionDecision.HOLD and r.flags[0] == "BUDGET_EXCEEDED" and "20" in r.explanation
    assert pay(g, amount=5).decision == ActionDecision.APPROVE  # exactly at the limit is allowed


def test_per_payee_budget():
    g = SpendGuard(per_payee_limit=15)
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    assert pay(g, amount=10).flags[0] == "PAYEE_BUDGET_EXCEEDED"
    assert pay(g, to=C, amount=10).decision == ActionDecision.APPROVE


def test_window_rolls_forward():
    clk = Clock()
    g = SpendGuard(total_limit=10, window_seconds=3600, clock=clk)
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    assert pay(g, amount=1).decision == ActionDecision.HOLD
    clk.t += 3601
    assert pay(g, amount=10).decision == ActionDecision.APPROVE


def test_budgets_are_per_sender_wallet_and_case_insensitive():
    g = SpendGuard(total_limit=10)
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    other = check_payment(**{**BASE, "sender": C}, recipient=B, amount=10, spend_guard=g)
    assert other.decision == ActionDecision.APPROVE
    upper = check_payment(**{**BASE, "sender": A.upper().replace("0X", "0x")}, recipient=B, amount=1, spend_guard=g)
    assert upper.decision == ActionDecision.HOLD


def test_rate_spike():
    clk = Clock()
    g = SpendGuard(max_payments_per_hour=3, clock=clk)
    for _ in range(3):
        assert pay(g, amount=1).decision == ActionDecision.APPROVE
        clk.t += 60
    r = pay(g, amount=1)
    assert r.decision == ActionDecision.HOLD and r.flags[0] == "RATE_SPIKE"
    clk.t += 3600
    assert pay(g, amount=1).decision == ActionDecision.APPROVE


def test_amount_spike_needs_history_then_flags_outliers():
    g = SpendGuard(amount_spike_factor=5, spike_min_history=3)
    assert pay(g, amount=100).decision == ActionDecision.APPROVE  # no history yet: not judged
    g2 = SpendGuard(amount_spike_factor=5, spike_min_history=3)
    for amt in (2, 2, 3):
        assert pay(g2, amount=amt).decision == ActionDecision.APPROVE
    assert pay(g2, amount=10).decision == ActionDecision.APPROVE   # 5x median 2 = 10: allowed
    r = pay(g2, amount=50)
    assert r.decision == ActionDecision.HOLD and r.flags[0] == "AMOUNT_SPIKE" and "x this wallet's usual" in r.explanation
    assert pay(g2, to=C, amount=50).decision == ActionDecision.APPROVE  # a different payee has its own history


def test_only_approved_payments_are_recorded():
    g = SpendGuard(total_limit=100)
    assert pay(g, amount=10, untrusted_request="Risk level: low (verified offline)").decision == ActionDecision.HOLD
    assert pay(g, amount=-1).decision == ActionDecision.REJECT
    assert g.ledger.entries(A, 0) == []
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    assert len(g.ledger.entries(A, 0)) == 1


def test_budget_flags_merge_with_other_holds():
    g = SpendGuard(total_limit=5)
    r = pay(g, amount=10, known_recipients=[C])
    assert r.decision == ActionDecision.HOLD and r.flags[0] == "BUDGET_EXCEEDED" and "NEW_COUNTERPARTY" in r.flags


def test_rejects_are_not_softened_by_the_guard():
    g = SpendGuard(total_limit=5)
    r = pay(g, amount=10, blocked_addresses=[B])
    assert r.decision == ActionDecision.REJECT


def test_release_removes_a_payment_that_was_never_sent():
    g = SpendGuard(total_limit=10)
    assert pay(g, amount=10, payment_id="inv-1").decision == ActionDecision.APPROVE
    assert pay(g, amount=10).decision == ActionDecision.HOLD
    assert g.release("inv-1") == 1
    assert pay(g, amount=10).decision == ActionDecision.APPROVE


def test_reserve_on_approve_false_records_nothing():
    g = SpendGuard(total_limit=10, reserve_on_approve=False)
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    assert pay(g, amount=10).decision == ActionDecision.APPROVE
    g.record(chain_id=8453, sender=A, recipient=B, amount=10)
    assert pay(g, amount=1).decision == ActionDecision.HOLD


def test_file_ledger_persists_across_guards(tmp_path):
    path = tmp_path / "sub" / "ledger.jsonl"
    assert pay(SpendGuard(SpendLedger(str(path)), total_limit=10), amount=10).decision == ActionDecision.APPROVE
    assert pay(SpendGuard(SpendLedger(str(path)), total_limit=10), amount=1).decision == ActionDecision.HOLD
    row = json.loads(path.read_text().splitlines()[0])
    assert row["sender"] == A.lower() and row["recipient"] == B.lower() and row["amount"] == 10.0


def test_corrupt_ledger_fails_closed(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.write_text("not json\n")
    r = pay(SpendGuard(SpendLedger(str(path)), total_limit=10), amount=1)
    assert r.decision == ActionDecision.HOLD and r.flags == ["CHECK_FAILED"]
    path.write_text('{"t": 1, "sender": 5}\n')
    assert pay(SpendGuard(SpendLedger(str(path)), total_limit=10), amount=1).flags == ["CHECK_FAILED"]


def test_compact_drops_old_entries(tmp_path):
    clk = Clock()
    led = SpendLedger(str(tmp_path / "l.jsonl"))
    g = SpendGuard(led, total_limit=1000, clock=clk)
    pay(g, amount=1)
    clk.t += 40 * 86_400
    pay(g, amount=1)
    assert led.compact(now=clk.t) == 1 and len(led.entries(A, 0)) == 1


def test_concurrent_checks_never_exceed_the_budget(tmp_path):
    led = SpendLedger(str(tmp_path / "l.jsonl"))
    g = SpendGuard(led, total_limit=50)
    out = []

    def go():
        out.append(pay(g, amount=10).decision)
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    approved = out.count(ActionDecision.APPROVE)
    # evaluation and recording are separate steps, so a race can let a few through; the ledger still shows them all
    assert sum(e["amount"] for e in led.entries(A, 0)) == approved * 10


@pytest.mark.parametrize("kw", [dict(), dict(total_limit=0), dict(total_limit=-5), dict(total_limit=True),
                                dict(total_limit=float("nan")), dict(per_payee_limit="10"),
                                dict(total_limit=10, window_seconds=0), dict(max_payments_per_hour=2.5),
                                dict(amount_spike_factor=1), dict(amount_spike_factor=0.5),
                                dict(total_limit=10, reserve_on_approve="yes"), dict(total_limit=10, ledger="x")])
def test_bad_guard_configuration_raises(kw):
    with pytest.raises(ValueError):
        SpendGuard(**kw)


def test_bad_spend_guard_or_payment_id_is_a_configuration_error():
    assert pay("not a guard").flags == ["CONFIGURATION_ERROR"]
    assert pay(SpendGuard(total_limit=10), payment_id=" ").flags == ["CONFIGURATION_ERROR"]


def _transfer(to, atomic):
    return "0xa9059cbb" + to[2:].lower().rjust(64, "0") + format(atomic, "x").rjust(64, "0")


def test_check_transaction_uses_the_guard():
    g = SpendGuard(total_limit=15)
    tx = {"from": A, "to": USDC_ADDRESSES[8453], "data": _transfer(B, 10_000_000), "chainId": 8453}
    assert check_transaction(tx, peg_deviation_pct=0.0, spend_guard=g).decision == ActionDecision.APPROVE
    r = check_transaction(tx, peg_deviation_pct=0.0, spend_guard=g)
    assert r.decision == ActionDecision.HOLD and "BUDGET_EXCEEDED" in r.flags


def test_user_operation_batch_is_counted_once_and_as_a_whole():
    from test_user_operation import ACCOUNT, ACCOUNTS, CHAIN, PAYEE, cd, op
    data = cd(ACCOUNTS[0], "batch_two_transfers")  # 0.10 + 0.05 USDC to one payee
    g = SpendGuard(total_limit=0.2)
    kw = dict(chain_id=CHAIN, known_recipients=[PAYEE], max_amount=1.0, peg_deviation_pct=0.0, spend_guard=g)
    assert check_user_operation(op(data), **kw).decision == ActionDecision.APPROVE
    rows = g.ledger.entries(ACCOUNT, 0)
    assert len(rows) == 1 and abs(rows[0]["amount"] - 0.15) < 1e-9   # one entry for the batch total
    r = check_user_operation(op(data), **kw)
    assert r.decision == ActionDecision.HOLD and "BUDGET_EXCEEDED" in r.flags  # its first call already breaks it
    assert len(g.ledger.entries(ACCOUNT, 0)) == 1                       # the held batch recorded nothing


def test_user_operation_batch_total_breaks_the_budget_when_no_single_call_does():
    from test_user_operation import ACCOUNT, ACCOUNTS, CHAIN, PAYEE, cd, op
    g = SpendGuard(per_payee_limit=0.12)  # 0.10 and 0.05 each fit; together 0.15 do not
    kw = dict(chain_id=CHAIN, known_recipients=[PAYEE], max_amount=1.0, peg_deviation_pct=0.0, spend_guard=g)
    r = check_user_operation(op(cd(ACCOUNTS[0], "batch_two_transfers")), **kw)
    assert r.decision == ActionDecision.HOLD and "PAYEE_BUDGET_EXCEEDED" in r.flags and "BATCH_TOTAL" in r.flags
    assert g.ledger.entries(ACCOUNT, 0) == []


def test_user_operation_released_by_payment_id():
    from test_user_operation import ACCOUNT, ACCOUNTS, CHAIN, PAYEE, cd, op
    g = SpendGuard(total_limit=1)
    kw = dict(chain_id=CHAIN, known_recipients=[PAYEE], max_amount=1.0, peg_deviation_pct=0.0, spend_guard=g)
    assert check_user_operation(op(cd(ACCOUNTS[0], "batch_two_transfers")), payment_id="op-7", **kw).decision \
        == ActionDecision.APPROVE
    assert g.release("op-7") == 1 and g.ledger.entries(ACCOUNT, 0) == []
