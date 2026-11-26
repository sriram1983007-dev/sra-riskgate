"""Error analysis of the published predictions (Section 8) and the contamination analysis (Section 11).

    python paper/study/failures.py TEST TRAIN V1_PRED V2_PRED Q4_PRED

TEST and TRAIN are data/benchmark/test.jsonl and train.jsonl of sra-stablecoin-risk-bench; the *_PRED
files are predictions.jsonl of sra-riskgate-4b, sra-riskgate-4b-v2 and sra-riskgate-4b-q4_k_m in
sra-bench-results. Uses the installed sra-riskgate for the two deterministic checks.
"""
import hashlib
import json
import sys

from sra_riskgate import check_dispute_verdict, scan_payload_claims

from _common import emit, label, load_jsonl, predictions

REFUND = {"reverse_before_release", "forced_refund", "voluntary_refund", "recommend_voluntary_refund"}
DENY = {"deny", "dismiss"}
DAY = 86400


def payload(row):
    return json.loads(row["input"]).get("payload")


def gold_decision(row):
    return label(row).get("decision", row.get("decision"))


def claims(test, train, preds):
    rg = [r for r in test if r.get("task") == "risk_gate"]
    risky = [r for r in rg if gold_decision(r) in ("hold", "reject")]
    approved = [r for r in risky if preds.get(r["id"], {}).get("decision") == "approve"]
    still = [r for r in approved if not scan_payload_claims(payload(r))]
    return {"risky": len(risky), "unsafe": len(approved), "unsafe_after_check": len(still),
            "unsafe_injected": sum("injection" in (r.get("perturbations") or []) for r in approved),
            "held_by_check": len(approved) - len(still),
            "unsafe_rate_after_check": len(still) / len(risky)}


def false_holds(rows):
    legit = [r for r in rows if r.get("task") == "risk_gate" and gold_decision(r) == "approve"]
    return len(legit), sum(bool(scan_payload_claims(payload(r))) for r in legit)


def outcome_metrics(rows, outcome_of):
    n = ok = ref_n = den = notref = wr = 0
    for g in rows:
        gold = label(g)["outcome"]
        po = outcome_of(g)
        n += 1
        ok += po == gold
        if gold in REFUND:
            ref_n += 1
            den += po in DENY
        else:
            notref += 1
            wr += po in REFUND
    return {"accuracy": ok / n, "wrongful_denials": den / ref_n, "wrongful_refunds": wr / notref}


def window_check(test, preds):
    rows = [g for g in test if g.get("task") == "dispute"]
    checked = {g["id"]: check_dispute_verdict(json.loads(g["input"]), preds.get(g["id"], {})) for g in rows}
    before = outcome_metrics(rows, lambda g: preds.get(g["id"], {}).get("outcome", "invalid"))
    after = outcome_metrics(rows, lambda g: checked[g["id"]].get("outcome", "invalid"))
    return {"before": before, "after": after}


def window_claims(test, preds):
    """The model's outside_dispute_window claims against the dates in each input."""
    gold_outside = gold_flag_inside = claims_n = false_claims = 0
    denied = denied_dismiss_window = 0
    for g in test:
        if g.get("task") != "dispute":
            continue
        x = json.loads(g["input"])
        p = x.get("payload", {})
        paid = (p.get("payment") or {}).get("paid_at")
        filed = (p.get("claim") or {}).get("filed_at")
        win = (x.get("policy") or {}).get("dispute_window_days")
        gl, pv = label(g), preds.get(g["id"], {})
        pflags = pv.get("flags") or []
        if gl["outcome"] in REFUND and pv.get("outcome") in DENY:
            denied += 1
            denied_dismiss_window += pv.get("outcome") == "dismiss" and "outside_dispute_window" in pflags
        if not all(isinstance(v, (int, float)) for v in (paid, filed, win)):
            continue
        inside = (filed - paid) / DAY <= win
        if "outside_dispute_window" in gl.get("flags", []):
            gold_outside += 1
            gold_flag_inside += inside
        if "outside_dispute_window" in pflags:
            claims_n += 1
            false_claims += inside
    true_claims = claims_n - false_claims
    return {"gold_outside": gold_outside, "gold_outside_but_inside": gold_flag_inside,
            "claims": claims_n, "false_claims": false_claims, "false_claim_share": false_claims / claims_n,
            "true_claims": true_claims, "missed_outside": gold_outside - true_claims,
            "wrongful_denials": denied, "wrongful_denials_dismiss_window": denied_dismiss_window}


MASK = __import__("re").compile(r"0x[0-9a-fA-F]+|\d+")


def _h(s):
    return hashlib.sha256(s.encode()).hexdigest()


def contamination(test, train, preds):
    train_exact = {_h(r["input"]) for r in train}
    twin_labels = {}
    for r in train:
        twin_labels.setdefault(_h(MASK.sub("#", r["input"])), set()).add(r.get("decision"))
    exact = sum(_h(g["input"]) in train_exact for g in test)
    groups = {"twin": [0, 0, 0, 0], "no_twin": [0, 0, 0, 0]}  # n, correct, risky, unsafe
    twins = twins_same = dispute_twins = 0
    for g in test:
        labels = twin_labels.get(_h(MASK.sub("#", g["input"])))
        if g.get("task") == "dispute":
            dispute_twins += labels is not None
            continue
        if labels is not None:
            twins += 1
            twins_same += g.get("decision") in labels
        s = groups["twin" if labels is not None else "no_twin"]
        gd = gold_decision(g)
        pd = preds.get(g["id"], {}).get("decision")
        s[0] += 1
        s[1] += pd == gd
        if gd != "approve":
            s[2] += 1
            s[3] += pd == "approve"
    out = {"exact_duplicates": exact, "payment_twins": twins, "payment_twins_same_label": twins_same,
           "dispute_twins": dispute_twins}
    for k, (n, ok, risky, unsafe) in groups.items():
        out[k] = {"cases": n, "accuracy": ok / max(n, 1), "risky": risky, "unsafe": unsafe,
                  "unsafe_rate": unsafe / max(risky, 1)}
    return out


def splits(test, train):
    rg = [r for r in test if r.get("task") == "risk_gate"]
    return {"test": len(test), "train": len(train), "total": len(test) + len(train),
            "payments": len(rg), "disputes": len(test) - len(rg),
            "risky": sum(gold_decision(r) in ("hold", "reject") for r in rg),
            "legitimate": sum(gold_decision(r) == "approve" for r in rg),
            "injected": sum("injection" in (r.get("perturbations") or []) for r in rg)}


def main(args):
    if len(args) != 5:
        sys.exit(__doc__)
    test, train = load_jsonl(args[0]), load_jsonl(args[1])
    v1, v2, q4 = (predictions(p) for p in args[2:5])
    n_test, held_test = false_holds(test)
    n_train, held_train = false_holds(train)
    emit({
        "splits": splits(test, train),
        "claims": {"v1": claims(test, train, v1), "v2": claims(test, train, v2),
                   "legitimate_checked": n_test + n_train, "legitimate_flagged": held_test + held_train},
        "window_claims_v1": window_claims(test, v1),
        "window_check": {"v1": window_check(test, v1), "v2": window_check(test, v2), "q4": window_check(test, q4)},
        "contamination_v1": contamination(test, train, v1),
    })


if __name__ == "__main__":
    main(sys.argv[1:])
