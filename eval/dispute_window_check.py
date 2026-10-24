#!/usr/bin/env python3
"""Measure check_dispute_verdict on the published SRA-RiskGate-4B dispute predictions.

    python eval/dispute_window_check.py test.jsonl predictions.jsonl

test.jsonl and predictions.jsonl are the files in the sra-bench-results dataset
(https://huggingface.co/datasets/sriram1983007/sra-bench-results, folder sra-riskgate-4b/). Prints
outcome accuracy, wrongful denials and wrongful refunds with the definitions of the benchmark's score.py,
before and after the deterministic window check.
"""
import json
import re
import sys

from sra_riskgate import check_dispute_verdict

REFUND = {"reverse_before_release", "forced_refund", "voluntary_refund", "recommend_voluntary_refund"}
DENY = {"deny", "dismiss"}


def parse(text):
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        return None
    text = re.sub(r"```(?:json)?", "", text)
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text, m.start())
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def metrics(rows, outcome_of):
    n = ok = ref_n = den = notref = wr = 0
    for g in rows:
        gold = json.loads(g["label"])["outcome"]
        po = outcome_of(g)
        n += 1
        ok += po == gold
        if gold in REFUND:
            ref_n += 1
            den += po in DENY
        else:
            notref += 1
            wr += po in REFUND
    return {"outcome_accuracy": ok / n, "wrongful_denials": den / ref_n, "wrongful_refunds": wr / notref}


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    gold = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
    preds = {}
    for l in open(sys.argv[2], encoding="utf-8"):
        if l.strip():
            r = json.loads(l)
            preds[r["id"]] = parse(r["prediction"]) or {}
    rows = [g for g in gold if g.get("task") == "dispute"]

    checked, changed, contradicted = {}, 0, 0
    for g in rows:
        v = preds.get(g["id"], {})
        c = check_dispute_verdict(json.loads(g["input"]), v)
        checked[g["id"]] = c
        changed += c.get("outcome") != v.get("outcome")
        contradicted += "dispute_window_claim_contradicted" in c.get("flags", [])

    before = metrics(rows, lambda g: preds.get(g["id"], {}).get("outcome", "invalid"))
    after = metrics(rows, lambda g: checked[g["id"]].get("outcome", "invalid"))
    print(f"dispute cases: {len(rows)}; window claims contradicted: {contradicted}; outcomes changed: {changed}")
    for k in before:
        print(f"  {k:17s} {before[k]:.4f} -> {after[k]:.4f}")


if __name__ == "__main__":
    main()
