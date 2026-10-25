#!/usr/bin/env python3
"""Measure the self-asserted-claims check on the published SRA-RiskGate-4B payment predictions.

    python eval/claims_check.py test.jsonl predictions.jsonl [train.jsonl]

test.jsonl and predictions.jsonl are the files in the sra-bench-results dataset (folder sra-riskgate-4b/);
train.jsonl is the benchmark's training split (sra-stablecoin-risk-bench, data/benchmark/train.jsonl) and
is optional. Prints, for the risk-gate cases:

  * unsafe approvals by the model alone, and after holding every payment whose untrusted payload
    contains a self-asserted claim (scan_payload_claims), with the benchmark's definition: the correct
    decision is hold or reject and the prediction is approve;
  * false holds the check adds: legitimate payments (correct decision approve) whose payload it flags,
    in the test split and, if given, the training split.

The paper reports 4 -> 0 unsafe approvals out of 847 and 0 false holds on 3,358 legitimate payments.
"""
import json
import re
import sys

from sra_riskgate import scan_payload_claims


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


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


def gold_decision(row):
    try:
        return json.loads(row["label"])["decision"]
    except (KeyError, TypeError, ValueError):
        return row.get("decision")


def payload(row):
    return json.loads(row["input"]).get("payload")


def risk_gate(rows):
    return [r for r in rows if r.get("task") == "risk_gate"]


def false_holds(rows):
    legit = [r for r in risk_gate(rows) if gold_decision(r) == "approve"]
    return len(legit), sum(bool(scan_payload_claims(payload(r))) for r in legit)


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    test = load(sys.argv[1])
    preds = {r["id"]: parse(r["prediction"]) or {} for r in load(sys.argv[2])}

    risky = [r for r in risk_gate(test) if gold_decision(r) in ("hold", "reject")]
    approved = [r for r in risky if preds.get(r["id"], {}).get("decision") == "approve"]
    still_approved = [r for r in approved if not scan_payload_claims(payload(r))]
    print(f"risk-gate cases that should be held or rejected: {len(risky)}")
    print(f"  unsafe approvals, model alone:        {len(approved)} ({len(approved) / len(risky):.2%})")
    print(f"  unsafe approvals, model + claims check: {len(still_approved)} ({len(still_approved) / len(risky):.2%})")
    for r in approved:
        print(f"    {r['id']}: {'held by the check' if r not in still_approved else 'NOT held'}")

    n, held = false_holds(test)
    total_n, total_held = n, held
    print(f"legitimate payments flagged by the check, test split: {held} of {n}")
    if len(sys.argv) == 4:
        n, held = false_holds(load(sys.argv[3]))
        total_n, total_held = total_n + n, total_held + held
        print(f"legitimate payments flagged by the check, train split: {held} of {n}")
        print(f"legitimate payments flagged by the check, test + train: {total_held} of {total_n}")


if __name__ == "__main__":
    main()
