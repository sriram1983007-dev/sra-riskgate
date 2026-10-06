#!/usr/bin/env python3
"""Collect results/*/scores.json into a Markdown table for the model card.

    python make_table.py                 # all runs in results/
    python make_table.py --order sra-riskgate-4b,qwen3-4b-instruct-base,llama-3.3-70b
"""
import argparse
import json
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--results", default="results")
ap.add_argument("--order", help="comma-separated run names, in table order")
a = ap.parse_args()

runs = {p.parent.name: json.load(p.open()) for p in Path(a.results).glob("*/scores.json")}
names = a.order.split(",") if a.order else sorted(runs, key=lambda n: -runs[n]["sra_score"])

def pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"

cols = ["Model", "SRA score ↑", "Risk-gate acc. ↑", "Unsafe approvals ↓", "Over-blocking ↓",
        "Injections approved ↓", "Dispute score ↑", "Impossible remedies ↓", "Wrongful refunds ↓",
        "Refund details ↑", "Schema valid ↑"]
print("| " + " | ".join(cols) + " |")
print("|" + "---|" * len(cols))
for n in names:
    m = runs[n]
    rg, dp = m.get("risk_gate", {}), m.get("dispute", {})
    schema = [x for x in (rg.get("schema_valid_rate"), dp.get("schema_valid_rate")) if x is not None]
    print("| " + " | ".join([
        n, f"{m['sra_score']:.3f}",
        pct(rg.get("decision_accuracy")), pct(rg.get("unsafe_approval_rate")), pct(rg.get("over_blocking_rate")),
        pct((rg.get("injection") or {}).get("approved_rate")),
        f"{dp['dispute_score']:.3f}" if dp else "n/a",
        pct(dp.get("impossible_remedy_rate")), pct(dp.get("wrongful_refund_rate")),
        pct(dp.get("refund_detail_accuracy")),
        pct(sum(schema) / len(schema)) if schema else "n/a",
    ]) + " |")
