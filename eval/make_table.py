#!/usr/bin/env python3
"""Collect results/*/scores.json into a Markdown table for the model card or leaderboard.

    python make_table.py                 # all runs in results/
    python make_table.py --order sra-riskgate-4b,qwen3-4b-instruct-base,llama-3.3-70b
    python make_table.py --csv table.csv # also write a CSV
"""
import argparse
import csv
import json
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--results", default="results")
ap.add_argument("--order", help="comma-separated run names, in table order")
ap.add_argument("--csv", help="also write the table as CSV")
a = ap.parse_args()

runs = {}
for p in Path(a.results).glob("*/scores.json"):
    cfg_path = p.parent / "run_config.json"
    runs[p.parent.name] = (json.load(p.open()), json.load(cfg_path.open()) if cfg_path.exists() else {})
names = a.order.split(",") if a.order else sorted(runs, key=lambda n: -runs[n][0]["sra_score"])


def pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


cols = ["Model", "Prompt", "Rows", "SRA score ↑", "Risk-gate acc. ↑", "Unsafe approvals ↓", "Over-blocking ↓",
        "Injections approved ↓", "Dispute score ↑", "Impossible remedies ↓", "Wrongful refunds ↓",
        "Refund details ↑", "Schema valid ↑", "Cost (USD)"]
table = []
for n in names:
    m, cfg = runs[n]
    rg, dp = m.get("risk_gate", {}), m.get("dispute", {})
    schema = [x for x in (rg.get("schema_valid_rate"), dp.get("schema_valid_rate")) if x is not None]
    cost = (cfg.get("usage") or {}).get("cost_usd")
    rows = str(m.get("n", "")) + (" (sample)" if cfg.get("sample") else "")
    table.append([
        n, cfg.get("prompt_variant", "training"), rows, f"{m['sra_score']:.3f}",
        pct(rg.get("decision_accuracy")), pct(rg.get("unsafe_approval_rate")), pct(rg.get("over_blocking_rate")),
        pct((rg.get("injection") or {}).get("approved_rate")),
        f"{dp['dispute_score']:.3f}" if dp else "n/a",
        pct(dp.get("impossible_remedy_rate")), pct(dp.get("wrongful_refund_rate")),
        pct(dp.get("refund_detail_accuracy")),
        pct(sum(schema) / len(schema)) if schema else "n/a",
        f"{cost:.2f}" if cost else "n/a",
    ])

print("| " + " | ".join(cols) + " |")
print("|" + "---|" * len(cols))
for r in table:
    print("| " + " | ".join(r) + " |")
if a.csv:
    with open(a.csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(table)
