"""Benchmark results of every published run (Tables 2 and the quantised builds, SRA-Real v1).

    python paper/study/benchmark.py BASE V1 V2 V2_NO_WINDOW Q8 Q4 REAL_BASE REAL_V1 REAL_V2 REAL_SUMMARY

Each argument is a scores.json (or, last, summary.json) from the sra-bench-results dataset. Prints the
quantities the paper cites, as fractions (a printed percent is 100 times its value).
"""
import sys

from _common import emit, load_json

NAMES = ["base", "v1", "v2", "v2_no_window", "q8", "q4"]


def run(s):
    rg, d = s["risk_gate"], s.get("dispute", {})
    return {
        "sra_score": s["sra_score"],
        "cases": s["n"],
        "payments": rg["n"],
        "decision_accuracy": rg["decision_accuracy"],
        "unsafe_approvals": rg["unsafe_approval_rate"],
        "over_blocking": rg["over_blocking_rate"],
        "injected": rg["injection"]["n"],
        "injected_approved": rg["injection"]["approved_rate"],
        "disputes": d.get("n"),
        "dispute_accuracy": d.get("outcome_accuracy"),
        "wrongful_denials": d.get("wrongful_denial_rate"),
        "wrongful_refunds": d.get("wrongful_refund_rate"),
        "impossible_remedies": d.get("impossible_remedy_rate"),
        "refund_details": d.get("refund_detail_accuracy"),
    }


def main(args):
    if len(args) != 10:
        sys.exit(__doc__)
    out = {"runs": {n: run(load_json(p)) for n, p in zip(NAMES, args[:6])}}
    real = {}
    for n, p in zip(["base", "v1", "v2"], args[6:9]):
        s = load_json(p)["risk_gate"]
        real[n] = {"cases": s["n"], "decision_accuracy": s["decision_accuracy"],
                   "unsafe_approvals": s["unsafe_approval_rate"]}
    clean = load_json(args[9])["sra-riskgate-4b-v2"]["by_kind"]
    total = sum(int(v.split("/")[1]) for v in clean.values())
    unchanged = int(clean["clean"].split("/")[1])
    real["unchanged"], real["changed"] = unchanged, total - unchanged
    real["v2_unchanged_approved"] = int(clean["clean"].split("/")[0])
    real["v2_changed_stopped"] = sum(int(v.split("/")[0]) for k, v in clean.items() if k != "clean")
    out["sra_real"] = real
    emit(out)


if __name__ == "__main__":
    main(sys.argv[1:])
