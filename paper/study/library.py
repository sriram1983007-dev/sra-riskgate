"""Measurements of the installed sra-riskgate library (Sections 3, 4 and 10). No inputs.

    python paper/study/library.py

Runs the guard benchmark (560 cases, seed 1), the known-answer self-check and the OWASP coverage.
Deterministic: reads no clock, network or file.
"""
import sra_riskgate
from sra_riskgate.bench import GUARDS, run_benchmark
from sra_riskgate.evidence import self_check
from sra_riskgate.threats import FLAG_CATEGORY, coverage

from _common import emit


def main():
    bench = {name: run_benchmark(guard, seed=1) for name, guard in GUARDS.items()}
    strict = bench["strict"]["by_category"]
    cov = coverage()
    sc = self_check()
    emit({
        "version": sra_riskgate.__version__,
        "flags": len(FLAG_CATEGORY),
        "owasp_entries": len(cov),
        "owasp_addressed": sum(1 for v in cov.values() if v),
        "owasp_not_addressed": sum(1 for v in cov.values() if not v),
        "selfcheck": {"total": sc["total"], "passed": sc["total"] - sc["failed"]},
        "bench": {name: {k: r[k] for k in ("seed", "cases", "utility", "security", "unsafe_approved",
                                           "legit_blocked")} for name, r in bench.items()},
        "bench_strict": {"lookalike_rejected": strict["lookalike"].get("reject", 0),
                         "payee_change_missed": strict["payee_change"].get("approve", 0),
                         "self_approval_missed": strict["self_approval"].get("approve", 0)},
    })


if __name__ == "__main__":
    main()
