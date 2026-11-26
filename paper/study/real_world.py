"""Real-world evaluation (Section 9, Table 4) from the sra-real-world-poisoning dataset.

    python paper/study/real_world.py ATTACKS_CSV NORMAL_CSV SUMMARY_JSON MODEL_SUMMARY_JSON

Dollar totals are rounded to whole dollars. The look-alike figures are recomputed from the published rows; the busy-wallet sensitivity (published as
counts only) and the model runs are read from the dataset's summary files.
"""
import csv
import statistics
import sys

from _common import emit, load_json


def of(text):
    """'2 of 58' -> (2, 58)."""
    a, b = text.split(" of ")
    return int(a), int(b)


def main(args):
    if len(args) != 4:
        sys.exit(__doc__)
    with open(args[0], encoding="utf-8") as f:
        attacks = list(csv.DictReader(f))
    with open(args[1], encoding="utf-8") as f:
        normal = list(csv.DictReader(f))
    summary, model = load_json(args[2]), load_json(args[3])

    rejected = [a for a in attacks if a["decision"] == "reject" and "LOOKALIKE_RECIPIENT" in a["flags"]]
    others = [a for a in attacks if a not in rejected]
    loss = [float(a["loss_amount"]) for a in attacks]
    repeat = [n for n in normal if n["repeat_payee"] == "True"]

    def close(n, k):
        return int(n["closest_known_prefix"] or 0) >= k[0] and int(n["closest_known_suffix"] or 0) >= k[1]

    sens = {}
    for s in summary["sensitivity_by_busy_wallet_limit"]:
        key = s["max_candidates_per_wallet"].split()[0].replace("no", "none")
        sens[key] = {"attacks": s["attacks"], "rejected": s["rejected_as_lookalike"],
                     "share": s["rejected_as_lookalike"] / s["attacks"], "approved": s["approved"]}

    a, b, c = model["A_real_payments"], model["B_attacks_with_known_payee_given"], model["B_control_known_payee"]
    emit({
        "attacks": len(attacks),
        "victims": len({x["victim"] for x in attacks}),
        "lost_usd": round(sum(loss)),
        "lost_usd_median": statistics.median(loss),
        "rejected": len(rejected),
        "rejected_share": len(rejected) / len(attacks),
        "rejected_lost_usd": round(sum(float(x["loss_amount"]) for x in rejected)),
        "not_rejected": len(others),
        "not_rejected_three_and_three": sum(x["shared_prefix"] == "3" and x["shared_suffix"] == "3" for x in others),
        "not_rejected_held": sum(x["decision"] == "hold" for x in others),
        "approved": sum(x["decision"] == "approve" for x in attacks),
        "normal": len(normal),
        "normal_wrongly_rejected": sum("LOOKALIKE_RECIPIENT" in n["flags"] for n in normal),
        "normal_strict_would_reject": sum(close(n, (3, 3)) for n in normal),
        "repeat_payee": len(repeat),
        "repeat_payee_approved": sum(n["decision"] == "approve" for n in repeat),
        "busy_wallet_limit": sens,
        "model": {
            "real_payments": a["cases"], "real_payments_matching": of(a["decision_matches_rule_label"])[0],
            "under_limit": of(a["under_limit_wrongly_held_or_rejected"])[1],
            "under_limit_blocked": of(a["under_limit_wrongly_held_or_rejected"])[0],
            "over_limit": of(a["over_limit_wrongly_approved"])[1],
            "over_limit_approved": of(a["over_limit_wrongly_approved"])[0],
            "attacks_under_limit": b["under_limit_cases"], "attacks_under_limit_stopped": of(b["under_limit_stopped"])[0],
            "known_payee_controls": c["cases"], "known_payee_controls_stopped": of(c["stopped (hold or reject)"])[0],
        },
    })


if __name__ == "__main__":
    main(sys.argv[1:])
