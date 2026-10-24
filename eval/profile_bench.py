#!/usr/bin/env python3
"""Profile SRA-RiskGate-4B's dispute mistakes and check the benchmark for train/test overlap.

Reads the published files (download them first; see the command in the chat):
  test.jsonl         gold test split (from sra-bench-results/sra-riskgate-4b/)
  predictions.jsonl  the model's published predictions
  train.jsonl        benchmark train split (from sra-stablecoin-risk-bench/data/benchmark/), optional
Prints a compact text report. Standard library only; reads nothing else and sends nothing anywhere.
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict

REFUND = {"reverse_before_release", "forced_refund", "voluntary_refund", "recommend_voluntary_refund"}
DENY = {"deny", "dismiss"}


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


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


def table(title, counter, total=None, top=25):
    print(f"\n## {title}")
    for k, v in counter.most_common(top):
        share = f"  ({100 * v / total:.0f}%)" if total else ""
        print(f"  {v:5d}  {k}{share}")


def features(g):
    """Facts about a dispute case that might explain a decision (from the input, not the label)."""
    x = json.loads(g["input"])
    p, t = x.get("payload", {}), x.get("tool_results", {})
    claim, resp = p.get("claim") or {}, p.get("merchant_response") or {}
    oc = t.get("order_check") or {}
    st = t.get("settlement") or {}
    f = {
        "rail": g.get("format"),
        "settlement": st.get("state"),
        "bond": "bond" if st.get("bond") else "no_bond",
        "claim": claim.get("reason"),
        "merchant": resp.get("status"),
        "merchant_evidence": "evidence" if resp.get("evidence") else "no_evidence",
        "delivery_evidence": f"delivery_evidence={len(t.get('delivery_evidence') or [])}",
        "order_sig": "order_sig_valid" if oc.get("signature_valid") else "order_sig_invalid_or_missing",
        "refund_to": "refund_to_set" if claim.get("refund_to") else "refund_to_none",
        "addr_change": "refund_address_change" if (t.get("refund_address_change") or {}).get("requested") else "no_addr_change",
        "prior_refunds": "prior_refunds" if str(t.get("prior_refunds_usdc", "0")) not in ("0", "0.0", "") else "no_prior_refunds",
        "other_disputes": "other_disputes" if t.get("other_disputes_for_order") else "no_other_disputes",
    }
    return f


def disputes(gold, preds):
    rows = [g for g in gold if g.get("task") == "dispute"]
    print(f"# Disputes: {len(rows)} cases")
    conf = Counter()
    refund_cases, denied = [], []
    for g in rows:
        gl = json.loads(g["label"])
        pv = parse(preds.get(g["id"])) or {}
        po = pv.get("outcome", "invalid")
        conf[(gl["outcome"], po)] += 1
        if gl["outcome"] in REFUND:
            refund_cases.append((g, gl, pv))
            if po in DENY:
                denied.append((g, gl, pv))

    print("\n## Confusion: gold outcome -> predicted outcome (mistakes only)")
    for (go, po), v in sorted(conf.items(), key=lambda kv: -kv[1]):
        if go != po:
            print(f"  {v:4d}  {go:28s} -> {po}")

    n_ref = len(refund_cases)
    print(f"\n# Wrongful denials: {len(denied)} of {n_ref} gold-refund cases predicted deny/dismiss "
          f"({100 * len(denied) / max(n_ref, 1):.1f}%)")
    table("Denied cases by gold outcome", Counter(gl["outcome"] for _, gl, _ in denied))
    by_gold = Counter(gl["outcome"] for _, gl, _ in refund_cases)
    print("\n## Denial rate within each gold refund outcome")
    den_gold = Counter(gl["outcome"] for _, gl, _ in denied)
    for k, n in by_gold.most_common():
        print(f"  {den_gold[k]:4d} / {n:4d}  ({100 * den_gold[k] / n:4.0f}%)  {k}")
    table("Denied cases: predicted outcome", Counter(pv.get("outcome") for _, _, pv in denied))

    # Which input facts are over-represented among denials, compared with all gold-refund cases?
    print("\n## Input facts: share among denied vs share among all gold-refund cases (lift > 1.5 marked *)")
    all_f, den_f = Counter(), Counter()
    for g, _, _ in refund_cases:
        for k, v in features(g).items():
            all_f[f"{k}={v}"] += 1
    for g, _, _ in denied:
        for k, v in features(g).items():
            den_f[f"{k}={v}"] += 1
    rows_out = []
    for key, n_all in all_f.items():
        a, d = n_all / n_ref, den_f[key] / max(len(denied), 1)
        rows_out.append((d / a if a else 0, key, den_f[key], n_all))
    for lift, key, nd, na in sorted(rows_out, reverse=True):
        if nd >= 3:
            print(f"  {'*' if lift > 1.5 else ' '} lift {lift:4.2f}  denied {nd:3d}  all {na:4d}  {key}")

    print("\n## Perturbation tags: denial rate per tag (gold-refund cases)")
    tag_all, tag_den = Counter(), Counter()
    for g, _, _ in refund_cases:
        tag_all.update(g.get("perturbations") or [])
    for g, _, _ in denied:
        tag_den.update(g.get("perturbations") or [])
    for tag, n in sorted(tag_all.items(), key=lambda kv: -tag_den[kv[0]] / kv[1]):
        if n >= 5:
            print(f"  {tag_den[tag]:4d} / {n:4d}  ({100 * tag_den[tag] / n:4.0f}%)  {tag}")

    table("Gold flags the model missed on denied cases", Counter(
        f for _, gl, pv in denied for f in set(gl.get("flags", [])) - set(pv.get("flags") or [])))
    table("Flags the model added on denied cases (not in gold)", Counter(
        f for _, gl, pv in denied for f in set(pv.get("flags") or []) - set(gl.get("flags", []))))

    print("\n## Three example denials (ids, gold vs predicted explanation)")
    for g, gl, pv in denied[:3]:
        print(f"  {g['id']}  gold={gl['outcome']}  pred={pv.get('outcome')}")
        print(f"    gold: {gl.get('explanation', '')[:220]}")
        print(f"    pred: {str(pv.get('explanation', ''))[:220]}")


MASK = re.compile(r"0x[0-9a-fA-F]+|\d+")


def leakage(gold, train):
    print(f"\n# Train/test overlap: {len(gold)} test rows vs {len(train)} train rows")
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()
    train_exact = {h(r["input"]) for r in train}
    exact = [g["id"] for g in gold if h(g["input"]) in train_exact]
    print(f"  exact duplicate inputs (test input appears verbatim in train): {len(exact)}")
    for i in exact[:10]:
        print(f"    {i}")

    # Same case with only ids, addresses, hashes and numbers changed: a template-level match.
    # Expected to be common in synthetic data, so it is reported by task and label, not as leakage.
    masked = defaultdict(Counter)
    for r in train:
        masked[h(MASK.sub("#", r["input"]))][r.get("decision")] += 1
    near = Counter()
    near_same_label = 0
    for g in gold:
        m = masked.get(h(MASK.sub("#", g["input"])))
        if m:
            near[g.get("task")] += 1
            near_same_label += m.get(g.get("decision"), 0) > 0
    print(f"  template-level matches (identical after masking hex values and numbers): "
          f"{sum(near.values())}  by task: {dict(near)}  with the same label in train: {near_same_label}")


def main():
    flags = [a for a in sys.argv if a in ("--window", "--leak-split")]
    sys.argv = [a for a in sys.argv if a not in flags] + flags
    if len(sys.argv) < 3:
        sys.exit("usage: profile_bench.py test.jsonl predictions.jsonl [train.jsonl]")
    gold = load(sys.argv[1])
    preds = {r["id"]: r["prediction"] for r in load(sys.argv[2])}
    if "--leak-split" in sys.argv:
        leak_split(gold, preds, load(sys.argv[3]))
        return
    if "--window" in sys.argv:
        window(gold, preds)
        return
    disputes(gold, preds)
    if len(sys.argv) > 3:
        leakage(gold, load(sys.argv[3]))



def window(gold, preds):
    """The model's 'outside_dispute_window' claims, checked against the dates in the input."""
    print("\n# Dispute window: the model's claim vs the arithmetic")
    rows = [g for g in gold if g.get("task") == "dispute"]
    gold_flag = Counter()
    pred_flag = Counter()
    gold_of_wrong = Counter()
    fixed = []
    for g in rows:
        x = json.loads(g["input"])
        p = x.get("payload", {})
        paid = (p.get("payment") or {}).get("paid_at")
        filed = (p.get("claim") or {}).get("filed_at")
        win = (x.get("policy") or {}).get("dispute_window_days")
        if not all(isinstance(v, (int, float)) for v in (paid, filed, win)):
            continue
        days = (filed - paid) / 86400
        inside = days <= win
        gl = json.loads(g["label"])
        pv = parse(preds.get(g["id"])) or {}
        if "outside_dispute_window" in gl.get("flags", []):
            gold_flag["inside by arithmetic" if inside else "outside by arithmetic"] += 1
        if "outside_dispute_window" in (pv.get("flags") or []):
            pred_flag["inside by arithmetic (claim is false)" if inside else "outside by arithmetic (claim is true)"] += 1
            if inside:
                gold_of_wrong[gl["outcome"]] += 1
                fixed.append((g, gl, pv))
    table("Gold labels with outside_dispute_window", gold_flag)
    table("Predictions with outside_dispute_window", pred_flag)
    table("Gold outcome where the model's window claim is false", gold_of_wrong)

    # What a deterministic post-check would do: a dismissal resting on a false window claim is
    # escalated to a human instead (never turned into a refund).
    def rates(override):
        n = ok = ref_n = den = notref = wr = 0
        for g in rows:
            gl = json.loads(g["label"])
            po = override.get(g["id"]) or (parse(preds.get(g["id"])) or {}).get("outcome", "invalid")
            n += 1
            ok += po == gl["outcome"]
            if gl["outcome"] in REFUND:
                ref_n += 1
                den += po in DENY
            else:
                notref += 1
                wr += po in REFUND
        return ok / n, den / max(ref_n, 1), wr / max(notref, 1)
    before = rates({})
    after = rates({g["id"]: "escalate_to_human" for g, _, pv in fixed if pv.get("outcome") in DENY})
    print("\n## If a post-check escalated dismissals that rest on a false window claim")
    print(f"  outcome accuracy   {before[0]:.4f} -> {after[0]:.4f}")
    print(f"  wrongful denials   {before[1]:.4f} -> {after[1]:.4f}")
    print(f"  wrongful refunds   {before[2]:.4f} -> {after[2]:.4f}")


def leak_split(gold, preds, train):
    """Risk-gate accuracy on test cases with and without a template-level twin in train."""
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()
    twins = {h(MASK.sub("#", r["input"])) for r in train}
    groups = {"has a train twin": [0, 0, 0, 0], "no train twin": [0, 0, 0, 0]}  # n, correct, risky, unsafe
    for g in gold:
        if g.get("task", "risk_gate") != "risk_gate":
            continue
        key = "has a train twin" if h(MASK.sub("#", g["input"])) in twins else "no train twin"
        gl = json.loads(g["label"])
        if "decision" not in gl:
            continue
        pd = (parse(preds.get(g["id"])) or {}).get("decision")
        s = groups[key]
        s[0] += 1
        s[1] += pd == gl["decision"]
        if gl["decision"] != "approve":
            s[2] += 1
            s[3] += pd == "approve"
    print("\n# Risk gate: test cases with vs without a template twin in train")
    for k, (n, ok, risky, unsafe) in groups.items():
        print(f"  {k:17s}  n={n:4d}  decision accuracy {ok / max(n, 1):.4f}  "
              f"unsafe approvals {unsafe}/{risky} ({unsafe / max(risky, 1):.4f})")


if __name__ == "__main__":
    main()
