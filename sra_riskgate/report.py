"""Audit reports from signed receipts (1.12.0+): evidence that every agent payment was checked, for people who
were not there.

A compliance officer, an auditor, a customer or a grant assessor wants one document that says: over this period, this
many payments were checked, under these policies, with these outcomes and amounts, against these known risks; and
that the record has not been edited. ``audit_report`` builds it from the receipts themselves and verifies every one:

    from sra_riskgate import audit_report, audit_report_markdown
    report = audit_report(receipts, key=secret)          # or expected_signer="0x..." for Ethereum receipts
    print(audit_report_markdown(report))

    sra-riskgate receipt report receipts.jsonl --key-env SRA_RECEIPT_KEY [--json]

What it contains: how many receipts verified, whether the chain is intact (for chained receipts) and its latest
link (``head_sha256``, to record somewhere else so receipts cut off the end can be detected too), the period,
decisions and amounts per token, the most frequent flags, the control categories and OWASP risks they map to
(``sra_riskgate.threats``), the policies and signers seen, and a ``report_sha256`` so two people can confirm they
hold the same report. Receipts that do not verify are counted and listed, never summarised.

The report is deterministic: the same receipts give the same report and the same ``report_sha256``. It proves what
the gate decided, not that payments were sent or settled (``verify_settlement`` covers that).
"""
from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any, Dict, List, Mapping, Optional

from sra_riskgate.receipts import canonical_json, receipt_sha256, verify_receipt, verify_receipt_chain
from sra_riskgate.threats import FLAG_CATEGORY, FLAG_THREATS, THREATS

__all__ = ["audit_report", "audit_report_markdown"]

_MAX_LISTED = 20


def _unwrap(r: Any) -> Any:
    return r["receipt"] if isinstance(r, Mapping) and isinstance(r.get("receipt"), Mapping) else r


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def audit_report(receipts: Any, *, key: Optional[bytes] = None, expected_signer: Optional[str] = None,
                 title: str = "Agent payment decisions") -> Dict[str, Any]:
    """Verify and summarise receipts, oldest first. Never raises on bad receipts; they are counted as invalid.

    Pass ``key`` for ``hmac-sha256`` receipts or ``expected_signer`` for ``eip191`` receipts, as for
    ``verify_receipt``. A whole MCP tool result (``{"receipt": {...}}``) is accepted in place of a receipt.
    """
    from sra_riskgate import __version__
    try:
        rows = [_unwrap(r) for r in list(receipts)]
    except Exception:
        rows = []
    valid: List[Mapping] = []
    invalid: List[int] = []
    for i, r in enumerate(rows):
        if verify_receipt(r, key=key, expected_signer=expected_signer):
            valid.append(r)
        else:
            invalid.append(i)

    chained = bool(rows) and any(isinstance(r, Mapping) and "prev_sha256" in r for r in rows)
    chain: Dict[str, Any] = {"chained": chained}
    if chained:
        c = verify_receipt_chain(rows, key=key, expected_signer=expected_signer)
        chain.update({"intact": c.ok, "checked": c.checked, "bad_index": c.bad_index, "reason": c.reason,
                      "head_sha256": receipt_sha256(rows[-1]) if c.ok else None})

    decisions: Counter = Counter()
    amounts: Dict[str, Dict[str, float]] = {}
    flags: Counter = Counter()
    categories: Counter = Counter()
    threats: Counter = Counter()
    policies: Counter = Counter()
    signers: Counter = Counter()
    libraries: Counter = Counter()
    times: List[str] = []
    for r in valid:
        d = str(r.get("decision"))
        decisions[d] += 1
        p = r.get("payment") if isinstance(r.get("payment"), Mapping) else {}
        amt = _num(p.get("amount"))
        if amt is not None:
            tok = str(p.get("token") or "USDC").upper()
            amounts.setdefault(d, {}).setdefault(tok, 0.0)
            amounts[d][tok] = round(amounts[d][tok] + amt, 6)
        fl = [f for f in (r.get("flags") or []) if isinstance(f, str)]
        flags.update(fl)
        categories.update({FLAG_CATEGORY.get(f, "other") for f in fl})
        threats.update({t for f in fl for t in FLAG_THREATS.get(f, ())})
        policies[str(r.get("policy_sha256") or "none")] += 1
        signers[f"{r.get('alg')}:{r.get('signer')}"] += 1
        libraries[str(r.get("library"))] += 1
        if isinstance(r.get("issued_at"), str):
            times.append(r["issued_at"])

    body: Dict[str, Any] = {
        "title": title,
        "generated_by": f"sra-riskgate {__version__}",
        "receipts": len(rows),
        "verified": len(valid),
        "invalid": len(invalid),
        "invalid_indexes": invalid[:_MAX_LISTED],
        "chain": chain,
        "period": {"first": min(times) if times else None, "last": max(times) if times else None},
        "decisions": {k: decisions.get(k, 0) for k in ("approve", "hold", "reject")},
        "amounts": {d: dict(sorted(v.items())) for d, v in sorted(amounts.items())},
        "top_flags": [[f, n] for f, n in sorted(flags.items(), key=lambda x: (-x[1], x[0]))[:_MAX_LISTED]],
        "categories": dict(sorted(categories.items())),
        "threats": {t: {"decisions": threats[t], "name": THREATS[t][0], "source": THREATS[t][1]}
                    for t in THREATS if threats.get(t)},
        "policies": dict(sorted(policies.items())),
        "signers": dict(sorted(signers.items())),
        "libraries": dict(sorted(libraries.items())),
    }
    body["report_sha256"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    return body


def audit_report_markdown(report: Mapping[str, Any]) -> str:
    """The report as Markdown, for a ticket, an email or a PDF."""
    r = report
    ch = r.get("chain") or {}
    lines = [f"# {r.get('title', 'Agent payment decisions')}", ""]
    status = "all verified" if r.get("invalid") == 0 and r.get("receipts") else f"{r.get('invalid')} did NOT verify"
    lines += [f"- **Receipts:** {r.get('receipts')} ({status})"]
    if ch.get("chained"):
        lines += ["- **Chain:** " + ("intact; nothing edited, deleted, inserted or reordered" if ch.get("intact")
                                     else f"BROKEN at receipt {ch.get('bad_index')}: {ch.get('reason')}")]
        if ch.get("head_sha256"):
            lines += [f"- **Latest link (record it elsewhere):** `{ch['head_sha256']}`"]
    else:
        lines += ["- **Chain:** not chained; each receipt verified on its own, so a deleted receipt would not show"]
    per = r.get("period") or {}
    if per.get("first"):
        lines += [f"- **Period:** {per['first']} to {per['last']}"]
    lines += [f"- **Generated by:** {r.get('generated_by')}", f"- **Report SHA-256:** `{r.get('report_sha256')}`", ""]

    d = r.get("decisions") or {}
    lines += ["## Decisions", "", "| Decision | Count | Amounts |", "|---|---:|---|"]
    for k in ("approve", "hold", "reject"):
        am = (r.get("amounts") or {}).get(k) or {}
        lines.append(f"| {k} | {d.get(k, 0)} | " + (", ".join(f"{v:,.2f} {t}" for t, v in am.items()) or "-") + " |")
    lines.append("")

    if r.get("threats"):
        lines += ["## Known risks addressed", "", "Decisions whose flags map to each OWASP entry "
                  "(this project's mapping; not reviewed by OWASP).", "", "| Entry | Risk | Decisions |",
                  "|---|---|---:|"]
        for t, v in r["threats"].items():
            lines.append(f"| {t} | {v['name']} | {v['decisions']} |")
        lines.append("")
    if r.get("top_flags"):
        lines += ["## Most frequent flags", "", "| Flag | Category | Count |", "|---|---|---:|"]
        for f, n in r["top_flags"]:
            lines.append(f"| `{f}` | {FLAG_CATEGORY.get(f, 'other')} | {n} |")
        lines.append("")
    lines += ["## Policies and signers", ""]
    for h, n in (r.get("policies") or {}).items():
        lines.append(f"- Policy `{h}`: {n} decision(s)" if h != "none" else f"- No policy bound: {n} decision(s)")
    for s, n in (r.get("signers") or {}).items():
        lines.append(f"- Signer `{s}`: {n}")
    lines.append("")
    if r.get("invalid"):
        lines += ["## Receipts that did not verify", "",
                  "Positions (from 0): " + ", ".join(str(i) for i in r.get("invalid_indexes") or [])
                  + (" (first 20)" if (r.get("invalid") or 0) > 20 else ""), "",
                  "They are excluded from every figure above.", ""]
    lines += ["## Limits", "",
              "- A receipt proves what the gate decided, not that a payment was sent or settled.",
              "- Only the receipts supplied are covered. A chain shows edits, deletions, insertions and reordering, "
              "but not receipts cut off the end: compare the latest link with the copy recorded elsewhere.",
              "- Risk mappings are indicative; a mapped entry is addressed in part, for payments.", ""]
    return "\n".join(lines)

