"""``sra-riskgate`` command line (1.9.0+): check a payment, validate a policy file, verify a receipt.

    sra-riskgate check --chain 8453 --sender 0x... --to 0x... --amount 25 [--policy policy.json] [--json]
                                    # a dry run: budgets are read, never spent (add --record to count it)
    sra-riskgate policy validate payment-policy.json
    sra-riskgate receipt verify receipt.json --key-env SRA_RECEIPT_KEY      # HMAC receipts
    sra-riskgate receipt verify receipt.json --signer 0xYourReceiptAddress  # Ethereum receipts
    sra-riskgate receipt verify-chain receipts.jsonl --key-env SRA_RECEIPT_KEY  # a chain, oldest first
    sra-riskgate receipt report receipts.jsonl --key-env SRA_RECEIPT_KEY [--json]  # audit report (Markdown)
    sra-riskgate threats [--json]                                           # flags mapped to OWASP risks
    sra-riskgate bench [--guard strict] [--json]                            # utility vs security benchmark
    sra-riskgate evidence build --out evidence/ [--receipts FILE --key-env VAR] [--tests tests/] [--zip]
    sra-riskgate evidence verify evidence/                                  # nothing edited since it was built
    sra-riskgate scan 0xWallet --rpc URL [--write-policy FILE]             # look-alikes already targeting a wallet
    sra-riskgate version

Exit codes, so a CI pipeline or a shell script can act on the result:
    check            0 approve, 10 hold, 20 reject
    policy validate  0 valid, 1 invalid
    receipt verify   0 valid, 1 invalid
    receipt report   0 every receipt verified (and the chain is intact), 1 otherwise
    evidence build   0 self-check passed (and receipts verified, tests passed, if given), 1 otherwise
    evidence verify  0 every file unchanged, 1 otherwise
    scan             0 nothing found, 10 look-alikes found, 1 nothing found but the range was not fully read
    any command      2 bad usage (argparse), 3 a file or setting could not be read
"""
from __future__ import annotations

import argparse
import contextlib
import base64
import json
import os
import sys
from typing import Optional, Sequence

EXIT_APPROVE, EXIT_HOLD, EXIT_REJECT = 0, 10, 20
EXIT_INVALID, EXIT_ERROR = 1, 3
_CODES = {"approve": EXIT_APPROVE, "hold": EXIT_HOLD, "reject": EXIT_REJECT}


def _out(args, data: dict, text: str) -> None:
    print(json.dumps(data, indent=2) if getattr(args, "json", False) else text)


def _fail(msg: str) -> int:
    print(f"sra-riskgate: {msg}", file=sys.stderr)
    return EXIT_ERROR


def _cmd_check(args) -> int:
    from sra_riskgate import check_payment, load_policy
    kw = {}
    if args.policy:
        try:
            kw = load_policy(args.policy).check_kwargs()
        except Exception as e:
            return _fail(f"policy {args.policy}: {e}")
    if args.max_amount is not None:
        if "max_amount" in kw:
            return _fail("--max-amount is also set by the policy file; keep one of them")
        kw["max_amount"] = args.max_amount
    if args.lookalike is not None:
        if "lookalike_check" in kw:
            return _fail("--lookalike is also set by the policy file; keep one of them")
        kw["lookalike_check"] = args.lookalike
    if args.new_payee is not None:
        if "new_counterparty" in kw:
            return _fail("--new-payee is also set by the policy file; keep one of them")
        kw["new_counterparty"] = args.new_payee
    if args.known:
        if "known_recipients" in kw:
            return _fail("--known is also set by the policy file; keep one of them")
        kw["known_recipients"] = args.known
    from sra_riskgate.spend import suppress_recording
    # A dry run by default: budgets are checked against the ledger, but this payment is not added to it,
    # so testing a policy never spends an agent's real budget. --record counts it like an agent's payment.
    with (contextlib.nullcontext() if args.record else suppress_recording()):
        r = check_payment(chain_id=args.chain, sender=args.sender, recipient=args.to, amount=args.amount,
                          token=args.token, untrusted_request=args.text, peg_deviation_pct=args.peg, **kw)
    d = r.decision.value
    data = {"decision": d, "risk_score": r.risk_score, "flags": r.flags, "explanation": r.explanation,
            "required_actions": r.required_actions}
    mark = {"approve": "APPROVE ✓", "hold": "HOLD ⏸", "reject": "REJECT ✗"}[d]
    lines = [mark, f"  {r.explanation}"]
    if r.flags:
        lines.append("  flags: " + ", ".join(r.flags))
    _out(args, data, "\n".join(lines))
    return _CODES[d]


def _cmd_policy_validate(args) -> int:
    from sra_riskgate import load_policy
    try:
        p = load_policy(args.file)
    except (OSError, UnicodeDecodeError) as e:
        return _fail(f"cannot read {args.file}: {e}")
    except Exception as e:  # ValueError for an invalid policy, JSON/YAML errors
        _out(args, {"valid": False, "error": str(e)}, f"INVALID ✗  {args.file}\n  {e}")
        return EXIT_INVALID
    d = p.as_dict()
    parts = [k for k in ("max_amount", "known_recipients", "blocked_addresses", "allowed_tokens", "lookalike_check",
                         "new_counterparty", "screening",
                         "budgets", "anomalies") if k in d]
    _out(args, {"valid": True, "name": p.name, "sha256": p.sha256, "sets": parts},
         f"VALID ✓  {args.file}" + (f" ({p.name})" if p.name else "") +
         f"\n  sha256: {p.sha256}\n  sets: {', '.join(parts) or 'nothing beyond the defaults'}")
    return 0


def _key_from_env(name: str) -> bytes:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        raise ValueError(f"environment variable {name} is not set")
    raw = raw.strip()
    try:
        return bytes.fromhex(raw[2:] if raw.lower().startswith("0x") else raw)
    except ValueError:
        return base64.b64decode(raw, validate=True)


def _cmd_receipt_verify(args) -> int:
    from sra_riskgate import verify_receipt
    try:
        with open(args.file, encoding="utf-8") as fh:
            receipt = json.load(fh)
    except (OSError, ValueError) as e:
        return _fail(f"cannot read {args.file}: {e}")
    if isinstance(receipt, dict) and isinstance(receipt.get("receipt"), dict):
        receipt = receipt["receipt"]  # accept a whole MCP tool result too
    try:
        ok = verify_receipt(receipt, key=_key_from_env(args.key_env)) if args.key_env \
            else verify_receipt(receipt, expected_signer=args.signer)
    except Exception as e:
        return _fail(str(e))
    info = {k: receipt.get(k) for k in ("decision", "issued_at", "id", "signer", "policy_sha256")} \
        if isinstance(receipt, dict) else {}
    _out(args, {"valid": ok, **info},
         (f"VALID ✓  {info.get('decision')} at {info.get('issued_at')} (id {info.get('id')})" if ok
          else "INVALID ✗  the receipt was changed after it was issued, or was signed by someone else"))
    return 0 if ok else EXIT_INVALID


def _read_receipts(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        rows = json.loads(text)
    except ValueError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]  # JSON Lines
    if isinstance(rows, dict):
        rows = [rows]
    return [r["receipt"] if isinstance(r, dict) and isinstance(r.get("receipt"), dict) else r for r in rows]


def _cmd_receipt_verify_chain(args) -> int:
    from sra_riskgate import verify_receipt_chain
    try:
        rows = _read_receipts(args.file)
    except (OSError, ValueError) as e:
        return _fail(f"cannot read {args.file}: {e}")
    try:
        res = verify_receipt_chain(rows, key=_key_from_env(args.key_env)) if args.key_env \
            else verify_receipt_chain(rows, expected_signer=args.signer)
    except Exception as e:
        return _fail(str(e))
    _out(args, {"valid": res.ok, "checked": res.checked, "bad_index": res.bad_index, "reason": res.reason},
         f"VALID ✓  chain of {res.checked} receipts" if res.ok
         else f"INVALID ✗  receipt {res.bad_index}: {res.reason}")
    return 0 if res.ok else EXIT_INVALID


def _cmd_receipt_report(args) -> int:
    from sra_riskgate import audit_report, audit_report_markdown
    try:
        rows = _read_receipts(args.file)
    except (OSError, ValueError) as e:
        return _fail(f"cannot read {args.file}: {e}")
    try:
        rep = audit_report(rows, key=_key_from_env(args.key_env)) if args.key_env \
            else audit_report(rows, expected_signer=args.signer)
    except Exception as e:
        return _fail(str(e))
    _out(args, rep, audit_report_markdown(rep))
    ch = rep["chain"]
    ok = rep["receipts"] > 0 and rep["invalid"] == 0 and (not ch["chained"] or ch["intact"])
    return 0 if ok else EXIT_INVALID


def _cmd_threats(args) -> int:
    from sra_riskgate.threats import THREATS, coverage
    cov = coverage()
    data = {t: {"name": THREATS[t][0], "source": THREATS[t][1], "flags": cov[t]} for t in THREATS}
    text = "\n".join(f"{t}  {THREATS[t][0]:<38} " + (", ".join(cov[t]) if cov[t] else "(not addressed)")
                     for t in THREATS)
    _out(args, data, text + "\n\nThis project's mapping of its flags to OWASP entries; OWASP has not reviewed it.")
    return 0


def _cmd_bench(args) -> int:
    from sra_riskgate.bench import GUARD_NOTES, GUARDS, CommandGuard, format_table, generate_cases, run_benchmark
    cases = generate_cases(args.seed)
    if args.cases_out:
        with open(args.cases_out, "w", encoding="utf-8") as fh:
            for c in cases:
                fh.write(json.dumps(c) + "\n")
    reports = {}
    if args.guard_cmd:
        try:
            g = CommandGuard(args.guard_cmd)
        except OSError as e:
            return _fail(f"cannot start the guard command: {e}")
        try:
            reports["your guard"] = run_benchmark(g, seed=args.seed, cases=cases)
        finally:
            g.close()
    names = list(GUARDS) if args.guard == "all" else [args.guard]
    if not args.guard_cmd or args.guard != "all":
        for n in names:
            reports[n] = run_benchmark(GUARDS[n], seed=args.seed, cases=cases)
    else:
        for n in ("approve-all", "strict"):
            reports[n] = run_benchmark(GUARDS[n], seed=args.seed, cases=cases)
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        print(f"{len(cases)} generated cases (seed {args.seed}): utility = legitimate payments approved, "
              f"security = unsafe payments not approved\n")
        print(format_table(reports))
        print("\n" + "\n".join(f"  {n}: {GUARD_NOTES[n]}" for n in reports if n in GUARD_NOTES))
        print("\nSynthetic cases in real attack shapes; see `python -m pydoc sra_riskgate.bench` for scope.")
    return 0


def _cmd_evidence_build(args) -> int:
    from sra_riskgate.evidence import build_evidence_pack
    kw = {}
    if args.receipts:
        if not (args.key_env or args.signer):
            return _fail("--receipts needs --key-env or --signer to verify them")
        try:
            kw["receipts"] = _read_receipts(args.receipts)
            kw.update({"key": _key_from_env(args.key_env)} if args.key_env else {"expected_signer": args.signer})
        except (OSError, ValueError) as e:
            return _fail(f"cannot read {args.receipts}: {e}")
    elif args.key_env or args.signer:
        return _fail("--key-env and --signer go with --receipts")
    try:
        m = build_evidence_pack(args.out, policy=args.policy, seed=args.seed, tests=args.tests,
                                make_zip=args.zip, **kw)
    except (OSError, ValueError) as e:
        return _fail(str(e))
    s = m["summary"]
    lines = [("READY ✓  " if m["ok"] else "PROBLEMS ✗  ") + str(args.out),
             f"  self-check: {s['selfcheck']['total'] - s['selfcheck']['failed']} of {s['selfcheck']['total']} passed",
             f"  bench (strict): utility {s['bench']['strict']['utility']:.1%}, "
             f"security {s['bench']['strict']['security']:.1%}",
             f"  OWASP entries addressed: {s['threats']['addressed']} of {s['threats']['total']}",
             f"  audit report: {s['audit']['verified']} of {s['audit']['receipts']} receipts verified"
             + (" (demo chain)" if m["demo_audit_report"] else "")]
    if "tests" in s:
        lines.append(f"  tests: {s['tests'].get('summary') or s['tests'].get('error')}")
    lines.append(f"  pack_sha256: {m['pack_sha256']}")
    if m.get("zip"):
        lines.append(f"  zip: {m['zip']}")
    _out(args, m, "\n".join(lines))
    return 0 if m["ok"] else EXIT_INVALID


def _cmd_evidence_verify(args) -> int:
    from sra_riskgate.evidence import verify_evidence_pack
    r = verify_evidence_pack(args.path)
    _out(args, r, (f"VALID ✓  {args.path}: every file unchanged ({r['library']}, built {r['built_at']})\n"
                   f"  pack_sha256: {r['pack_sha256']}") if r["ok"]
         else f"INVALID ✗  {args.path}\n" + "\n".join(f"  {x}" for x in r["problems"]))
    return 0 if r["ok"] else EXIT_INVALID


def _cmd_scan(args) -> int:
    from sra_riskgate.scan import ScanError, scan_policy, scan_wallet
    url = args.rpc or os.environ.get("SRA_RPC_URL")
    if not url:
        return _fail("give --rpc URL or set SRA_RPC_URL (any JSON-RPC endpoint for the wallet's chain)")
    known = None
    if args.known:
        try:
            with open(args.known, encoding="utf-8") as fh:
                known = [x.strip() for x in fh if x.strip() and not x.lstrip().startswith("#")]
        except OSError as e:
            return _fail(f"cannot read {args.known}: {e}")
    try:
        r = scan_wallet(args.wallet, rpc_url=url, blocks=args.blocks, from_block=args.from_block,
                        known_payees=known, lookalike_check=args.lookalike_check, max_requests=args.max_requests)
    except (ScanError, ValueError) as e:
        return _fail(str(e))
    if args.write_policy:
        try:
            with open(args.write_policy, "w", encoding="utf-8") as fh:
                json.dump(scan_policy(r, include_payees=args.include_payees), fh, indent=2)
                fh.write("\n")
        except OSError as e:
            return _fail(f"cannot write {args.write_policy}: {e}")
    found = bool(r["findings"] or r["suspicious_payees"])
    head = (f"FOUND {len(r['findings'])} look-alike(s) targeting {r['wallet']}" if found
            else f"CLEAN  no look-alikes of your payees in {r['wallet']}'s history")
    lines = [head, f"  chain {r['chain_id']}, blocks {r['from_block']}-{r['to_block']}, {r['payees']} payees, "
                   f"{r['events_checked']} other transfers checked ({r['lookalike_check']} rule)"]
    for f in r["findings"]:
        lines.append(f"  {f['address']}  imitates {f['imitates']}  ({f['shared_prefix']}+{f['shared_suffix']} "
                     f"characters, {', '.join(f['kinds'])}, {len(f['transactions'])} tx)")
    for s in r["suspicious_payees"]:
        a, b = s["addresses"]
        lines.append(f"  PAID BOTH {a} and {b}: one may be a poisoned copy, confirm both before paying again")
    if not r["complete"]:
        lines.append(f"  INCOMPLETE: stopped at block {r['stopped_at_block']}; raise --max-requests or narrow --blocks")
    if args.write_policy:
        lines.append(f"  policy written: {args.write_policy} (sra-riskgate policy validate {args.write_policy})")
    _out(args, r, "\n".join(lines))
    if found:
        return EXIT_HOLD
    return 0 if r["complete"] else EXIT_INVALID


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sra-riskgate",
                                description="The pre-sign firewall for AI agents that pay.")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="check one stablecoin payment (exit 0 approve, 10 hold, 20 reject)")
    c.add_argument("--chain", type=int, required=True, help="chain id, e.g. 8453 for Base")
    c.add_argument("--sender", required=True, help="the paying wallet")
    c.add_argument("--to", required=True, help="the payee")
    c.add_argument("--amount", type=float, required=True, help="amount in whole tokens, e.g. 25 for 25 USDC")
    c.add_argument("--token", default="USDC", help="USDC (default), USDT, USDB or USDG")
    c.add_argument("--text", default=None, help="the payment request's own text (checked for self-approval)")
    c.add_argument("--peg", type=float, default=None,
                   help="the stablecoin's current deviation from $1 in percent (omit it and the depeg check is "
                        "skipped and flagged PEG_NOT_CHECKED)")
    c.add_argument("--max-amount", type=float, default=None, help="per-payment ceiling (default 1000)")
    c.add_argument("--known", nargs="+", default=None, metavar="ADDRESS", help="payees you already trust")
    c.add_argument("--lookalike", choices=["standard", "strict"], default=None,
                   help="look-alike payee rule with --known: standard (7+ shared characters, default) or strict "
                        "(also 3 at each end)")
    c.add_argument("--new-payee", choices=["hold", "allow"], default=None,
                   help="with --known: hold a payee not in the list (default) or allow it (the look-alike check "
                        "still applies)")
    c.add_argument("--policy", default=None, help="a policy file (JSON or YAML)")
    c.add_argument("--record", action="store_true",
                   help="count an approved payment against the policy's budgets (default: a dry run that "
                        "reads the ledger but never writes to it)")
    c.add_argument("--json", action="store_true", help="print JSON")
    c.set_defaults(func=_cmd_check)

    pol = sub.add_parser("policy", help="policy files").add_subparsers(dest="action", required=True)
    v = pol.add_parser("validate", help="check a policy file (exit 0 valid, 1 invalid)")
    v.add_argument("file")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_policy_validate)

    rec = sub.add_parser("receipt", help="decision receipts").add_subparsers(dest="action", required=True)
    rv = rec.add_parser("verify", help="verify a signed receipt (exit 0 valid, 1 invalid)")
    rv.add_argument("file", help="a receipt as JSON (or a whole MCP tool result containing one)")
    g = rv.add_mutually_exclusive_group(required=True)
    g.add_argument("--key-env", metavar="VAR", help="environment variable holding the HMAC key (hex or base64)")
    g.add_argument("--signer", metavar="ADDRESS", help="expected signer address for Ethereum receipts")
    rv.add_argument("--json", action="store_true")
    rv.set_defaults(func=_cmd_receipt_verify)

    rc = rec.add_parser("verify-chain", help="verify a chain of receipts, oldest first (exit 0 valid, 1 invalid)")
    rc.add_argument("file", help="a JSON array or JSON Lines file of receipts (or MCP tool results)")
    g = rc.add_mutually_exclusive_group(required=True)
    g.add_argument("--key-env", metavar="VAR", help="environment variable holding the HMAC key (hex or base64)")
    g.add_argument("--signer", metavar="ADDRESS", help="expected signer address for Ethereum receipts")
    rc.add_argument("--json", action="store_true")
    rc.set_defaults(func=_cmd_receipt_verify_chain)

    rr = rec.add_parser("report", help="audit report from receipts (exit 0 all verified, 1 otherwise)")
    rr.add_argument("file", help="a JSON array or JSON Lines file of receipts (or MCP tool results), oldest first")
    g = rr.add_mutually_exclusive_group(required=True)
    g.add_argument("--key-env", metavar="VAR", help="environment variable holding the HMAC key (hex or base64)")
    g.add_argument("--signer", metavar="ADDRESS", help="expected signer address for Ethereum receipts")
    rr.add_argument("--json", action="store_true")
    rr.set_defaults(func=_cmd_receipt_report)

    th = sub.add_parser("threats", help="which OWASP LLM and agentic risks each flag addresses")
    th.add_argument("--json", action="store_true")
    th.set_defaults(func=_cmd_threats)

    b = sub.add_parser("bench", help="utility vs security benchmark for payment guards (offline, deterministic)")
    b.add_argument("--guard", default="all", choices=["all", "approve-all", "hold-new", "standard", "strict",
                                                      "strict-hold-new"])
    b.add_argument("--guard-cmd", default=None, metavar="COMMAND",
                   help="score your own guard: it reads one JSON case per line and answers {\"decision\": ...}")
    b.add_argument("--seed", type=int, default=1)
    b.add_argument("--cases-out", default=None, metavar="FILE", help="also write the cases (with answers) as JSONL")
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=_cmd_bench)

    ev = sub.add_parser("evidence", help="evidence packs for grant assessors, auditors and security reviewers"
                        ).add_subparsers(dest="action", required=True)
    eb = ev.add_parser("build", help="write an evidence pack (exit 0 ready, 1 a check failed)")
    eb.add_argument("--out", required=True, metavar="DIR", help="an empty or new folder")
    eb.add_argument("--receipts", default=None, metavar="FILE",
                    help="your receipts (JSON array or JSON Lines, oldest first) for the audit report; "
                         "without it a labelled demo chain is used")
    g = eb.add_mutually_exclusive_group()
    g.add_argument("--key-env", metavar="VAR", help="environment variable holding the HMAC key (hex or base64)")
    g.add_argument("--signer", metavar="ADDRESS", help="expected signer address for Ethereum receipts")
    eb.add_argument("--policy", default=None, metavar="FILE", help="record a policy's name, hash and settings used")
    eb.add_argument("--tests", default=None, metavar="DIR", help="also run pytest on this folder and record it")
    eb.add_argument("--seed", type=int, default=1, help="benchmark seed (default 1)")
    eb.add_argument("--zip", action="store_true", help="also write DIR.zip")
    eb.add_argument("--json", action="store_true", help="print the manifest as JSON")
    eb.set_defaults(func=_cmd_evidence_build)
    evv = ev.add_parser("verify", help="check a pack is unchanged (exit 0 valid, 1 invalid)")
    evv.add_argument("path", help="the pack folder or its .zip")
    evv.add_argument("--json", action="store_true")
    evv.set_defaults(func=_cmd_evidence_verify)

    sc = sub.add_parser("scan", help="find look-alike addresses already planted in a wallet's history "
                                     "(exit 0 clean, 10 found, 1 incomplete)")
    sc.add_argument("wallet", help="the wallet address to scan")
    sc.add_argument("--rpc", default=None, metavar="URL", help="JSON-RPC endpoint for the chain (or SRA_RPC_URL)")
    sc.add_argument("--blocks", type=int, default=200_000, help="how many recent blocks to read (default 200000)")
    sc.add_argument("--from-block", type=int, default=None, help="read from this block instead of --blocks")
    sc.add_argument("--known", default=None, metavar="FILE", help="extra payees, one address per line")
    sc.add_argument("--lookalike-check", choices=["strict", "standard"], default="strict")
    sc.add_argument("--max-requests", type=int, default=1000, help="RPC request budget (default 1000)")
    sc.add_argument("--write-policy", default=None, metavar="FILE",
                    help="write a policy file blocking every look-alike found")
    sc.add_argument("--include-payees", action="store_true",
                    help="with --write-policy, also list the payees found as known_recipients")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=_cmd_scan)

    ver = sub.add_parser("version", help="print the version")
    ver.set_defaults(func=lambda a: (print(__import__("sra_riskgate").__version__), 0)[1])
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
