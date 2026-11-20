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
    sra-riskgate version

Exit codes, so a CI pipeline or a shell script can act on the result:
    check            0 approve, 10 hold, 20 reject
    policy validate  0 valid, 1 invalid
    receipt verify   0 valid, 1 invalid
    receipt report   0 every receipt verified (and the chain is intact), 1 otherwise
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
            reports["your guard"] = run_benchmark(g, cases=cases)
        finally:
            g.close()
    names = list(GUARDS) if args.guard == "all" else [args.guard]
    if not args.guard_cmd or args.guard != "all":
        for n in names:
            reports[n] = run_benchmark(GUARDS[n], cases=cases)
    else:
        for n in ("approve-all", "strict"):
            reports[n] = run_benchmark(GUARDS[n], cases=cases)
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        print(f"{len(cases)} generated cases (seed {args.seed}): utility = legitimate payments approved, "
              f"security = unsafe payments not approved\n")
        print(format_table(reports))
        print("\n" + "\n".join(f"  {n}: {GUARD_NOTES[n]}" for n in reports if n in GUARD_NOTES))
        print("\nSynthetic cases in real attack shapes; see `python -m pydoc sra_riskgate.bench` for scope.")
    return 0


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

    ver = sub.add_parser("version", help="print the version")
    ver.set_defaults(func=lambda a: (print(__import__("sra_riskgate").__version__), 0)[1])
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
