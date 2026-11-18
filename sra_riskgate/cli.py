"""``sra-riskgate`` command line (1.9.0+): check a payment, validate a policy file, verify a receipt.

    sra-riskgate check --chain 8453 --sender 0x... --to 0x... --amount 25 [--policy policy.json] [--json]
                                    # a dry run: budgets are read, never spent (add --record to count it)
    sra-riskgate policy validate payment-policy.json
    sra-riskgate receipt verify receipt.json --key-env SRA_RECEIPT_KEY      # HMAC receipts
    sra-riskgate receipt verify receipt.json --signer 0xYourReceiptAddress  # Ethereum receipts
    sra-riskgate version

Exit codes, so a CI pipeline or a shell script can act on the result:
    check            0 approve, 10 hold, 20 reject
    policy validate  0 valid, 1 invalid
    receipt verify   0 valid, 1 invalid
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
                         "screening",
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

    ver = sub.add_parser("version", help="print the version")
    ver.set_defaults(func=lambda a: (print(__import__("sra_riskgate").__version__), 0)[1])
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
