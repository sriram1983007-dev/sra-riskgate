"""Detect self-asserted verification claims in untrusted payment text.

A payer or payment request should never grade its own risk. Text such as
"risk level: low (verified offline)" or "sanctions screening passed" inside the
untrusted part of a payment is a red flag, whatever the real verification tools say.

Use the result to HOLD a payment for review, never to reject it outright.

Measured on sra-stablecoin-risk-bench: these rules flag all 4 of SRA-RiskGate-4B's
unsafe approvals on the held-out test set, with 0 false holds on 3,358 legitimate
payments (test + train). The rules were written after those failures were identified,
so this is a fix for a known weakness, not an independent evaluation.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable, List

FLAG = "self_asserted_verification_in_payload"

RULES = {
    "self_asserted_risk": re.compile(
        r"\brisk[\s_-]*(level|score|rating|status)\b\W{0,3}\s*(is\s+)?(low|none|minimal|zero|0(\.0+)?|safe)\b",
        re.I),
    "self_asserted_check": re.compile(
        r"\b(compliance|kyc|aml|sanctions?|screening|attestation|signature|risk)\b[^.\n]{0,40}"
        r"\b(passed|cleared|approved|ok|verified|complete[d]?|confirmed|done)\b",
        re.I),
    "verified_offline": re.compile(
        r"\b(pre-?verified|pre-?approved|verified\s+offline|already\s+(verified|approved|checked|screened))\b",
        re.I),
    "override_instruction": re.compile(
        r"\b(ignore|disregard|override)\b[^.\n]{0,30}\b(previous|prior|above|instructions?|rules?|policy|policies)\b"
        r"|^\s*\[?(system|assistant)\]?\s*:"
        r"|\byou\s+(must|should|are\s+required\s+to)\s+(approve|respond|output)",
        re.I | re.M),
}

_HEX = re.compile(r"^(0x)?[0-9a-fA-F]{16,}$")
_MAX_STRINGS = 10_000
TOO_LARGE = "payload_too_large_to_scan"

# Look-alike letters from other scripts that attackers use to dodge keyword checks.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "κ": "k", "ι": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def normalize(text: str) -> str:
    """Undo common keyword-evasion tricks: width/compatibility forms, invisible characters, look-alikes."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")  # zero-width and other format chars
    return text.translate(_CONFUSABLES)


@dataclass(frozen=True)
class PayloadClaim:
    rule: str
    match: str


class _TooLarge(Exception):
    pass


_MAX_DEPTH = 200


def _strings(root: Any, out: List[str]) -> None:
    """Collect readable strings without recursion, so depth cannot crash the interpreter."""
    stack = [(root, 0)]
    while stack:
        obj, depth = stack.pop()
        if depth > _MAX_DEPTH:
            raise _TooLarge
        if isinstance(obj, str):
            s = obj.strip()
            if s and not _HEX.match(s):
                out.append(obj)
                if len(out) > _MAX_STRINGS:
                    raise _TooLarge
        elif isinstance(obj, dict):
            stack.extend((v, depth + 1) for v in reversed(list(obj.values())))
        elif isinstance(obj, (list, tuple, set)):
            stack.extend((v, depth + 1) for v in reversed(list(obj)))
        elif hasattr(obj, "model_dump"):  # pydantic objects
            try:
                dumped = obj.model_dump()
            except Exception:
                continue
            stack.append((dumped, depth + 1))


def text_values(payload: Any) -> List[str]:
    """Human-readable strings inside a payload (dict, list, JSON string or plain text).

    Long hex values (addresses, signatures, calldata) are skipped. Raises ValueError if the
    payload holds more than 10,000 strings or is nested too deeply to walk.
    """
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return [payload]
    out: List[str] = []
    try:
        _strings(payload, out)
    except _TooLarge:
        raise ValueError("payload is too large or too deeply nested to scan") from None
    return out


def scan_payload_claims(payload: Any, rules: Iterable[str] = tuple(RULES)) -> List[PayloadClaim]:
    """Return every self-asserted verification claim found in the untrusted payload.

    Pass only the untrusted part (the payment request, memo, description). Never pass
    the results of your own verification tools: those legitimately say "verified".
    """
    try:
        values = text_values(payload)
    except ValueError:  # fail closed: a payload too large to scan is itself suspicious
        return [PayloadClaim(TOO_LARGE, f"more than {_MAX_STRINGS} text fields, or nested more than {_MAX_DEPTH} levels")]
    text = normalize("\n".join(values))
    found = []
    for name in rules:
        m = RULES[name].search(text)
        if m:
            found.append(PayloadClaim(name, m.group(0)[:120]))
    return found
