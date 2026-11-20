"""Which published AI-security risks each decision flag addresses (1.12.0+).

Security reviewers, auditors and grant assessors ask the same question: which known risks does this control cover?
This module maps every flag the library can return to entries in two public OWASP lists, so a decision, a receipt or
an audit report can answer in their terms:

- **OWASP Top 10 for LLM Applications (2025)**: ``LLM01`` to ``LLM10``.
- **OWASP Top 10 for Agentic Applications (2026)**: ``ASI01`` to ``ASI10``.

    from sra_riskgate.threats import threats_for, describe
    threats_for(result.flags)          # ["ASI01", "ASI07", "LLM01"]
    describe("ASI01")                  # "Agent Goal Hijack (OWASP Top 10 for Agentic Applications 2026)"

Every flag also has a ``category`` (what kind of control raised it), including flags with no OWASP entry, such as
sanctions matches (a compliance control) or a depeg (a market control).

The mapping is this project's own reading of the OWASP descriptions. OWASP has not reviewed or endorsed it. A flag
mapped to an entry means the check addresses part of that risk in payments, not that it covers the whole entry.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

__all__ = ["THREATS", "FLAG_CATEGORY", "FLAG_THREATS", "threats_for", "categories_for", "describe", "coverage"]

_LLM = "OWASP Top 10 for LLM Applications 2025"
_ASI = "OWASP Top 10 for Agentic Applications 2026"

THREATS: Dict[str, Tuple[str, str]] = {
    "LLM01": ("Prompt Injection", _LLM),
    "LLM02": ("Sensitive Information Disclosure", _LLM),
    "LLM03": ("Supply Chain", _LLM),
    "LLM04": ("Data and Model Poisoning", _LLM),
    "LLM05": ("Improper Output Handling", _LLM),
    "LLM06": ("Excessive Agency", _LLM),
    "LLM07": ("System Prompt Leakage", _LLM),
    "LLM08": ("Vector and Embedding Weaknesses", _LLM),
    "LLM09": ("Misinformation", _LLM),
    "LLM10": ("Unbounded Consumption", _LLM),
    "ASI01": ("Agent Goal Hijack", _ASI),
    "ASI02": ("Tool Misuse and Exploitation", _ASI),
    "ASI03": ("Identity and Privilege Abuse", _ASI),
    "ASI04": ("Agentic Supply Chain Vulnerabilities", _ASI),
    "ASI05": ("Unexpected Code Execution", _ASI),
    "ASI06": ("Memory and Context Poisoning", _ASI),
    "ASI07": ("Insecure Inter-Agent Communication", _ASI),
    "ASI08": ("Cascading Failures", _ASI),
    "ASI09": ("Human-Agent Trust Exploitation", _ASI),
    "ASI10": ("Rogue Agents", _ASI),
}

# category, OWASP entries
_MAP: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # text in the payment request that tries to steer the decision
    "self_asserted_verification_in_payload": ("injection", ("LLM01", "ASI01")),
    "self_asserted_risk": ("injection", ("LLM01", "ASI01")),
    "self_asserted_check": ("injection", ("LLM01", "ASI01")),
    "verified_offline": ("injection", ("LLM01", "ASI01", "ASI09")),
    "override_instruction": ("injection", ("LLM01", "ASI01")),
    "payload_too_large_to_scan": ("injection", ("LLM01",)),
    "PAYEE_CHANGE_REQUEST": ("injection", ("LLM01", "ASI01", "ASI07")),
    "address_changed": ("injection", ("LLM01", "ASI01", "ASI07")),
    "send_to_new_address": ("injection", ("LLM01", "ASI01", "ASI07")),
    "stop_old_address": ("injection", ("LLM01", "ASI01", "ASI07")),
    "new_address_named": ("injection", ("LLM01", "ASI01", "ASI07")),
    "other_address_in_request": ("injection", ("LLM01", "ASI01", "ASI07")),
    # who gets paid
    "LOOKALIKE_RECIPIENT": ("payee", ("ASI06", "ASI02")),
    "NEW_COUNTERPARTY": ("payee", ("LLM06", "ASI02")),
    "BLOCKLISTED_ADDRESS": ("payee", ("ASI02",)),
    # negotiation sessions (1.12.0+)
    "SESSION_PAYEE_DRIFT": ("negotiation", ("ASI01", "ASI07")),
    "SESSION_AMOUNT_DRIFT": ("negotiation", ("ASI01", "ASI07", "LLM06")),
    "SESSION_ASSET_DRIFT": ("negotiation", ("ASI01", "ASI07")),
    "SESSION_PAYEE_CHANGE_SEEN": ("negotiation", ("LLM01", "ASI01", "ASI06", "ASI07")),
    "SESSION_ALREADY_PAID": ("negotiation", ("LLM06", "ASI08")),
    "SESSION_CLOSED": ("negotiation", ("LLM06",)),
    "unreadable_message": ("fail_closed", ()),
    # how much, how often
    "HIGH_VALUE_TRANSFER": ("limits", ("LLM06",)),
    "ROUND_AMOUNT": ("limits", ("LLM06",)),
    "BUDGET_EXCEEDED": ("limits", ("LLM06", "LLM10")),
    "PAYEE_BUDGET_EXCEEDED": ("limits", ("LLM06", "LLM10")),
    "RATE_SPIKE": ("limits", ("LLM10", "ASI08", "ASI10")),
    "AMOUNT_SPIKE": ("limits", ("LLM06", "ASI10")),
    "BATCH_TOTAL": ("limits", ("LLM06",)),
    # permissions the agent would grant
    "UNLIMITED_APPROVAL": ("permissions", ("LLM06", "ASI02", "ASI03")),
    "UNLIMITED_ALLOWANCE": ("permissions", ("LLM06", "ASI03")),
    "TOKEN_APPROVAL": ("permissions", ("LLM06", "ASI03")),
    "ALLOWANCE_ABOVE_LIMIT": ("permissions", ("LLM06", "ASI03")),
    "UNKNOWN_SPENDER": ("permissions", ("ASI03",)),
    "BLOCKLISTED_SPENDER": ("permissions", ("ASI03",)),
    "CODE_DELEGATION": ("permissions", ("ASI03",)),
    "ACCOUNT_DELEGATED": ("permissions", ("ASI03",)),
    "DELEGATECALL": ("permissions", ("ASI03", "ASI05")),
    "LONG_LIVED_AUTHORIZATION": ("permissions", ("ASI03",)),
    "LONG_TIMEOUT_REQUESTED": ("permissions", ("ASI03",)),
    "UNKNOWN_PAYMASTER": ("permissions", ("ASI03",)),
    "UNKNOWN_WALLET": ("permissions", ("ASI03",)),
    # what is signed is not what the agent said it would do
    "TRANSACTION_MISMATCH": ("integrity", ("LLM05", "ASI02")),
    "AUTHORIZATION_MISMATCH": ("integrity", ("LLM05", "ASI02")),
    "USER_OPERATION_MISMATCH": ("integrity", ("LLM05", "ASI02")),
    "WALLET_MISMATCH": ("integrity", ("LLM05", "ASI02")),
    "ACCOUNT_CODE_MISMATCH": ("integrity", ("ASI03",)),
    "UNEXPECTED_TRANSFER": ("integrity", ("LLM05", "ASI02")),
    "NATIVE_VALUE_TRANSFER": ("integrity", ("LLM05", "ASI02")),
    "UNSUPPORTED_FUNCTION": ("integrity", ("ASI02",)),
    "UNSUPPORTED_ACCOUNT_CALL": ("integrity", ("ASI02",)),
    "ACCOUNT_SELF_CALL": ("integrity", ("ASI02",)),
    "ACCOUNT_DEPLOYMENT": ("integrity", ("ASI02",)),
    # compliance controls (no OWASP entry)
    "OFAC_SDN_MATCH": ("compliance", ()),
    "PROVIDER_SANCTIONS_MATCH": ("compliance", ()),
    "PROVIDER_RISK_SEVERE": ("compliance", ()),
    "PROVIDER_RISK_HIGH": ("compliance", ()),
    "SANCTIONED_SPENDER": ("compliance", ()),
    "SANCTIONS_LIST_STALE": ("compliance", ()),
    "SANCTIONS_NOT_CHECKED": ("compliance", ()),
    # market controls (no OWASP entry)
    "MODERATE_DEPEG": ("market", ()),
    "CRITICAL_DEPEG_EVENT": ("market", ()),
    "PEG_NOT_CHECKED": ("market", ()),
    "INVALID_PEG_VALUE": ("market", ()),
    "UNSUPPORTED_ASSET": ("market", ()),
    "UNSUPPORTED_CHAIN": ("market", ()),
    # the check itself could not complete, so it held (fail closed)
    "CHECK_FAILED": ("fail_closed", ("ASI08",)),
    "SCREENING_UNAVAILABLE": ("fail_closed", ("ASI08",)),
    "CONFIGURATION_ERROR": ("fail_closed", ()),
    "INVALID_REQUEST": ("fail_closed", ()),
    "INVALID_TRANSACTION": ("fail_closed", ()),
    "INVALID_AUTHORIZATION": ("fail_closed", ()),
    "INVALID_USER_OPERATION": ("fail_closed", ()),
    "INVALID_ACCOUNT_CODE": ("fail_closed", ()),
    "INVALID_PAYMENT": ("fail_closed", ()),
    "INVALID_REQUIREMENTS": ("fail_closed", ()),
    "UNSUPPORTED_OPERATION": ("fail_closed", ()),
    "UNSUPPORTED_SIGNATURE": ("fail_closed", ()),
    # after the payment: did it settle as decided (verify_settlement)
    "SETTLEMENT_NOT_FOUND": ("settlement", ()),
    "INVALID_RECEIPT": ("settlement", ()),
    "SETTLEMENT_FAILED": ("settlement", ()),
    "SETTLEMENT_PAYEE_MISMATCH": ("settlement", ("LLM05",)),
    "SETTLEMENT_AMOUNT_MISMATCH": ("settlement", ("LLM05",)),
    "DUPLICATE_SETTLEMENT": ("settlement", ("ASI08",)),
    "GATEWAY_PAYER_NOT_DEBITED": ("settlement", ()),
    "GATEWAY_PAYEE_NOT_CREDITED": ("settlement", ()),
    "GATEWAY_VALIDITY_TOO_SHORT": ("settlement", ()),
    "AUTHORIZATION_EXPIRED": ("settlement", ()),
    "AUTHORIZATION_NOT_YET_VALID": ("settlement", ()),
    "AUTHORIZATION_NOT_USED": ("settlement", ()),
}

FLAG_CATEGORY: Dict[str, str] = {f: c for f, (c, _) in _MAP.items()}
FLAG_THREATS: Dict[str, Tuple[str, ...]] = {f: t for f, (_, t) in _MAP.items()}

_ORDER = {k: i for i, k in enumerate(THREATS)}


def _flags(flags: Iterable[str]) -> List[str]:
    if isinstance(flags, str):
        return [flags]
    try:
        return [f for f in flags if isinstance(f, str)]
    except TypeError:
        return []


def threats_for(flags: Iterable[str]) -> List[str]:
    """OWASP entries addressed by these flags, de-duplicated, LLM list first. Unknown flags are ignored."""
    seen = {t for f in _flags(flags) for t in FLAG_THREATS.get(f, ())}
    return sorted(seen, key=_ORDER.__getitem__)


def categories_for(flags: Iterable[str]) -> List[str]:
    """Control categories of these flags, in first-seen order. Unknown flags are reported as ``other``."""
    out: List[str] = []
    for f in _flags(flags):
        c = FLAG_CATEGORY.get(f, "other")
        if c not in out:
            out.append(c)
    return out


def describe(threat_id: str) -> str:
    """``"Agent Goal Hijack (OWASP Top 10 for Agentic Applications 2026)"`` for ``"ASI01"``; ``""`` if unknown."""
    name, source = THREATS.get(threat_id, ("", ""))
    return f"{name} ({source})" if name else ""


def coverage() -> Dict[str, List[str]]:
    """For every OWASP entry, the flags that address it (an empty list where the library has none)."""
    out: Dict[str, List[str]] = {t: [] for t in THREATS}
    for f, ts in FLAG_THREATS.items():
        for t in ts:
            out[t].append(f)
    return out
