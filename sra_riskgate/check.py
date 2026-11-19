"""One-call, fail-closed payment check: validation, rules and the self-asserted claims scan together."""
from __future__ import annotations

from typing import Any, Iterable, Optional

from sra_riskgate.account_code import account_hold
from sra_riskgate.chains import STABLECOINS, parse_allowed_tokens
from sra_riskgate.client import DEFAULT_SANCTIONS_MAX_AGE_DAYS, RulePreFilter
from sra_riskgate.counterparty import parse_address_list, parse_lookalike_check, parse_new_counterparty
from sra_riskgate.models import ActionDecision, RiskAssessment, TransactionPayload
from sra_riskgate.payload_claims import FLAG as CLAIMS_FLAG
from sra_riskgate.payload_claims import PAYEE_CHANGE_FLAG, scan_payee_change, scan_payload_claims
from sra_riskgate.sanctions import SanctionsList
from sra_riskgate.screening import screen_addresses, screening_decision
from sra_riskgate.spend import SpendGuard, recording_suppressed



def _verdict(decision: ActionDecision, flags: list, explanation: str, actions: list) -> RiskAssessment:
    score = {ActionDecision.APPROVE: 0.05, ActionDecision.HOLD: 0.65, ActionDecision.REJECT: 1.0}[decision]
    return RiskAssessment(decision=decision, risk_score=score, flags=flags,
                          explanation=explanation[:500], required_actions=actions)


def _first_error(e: Exception) -> str:
    errors = getattr(e, "errors", None)
    if callable(errors):
        try:
            return str(errors()[0]["msg"])
        except Exception:
            pass
    return str(e).splitlines()[0] if str(e) else type(e).__name__


def _check_payment_core(
    *,
    chain_id: int,
    sender: str,
    recipient: str,
    amount: float,
    token: str = "USDC",
    untrusted_request: Any = None,
    peg_deviation_pct: Optional[float] = None,
    max_amount: float = 1_000.0,
    depeg_hold_pct: float = 1.0,
    depeg_reject_pct: float = 5.0,
    check_sanctions: bool = True,
    sanctions_list: Optional[SanctionsList] = None,
    gate: Optional[RulePreFilter] = None,
    known_recipients: Optional[Iterable[str]] = None,
    blocked_addresses: Optional[Iterable[str]] = None,
    sanctions_max_age_days: Optional[int] = DEFAULT_SANCTIONS_MAX_AGE_DAYS,
    account_code: Any = None,
    expected_delegates: Optional[Iterable[str]] = None,
    allowed_tokens: Optional[Iterable[str]] = None,
    screening_providers: Optional[Iterable[Any]] = None,
    screening_hold_at: str = "high",
    screening_reject_at: str = "severe",
    lookalike_check: str = "standard",
    new_counterparty: str = "hold",
) -> RiskAssessment:
    """The checks of ``check_payment`` without budgets; see ``check_payment``."""
    try:
        if gate is None:
            try:
                gate = RulePreFilter(max_amount=max_amount, depeg_hold_pct=depeg_hold_pct,
                                     depeg_reject_pct=depeg_reject_pct, check_sanctions=check_sanctions,
                                     sanctions_list=sanctions_list,
                                     sanctions_max_age_days=sanctions_max_age_days)
            except (TypeError, ValueError) as e:
                return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                                f"The risk gate is misconfigured: {_first_error(e)}", ["fix_configuration"])
        try:
            known_recipients = parse_address_list("known_recipients", known_recipients)
            blocked_addresses = parse_address_list("blocked_addresses", blocked_addresses)
            compromised = account_hold(sender, account_code, expected_delegates)
            allowed = parse_allowed_tokens(allowed_tokens)
            providers = list(screening_providers) if screening_providers is not None else []
            if screening_providers is not None and (isinstance(screening_providers, (str, bytes)) or not providers
                                                    or not all(callable(getattr(p, "screen", None)) for p in providers)):
                raise ValueError("screening_providers must be a non-empty list of providers with a screen() method")
            screening_decision([], hold_at=screening_hold_at, reject_at=screening_reject_at)  # validates thresholds
            parse_lookalike_check(lookalike_check)
            parse_new_counterparty(new_counterparty)
        except (TypeError, ValueError) as e:
            return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                            f"The risk gate is misconfigured: {_first_error(e)}", ["fix_configuration"])

        sanctioned = gate.screen_sanctions(sender, recipient)
        if sanctioned is not None:
            return sanctioned
        blocked = gate.screen_blocklist(sender, recipient, blocked_addresses)
        if blocked is not None:
            return blocked
        if compromised is not None:
            return compromised

        sym = token.strip().upper() if isinstance(token, str) else None
        if sym not in STABLECOINS:
            return _verdict(ActionDecision.HOLD, ["UNSUPPORTED_ASSET"],
                            f"Only {', '.join(STABLECOINS)} are checked; got {token!r}.", ["manual_review"])
        if sym not in allowed:
            return _verdict(ActionDecision.HOLD, ["UNSUPPORTED_ASSET"],
                            f"{sym} is not enabled for this gate (allowed_tokens: {', '.join(sorted(allowed))}). "
                            f"Add it to allowed_tokens to check {sym} payments.", ["manual_review"])
        if isinstance(chain_id, bool) or chain_id not in STABLECOINS[sym]:
            chains = ", ".join(str(c) for c in sorted(STABLECOINS[sym]))
            return _verdict(ActionDecision.HOLD, ["UNSUPPORTED_CHAIN"],
                            f"Chain {chain_id!r} is not checked for {sym}; supported chain ids: {chains}.",
                            ["manual_review"])

        if isinstance(amount, bool):  # True would otherwise be read as 1.0 USDC
            return _verdict(ActionDecision.REJECT, ["INVALID_PAYMENT"],
                            "Payment failed validation: amount must be a number, not a boolean.", ["reject_payment"])
        try:
            payload = TransactionPayload(chain_id=chain_id, token=sym, sender=sender, recipient=recipient,
                                         amount=amount, peg_deviation_pct=peg_deviation_pct)
        except (TypeError, ValueError) as e:
            return _verdict(ActionDecision.REJECT, ["INVALID_PAYMENT"],
                            f"Payment failed validation: {_first_error(e)}", ["reject_payment"])

        result = gate.inspect(payload, known_recipients=known_recipients, blocked_addresses=blocked_addresses,
                              lookalike_check=lookalike_check, new_counterparty=new_counterparty)
        if result.decision == ActionDecision.REJECT:
            return result
        if providers:
            screened = screening_decision(screen_addresses(providers, [sender, recipient], chain_id),
                                          hold_at=screening_hold_at, reject_at=screening_reject_at)
            if screened is not None:
                kind, sflags, why = screened
                if kind == "reject":
                    return _verdict(ActionDecision.REJECT, sflags, why, ["block_payment"])
                if result.decision == ActionDecision.HOLD:
                    why += " Also: " + result.explanation
                    sflags = sflags + [f for f in result.flags if f not in sflags]
                result = _verdict(ActionDecision.HOLD, sflags, why, ["manual_review"])
        if untrusted_request is None:
            return result

        claims = scan_payload_claims(untrusted_request)
        change = scan_payee_change(untrusted_request, recipient=recipient, sender=sender)
        if not claims and not change:
            return result
        flags, whys = [], []
        if claims:
            found = "; ".join(f"{c.rule}: {c.match!r}" for c in claims[:3])
            flags += [CLAIMS_FLAG] + [c.rule for c in claims]
            whys.append(f"The payment request claims its own verification ({found}). Real checks must come from "
                        "your own tools.")
        if change:
            found = "; ".join(f"{c.rule}: {c.match!r}" for c in change[:3])
            flags += [PAYEE_CHANGE_FLAG] + [c.rule for c in change if c.rule not in flags]
            whys.append(f"The payment request asks to pay a new or different address ({found}). Confirm the payee "
                        "through a channel you already trust, never through the request itself.")
        flags += [f for f in result.flags if f not in flags]
        why = " ".join(whys)
        if result.decision == ActionDecision.HOLD:
            why += " Also: " + result.explanation
        return _verdict(ActionDecision.HOLD, flags, why, ["manual_review"])
    except Exception as e:  # fail closed: no error path may approve
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The payment check failed ({type(e).__name__}), so the payment is held.",
                        ["manual_review"])


def check_payment(
    *,
    chain_id: int,
    sender: str,
    recipient: str,
    amount: float,
    token: str = "USDC",
    untrusted_request: Any = None,
    peg_deviation_pct: Optional[float] = None,
    max_amount: float = 1_000.0,
    depeg_hold_pct: float = 1.0,
    depeg_reject_pct: float = 5.0,
    check_sanctions: bool = True,
    sanctions_list: Optional[SanctionsList] = None,
    gate: Optional[RulePreFilter] = None,
    known_recipients: Optional[Iterable[str]] = None,
    blocked_addresses: Optional[Iterable[str]] = None,
    sanctions_max_age_days: Optional[int] = DEFAULT_SANCTIONS_MAX_AGE_DAYS,
    account_code: Any = None,
    expected_delegates: Optional[Iterable[str]] = None,
    allowed_tokens: Optional[Iterable[str]] = None,
    screening_providers: Optional[Iterable[Any]] = None,
    screening_hold_at: str = "high",
    screening_reject_at: str = "severe",
    spend_guard: Optional[SpendGuard] = None,
    payment_id: Optional[str] = None,
    lookalike_check: str = "standard",
    new_counterparty: str = "hold",
) -> RiskAssessment:
    """Check a stablecoin payment before sending it. Never raises on bad payment data; anything unexpected becomes HOLD.

    Runs, in order:
      1. Sanctions: sender or recipient on the OFAC SDN list gives REJECT (flag OFAC_SDN_MATCH).
         Uses the bundled snapshot unless ``sanctions_list`` is given; ``check_sanctions=False``
         turns it off. It is an exact address match against a dated snapshot, not a screening service.
         A list older than ``sanctions_max_age_days`` adds the informational flag SANCTIONS_LIST_STALE.
      1b. Blocklist: sender or recipient in ``blocked_addresses`` gives REJECT (BLOCKLISTED_ADDRESS).
      1c. The sender's own account: if ``account_code`` (its ``eth_getCode`` result) is given and is an EIP-7702
          delegation designator (0xef0100 + address) to a contract not in ``expected_delegates``, HOLD
          (ACCOUNT_DELEGATED): someone else may control the account. ``account_code`` may also be a mapping
          ``{address: code}``; then it must contain the sender (else HOLD, ACCOUNT_CODE_MISMATCH).
          ``expected_delegates`` is validated even without ``account_code``.
      2. Supported asset and chain: ``token`` must be one of ``allowed_tokens`` (default ``["USDC"]``) and
         listed on ``chain_id``, otherwise HOLD (UNSUPPORTED_ASSET or UNSUPPORTED_CHAIN). Listed: USDC on
         Ethereum (1), Base (8453), Base Sepolia (84532), Arc (5042) and Arc Testnet (5042002); USDT on
         Ethereum; USDB (Bridge) on Ethereum and Base; USDG on Ethereum and Robinhood Chain (4663).
         Enable the others with ``allowed_tokens=["USDC", "USDT", "USDB", "USDG"]``. ``max_amount`` and
         ``peg_deviation_pct`` then apply to the token being paid: pass that token's own peg.
      3. Validation: malformed, zero or self address, or a non-positive amount, gives REJECT.
      4. Rules (``RulePreFilter``): per-payment ceiling and, if ``peg_deviation_pct`` is given,
         depeg thresholds. If ``known_recipients`` is given (even empty), a recipient not on it
         gives HOLD (NEW_COUNTERPARTY), and one that imitates a known payee (same first and last hex
         characters) gives REJECT (LOOKALIKE_RECIPIENT): address poisoning. ``None`` turns both off.
         A look-alike shares at least 7 hex characters with a known payee, 3 or more at each end;
         ``lookalike_check="strict"`` (1.10.0+) rejects one sharing only 3 at each end too.
         ``new_counterparty="allow"`` (1.11.0+) keeps the look-alike check without holding every new payee.
      4b. Screening providers (1.4.0+): if ``screening_providers`` is given (e.g. ``[ChainalysisSanctions(key),
          RangeRisk(key)]``), each screens the sender and the recipient. A sanctions match gives REJECT
          (PROVIDER_SANCTIONS_MATCH); risk at or above ``screening_reject_at`` gives REJECT (PROVIDER_RISK_SEVERE),
          at or above ``screening_hold_at`` HOLD (PROVIDER_RISK_HIGH). A provider with no usable answer gives HOLD
          (SCREENING_UNAVAILABLE). Runs only after every local check passes, so invalid payments make no calls.
      5. Self-asserted claims in ``untrusted_request`` (the payment request, memo or description
         exactly as received), such as "risk level: low (verified offline)", give HOLD.
         Never pass your own verification results here: those legitimately say "verified".
         A request asking to pay a new or different address ("our wallet address has changed", or an address in
         its text that is not the recipient) gives HOLD with PAYEE_CHANGE_REQUEST (1.11.0+).

      6. Budgets and anomalies (1.8.0+): if ``spend_guard`` (a ``SpendGuard``) is given and no check above rejected
         the payment, a payment that would exceed a rolling budget or looks unlike the wallet's history gives HOLD
         (BUDGET_EXCEEDED, PAYEE_BUDGET_EXCEEDED, RATE_SPIKE, AMOUNT_SPIKE). An approved payment is then recorded in
         the guard's ledger (``reserve_on_approve``), under ``payment_id`` if given so ``guard.release(payment_id)``
         can remove it if it is never sent.

    Only send the payment if ``result.decision`` is ``ActionDecision.APPROVE``.
    Pass ``gate`` to reuse a configured ``RulePreFilter``; the threshold and sanctions arguments are
    then ignored. ``known_recipients`` and ``blocked_addresses`` always apply, added to the gate's own.
    A malformed address list is a configuration error (REJECT), never a silently weaker check.
    """
    if spend_guard is not None and not isinstance(spend_guard, SpendGuard):
        return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                        "The risk gate is misconfigured: spend_guard must be a SpendGuard", ["fix_configuration"])
    if payment_id is not None and (not isinstance(payment_id, str) or not payment_id.strip()):
        return _verdict(ActionDecision.REJECT, ["CONFIGURATION_ERROR"],
                        "The risk gate is misconfigured: payment_id must be a non-empty string", ["fix_configuration"])
    result = _check_payment_core(chain_id=chain_id, sender=sender, recipient=recipient, amount=amount, token=token, untrusted_request=untrusted_request, peg_deviation_pct=peg_deviation_pct, max_amount=max_amount, depeg_hold_pct=depeg_hold_pct, depeg_reject_pct=depeg_reject_pct, check_sanctions=check_sanctions, sanctions_list=sanctions_list, gate=gate, known_recipients=known_recipients, blocked_addresses=blocked_addresses, sanctions_max_age_days=sanctions_max_age_days, account_code=account_code, expected_delegates=expected_delegates, allowed_tokens=allowed_tokens, screening_providers=screening_providers, screening_hold_at=screening_hold_at, screening_reject_at=screening_reject_at, lookalike_check=lookalike_check, new_counterparty=new_counterparty)
    if spend_guard is None or result.decision == ActionDecision.REJECT:
        return result
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return result  # the core checks already held or rejected it; nothing to count
    try:
        broken = spend_guard.evaluate(sender=sender, recipient=recipient, amount=float(amount))
        if broken:
            flags = [f for f, _ in broken] + [f for f in result.flags if f not in {f for f, _ in broken}]
            why = " ".join(w for _, w in broken)
            if result.decision == ActionDecision.HOLD:
                why += " Also: " + result.explanation
            return _verdict(ActionDecision.HOLD, flags, why, ["manual_review"])
        if result.decision == ActionDecision.APPROVE and spend_guard.reserve_on_approve and not recording_suppressed():
            spend_guard.record(chain_id=chain_id, sender=sender, recipient=recipient, amount=float(amount),
                               token=token.strip().upper() if isinstance(token, str) else str(token),
                               payment_id=payment_id)
        return result
    except Exception as e:  # an unreadable ledger never approves
        return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                        f"The spending budget could not be checked ({type(e).__name__}), so the payment is held.",
                        ["manual_review"])
