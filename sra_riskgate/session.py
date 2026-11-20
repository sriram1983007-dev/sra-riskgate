"""Negotiation sessions (1.12.0+): hold a payment that drifts from the terms the agent agreed.

When agents negotiate before paying, the dangerous moment is often not the first message but a later one: "actually,
send it to our other wallet", a total that creeps up, a switch to another token or chain, or a second payment for
work already paid. Each payment can look fine on its own. A ``PaymentSession`` remembers what was agreed and checks
every payment against it, on top of the usual ``check_payment`` checks.

    from sra_riskgate import PaymentSession
    s = PaymentSession(payee="0xVendor...", amount=40, chain_id=8453, token="USDC")
    for msg in counterparty_messages:            # everything the other side sent, as received
        s.observe(msg)                           # remembers any request to pay a new or different address
    result = s.check(sender="0xMine...", recipient=to, amount=amt, known_recipients=[...])
    if result.decision == "approve": send()

Holds (on top of ``check_payment``):
- ``SESSION_PAYEE_DRIFT``: the recipient is not the agreed payee.
- ``SESSION_AMOUNT_DRIFT``: the amount is above the agreed amount plus ``tolerance_pct``.
- ``SESSION_ASSET_DRIFT``: a different token or chain from the one agreed.
- ``SESSION_PAYEE_CHANGE_SEEN``: earlier in the session, the other side asked to pay a new or different address, told
  the agent to ignore its instructions, or said the payment was already verified. It stays held for the rest of the
  session, even if the final request is clean, because a redirect is often made in one message and acted on several
  messages later.
- ``SESSION_ALREADY_PAID``: the session already approved ``max_payments`` payments (default 1).
- ``SESSION_CLOSED``: the session was closed.

Only the principal changes the terms, with ``amend(...)``, which records who changed what and why. Nothing a
counterparty says changes them. A session never raises from ``check``; anything unexpected becomes HOLD.
"""
from __future__ import annotations

import math
import re
import secrets
import threading
from typing import Any, Dict, List, Optional

from sra_riskgate.check import _verdict, check_payment
from sra_riskgate.models import ActionDecision, RiskAssessment
from sra_riskgate.payload_claims import scan_payee_change, scan_payload_claims

__all__ = ["PaymentSession"]

# claims that are never part of an honest negotiation; ordinary words such as "verified" are not sticky
_STICKY_CLAIMS = {"override_instruction", "verified_offline", "payload_too_large_to_scan"}
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _addr(name: str, v: Any) -> str:
    if not isinstance(v, str) or not _ADDR.match(v.strip()):
        raise ValueError(f"{name} must be a 0x-prefixed 40-hex-character address")
    return v.strip()


def _pos(name: str, v: Any) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return float(v)


class PaymentSession:
    """The agreed terms of one negotiation, and the payments checked against them."""

    def __init__(self, *, payee: str, amount: float, chain_id: int, token: str = "USDC",
                 sender: Optional[str] = None, tolerance_pct: float = 0.0, max_payments: int = 1,
                 session_id: Optional[str] = None):
        self.payee = _addr("payee", payee)
        self.amount = _pos("amount", amount)
        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError("chain_id must be a positive integer")
        self.chain_id = chain_id
        if not isinstance(token, str) or not token.strip():
            raise ValueError("token must be a symbol such as 'USDC'")
        self.token = token.strip().upper()
        self.sender = _addr("sender", sender) if sender is not None else None
        if isinstance(tolerance_pct, bool) or not isinstance(tolerance_pct, (int, float)) \
                or not math.isfinite(tolerance_pct) or not 0 <= tolerance_pct <= 100:
            raise ValueError("tolerance_pct must be between 0 and 100")
        self.tolerance_pct = float(tolerance_pct)
        if isinstance(max_payments, bool) or not isinstance(max_payments, int) or max_payments < 1:
            raise ValueError("max_payments must be a positive integer")
        self.max_payments = max_payments
        if session_id is not None and (not isinstance(session_id, str) or not session_id.strip()):
            raise ValueError("session_id must be a non-empty string")
        self.session_id = session_id or secrets.token_hex(8)
        self.closed = False
        self.messages_seen = 0
        self.warnings: List[Dict[str, str]] = []      # requests to redirect payment, or self-asserted checks
        self.approved: List[Dict[str, Any]] = []      # payments this session approved
        self.amendments: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ what the other side says

    def observe(self, message: Any) -> List[str]:
        """Read one message from the counterparty, exactly as received. Returns the rules it triggered.

        A request to pay a new or different address, an instruction to ignore the agent's rules, or a claim that
        the payment is pre-verified is remembered for the rest of the session (``SESSION_PAYEE_CHANGE_SEEN``).
        """
        try:
            hits = scan_payee_change(message, recipient=self.payee, sender=self.sender) + \
                [h for h in scan_payload_claims(message) if h.rule in _STICKY_CLAIMS]
        except Exception:
            hits = []
            rules = ["unreadable_message"]
        else:
            rules = [h.rule for h in hits]
        with self._lock:
            self.messages_seen += 1
            for i, r in enumerate(rules):
                match = hits[i].match if hits else ""
                self.warnings.append({"message": str(self.messages_seen), "rule": r, "match": str(match)[:120]})
        return rules

    # ------------------------------------------------------------------ what the principal decides

    def amend(self, *, by: str, reason: str, payee: Optional[str] = None, amount: Optional[float] = None,
              token: Optional[str] = None, chain_id: Optional[int] = None, clear_warnings: bool = False) -> None:
        """Change the agreed terms. Call this only on the principal's instruction, never on the counterparty's.

        ``by`` and ``reason`` are recorded with the old and new values. ``clear_warnings=True`` forgets earlier
        redirect requests, for when the principal has confirmed the new payee through a trusted channel.
        """
        if not isinstance(by, str) or not by.strip() or not isinstance(reason, str) or not reason.strip():
            raise ValueError("amend needs who made the change (by) and why (reason)")
        new = {}
        if payee is not None:
            new["payee"] = _addr("payee", payee)
        if amount is not None:
            new["amount"] = _pos("amount", amount)
        if token is not None:
            if not isinstance(token, str) or not token.strip():
                raise ValueError("token must be a symbol such as 'USDC'")
            new["token"] = token.strip().upper()
        if chain_id is not None:
            if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
                raise ValueError("chain_id must be a positive integer")
            new["chain_id"] = chain_id
        if not new and not clear_warnings:
            raise ValueError("amend changed nothing")
        with self._lock:
            old = {k: getattr(self, k) for k in new}
            for k, v in new.items():
                setattr(self, k, v)
            self.amendments.append({"by": by.strip(), "reason": reason.strip(), "old": old, "new": new,
                                    "cleared_warnings": bool(clear_warnings)})
            if clear_warnings:
                self.warnings = []

    def close(self) -> None:
        """No further payments in this session (``SESSION_CLOSED``)."""
        with self._lock:
            self.closed = True

    def release(self) -> bool:
        """Forget the most recent approved payment, for one that was approved but never sent. True if one was."""
        with self._lock:
            if not self.approved:
                return False
            self.approved.pop()
            return True

    # ------------------------------------------------------------------ the check

    def _drift(self, sender: Any, recipient: Any, amount: Any, chain_id: Any, token: Any) -> List[tuple]:
        out = []
        if self.closed:
            out.append(("SESSION_CLOSED", "The negotiation session is closed."))
        if not isinstance(recipient, str) or recipient.strip().lower() != self.payee.lower():
            out.append(("SESSION_PAYEE_DRIFT", f"The recipient is not the payee agreed in this session "
                                               f"({self.payee})."))
        limit = self.amount * (1 + self.tolerance_pct / 100)
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(amount) \
                or amount > limit + 1e-9:
            out.append(("SESSION_AMOUNT_DRIFT", f"The amount is above the {self.amount:g} {self.token} agreed in "
                                                f"this session" + (f" (+{self.tolerance_pct:g}%)." if self.tolerance_pct
                                                                   else ".")))
        tok = token.strip().upper() if isinstance(token, str) else token
        if chain_id != self.chain_id or tok != self.token:
            out.append(("SESSION_ASSET_DRIFT", f"The payment is not in {self.token} on chain {self.chain_id}, as "
                                               "agreed in this session."))
        if self.sender is not None and (not isinstance(sender, str) or sender.strip().lower() != self.sender.lower()):
            out.append(("SESSION_ASSET_DRIFT", "The payment is not from the wallet agreed in this session."))
        if self.warnings:
            rules = ", ".join(sorted({w["rule"] for w in self.warnings}))
            out.append(("SESSION_PAYEE_CHANGE_SEEN", f"Earlier in this session the other side asked to change where "
                                                     f"the money goes, or to bypass the checks ({rules}). Confirm "
                                                     "the payee through a channel you already trust."))
        if len(self.approved) >= self.max_payments:
            out.append(("SESSION_ALREADY_PAID", f"This session already approved {len(self.approved)} payment(s)."))
        return out

    def check(self, *, sender: str, recipient: str, amount: float, chain_id: Optional[int] = None,
              token: Optional[str] = None, **check_kwargs: Any) -> RiskAssessment:
        """``check_payment`` plus the session's terms. ``chain_id`` and ``token`` default to the agreed ones.

        Any other keyword (``known_recipients``, ``spend_guard``, ``untrusted_request``, a policy's ``kwargs()``)
        is passed to ``check_payment``. An approved payment counts towards ``max_payments``.
        """
        try:
            with self._lock:
                cid = self.chain_id if chain_id is None else chain_id
                tok = self.token if token is None else token
                base = check_payment(chain_id=cid, sender=sender, recipient=recipient, amount=amount, token=tok,
                                     **check_kwargs)
                drift = self._drift(sender, recipient, amount, cid, tok)
                if not drift:
                    if base.decision == ActionDecision.APPROVE:
                        self.approved.append({"recipient": recipient, "amount": float(amount), "token": str(tok),
                                              "chain_id": cid})
                    return base
                flags, seen = [], set()
                for f, _ in drift:
                    if f not in seen:
                        flags.append(f)
                        seen.add(f)
                flags += [f for f in base.flags if f not in seen]
                why = " ".join(dict.fromkeys(w for _, w in drift))
                if base.decision == ActionDecision.REJECT:
                    return _verdict(ActionDecision.REJECT, flags, base.explanation + " Also: " + why,
                                    list(base.required_actions or []))
                if base.decision == ActionDecision.HOLD:
                    why += " Also: " + base.explanation
                return _verdict(ActionDecision.HOLD, flags, why, ["manual_review"])
        except Exception as e:  # fail closed
            return _verdict(ActionDecision.HOLD, ["CHECK_FAILED"],
                            f"The session check failed ({type(e).__name__}), so the payment is held.", ["manual_review"])

    def summary(self) -> Dict[str, Any]:
        """The session's terms and history, JSON-safe: pass it as part of ``payment=`` to bind it into a receipt."""
        with self._lock:
            return {"session_id": self.session_id, "payee": self.payee, "amount": self.amount, "token": self.token,
                    "chain_id": self.chain_id, "tolerance_pct": self.tolerance_pct,
                    "max_payments": self.max_payments, "approved_payments": len(self.approved),
                    "messages_seen": self.messages_seen, "warnings": [dict(w) for w in self.warnings],
                    "amendments": [dict(a) for a in self.amendments], "closed": self.closed}
