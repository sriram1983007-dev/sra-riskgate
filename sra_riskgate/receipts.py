"""Signed decision receipts (1.8.0+): a tamper-evident record of every payment decision.

An auditor, a counterparty or your own back office can later prove what the gate decided, for which payment,
under which policy, and when, without trusting the log it came from:

    signer = ReceiptSigner.hmac(secret_bytes)                 # shared secret, standard library only
    signer = ReceiptSigner.ethereum(private_key)              # secp256k1; anyone can verify with your address
                                                              # (pip install "sra-riskgate[receipts]")
    result = check_payment(chain_id=8453, sender=a, recipient=b, amount=5)
    receipt = issue_receipt(result, signer, payment={"chain_id": 8453, "sender": a, "recipient": b, "amount": 5},
                            policy=my_policy)                 # optional: binds the policy's hash
    verify_receipt(receipt, key=secret_bytes)                 # or expected_signer="0x..." for Ethereum receipts

What a receipt holds (``v`` 1): the decision, risk score, flags and explanation; the payment fields you pass
(canonical JSON, plus its SHA-256); the SHA-256 of the policy if given; the issue time (UTC, seconds); the
library version; a random ``id``; and the signature over all of it. Change any field and verification fails.

Signatures:
- ``hmac-sha256``: HMAC-SHA256 with your secret over the canonical JSON. Anyone holding the secret can also
  create receipts, so it proves integrity to you, not to an outside party.
- ``eip191``: an Ethereum ``personal_sign`` (EIP-191) signature by your key over the canonical JSON's SHA-256 hex.
  Verification recovers the signer's address, so anyone who knows the address can check it, and nobody without the
  key can create one. Use a key that holds no funds and is used only for receipts.

A receipt proves what this gate decided. It does not prove the payment was sent or settled; use
``verify_settlement`` for that.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac as _hmac
import json
import math
import secrets
from typing import Any, Mapping, Optional

__all__ = ["ReceiptSigner", "issue_receipt", "verify_receipt", "canonical_json", "policy_hash"]

_SIG_FIELDS = ("alg", "signer", "sig")


def _plain(v: Any) -> Any:
    """JSON-safe copy: mappings with string keys, lists, str, int, finite float, bool, None. Anything else raises."""
    if isinstance(v, Mapping):
        out = {}
        for k, x in v.items():
            if not isinstance(k, str):
                raise ValueError("receipt fields must have string keys")
            out[k] = _plain(x)
        return out
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ValueError("receipt numbers must be finite")
        return v
    if v is None or isinstance(v, (str, int, bool)):
        return v
    if hasattr(v, "value") and isinstance(getattr(v, "value"), str):  # enums
        return v.value
    raise ValueError(f"cannot put a {type(v).__name__} in a receipt")


def canonical_json(obj: Any) -> str:
    """Sorted keys, no spaces, ASCII only: the exact text that is hashed and signed."""
    return json.dumps(_plain(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def policy_hash(policy: Any) -> str:
    """SHA-256 hex of a policy's canonical JSON (a mapping, or a ``Policy`` from ``load_policy``)."""
    data = policy.as_dict() if hasattr(policy, "as_dict") else policy
    return hashlib.sha256(canonical_json(data).encode()).hexdigest()


class ReceiptSigner:
    """Signs receipts. Build one with ``ReceiptSigner.hmac(key)`` or ``ReceiptSigner.ethereum(private_key)``."""

    def __init__(self, alg: str, signer_id: str, sign):
        self.alg, self.signer_id, self._sign = alg, signer_id, sign

    @classmethod
    def hmac(cls, key: bytes, key_id: str = "default") -> "ReceiptSigner":
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("the HMAC receipt key must be at least 16 bytes")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")
        k = bytes(key)
        return cls("hmac-sha256", key_id, lambda msg: _hmac.new(k, msg.encode(), hashlib.sha256).hexdigest())

    @classmethod
    def ethereum(cls, private_key: Any) -> "ReceiptSigner":
        try:
            from eth_account import Account
            from eth_account.messages import encode_defunct
        except ImportError as e:  # pragma: no cover - depends on the environment
            raise ImportError('Ethereum receipts need eth-account: pip install "sra-riskgate[receipts]"') from e
        acct = Account.from_key(private_key)

        def sign(msg: str) -> str:
            digest = hashlib.sha256(msg.encode()).hexdigest()
            return "0x" + acct.sign_message(encode_defunct(text=digest)).signature.hex().removeprefix("0x")

        return cls("eip191", acct.address, sign)


def issue_receipt(result: Any, signer: ReceiptSigner, *, payment: Optional[Mapping] = None, policy: Any = None,
                  now: Optional[_dt.datetime] = None) -> dict:
    """A signed receipt for a ``RiskAssessment`` (or any object or mapping with the same fields)."""
    if not isinstance(signer, ReceiptSigner):
        raise ValueError("signer must be a ReceiptSigner")
    r = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    from sra_riskgate import __version__
    body = {
        "v": 1,
        "id": secrets.token_hex(16),
        "issued_at": (now or _dt.datetime.now(_dt.timezone.utc)).astimezone(_dt.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "library": f"sra-riskgate {__version__}",
        "decision": _plain(r.get("decision")),
        "risk_score": r.get("risk_score"),
        "flags": list(r.get("flags") or []),
        "explanation": r.get("explanation", ""),
        "payment": _plain(dict(payment)) if payment is not None else None,
        "payment_sha256": hashlib.sha256(canonical_json(payment).encode()).hexdigest() if payment is not None else None,
        "policy_sha256": policy_hash(policy) if policy is not None else None,
        "alg": signer.alg,
        "signer": signer.signer_id,
    }
    body["sig"] = signer._sign(canonical_json(body))
    return body


def verify_receipt(receipt: Any, *, key: Optional[bytes] = None, expected_signer: Optional[str] = None) -> bool:
    """True only if the receipt is intact and signed by the expected party. Never raises on bad input.

    ``hmac-sha256`` receipts need ``key``; ``eip191`` receipts need ``expected_signer`` (the address).
    """
    try:
        if not isinstance(receipt, Mapping) or receipt.get("v") != 1 or not isinstance(receipt.get("sig"), str):
            return False
        body = {k: v for k, v in receipt.items() if k != "sig"}
        msg = canonical_json(body)
        p = receipt.get("payment")
        if p is not None and receipt.get("payment_sha256") != hashlib.sha256(canonical_json(p).encode()).hexdigest():
            return False
        if receipt.get("alg") == "hmac-sha256":
            if not isinstance(key, (bytes, bytearray)):
                return False
            want = _hmac.new(bytes(key), msg.encode(), hashlib.sha256).hexdigest()
            return _hmac.compare_digest(want, receipt["sig"])
        if receipt.get("alg") == "eip191":
            if not isinstance(expected_signer, str):
                return False
            from eth_account import Account
            from eth_account.messages import encode_defunct
            digest = hashlib.sha256(msg.encode()).hexdigest()
            who = Account.recover_message(encode_defunct(text=digest), signature=receipt["sig"])
            return who.lower() == expected_signer.lower() == str(receipt.get("signer", "")).lower()
        return False
    except Exception:
        return False
