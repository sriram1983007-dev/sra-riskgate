"""One policy file for every check (1.8.0+): limits, payees, tokens, screening, budgets and anomaly rules.

A team keeps its payment rules in one reviewed file instead of in each agent's code:

    policy = load_policy("payment-policy.json")         # or .yaml / .yml (needs PyYAML), or a dict
    result = check_payment(chain_id=8453, sender=a, recipient=b, amount=5, **policy.check_kwargs())
    result = check_transaction(tx, **policy.check_kwargs())   # the same kwargs work for every check_* function

Example (every key optional except ``version``)::

    {
      "version": 1,
      "name": "treasury-agents",
      "max_amount": 250,
      "depeg_hold_pct": 1.0, "depeg_reject_pct": 5.0,
      "allowed_tokens": ["USDC", "USDT"],
      "known_recipients": ["0x..."], "blocked_addresses": ["0x..."], "expected_delegates": [],
      "lookalike_check": "strict",
      "screening": {
        "providers": [{"type": "chainalysis", "api_key_env": "CHAINALYSIS_API_KEY"},
                      {"type": "trm"},
                      {"type": "elliptic", "api_key_env": "ELLIPTIC_KEY", "api_secret_env": "ELLIPTIC_SECRET",
                       "high_risk_score": 5, "severe_risk_score": 10}],
        "hold_at": "high", "reject_at": "severe", "timeout": 10
      },
      "budgets": {"window_hours": 24, "total": 1000, "per_payee": 200},
      "anomalies": {"max_payments_per_hour": 60, "amount_spike_factor": 5, "min_history": 5},
      "ledger": "~/.sra-riskgate/ledger.jsonl"
    }

Rules that keep a policy file safe:
- API keys never go in the file: name the environment variable that holds them (``api_key_env``). A literal
  ``api_key`` field is refused, and a named variable that is unset is a configuration error.
- Unknown keys are refused, so a typo (``max_ammount``) cannot silently drop a limit.
- ``policy.sha256`` is the hash of the file's content; pass ``policy=policy`` to ``issue_receipt`` to bind it.
"""
from __future__ import annotations

import json
import math
import os
from typing import Any, Mapping, Optional

from sra_riskgate.receipts import policy_hash

__all__ = ["Policy", "load_policy"]

_TOP = {"version", "name", "max_amount", "depeg_hold_pct", "depeg_reject_pct", "allowed_tokens", "known_recipients",
        "blocked_addresses", "expected_delegates", "lookalike_check", "new_counterparty", "screening", "budgets",
        "anomalies", "ledger"}
_PROVIDER_KEYS = {
    "chainalysis": {"type", "api_key_env"},
    "trm": {"type", "api_key_env"},
    "range": {"type", "api_key_env"},
    "webacy": {"type", "api_key_env", "high_risk_score"},
    "elliptic": {"type", "api_key_env", "api_secret_env", "high_risk_score", "severe_risk_score", "unseen_is_clean"},
}
_NEEDS_KEY = {"chainalysis", "range", "webacy", "elliptic"}


def _num(where: str, v: Any, *, positive: bool = True) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or (positive and v <= 0):
        raise ValueError(f"{where} must be a {'positive ' if positive else ''}number")
    return float(v)


def _only(where: str, d: Any, allowed: set) -> Mapping:
    if not isinstance(d, Mapping):
        raise ValueError(f"{where} must be an object")
    extra = sorted(set(d) - allowed)
    if extra:
        hint = " (put API keys in environment variables and name them with api_key_env)" \
            if any(k in ("api_key", "api_secret", "key", "secret") for k in extra) else ""
        raise ValueError(f"{where}: unknown key(s) {', '.join(extra)}{hint}")
    return d


def _strs(where: str, v: Any) -> list:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{where} must be a list of strings")
    return list(v)


class Policy:
    """A validated policy. Build it with ``load_policy``."""

    def __init__(self, data: Mapping, source: Optional[str] = None):
        self._data = json.loads(json.dumps(data))  # a private, JSON-plain copy
        self.source = source
        self.sha256 = policy_hash(self._data)
        self._guard = None
        self._validate()

    def as_dict(self) -> dict:
        return json.loads(json.dumps(self._data))

    @property
    def name(self) -> Optional[str]:
        return self._data.get("name")

    def _validate(self) -> None:
        d = _only("policy", self._data, _TOP)
        if d.get("version") != 1:
            raise ValueError("policy version must be 1")
        if "name" in d and not isinstance(d["name"], str):
            raise ValueError("policy name must be a string")
        for k in ("max_amount", "depeg_hold_pct", "depeg_reject_pct"):
            if k in d:
                _num(k, d[k])
        for k in ("allowed_tokens", "known_recipients", "blocked_addresses", "expected_delegates"):
            if k in d:
                _strs(k, d[k])
        if "lookalike_check" in d:
            from sra_riskgate.counterparty import parse_lookalike_check
            parse_lookalike_check(d["lookalike_check"])
        if "new_counterparty" in d:
            from sra_riskgate.counterparty import parse_new_counterparty
            parse_new_counterparty(d["new_counterparty"])
        if "ledger" in d and (not isinstance(d["ledger"], str) or not d["ledger"].strip()):
            raise ValueError("ledger must be a file path")
        if "screening" in d:
            s = _only("screening", d["screening"], {"providers", "hold_at", "reject_at", "timeout"})
            provs = s.get("providers")
            if not isinstance(provs, list) or not provs:
                raise ValueError("screening.providers must be a non-empty list")
            for i, p in enumerate(provs):
                if not isinstance(p, Mapping) or p.get("type") not in _PROVIDER_KEYS:
                    raise ValueError(f"screening.providers[{i}].type must be one of {', '.join(sorted(_PROVIDER_KEYS))}")
                _only(f"screening.providers[{i}]", p, _PROVIDER_KEYS[p["type"]])
                if p["type"] in _NEEDS_KEY and not p.get("api_key_env"):
                    raise ValueError(f"screening.providers[{i}] ({p['type']}) needs api_key_env")
                if p["type"] == "elliptic" and not p.get("api_secret_env"):
                    raise ValueError(f"screening.providers[{i}] (elliptic) needs api_secret_env")
                for k in ("api_key_env", "api_secret_env"):
                    if k in p and (not isinstance(p[k], str) or not p[k].strip()):
                        raise ValueError(f"screening.providers[{i}].{k} must name an environment variable")
            if "timeout" in s:
                _num("screening.timeout", s["timeout"])
            from sra_riskgate.screening import screening_decision
            screening_decision([], hold_at=s.get("hold_at", "high"), reject_at=s.get("reject_at", "severe"))
        if "budgets" in d:
            b = _only("budgets", d["budgets"], {"window_hours", "total", "per_payee"})
            for k in b:
                _num(f"budgets.{k}", b[k])
            if not ({"total", "per_payee"} & set(b)):
                raise ValueError("budgets needs total or per_payee")
        if "anomalies" in d:
            a = _only("anomalies", d["anomalies"], {"max_payments_per_hour", "amount_spike_factor", "min_history"})
            for k in a:
                _num(f"anomalies.{k}", a[k])
            if not ({"max_payments_per_hour", "amount_spike_factor"} & set(a)):
                raise ValueError("anomalies needs max_payments_per_hour or amount_spike_factor")
        if ("budgets" in d or "anomalies" in d):
            self._build_guard()  # validates the numbers the way SpendGuard will use them

    def _build_guard(self):
        if self._guard is None:
            from sra_riskgate.spend import SpendGuard, SpendLedger
            b, a = self._data.get("budgets", {}), self._data.get("anomalies", {})
            self._guard = SpendGuard(
                SpendLedger(self._data.get("ledger")),
                total_limit=b.get("total"), per_payee_limit=b.get("per_payee"),
                window_seconds=float(b.get("window_hours", 24)) * 3600,
                max_payments_per_hour=a.get("max_payments_per_hour"),
                amount_spike_factor=a.get("amount_spike_factor"), spike_min_history=a.get("min_history", 5))
        return self._guard

    @property
    def spend_guard(self):
        """The policy's ``SpendGuard`` (one per ``Policy``, so every check shares its ledger), or ``None``."""
        return self._build_guard() if ("budgets" in self._data or "anomalies" in self._data) else None

    def screening_providers(self, env: Optional[Mapping[str, str]] = None) -> list:
        """Provider objects, with keys read from ``env`` (default ``os.environ``). An unset variable raises."""
        from sra_riskgate.screening import ChainalysisSanctions, EllipticRisk, RangeRisk, TRMSanctions, WebacyRisk
        env = os.environ if env is None else env
        s = self._data.get("screening")
        if not s:
            return []
        timeout = float(s.get("timeout", 10))

        def var(p, k):
            name = p[k]
            v = env.get(name)
            if v is None or not str(v).strip():
                raise ValueError(f"environment variable {name} (named by the policy for {p['type']}) is not set")
            return v

        out = []
        for p in s["providers"]:
            t = p["type"]
            if t == "chainalysis":
                out.append(ChainalysisSanctions(var(p, "api_key_env"), timeout=timeout))
            elif t == "trm":
                out.append(TRMSanctions(var(p, "api_key_env") if p.get("api_key_env") else None, timeout=timeout))
            elif t == "range":
                out.append(RangeRisk(var(p, "api_key_env"), timeout=timeout))
            elif t == "webacy":
                out.append(WebacyRisk(var(p, "api_key_env"), timeout=timeout,
                                      high_risk_score=p.get("high_risk_score", 50)))
            elif t == "elliptic":
                out.append(EllipticRisk(var(p, "api_key_env"), var(p, "api_secret_env"), timeout=timeout,
                                        high_risk_score=p.get("high_risk_score", 5.0),
                                        severe_risk_score=p.get("severe_risk_score", 10.0),
                                        unseen_is_clean=bool(p.get("unseen_is_clean", False))))
        return out

    def check_kwargs(self, env: Optional[Mapping[str, str]] = None) -> dict:
        """Keyword arguments for ``check_payment`` and every other ``check_*`` function."""
        d, kw = self._data, {}
        for k in ("max_amount", "depeg_hold_pct", "depeg_reject_pct", "allowed_tokens", "known_recipients",
                  "blocked_addresses", "expected_delegates", "lookalike_check", "new_counterparty"):
            if k in d:
                kw[k] = d[k]
        if "screening" in d:
            kw["screening_providers"] = self.screening_providers(env)
            kw["screening_hold_at"] = d["screening"].get("hold_at", "high")
            kw["screening_reject_at"] = d["screening"].get("reject_at", "severe")
        if self.spend_guard is not None:
            kw["spend_guard"] = self.spend_guard
        return kw


def load_policy(source: Any) -> Policy:
    """A ``Policy`` from a JSON or YAML file path, or from a mapping. Invalid policies raise ``ValueError``."""
    if isinstance(source, Mapping):
        return Policy(source)
    path = os.path.expanduser(os.fspath(source))
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as e:  # pragma: no cover
            raise ImportError("YAML policies need PyYAML: pip install pyyaml (or use a .json policy)") from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return Policy(data, source=path)
