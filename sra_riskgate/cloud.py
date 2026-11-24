"""SRA-RiskGate Cloud client (2.0.0+): shared budgets, a threat feed and a receipt vault, for agents on many machines.

The library stays free, offline and open source; nothing here runs unless you create a ``CloudClient``. The cloud
adds what one machine cannot do alone:

- **Shared budgets**: one spend ledger for every machine your agents run on, checked and updated atomically.
- **Threat feed**: look-alike addresses reported by poisoning scans across organisations, applied as a blocklist.
- **Receipt vault**: every cloud decision signed, chained and stored, with an audit report on demand.

    from sra_riskgate.cloud import CloudClient
    cloud = CloudClient()                     # SRA_CLOUD_URL and SRA_CLOUD_API_KEY from the environment
    r = cloud.check_payment(chain_id=8453, sender=agent, recipient=payee, amount=25, peg_deviation_pct=0.0,
                            untrusted_request=invoice_text, payment_id="inv-42")
    if r.approved:
        ...send the payment...
    else:
        cloud.release("inv-42")               # only if you approved and then did not send

How a check runs, and why it is safe to depend on:

1. ``check_payment`` runs **locally first**, with every argument you pass (text, policy, screening). The payment's
   free text never leaves your machine.
2. Only if the local check approves, the payment fields (chain, sender, payee, amount, token, payment id, known
   payees) go to the cloud, which runs the same library with your organisation's policy, the shared ledger and the
   threat feed, and returns a signed receipt.
3. The stricter decision wins. If the cloud cannot be reached, refuses the key or the plan's monthly limit is
   reached, the result is **hold** (``CLOUD_UNAVAILABLE``, ``CLOUD_AUTH_FAILED``, ``CLOUD_QUOTA_EXCEEDED``), never
   approve. ``on_cloud_error="local"`` uses the local decision instead, which keeps payments flowing but loses the
   shared budget for that payment: choose it knowingly.

Keep budgets in one place: with the cloud's shared budgets, do not also pass a local ``spend_guard`` (it would
record the payment locally even when the cloud then holds it).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from sra_riskgate.models import ActionDecision, RiskAssessment

__all__ = ["CloudClient", "CloudCheck", "CloudError"]

_ORDER = {ActionDecision.APPROVE: 0, ActionDecision.HOLD: 1, ActionDecision.REJECT: 2}
_PAYMENT_FIELDS = ("chain_id", "sender", "recipient", "amount", "token", "peg_deviation_pct", "payment_id")

Transport = Callable[[str, str, Optional[dict], Dict[str, str]], Tuple[int, Any]]


class CloudError(Exception):
    """The cloud answered with an error, or could not be reached. ``status`` is the HTTP status (0 if none)."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


@dataclass
class CloudCheck:
    """The combined decision. ``local`` is the on-machine result; ``cloud`` the service's answer (``None`` if not
    asked or not reached); ``receipt`` the cloud's signed receipt when there is one."""
    decision: ActionDecision
    risk_score: float
    flags: List[str]
    explanation: str
    required_actions: List[str]
    local: RiskAssessment
    cloud: Optional[Dict[str, Any]] = None
    receipt: Optional[Dict[str, Any]] = None
    usage: Optional[Dict[str, Any]] = field(default=None)

    @property
    def approved(self) -> bool:
        return self.decision == ActionDecision.APPROVE

    def assessment(self) -> RiskAssessment:
        return RiskAssessment(decision=self.decision, risk_score=self.risk_score, flags=self.flags,
                              explanation=self.explanation, required_actions=self.required_actions)


def _urllib_transport(base_url: str, timeout: float) -> Transport:
    def send(method: str, path: str, body: Optional[dict], headers: Dict[str, str]) -> Tuple[int, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(base_url + path, data=data, method=method,
                                     headers={**headers, "Content-Type": "application/json",
                                              "User-Agent": "sra-riskgate"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (configured service URL)
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        except (urllib.error.URLError, OSError) as e:
            raise CloudError(f"cloud unreachable: {e}") from e
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            return status, raw.decode("utf-8", "replace")
    return send


class CloudClient:
    """A client for SRA-RiskGate Cloud. ``base_url`` / ``api_key`` default to ``SRA_CLOUD_URL`` /
    ``SRA_CLOUD_API_KEY``. ``transport`` replaces HTTP (for tests or your own client)."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, *, timeout: float = 10.0,
                 on_cloud_error: str = "hold", transport: Optional[Transport] = None):
        self.api_key = api_key or os.environ.get("SRA_CLOUD_API_KEY")
        url = (base_url or os.environ.get("SRA_CLOUD_URL") or "").rstrip("/")
        if not self.api_key:
            raise ValueError("api_key is required (or set SRA_CLOUD_API_KEY)")
        if transport is None:
            if not url.startswith("https://") and not url.startswith("http://localhost") \
                    and not url.startswith("http://127.0.0.1"):
                raise ValueError("base_url must be an https:// URL (or http://localhost for testing); "
                                 "or set SRA_CLOUD_URL")
        if on_cloud_error not in ("hold", "local"):
            raise ValueError("on_cloud_error must be 'hold' or 'local'")
        self.base_url, self.on_cloud_error = url, on_cloud_error
        self._send = transport or _urllib_transport(url, timeout)

    # ------------------------------------------------------------ HTTP

    def _call(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        status, data = self._send(method, path, body, {"Authorization": f"Bearer {self.api_key}"})
        if status >= 400:
            detail = data.get("detail") if isinstance(data, dict) else data
            raise CloudError(f"cloud returned {status}: {detail}", status)
        return data

    # ------------------------------------------------------------ checks

    def check_payment(self, **kwargs: Any) -> CloudCheck:
        """``check_payment`` locally, then the cloud for shared budgets, the threat feed and a vault receipt.

        Takes every argument ``sra_riskgate.check_payment`` takes. Never raises on a cloud problem: see the module
        docstring for how each case is decided.
        """
        from sra_riskgate.check import check_payment
        local = check_payment(**kwargs)
        if local.decision != ActionDecision.APPROVE:
            return self._combine(local, None, [], "")
        body = {k: kwargs[k] for k in _PAYMENT_FIELDS if kwargs.get(k) is not None}
        body.setdefault("token", "USDC")
        known = kwargs.get("known_recipients")
        if known:
            body["known_recipients"] = list(known)
        try:
            cloud = self._call("POST", "/v1/check", body)
            if not isinstance(cloud, dict) or cloud.get("decision") not in ("approve", "hold", "reject"):
                raise CloudError("cloud answer has no decision")
        except CloudError as e:
            flag = ("CLOUD_QUOTA_EXCEEDED" if e.status == 429 else
                    "CLOUD_AUTH_FAILED" if e.status in (401, 403) else "CLOUD_UNAVAILABLE")
            if self.on_cloud_error == "local":
                return self._combine(local, None, [flag], "")
            return self._combine(local, None, [flag], f"The cloud check could not complete ({e}); held, since the "
                                                      "shared budget and threat feed were not applied.",
                                 force=ActionDecision.HOLD)
        except Exception as e:  # any other failure also fails closed
            return self._combine(local, None, ["CLOUD_UNAVAILABLE"], f"The cloud check failed ({type(e).__name__}).",
                                 force=ActionDecision.HOLD)
        return self._combine(local, cloud, [], "")

    @staticmethod
    def _combine(local: RiskAssessment, cloud: Optional[dict], extra_flags: List[str], note: str,
                 force: Optional[ActionDecision] = None) -> CloudCheck:
        decision, score = local.decision, local.risk_score
        flags = list(local.flags)
        actions = list(local.required_actions or [])
        expl = [local.explanation] if local.explanation else []
        if cloud is not None:
            cd = ActionDecision(cloud["decision"])
            if _ORDER[cd] > _ORDER[decision]:
                decision = cd
            score = max(score, float(cloud.get("risk_score") or 0.0))
            flags += [f for f in cloud.get("flags") or [] if f not in flags]
            actions += [a for a in cloud.get("required_actions") or [] if a not in actions]
            if cd != ActionDecision.APPROVE and cloud.get("explanation"):
                expl.append("Cloud: " + str(cloud["explanation"]))
        if force is not None and _ORDER[force] > _ORDER[decision]:
            decision, score = force, max(score, 0.5)
        flags += [f for f in extra_flags if f not in flags]
        if note:
            expl.append(note)
            if "retry_or_review" not in actions:
                actions.append("retry_or_review")
        return CloudCheck(decision=decision, risk_score=min(1.0, score), flags=flags, explanation=" ".join(expl),
                          required_actions=actions, local=local, cloud=cloud,
                          receipt=(cloud or {}).get("receipt"), usage=(cloud or {}).get("usage"))

    def release(self, payment_id: str) -> int:
        """Give back the budget of an approved payment that was never sent. Returns how many entries were removed."""
        return int(self._call("POST", "/v1/ledger/release", {"payment_id": payment_id})["released"])

    # ------------------------------------------------------------ feed, policy, vault

    def feed_addresses(self) -> List[str]:
        """The threat feed, for offline use as ``blocked_addresses``."""
        return list(self._call("GET", "/v1/feed")["addresses"])

    def report_scan(self, scan_result: Dict[str, Any]) -> int:
        """Report a ``scan_wallet`` result's findings to the threat feed. Returns how many were reported. An address
        enters the shared feed only after several organisations report it, or an operator reviews it."""
        n = 0
        for f in scan_result.get("findings") or []:
            tx = (f.get("transactions") or [{}])[0].get("tx")
            self._call("POST", "/v1/feed/report", {"address": f["address"], "imitates": f.get("imitates"),
                                                   "chain_id": scan_result.get("chain_id"), "tx": tx})
            n += 1
        return n

    def get_policy(self) -> Dict[str, Any]:
        return self._call("GET", "/v1/policy")

    def set_policy(self, policy: Any) -> Dict[str, Any]:
        """Set the organisation's policy (a mapping, or a path to a policy file). ``ledger`` and ``screening`` are
        refused: the cloud keeps the ledger, and screening keys stay on your machines."""
        if not isinstance(policy, dict):
            from sra_riskgate.policy import load_policy
            policy = load_policy(policy).as_dict()
        return self._call("PUT", "/v1/policy", policy)

    def receipts(self, after: int = 0, limit: int = 1000) -> List[Dict[str, Any]]:
        return list(self._call("GET", f"/v1/receipts?after={int(after)}&limit={int(limit)}")["receipts"])

    def report(self) -> Dict[str, Any]:
        """The audit report over the organisation's receipt vault (``sra_riskgate.audit_report``)."""
        return self._call("GET", "/v1/report")

    def usage(self) -> Dict[str, Any]:
        return self._call("GET", "/v1/usage")
