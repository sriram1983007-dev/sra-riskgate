"""Address screening from outside providers, folded into ``check_payment`` (1.4.0+).

The bundled OFAC snapshot is an exact match against a dated list. Screening providers add what it cannot:
fresher sanctions data, attribution (hacks, scams, mixers) and exposure through the address's history. Each
adapter turns one provider's answer into a ``ScreeningResult``; ``check_payment(screening_providers=[...])``
then applies one policy to all of them:

- a sanctions match from any provider gives REJECT (``PROVIDER_SANCTIONS_MATCH``);
- risk at or above ``screening_reject_at`` (default ``severe``) gives REJECT, at or above ``screening_hold_at``
  (default ``high``) gives HOLD;
- a provider that errors, times out or answers in an unexpected shape gives HOLD (``SCREENING_UNAVAILABLE``):
  no answer is never treated as a clean answer.

Built in: ``ChainalysisSanctions`` (Chainalysis's free sanctions API), ``TRMSanctions`` (TRM Labs' free sanctions
API, 1.5.0+), ``RangeRisk`` (Range Risk API v2) and ``WebacyRisk`` (Webacy address risk). Anything else plugs in
through ``CallableProvider``.
Screening sends the sender's and recipient's addresses to the provider; nothing else leaves your process.
No API keys are bundled; you need an account with each provider.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional, Protocol

RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "severe": 4}

# (status, parsed JSON or None). Injected in tests; the default uses urllib with a timeout.
HttpGet = Callable[[str, Mapping[str, str], float], "tuple[int, Any]"]


def _urllib_get(url: str, headers: Mapping[str, str], timeout: float) -> "tuple[int, Any]":
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sra-riskgate", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URLs)
            body = resp.read()
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except ValueError:
            return e.code, None


HttpPost = Callable[[str, Mapping[str, str], Any, float], "tuple[int, Any]"]


def _urllib_post(url: str, headers: Mapping[str, str], body: Any, timeout: float) -> "tuple[int, Any]":
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Accept": "application/json", "Content-Type": "application/json", "User-Agent": "sra-riskgate", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except ValueError:
            return e.code, None


@dataclass
class ScreeningResult:
    """One provider's answer about one address. ``sanctioned`` and ``risk`` are None when unknown;
    ``error`` is set when there is no usable answer."""

    provider: str
    address: str
    sanctioned: Optional[bool] = None
    risk: Optional[str] = None  # none | low | medium | high | severe
    reasons: list = field(default_factory=list)
    error: Optional[str] = None
    raw: Any = None

    @property
    def ok(self) -> bool:
        return self.error is None and (self.sanctioned is not None or self.risk is not None)


class ScreeningProvider(Protocol):
    name: str

    def screen(self, address: str, chain_id: int) -> ScreeningResult: ...


def _fail(name: str, address: str, why: str, raw: Any = None) -> ScreeningResult:
    return ScreeningResult(provider=name, address=address, error=why, raw=raw)


class _HttpProvider:
    name = "provider"

    def __init__(self, api_key: str, *, timeout: float = 10.0, http_get: Optional[HttpGet] = None):
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError(f"{type(self).__name__} needs a non-empty api_key")
        self.api_key = api_key.strip()
        self.timeout = float(timeout)
        self._get = http_get or _urllib_get

    def _call(self, address: str, url: str, headers: Mapping[str, str]):
        try:
            return self._get(url, headers, self.timeout), None
        except Exception as e:  # network errors, timeouts, bad JSON: no answer
            return None, f"request failed ({type(e).__name__})"


class ChainalysisSanctions(_HttpProvider):
    """Chainalysis's free sanctions screening API (``GET /api/v1/address/{address}``, header ``X-API-Key``).

    An address with any ``identifications`` is sanctioned; an empty list is clean. Get a free key from
    Chainalysis. It reports sanctions only, so it never sets a risk level other than ``severe`` or ``none``."""

    name = "chainalysis"
    BASE_URL = "https://public.chainalysis.com/api/v1/address/"

    def screen(self, address: str, chain_id: int) -> ScreeningResult:
        out, err = self._call(address, self.BASE_URL + urllib.parse.quote(address), {"X-API-Key": self.api_key})
        if err:
            return _fail(self.name, address, err)
        status, body = out
        if status != 200 or not isinstance(body, Mapping) or not isinstance(body.get("identifications"), list):
            return _fail(self.name, address, f"unexpected response (HTTP {status})", body)
        ids = body["identifications"]
        reasons = [str(i.get("name") or i.get("category") or "sanctions") for i in ids if isinstance(i, Mapping)]
        return ScreeningResult(self.name, address, sanctioned=bool(ids), risk="severe" if ids else "none",
                               reasons=reasons or (["sanctions"] if ids else []), raw=body)


class RangeRisk(_HttpProvider):
    """Range Risk API v2 (``GET https://api.range.org/v2/risk/address``, ``Authorization: Bearer <key>``).

    Uses Range's ``severity`` (none to severe) as the risk level. Any triggered attribution signal for a
    government sanctions list is a sanctions match, whatever severity your Range workspace gives it: every
    signal id containing ``sanction`` (``ofac-sanctioned``, ``uk-sanctioned``, ``eu-sanctioned``,
    ``eu-sanction-ru``, ``france-sanctioned``, ``japan-sanctioned``, ``sanctioned``...) and
    ``nbctf-terror-financing``. Exposure signals (indirect flows) are reported as reasons and count through
    ``severity``, not as direct matches."""

    name = "range"
    BASE_URL = "https://api.range.org/v2/risk/address"

    def screen(self, address: str, chain_id: int) -> ScreeningResult:
        url = self.BASE_URL + "?" + urllib.parse.urlencode({"address": address})
        out, err = self._call(address, url, {"Authorization": f"Bearer {self.api_key}"})
        if err:
            return _fail(self.name, address, err)
        status, body = out
        sev = body.get("severity") if isinstance(body, Mapping) else None
        if status != 200 or sev not in RISK_ORDER:
            return _fail(self.name, address, f"unexpected response (HTTP {status})", body)
        triggered = ((body.get("attribution") or {}).get("triggered") or []) if isinstance(body.get("attribution"), Mapping) else []
        sanctions = [t for t in triggered if isinstance(t, Mapping) and t.get("result") is True
                     and _is_sanctions_signal(t.get("signal"))]
        reasons = [str(t.get("signal")) for t in triggered if isinstance(t, Mapping) and t.get("result") is True]
        exposure = (body.get("exposure") or {}).get("triggered") if isinstance(body.get("exposure"), Mapping) else None
        reasons += [f"exposure: {e.get('signal')} {e.get('percentage', '')}".strip() for e in exposure or []
                    if isinstance(e, Mapping) and e.get("result") is True]
        behaviours = (body.get("behaviour") or {}).get("detected") if isinstance(body.get("behaviour"), Mapping) else None
        reasons += [str(b.get("behaviour")) for b in behaviours or [] if isinstance(b, Mapping) and not b.get("ignored")]
        return ScreeningResult(self.name, address, sanctioned=bool(sanctions), risk=sev, reasons=reasons, raw=body)


def _is_sanctions_signal(signal: Any) -> bool:
    s = str(signal or "").strip().lower()
    return "sanction" in s or s == "nbctf-terror-financing"


class WebacyRisk(_HttpProvider):
    """Webacy address risk (``GET https://api.webacy.com/addresses/{address}?chain=...``, header ``x-api-key``).

    A ``sanctioned`` flag in ``details.address_info`` is a sanctions match. Otherwise the risk level comes from
    Webacy's own issue counts: any high-severity issue gives ``high``, any medium one ``medium``, else ``low``.
    A 202 (analysis still running) is treated as no answer."""

    name = "webacy"
    BASE_URL = "https://api.webacy.com/addresses/"
    CHAINS = {1: "eth", 8453: "base", 137: "pol", 42161: "arb", 56: "bsc", 10: "opt"}

    def screen(self, address: str, chain_id: int) -> ScreeningResult:
        chain = self.CHAINS.get(chain_id)
        if chain is None:
            return _fail(self.name, address, f"chain {chain_id} is not mapped for Webacy")
        url = self.BASE_URL + urllib.parse.quote(address) + "?" + urllib.parse.urlencode({"chain": chain})
        out, err = self._call(address, url, {"x-api-key": self.api_key})
        if err:
            return _fail(self.name, address, err)
        status, body = out
        if status != 200 or not isinstance(body, Mapping) or not isinstance(body.get("high"), int):
            return _fail(self.name, address, f"unexpected response (HTTP {status})", body)
        info = (body.get("details") or {}).get("address_info") or {} if isinstance(body.get("details"), Mapping) else {}
        sanctioned = info.get("sanctioned") is True
        risk = "severe" if sanctioned else "high" if body["high"] > 0 else "medium" if body.get("medium", 0) > 0 else "low"
        reasons = [f"overallRisk {body['overallRisk']}"] if isinstance(body.get("overallRisk"), (int, float)) else []
        for issue in body.get("issues") or []:
            for tag in (issue.get("tags") or []) if isinstance(issue, Mapping) else []:
                if isinstance(tag, Mapping) and tag.get("name"):
                    reasons.append(str(tag["name"]))
        return ScreeningResult(self.name, address, sanctioned=sanctioned, risk=risk, reasons=reasons, raw=body)


class TRMSanctions:
    """TRM Labs' free sanctions screening API (``POST https://api.trmlabs.com/public/v1/sanctions/screening``).

    Sends ``[{"address": ...}]`` and reads ``isSanctioned`` for the matching address. With an API key it uses
    HTTP Basic auth (the key as both user name and password); without one (``TRMSanctions()``) it sends no
    credentials, for TRM's free keyless access. If TRM requires a key and none is given, every check returns no
    answer and the payment is held. TRM sends its full documentation and a key after a sign-up form;
    if your key or TRM's answer does not match this shape, every check returns no answer, which holds the payment
    (fail closed) rather than passing it. Sanctions only: the risk level is ``severe`` or ``none``."""

    name = "trm"
    URL = "https://api.trmlabs.com/public/v1/sanctions/screening"

    def __init__(self, api_key: Optional[str] = None, *, timeout: float = 10.0, http_post: Optional[HttpPost] = None):
        if api_key is not None and (not isinstance(api_key, str) or not api_key.strip()):
            raise ValueError("TRMSanctions api_key must be a non-empty string, or omitted for keyless access")
        import base64
        key = api_key.strip() if api_key else None
        self._headers = {"Authorization": "Basic " + base64.b64encode(f"{key}:{key}".encode()).decode()} if key else {}
        self.timeout = float(timeout)
        self._post = http_post or _urllib_post

    def screen(self, address: str, chain_id: int) -> ScreeningResult:
        try:
            status, body = self._post(self.URL, dict(self._headers), [{"address": address}], self.timeout)
        except Exception as e:
            return _fail(self.name, address, f"request failed ({type(e).__name__})")
        if status not in (200, 201) or not isinstance(body, list):
            return _fail(self.name, address, f"unexpected response (HTTP {status})", body)
        match = [r for r in body if isinstance(r, Mapping) and str(r.get("address", "")).lower() == address.lower()]
        if len(match) != 1 or not isinstance(match[0].get("isSanctioned"), bool):
            return _fail(self.name, address, "no isSanctioned answer for this address", body)
        hit = match[0]["isSanctioned"]
        return ScreeningResult(self.name, address, sanctioned=hit, risk="severe" if hit else "none",
                               reasons=["sanctions (TRM)"] if hit else [], raw=body)


class CallableProvider:
    """Wrap your own lookup (TRM Labs, an internal list, another vendor) as a provider.

    ``fn(address, chain_id)`` returns a mapping with ``sanctioned`` (bool) and/or ``risk`` (none..severe) and
    optional ``reasons``; anything else, or an exception, counts as no answer (HOLD)."""

    def __init__(self, name: str, fn: Callable[[str, int], Any]):
        if not isinstance(name, str) or not name.strip() or not callable(fn):
            raise ValueError("CallableProvider needs a name and a callable")
        self.name, self._fn = name.strip(), fn

    def screen(self, address: str, chain_id: int) -> ScreeningResult:
        try:
            out = self._fn(address, chain_id)
        except Exception as e:
            return _fail(self.name, address, f"provider raised {type(e).__name__}")
        if not isinstance(out, Mapping):
            return _fail(self.name, address, "provider returned no mapping", out)
        sanctioned, risk = out.get("sanctioned"), out.get("risk")
        if sanctioned is not None and not isinstance(sanctioned, bool):
            return _fail(self.name, address, "sanctioned must be true or false", out)
        if risk is not None and risk not in RISK_ORDER:
            return _fail(self.name, address, f"risk must be one of {', '.join(RISK_ORDER)}", out)
        if sanctioned is None and risk is None:
            return _fail(self.name, address, "provider gave neither sanctioned nor risk", out)
        reasons = out.get("reasons") or []
        return ScreeningResult(self.name, address, sanctioned=sanctioned, risk=risk,
                               reasons=[str(r) for r in reasons] if isinstance(reasons, list) else [], raw=out)


def screen_addresses(providers: Iterable[ScreeningProvider], addresses: Iterable[str], chain_id: int) -> list:
    """Every provider's ``ScreeningResult`` for every address, in order. Never raises."""
    results = []
    for p in providers:
        for a in addresses:
            try:
                r = p.screen(a, chain_id)
                if not isinstance(r, ScreeningResult):
                    r = _fail(getattr(p, "name", type(p).__name__), a, "provider returned no ScreeningResult")
            except Exception as e:
                r = _fail(getattr(p, "name", type(p).__name__), a, f"provider raised {type(e).__name__}")
            results.append(r)
    return results


def screening_decision(results: Iterable[ScreeningResult], *, hold_at: str = "high", reject_at: str = "severe"):
    """``(decision, flags, explanation)`` for a set of results, or None if all are clean.
    ``decision`` is "reject" or "hold"."""
    if hold_at not in RISK_ORDER or reject_at not in RISK_ORDER or RISK_ORDER[hold_at] > RISK_ORDER[reject_at]:
        raise ValueError("screening_hold_at and screening_reject_at must be none..severe, hold_at <= reject_at")
    rejects, holds, flags = [], [], []
    for r in results:
        who = f"{r.provider} on {r.address[:10]}…"
        if r.sanctioned:
            rejects.append(f"{who}: sanctions match ({', '.join(r.reasons[:2]) or 'sanctions'})")
            flags.append("PROVIDER_SANCTIONS_MATCH")
        elif not r.ok:
            holds.append(f"{who}: no answer ({r.error or 'empty result'})")
            flags.append("SCREENING_UNAVAILABLE")
        elif r.risk is not None and RISK_ORDER[r.risk] >= RISK_ORDER[reject_at]:
            rejects.append(f"{who}: {r.risk} risk ({', '.join(r.reasons[:2]) or 'no detail'})")
            flags.append("PROVIDER_RISK_SEVERE")
        elif r.risk is not None and RISK_ORDER[r.risk] >= RISK_ORDER[hold_at]:
            holds.append(f"{who}: {r.risk} risk ({', '.join(r.reasons[:2]) or 'no detail'})")
            flags.append("PROVIDER_RISK_HIGH")
    flags = list(dict.fromkeys(flags))
    if rejects:
        return "reject", flags, "Address screening: " + "; ".join(rejects + holds)
    if holds:
        return "hold", flags, "Address screening: " + "; ".join(holds)
    return None
