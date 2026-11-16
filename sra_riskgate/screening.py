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
API, 1.5.0+), ``RangeRisk`` (Range Risk API v2), ``WebacyRisk`` (Webacy address risk) and ``EllipticRisk``
(Elliptic Lens wallet screening, 1.7.0+). Anything else plugs in through ``CallableProvider``.
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
    # A str or bytes body is sent exactly as given (Elliptic signs the body text); anything else is JSON-encoded.
    data = body.encode() if isinstance(body, str) else body if isinstance(body, bytes) else json.dumps(body).encode()
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
    ``nbctf-terror-financing``. A triggered exposure signal for a sanctions list (funds that came from or went
    to a sanctioned address) is not a direct match, but raises the risk level to at least ``high``, so it holds by
    default whatever severity Range gave it (1.6.2+)."""

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
        hit_exposure = [e for e in exposure or [] if isinstance(e, Mapping) and e.get("result") is True]
        reasons += [f"exposure: {e.get('signal')} {e.get('percentage', '')}".strip() for e in hit_exposure]
        if any(_is_sanctions_signal(e.get("signal")) for e in hit_exposure) and RISK_ORDER[sev] < RISK_ORDER["high"]:
            sev = "high"
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
    ``overallRisk`` (0 to 100) also sets a floor, using Webacy's documented bands: above ``high_risk_score``
    (default 50, Webacy's "High Risk" is 50.1 to 100) gives at least ``high``, above ``medium_risk_score``
    (default 23, Webacy's "Medium Risk" is 23.1 to 50) at least ``medium``. Before 1.8.1 the default was 100.
    A 202 (analysis still running) is treated as no answer."""

    name = "webacy"
    BASE_URL = "https://api.webacy.com/addresses/"
    CHAINS = {1: "eth", 8453: "base", 137: "pol", 42161: "arb", 56: "bsc", 10: "opt"}

    def __init__(self, api_key: str, *, high_risk_score: float = 50, medium_risk_score: float = 23, **kw):
        super().__init__(api_key, **kw)
        for label, v in (("high_risk_score", high_risk_score), ("medium_risk_score", medium_risk_score)):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 100:
                raise ValueError(f"{label} must be a number from 0 to 100")
        if medium_risk_score > high_risk_score:
            raise ValueError("medium_risk_score must not be above high_risk_score")
        self.high_risk_score = float(high_risk_score)
        self.medium_risk_score = float(medium_risk_score)

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
        score = body.get("overallRisk")
        scored = isinstance(score, (int, float)) and not isinstance(score, bool)
        scored_high = scored and score > self.high_risk_score
        scored_medium = scored and score > self.medium_risk_score
        risk = ("severe" if sanctioned else "high" if body["high"] > 0 or scored_high
                else "medium" if body.get("medium", 0) > 0 or scored_medium else "low")
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


class EllipticRisk:
    """Elliptic Lens wallet screening (``POST https://aml-api.elliptic.co/v2/wallet/synchronous``, 1.7.0+).

    Sends ``{"subject": {"asset": "holistic", "blockchain": "holistic", "type": "address", "hash": address},
    "type": "wallet_exposure"}``, signed as Elliptic's API requires: headers ``x-access-key``,
    ``x-access-timestamp`` (milliseconds) and ``x-access-sign``, the Base64 HMAC-SHA256, keyed with the
    Base64-decoded secret, of timestamp + ``POST`` + lowercased path + the exact body text.

    Reading the answer:

    - Only ``process_status: "complete"`` is an answer; ``running`` or ``error`` (with ``error.message``) is not.
    - A sanctions match (the wallet's own cluster, not its exposure): a label in ``cluster_entities`` whose category
      mentions sanctions, or that carries ``is_after_sanction_date`` (set only for sanctioned entities); a matched
      element whose ``risk_triggers.is_sanctioned`` is true for the wallet's own entity; or, if present,
      ``entity_details`` listing sanctions (1.8.1+).
    - ``risk_score`` (0 to 10, from the risk rules in your Elliptic account) sets the level: at or above
      ``severe_risk_score`` (default 10) ``severe``, at or above ``high_risk_score`` (default 5) ``high``, any other
      positive score ``medium``, 0 ``low``. ``null`` means no risk rule triggered: ``none``. Set the two
      thresholds to match how your Elliptic rules score.
    - Exposure to a sanctions or terrorism-financing category in ``evaluation_detail``, or to any entity whose
      ``risk_triggers.is_sanctioned`` is true (funds from or to it), raises the level to at least ``high``, whatever
      the score. It is not a direct match, so it never
      rejects on its own.
    - HTTP 404 (Elliptic has never seen the address on chain) is no answer and holds the payment, unless
      ``unseen_is_clean=True``. A brand-new payee address is the case to think about.

    Holistic screening covers the chains Elliptic supports; for any other chain Elliptic answers with an error,
    which holds the payment. The response shape follows Elliptic's published OpenAPI specification (Wallet
    Analyses API 2.0.0); the tests use that shape, not live calls."""

    name = "elliptic"
    BASE_URL = "https://aml-api.elliptic.co"
    PATH = "/v2/wallet/synchronous"

    def __init__(self, api_key: str, api_secret: str, *, high_risk_score: float = 5.0,
                 severe_risk_score: float = 10.0, unseen_is_clean: bool = False, timeout: float = 10.0,
                 http_post: Optional[HttpPost] = None, clock: Optional[Callable[[], float]] = None):
        import base64
        import binascii
        import time
        for label, v in (("api_key", api_key), ("api_secret", api_secret)):
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"EllipticRisk needs a non-empty {label}")
        try:
            self._secret = base64.b64decode(api_secret.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("EllipticRisk api_secret must be the Base64 secret Elliptic issued") from None
        if not self._secret:
            raise ValueError("EllipticRisk api_secret must be the Base64 secret Elliptic issued")
        for label, v in (("high_risk_score", high_risk_score), ("severe_risk_score", severe_risk_score)):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(f"{label} must be a number")
        if not 0 < high_risk_score <= severe_risk_score <= 10:
            raise ValueError("need 0 < high_risk_score <= severe_risk_score <= 10")
        if not isinstance(unseen_is_clean, bool):
            raise ValueError("unseen_is_clean must be True or False")
        self.api_key = api_key.strip()
        self.high_risk_score, self.severe_risk_score = float(high_risk_score), float(severe_risk_score)
        self.unseen_is_clean = unseen_is_clean
        self.timeout = float(timeout)
        self._post = http_post or _urllib_post
        self._clock = clock or time.time

    def _headers(self, body_text: str) -> dict:
        import base64
        import hashlib
        import hmac
        ts = str(int(self._clock() * 1000))
        msg = ts + "POST" + self.PATH.lower() + body_text
        sig = base64.b64encode(hmac.new(self._secret, msg.encode(), hashlib.sha256).digest()).decode()
        return {"x-access-key": self.api_key, "x-access-sign": sig, "x-access-timestamp": ts}

    def screen(self, address: str, chain_id: int) -> ScreeningResult:
        body_text = json.dumps({"subject": {"asset": "holistic", "blockchain": "holistic", "type": "address",
                                            "hash": address}, "type": "wallet_exposure"}, separators=(",", ":"))
        try:
            status, body = self._post(self.BASE_URL + self.PATH, self._headers(body_text), body_text, self.timeout)
        except Exception as e:
            return _fail(self.name, address, f"request failed ({type(e).__name__})")
        if status == 404 and self.unseen_is_clean:
            return ScreeningResult(self.name, address, sanctioned=False, risk="none",
                                   reasons=["not seen on chain by Elliptic"], raw=body)
        if status != 200 or not isinstance(body, Mapping):
            return _fail(self.name, address, f"unexpected response (HTTP {status})", body)
        if body.get("process_status") != "complete":
            err = body.get("error")
            why = err.get("message") if isinstance(err, Mapping) and err.get("message") else body.get("process_status")
            return _fail(self.name, address, f"analysis not complete ({why})", body)
        score = body.get("risk_score")
        if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10):
            return _fail(self.name, address, "risk_score is not a number from 0 to 10", body)
        reasons, sanctioned = [], False
        own_ids, own_names = set(), set()
        for e in body.get("cluster_entities") or []:
            if not isinstance(e, Mapping):
                continue
            cat = str(e.get("category") or "")
            if e.get("entity_id"):
                own_ids.add(str(e["entity_id"]))
            if e.get("name"):
                own_names.add(str(e["name"]).strip().lower())
            if "sanction" in cat.lower():
                sanctioned = True
            # Elliptic sets is_after_sanction_date only for sanctioned entities (1.8.1+)
            if isinstance(e.get("is_after_sanction_date"), bool):
                sanctioned = True
                reasons.append(f"{e.get('name') or 'unnamed'} is a sanctioned entity")
            if e.get("name") or cat:
                reasons.append(f"{e.get('name') or 'unnamed'} ({cat or 'no category'})")
        if _elliptic_entity_details_sanctioned(body.get("entity_details")):
            sanctioned = True
            reasons.append("entity_details lists sanctions")
        exposed = False
        detail = body.get("evaluation_detail") if isinstance(body.get("evaluation_detail"), Mapping) else {}
        for side in ("source", "destination"):
            for rule in detail.get(side) or []:
                if not isinstance(rule, Mapping):
                    continue
                for m in rule.get("matched_elements") or []:
                    if not isinstance(m, Mapping):
                        continue
                    cat = str(m.get("category") or "")
                    if any(w in cat.lower() for w in ("sanction", "terror")):
                        exposed = True
                    # risk_triggers.is_sanctioned on a contributing entity (1.8.1+): exposure, or a direct match
                    # when that entity is the screened wallet's own cluster
                    for c in m.get("contributions") or []:
                        if not isinstance(c, Mapping):
                            continue
                        rt = c.get("risk_triggers")
                        if isinstance(rt, Mapping) and rt.get("is_sanctioned") is True:
                            exposed = True
                            who = str(rt.get("name") or c.get("entity") or "an entity")
                            mine = (c.get("entity_id") is not None and str(c["entity_id"]) in own_ids) or \
                                who.strip().lower() in own_names
                            if mine:
                                sanctioned = True
                            reasons.append(f"{side}: {who} is sanctioned" + (" (this wallet's own entity)" if mine else ""))
                    pct = m.get("contribution_percentage")
                    reasons.append(f"{side} exposure: {cat or 'uncategorised'}"
                                   + (f" {pct:g}%" if isinstance(pct, (int, float)) and not isinstance(pct, bool) else ""))
        if score is None:
            risk = "none"
        else:
            reasons.insert(0, f"risk_score {score:g}")
            risk = ("severe" if score >= self.severe_risk_score else "high" if score >= self.high_risk_score
                    else "medium" if score > 0 else "low")
        if sanctioned:
            risk = "severe"
        elif exposed and RISK_ORDER[risk] < RISK_ORDER["high"]:
            risk = "high"
        return ScreeningResult(self.name, address, sanctioned=sanctioned, risk=risk, reasons=reasons, raw=body)


def _elliptic_entity_details_sanctioned(details: Any) -> bool:
    """True if an ``entity_details`` object (or list of them) lists sanctions. Not in Elliptic's published schema;
    checked defensively because some responses carry it."""
    items = details if isinstance(details, list) else [details] if isinstance(details, Mapping) else []
    for d in items:
        if not isinstance(d, Mapping):
            continue
        s = d.get("sanctions")
        if s is True or (isinstance(s, (list, Mapping)) and len(s) > 0) or d.get("is_sanctioned") is True:
            return True
    return False


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
