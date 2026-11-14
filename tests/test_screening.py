"""1.4.0: screening providers folded into check_payment, failing closed."""
import pytest

from sra_riskgate import (ActionDecision, CallableProvider, ChainalysisSanctions, RangeRisk, ScreeningResult,
                          WebacyRisk, check_payment, screen_addresses)

SENDER = "0x" + "1" * 39 + "a"
PAYEE = "0x" + "2" * 39 + "b"
BASE = dict(chain_id=8453, sender=SENDER, recipient=PAYEE, amount=5.0, check_sanctions=False)


class FakeHttp:
    def __init__(self, responses):
        self.responses, self.calls = responses, []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        r = self.responses(url) if callable(self.responses) else self.responses
        if isinstance(r, Exception):
            raise r
        return r


# ---- Chainalysis
def test_chainalysis_clean_and_sanctioned():
    hit_body = {"identifications": [{"category": "sanctions", "name": "SANCTIONS: OFAC SDN"}]}
    http = FakeHttp(lambda url: (200, hit_body) if PAYEE in url else (200, {"identifications": []}))
    p = ChainalysisSanctions("k", http_get=http)
    clean, hit = p.screen(SENDER, 8453), p.screen(PAYEE, 8453)
    assert clean.ok and clean.sanctioned is False and clean.risk == "none"
    assert hit.sanctioned is True and hit.risk == "severe" and "OFAC" in hit.reasons[0]
    url, headers = http.calls[0]
    assert url == "https://public.chainalysis.com/api/v1/address/" + SENDER and headers["X-API-Key"] == "k"


@pytest.mark.parametrize("resp", [(401, {"message": "bad key"}), (200, {}), (200, None), (200, {"identifications": "x"}),
                                  TimeoutError()])
def test_chainalysis_no_answer_is_an_error(resp):
    r = ChainalysisSanctions("k", http_get=FakeHttp(resp)).screen(SENDER, 8453)
    assert not r.ok and r.error


def test_providers_need_a_key():
    for cls in (ChainalysisSanctions, RangeRisk, WebacyRisk):
        with pytest.raises(ValueError):
            cls("  ")


# ---- Range
RANGE_OK = {"severity": "low", "attribution": {"triggered": []}, "behaviour": {"detected": []}}


def test_range_maps_severity_and_sanctions_signal():
    http = FakeHttp((200, {**RANGE_OK, "severity": "high",
                           "attribution": {"triggered": [{"signal": "sanctions_ofac", "severity": "severe", "result": True}]},
                           "behaviour": {"detected": [{"behaviour": "smurfing", "severity": "high", "confidence": 0.8}]}}))
    r = RangeRisk("k", http_get=http).screen(PAYEE, 8453)
    assert r.sanctioned is True and r.risk == "high" and "sanctions_ofac" in r.reasons and "smurfing" in r.reasons
    url, headers = http.calls[0]
    assert url.startswith("https://api.range.org/v2/risk/address?address=0x") and headers["X-API-KEY"] == "k"


def test_range_untriggered_sanctions_signal_is_not_a_match():
    r = RangeRisk("k", http_get=FakeHttp((200, {**RANGE_OK, "attribution": {"triggered": [
        {"signal": "sanctions_ofac", "severity": "severe", "result": False}]}}))).screen(PAYEE, 8453)
    assert r.ok and r.sanctioned is False and r.risk == "low"


def test_range_bad_severity_is_an_error():
    assert not RangeRisk("k", http_get=FakeHttp((200, {"severity": "critical"}))).screen(PAYEE, 8453).ok


# ---- Webacy
def webacy(high=0, medium=0, sanctioned=False):
    return (200, {"overallRisk": 10, "high": high, "medium": medium, "count": high + medium,
                  "issues": [{"tags": [{"name": "HACK"}]}] if high else [],
                  "details": {"address_info": {"sanctioned": sanctioned}}})


def test_webacy_levels_and_chain_mapping():
    http = FakeHttp(webacy(high=1))
    r = WebacyRisk("k", http_get=http).screen(PAYEE, 8453)
    assert r.risk == "high" and r.sanctioned is False and r.reasons == ["HACK"]
    assert http.calls[0][0].endswith("?chain=base") and http.calls[0][1]["x-api-key"] == "k"
    assert WebacyRisk("k", http_get=FakeHttp(webacy(medium=2))).screen(PAYEE, 1).risk == "medium"
    assert WebacyRisk("k", http_get=FakeHttp(webacy())).screen(PAYEE, 1).risk == "low"
    s = WebacyRisk("k", http_get=FakeHttp(webacy(sanctioned=True))).screen(PAYEE, 1)
    assert s.sanctioned is True and s.risk == "severe"


def test_webacy_pending_and_unmapped_chain_are_errors():
    assert not WebacyRisk("k", http_get=FakeHttp((202, {"status": "pending"}))).screen(PAYEE, 8453).ok
    assert not WebacyRisk("k", http_get=FakeHttp(webacy())).screen(PAYEE, 5042002).ok


# ---- CallableProvider (e.g. TRM Labs)
def test_callable_provider_validates_output():
    good = CallableProvider("trm", lambda a, c: {"sanctioned": False, "risk": "medium", "reasons": ["mixer"]})
    assert good.screen(PAYEE, 1).risk == "medium"
    for bad in [lambda a, c: None, lambda a, c: {"sanctioned": "no"}, lambda a, c: {"risk": "critical"},
                lambda a, c: {}, lambda a, c: 1 / 0]:
        assert not CallableProvider("x", bad).screen(PAYEE, 1).ok


# ---- check_payment policy
def prov(name="p", **kw):
    return CallableProvider(name, lambda a, c: kw.get("by_addr", {}).get(a, kw.get("default")))


def test_clean_screening_still_approves():
    r = check_payment(**BASE, screening_providers=[prov(default={"sanctioned": False, "risk": "low"})])
    assert r.decision == ActionDecision.APPROVE


def test_provider_sanctions_match_rejects():
    p = prov(by_addr={SENDER: {"sanctioned": False, "risk": "none"}, PAYEE: {"sanctioned": True}})
    r = check_payment(**BASE, screening_providers=[p])
    assert r.decision == ActionDecision.REJECT and "PROVIDER_SANCTIONS_MATCH" in r.flags


def test_risk_thresholds():
    high = [prov(default={"risk": "high"})]
    assert check_payment(**BASE, screening_providers=high).decision == ActionDecision.HOLD
    assert "PROVIDER_RISK_HIGH" in check_payment(**BASE, screening_providers=high).flags
    assert check_payment(**BASE, screening_providers=[prov(default={"risk": "severe"})]).decision == ActionDecision.REJECT
    assert check_payment(**BASE, screening_providers=high, screening_hold_at="severe").decision == ActionDecision.APPROVE
    assert check_payment(**BASE, screening_providers=[prov(default={"risk": "medium"})],
                         screening_hold_at="medium").decision == ActionDecision.HOLD


def test_no_answer_holds_never_approves():
    r = check_payment(**BASE, screening_providers=[prov(default=None)])
    assert r.decision == ActionDecision.HOLD and "SCREENING_UNAVAILABLE" in r.flags


def test_a_provider_that_raises_holds():
    class Boom:
        name = "boom"

        def screen(self, a, c):
            raise RuntimeError("down")

    assert check_payment(**BASE, screening_providers=[Boom()]).decision == ActionDecision.HOLD


def test_one_reject_beats_other_providers():
    r = check_payment(**BASE, screening_providers=[prov("a", default={"risk": "low"}),
                                                   prov("b", default={"sanctioned": True})])
    assert r.decision == ActionDecision.REJECT


def test_local_reject_makes_no_provider_calls():
    calls = []
    p = CallableProvider("p", lambda a, c: calls.append(a) or {"risk": "low"})
    r = check_payment(**{**BASE, "recipient": SENDER}, screening_providers=[p])
    assert r.decision == ActionDecision.REJECT and calls == []


def test_hold_merges_with_local_hold():
    r = check_payment(**BASE, known_recipients=[], screening_providers=[prov(default={"risk": "high"})])
    assert r.decision == ActionDecision.HOLD and {"PROVIDER_RISK_HIGH", "NEW_COUNTERPARTY"} <= set(r.flags)


@pytest.mark.parametrize("kw", [{"screening_providers": []}, {"screening_providers": "chainalysis"},
                                {"screening_providers": [object()]}, {"screening_hold_at": "critical"},
                                {"screening_hold_at": "severe", "screening_reject_at": "high"}])
def test_bad_screening_configuration_rejects(kw):
    kw.setdefault("screening_providers", [prov(default={"risk": "low"})])
    r = check_payment(**BASE, **kw)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]


def test_screen_addresses_never_raises():
    out = screen_addresses([prov(default={"risk": "low"})], [SENDER, PAYEE], 1)
    assert [type(r) for r in out] == [ScreeningResult, ScreeningResult] and all(r.ok for r in out)
