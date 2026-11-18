"""1.7.0: Elliptic Lens wallet screening, shaped like Elliptic's published OpenAPI spec (Wallet Analyses API 2.0.0)."""
import base64
import hashlib
import hmac
import json

import pytest

from sra_riskgate import ActionDecision, EllipticRisk, check_payment

SENDER = "0x" + "1" * 39 + "a"
PAYEE = "0x" + "2" * 39 + "b"
BASE = dict(chain_id=8453, sender=SENDER, recipient=PAYEE, amount=5.0, check_sanctions=False)
SECRET = base64.b64encode(b"elliptic-test-secret").decode()
NOW = 1_763_200_000.123


class FakePost:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, dict(headers), body))
        r = self.resp(json.loads(body)) if callable(self.resp) else self.resp
        if isinstance(r, Exception):
            raise r
        return r


def analysis(score=None, entities=(), source=(), destination=(), status="complete", error=None):
    def rules(elements):
        return [{"rule_id": "r1", "rule_name": "Illicit exposure", "risk_score": score,
                 "matched_elements": [{"category": c, "contribution_percentage": p,
                                       "contribution_value": {"usd": 1.0}, "contributions": []} for c, p in elements]}
                ] if elements else []
    return {"id": "a1", "type": "wallet_exposure", "process_status": status, "risk_score": score,
            "risk_score_detail": {"source": score, "destination": score}, "error": error,
            "cluster_entities": [{"name": n, "category": c, "is_primary_entity": i == 0} for i, (n, c) in enumerate(entities)],
            "evaluation_detail": {"source": rules(source), "destination": rules(destination)}, "triggered_rules": []}


def provider(resp, **kw):
    post = FakePost(resp)
    return EllipticRisk("key-1", SECRET, http_post=post, clock=lambda: NOW, **kw), post


def test_request_is_holistic_and_signed_as_elliptic_requires():
    p, post = provider((200, analysis()))
    assert p.screen(PAYEE, 8453).ok
    url, headers, body = post.calls[0]
    assert url == "https://aml-api.elliptic.co/v2/wallet/synchronous"
    assert json.loads(body) == {"subject": {"asset": "holistic", "blockchain": "holistic", "type": "address",
                                            "hash": PAYEE}, "type": "wallet_exposure"}
    assert headers["x-access-key"] == "key-1" and headers["x-access-timestamp"] == "1763200000123"
    msg = "1763200000123" + "POST" + "/v2/wallet/synchronous" + body
    want = base64.b64encode(hmac.new(b"elliptic-test-secret", msg.encode(), hashlib.sha256).digest()).decode()
    assert headers["x-access-sign"] == want


def test_signature_covers_the_exact_body_sent():
    p, post = provider((200, analysis()))
    p.screen(SENDER, 8453)
    p.screen(PAYEE, 8453)
    (_, h1, b1), (_, h2, b2) = post.calls
    assert b1 != b2 and h1["x-access-sign"] != h2["x-access-sign"]


def test_default_post_sends_a_string_body_unchanged(monkeypatch):
    import urllib.request
    from sra_riskgate import screening
    seen = {}

    class Resp:
        status = 200
        def read(self): return b"{}"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout):
        seen["data"] = req.data
        return Resp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    screening._urllib_post("https://x.test/", {}, '{"a":1}', 5)
    assert seen["data"] == b'{"a":1}'
    screening._urllib_post("https://x.test/", {}, [{"address": "0x1"}], 5)
    assert seen["data"] == json.dumps([{"address": "0x1"}]).encode()


@pytest.mark.parametrize("score,risk", [(None, "none"), (0, "low"), (0.5, "medium"), (4.99, "medium"), (5, "high"),
                                        (9.9, "high"), (10, "severe")])
def test_risk_score_bands(score, risk):
    p, _ = provider((200, analysis(score)))
    r = p.screen(PAYEE, 8453)
    assert r.ok and r.sanctioned is False and r.risk == risk


def test_thresholds_are_configurable():
    p, _ = provider((200, analysis(3)), high_risk_score=2.5, severe_risk_score=7)
    assert p.screen(PAYEE, 8453).risk == "high"
    p, _ = provider((200, analysis(7)), high_risk_score=2.5, severe_risk_score=7)
    assert p.screen(PAYEE, 8453).risk == "severe"


@pytest.mark.parametrize("category", ["Sanctions", "Sanctioned Entity", "Sanctioned Jurisdiction", "OFAC SANCTIONS"])
def test_sanctions_label_on_the_cluster_is_a_match(category):
    p, _ = provider((200, analysis(None, entities=[("Some Exchange", "Exchange"), ("Listed entity", category)])))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is True and r.risk == "severe" and any(category in x for x in r.reasons)


def test_other_cluster_labels_are_not_a_match():
    p, _ = provider((200, analysis(1.0, entities=[("Coinbase", "Exchange")])))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is False and r.risk == "medium" and "Coinbase (Exchange)" in r.reasons


@pytest.mark.parametrize("category", ["Sanctions", "Sanctioned Entity", "Terrorism Financing"])
@pytest.mark.parametrize("side", ["source", "destination"])
def test_sanctions_or_terror_exposure_holds_whatever_the_score(category, side):
    p, _ = provider((200, analysis(1.0, **{side: [(category, 2.5)]})))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is False and r.risk == "high"
    assert f"{side} exposure: {category} 2.5%" in r.reasons


def test_other_exposure_keeps_the_score_level():
    p, _ = provider((200, analysis(2.0, source=[("Mixer", 12.0)])))
    r = p.screen(PAYEE, 8453)
    assert r.risk == "medium" and "source exposure: Mixer 12%" in r.reasons and r.reasons[0] == "risk_score 2"


@pytest.mark.parametrize("resp", [
    (200, analysis(status="running")),
    (200, analysis(status="error", error={"message": "unsupported blockchain"})),
    (200, {**analysis(), "process_status": None}),
    (200, analysis(score="7")), (200, analysis(score=11)), (200, analysis(score=-1)), (200, analysis(score=True)),
    (200, []), (200, None), (401, None), (403, {"message": "forbidden"}), (429, None), (500, None), (404, None),
    ConnectionError(), TimeoutError()])
def test_anything_else_is_no_answer(resp):
    p, _ = provider(resp)
    r = p.screen(PAYEE, 8453)
    assert not r.ok and r.error


def test_error_message_is_kept():
    p, _ = provider((200, analysis(status="error", error={"message": "unsupported blockchain"})))
    assert "unsupported blockchain" in p.screen(PAYEE, 8453).error


def test_unseen_address_holds_unless_configured_clean():
    p, _ = provider((404, {"message": "subject not found"}))
    assert not p.screen(PAYEE, 8453).ok
    p, _ = provider((404, {"message": "subject not found"}), unseen_is_clean=True)
    r = p.screen(PAYEE, 8453)
    assert r.ok and r.risk == "none" and r.sanctioned is False


@pytest.mark.parametrize("kw", [dict(api_key=""), dict(api_key="  "), dict(api_secret=""), dict(api_secret="not base64!"),
                                dict(high_risk_score=0), dict(high_risk_score=8, severe_risk_score=6),
                                dict(severe_risk_score=11), dict(high_risk_score=True), dict(high_risk_score="5"),
                                dict(unseen_is_clean="yes")])
def test_bad_configuration_is_an_error(kw):
    args = {"api_key": "key-1", "api_secret": SECRET, **kw}
    with pytest.raises(ValueError):
        EllipticRisk(args.pop("api_key"), args.pop("api_secret"), **args)


def test_in_check_payment():
    def answer(body):
        return (200, analysis(None, entities=[("Listed", "Sanctions")] if body["subject"]["hash"] == PAYEE else []))
    p, post = provider(answer)
    r = check_payment(**BASE, screening_providers=[p])
    assert r.decision == ActionDecision.REJECT and "PROVIDER_SANCTIONS_MATCH" in r.flags
    assert [json.loads(b)["subject"]["hash"] for _, _, b in post.calls] == [SENDER, PAYEE]
    clean, _ = provider((200, analysis(None)))
    assert check_payment(**BASE, screening_providers=[clean]).decision == ActionDecision.APPROVE
    high, _ = provider((200, analysis(6.0)))
    r = check_payment(**BASE, screening_providers=[high])
    assert r.decision == ActionDecision.HOLD and "PROVIDER_RISK_HIGH" in r.flags
    down, _ = provider((503, None))
    r = check_payment(**BASE, screening_providers=[down])
    assert r.decision == ActionDecision.HOLD and "SCREENING_UNAVAILABLE" in r.flags


# ---------------------------------------------------------------- 1.8.1: Audit #18 (sanctions signals)

def _sanctioned_entity_response(**over):
    """Shaped like an OFAC-listed exchange in Elliptic's schema: category 'Exchange', not 'Sanctions'."""
    body = analysis(None, entities=[("Microvault", "Exchange")])
    body["cluster_entities"][0].update({"entity_id": "e-1", "is_after_sanction_date": True})
    body.update(over)
    return body


def test_is_after_sanction_date_marks_the_wallet_sanctioned():
    p, _ = provider((200, _sanctioned_entity_response()))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is True and r.risk == "severe" and any("sanctioned entity" in x for x in r.reasons)
    body = _sanctioned_entity_response()
    body["cluster_entities"][0]["is_after_sanction_date"] = False   # activity predates listing: still listed
    p, _ = provider((200, body))
    assert p.screen(PAYEE, 8453).sanctioned is True


def _with_trigger(entity_id, name, sanctioned=True):
    body = analysis(None, entities=[("Microvault", "Exchange")])
    body["cluster_entities"][0]["entity_id"] = "e-1"
    body["evaluation_detail"]["source"] = [{"rule_id": "r", "rule_name": "Exposure", "risk_score": None,
        "matched_elements": [{"category": "Exchange", "contribution_percentage": 100, "contributions": [
            {"entity": name, "entity_id": entity_id, "contribution_percentage": 100,
             "risk_triggers": {"name": name, "category": "Exchange", "is_sanctioned": sanctioned,
                               "country": ["RU"]}}]}]}]
    return body


def test_risk_trigger_on_own_entity_is_a_match():
    p, _ = provider((200, _with_trigger("e-1", "Microvault")))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is True and r.risk == "severe"


def test_risk_trigger_on_another_entity_is_exposure_that_holds():
    p, _ = provider((200, _with_trigger("e-9", "Garantex")))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is False and r.risk == "high" and any("Garantex is sanctioned" in x for x in r.reasons)


def test_unsanctioned_trigger_changes_nothing():
    p, _ = provider((200, _with_trigger("e-9", "Coinbase", sanctioned=False)))
    assert p.screen(PAYEE, 8453).risk == "none"


@pytest.mark.parametrize("details", [{"sanctions": ["OFAC SDN"]}, [{"sanctions": [{"list": "OFAC"}]}],
                                     {"sanctions": True}, {"is_sanctioned": True}])
def test_entity_details_listing_sanctions_is_a_match(details):
    p, _ = provider((200, {**analysis(None), "entity_details": details}))
    assert p.screen(PAYEE, 8453).sanctioned is True


@pytest.mark.parametrize("details", [{"sanctions": []}, {"sanctions": None}, [], "x", None])
def test_entity_details_without_sanctions_changes_nothing(details):
    p, _ = provider((200, {**analysis(None), "entity_details": details}))
    assert p.screen(PAYEE, 8453).sanctioned is False


def test_a_sanctioned_entity_response_never_approves_in_check_payment():
    def answer(body):
        return (200, _sanctioned_entity_response() if body["subject"]["hash"] == PAYEE else analysis(None))
    p, _ = provider(answer)
    r = check_payment(**BASE, screening_providers=[p])
    assert r.decision == ActionDecision.REJECT and "PROVIDER_SANCTIONS_MATCH" in r.flags
    p, _ = provider(lambda b: (200, _with_trigger("e-9", "Garantex")) if b["subject"]["hash"] == PAYEE
                    else (200, analysis(None)))
    assert check_payment(**BASE, screening_providers=[p]).decision == ActionDecision.HOLD


# ---------------------------------------------------------------- 1.10.1: Audit #19/#20 (nested entity_details)

def _nested(details, after_sanction_date=None):
    """A Microvault-shaped response: the sanctions listing sits inside the wallet's own cluster entity."""
    body = analysis(None, entities=[("Microvault", "Exchange")])
    body["cluster_entities"][0].update({"entity_id": "e-1", "entity_details": details})
    if after_sanction_date is not None:
        body["cluster_entities"][0]["is_after_sanction_date"] = after_sanction_date
    return body


@pytest.mark.parametrize("details", [{"sanctions": ["OFAC-SDN"]}, {"sanctions": "OFAC-SDN"},
                                     [{"sanctions": [{"list": "OFAC SDN", "program": "CYBER2"}]}],
                                     {"sanctions": True}, {"is_sanctioned": True}])
def test_nested_entity_details_without_sanction_date_rejects(details):
    p, _ = provider((200, _nested(details)))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is True and r.risk == "severe" and any("entity_details lists sanctions" in x for x in r.reasons)
    res = check_payment(**BASE, screening_providers=[provider((200, _nested(details)))[0]])
    assert res.decision == ActionDecision.REJECT and "PROVIDER_SANCTIONS_MATCH" in res.flags


@pytest.mark.parametrize("details", [{"sanctions": []}, {"sanctions": None}, {"sanctions": ""},
                                     {"sanctions": "none"}, {"sanctions": False}, [], None, "x"])
def test_nested_entity_details_without_a_listing_changes_nothing(details):
    p, _ = provider((200, _nested(details)))
    r = p.screen(PAYEE, 8453)
    assert r.sanctioned is False and r.risk == "none"
    assert check_payment(**BASE, screening_providers=[p]).decision == ActionDecision.APPROVE
