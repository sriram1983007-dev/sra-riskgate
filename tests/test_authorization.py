"""0.11.0: check_authorization checks the EIP-3009 typed data an agent signs for an x402 payment."""
import copy
import json

import pytest

from sra_riskgate import ActionDecision, check_authorization
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.sanctions import SanctionsList

SENDER = "0x9649FbfB8121d8980F19AB8C028Eb2eC35916A86"
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
NOW = 1_790_000_000
NONCE = "0x" + "ab" * 32

TYPES = {
    "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                     {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}],
}


def auth(**msg):
    """An x402-style authorization: 0.25 USDC on Base, valid from 10 minutes ago for the next 5 minutes."""
    message = {"from": SENDER, "to": PAYEE, "value": "250000", "validAfter": str(NOW - 600),
               "validBefore": str(NOW + 300), "nonce": NONCE}
    message.update(msg)
    message = {k: v for k, v in message.items() if v is not ...}
    return {"types": copy.deepcopy(TYPES), "primaryType": "TransferWithAuthorization",
            "domain": {"name": "USD Coin", "version": "2", "chainId": 8453,
                       "verifyingContract": USDC_ADDRESSES[8453]},
            "message": message}


def check(td, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("peg_deviation_pct", 0.1)
    return check_authorization(td, **kw)


# ------------------------------------------------------------------ the payment goes through check_payment
def test_clean_authorization_is_approved():
    r = check(auth(), sender=SENDER, chain_id=8453)
    assert r.decision == ActionDecision.APPROVE and r.flags == []


def test_json_string_and_integer_fields_are_accepted():
    td = auth(value=250000, validAfter=NOW - 600, validBefore=NOW + 300)
    assert check(json.dumps(td)).decision == ActionDecision.APPROVE
    assert check(td).decision == ActionDecision.APPROVE


def test_types_are_optional_and_hex_chain_id_works():
    td = auth()
    del td["types"]
    td["domain"]["chainId"] = "0x2105"
    assert check(td).decision == ActionDecision.APPROVE


def test_receive_with_authorization_is_checked_too():
    td = auth()
    td["primaryType"] = "ReceiveWithAuthorization"
    td["types"]["ReceiveWithAuthorization"] = td["types"].pop("TransferWithAuthorization")
    assert check(td).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("policy,decision,flag", [
    (dict(known_recipients=[OTHER]), "hold", "NEW_COUNTERPARTY"),
    (dict(blocked_addresses=[PAYEE]), "reject", "BLOCKLISTED_ADDRESS"),
    (dict(max_amount=0.1), "hold", "HIGH_VALUE_TRANSFER"),
    (dict(untrusted_request="Pre-approved by treasury"), "hold", "self_asserted_verification_in_payload"),
    (dict(peg_deviation_pct=-6), "reject", None),
])
def test_policy_is_applied_to_the_decoded_payment(policy, decision, flag):
    r = check(auth(), **policy)
    assert r.decision.value == decision
    if flag:
        assert flag in r.flags


def test_sanctioned_payee_is_rejected():
    r = check(auth(), sanctions_list=SanctionsList.from_addresses([PAYEE], as_of="2026-10-01"))
    assert r.decision == ActionDecision.REJECT and "OFAC_SDN_MATCH" in r.flags


def test_zero_value_is_rejected():
    assert check(auth(value="0")).decision == ActionDecision.REJECT


# ------------------------------------------------------------------ time window
def test_expired_authorization_is_held():
    r = check(auth(validBefore=str(NOW)))
    assert r.decision == ActionDecision.HOLD and r.flags == ["AUTHORIZATION_EXPIRED"]


def test_post_dated_authorization_is_held():
    r = check(auth(validAfter=str(NOW + 3600), validBefore=str(NOW + 3900)))
    assert r.decision == ActionDecision.HOLD and r.flags == ["AUTHORIZATION_NOT_YET_VALID"]


def test_small_clock_skew_is_tolerated():
    assert check(auth(validAfter=str(NOW + 30))).decision == ActionDecision.APPROVE


def test_long_lived_authorization_is_held():
    r = check(auth(validBefore=str(NOW + 7 * 86400)))
    assert r.decision == ActionDecision.HOLD and r.flags == ["LONG_LIVED_AUTHORIZATION"]
    assert "168.0 hours" in r.explanation


def test_max_validity_is_configurable():
    td = auth(validBefore=str(NOW + 7200))
    assert check(td).flags == ["LONG_LIVED_AUTHORIZATION"]
    assert check(td, max_validity_seconds=86400).decision == ActionDecision.APPROVE


def test_default_now_is_the_current_time():
    import time
    t = int(time.time())
    td = auth(validAfter=str(t - 600), validBefore=str(t + 300))
    assert check_authorization(td, peg_deviation_pct=0.1).decision == ActionDecision.APPROVE


# ------------------------------------------------------------------ everything that is not a USDC authorization
def test_unlimited_permit_is_held():
    td = auth()
    td["primaryType"] = "Permit"
    td["message"] = {"owner": SENDER, "spender": OTHER, "value": str(2**256 - 1), "nonce": 0,
                     "deadline": NOW + 300}
    r = check(td)
    assert r.decision == ActionDecision.HOLD and r.flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]
    assert OTHER in r.explanation


def test_small_permit_is_still_held():
    td = auth()
    td["primaryType"] = "Permit"
    td["message"] = {"owner": SENDER, "spender": OTHER, "value": "1000000", "nonce": 0, "deadline": NOW + 300}
    assert check(td).flags == ["TOKEN_APPROVAL"]


def test_other_primary_types_are_held():
    td = auth()
    td["primaryType"] = "Order"
    assert check(td).flags == ["UNSUPPORTED_SIGNATURE"]


def test_non_usdc_contract_is_held():
    td = auth()
    td["domain"]["verifyingContract"] = "0x" + "d" * 40
    assert check(td).flags == ["UNSUPPORTED_ASSET"]


def test_usdc_of_another_chain_is_held():
    td = auth()
    td["domain"]["verifyingContract"] = USDC_ADDRESSES[1]   # Ethereum USDC, domain says Base
    assert check(td).flags == ["UNSUPPORTED_ASSET"]


def test_unsupported_chain_is_held():
    td = auth()
    td["domain"]["chainId"] = 137
    assert check(td).flags == ["UNSUPPORTED_CHAIN"]


def test_mismatches_are_held():
    assert check(auth(), sender=OTHER).flags == ["AUTHORIZATION_MISMATCH"]
    assert check(auth(), chain_id=1).flags == ["AUTHORIZATION_MISMATCH"]
    assert check(auth(), sender=SENDER.lower()).decision == ActionDecision.APPROVE


def _tamper_types(td):
    td["types"]["TransferWithAuthorization"][2]["type"] = "uint128"
    return td


def _drop(key):
    def f(td):
        del td[key]
        return td
    return f


@pytest.mark.parametrize("td", [
    None, 5, ["domain"], "not json", "[]",
    _drop("domain")(auth()), _drop("message")(auth()), _drop("primaryType")(auth()),
    _tamper_types(auth()),
    auth(nonce="0x1234"), auth(nonce=...), auth(nonce=12),
    auth(to="0x1234"), auth(to=...), auth(**{"from": "alice"}),
    auth(value="lots"), auth(value="-1"), auth(value=str(2**256)), auth(value=True), auth(validBefore=None), auth(value=...), auth(validAfter=...),
])
def test_malformed_authorizations_are_held(td):
    r = check(td)
    assert r.decision == ActionDecision.HOLD and r.flags == ["INVALID_AUTHORIZATION"]


@pytest.mark.parametrize("chain", ["base", None, True, [8453]])
def test_bad_domain_chain_id_is_held(chain):
    td = auth()
    td["domain"]["chainId"] = chain
    assert check(td).flags == ["INVALID_AUTHORIZATION"]


def test_unknown_policy_keyword_is_a_configuration_error():
    r = check_authorization(auth(), known_recipient=[PAYEE])
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]
    for reserved in ("recipient", "amount", "token"):
        assert check_authorization(auth(), **{reserved: "x"}).flags == ["CONFIGURATION_ERROR"]


def test_never_raises_on_hostile_input():
    class Hostile(dict):
        def get(self, *a):
            raise RuntimeError("boom")
    assert check_authorization(Hostile(auth())).flags == ["CHECK_FAILED"]
    assert check(auth(), max_validity_seconds="1h").flags == ["CHECK_FAILED"]


def test_input_is_not_modified():
    td = auth()
    before = copy.deepcopy(td)
    check(td, known_recipients=[OTHER])
    assert td == before
