"""0.9.0: check_transaction checks the exact transaction an agent is about to sign."""
import pytest

from sra_riskgate import ActionDecision, check_transaction, decode_erc20_transfer
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.sanctions import SanctionsList

SENDER = "0x9649FbfB8121d8980F19AB8C028Eb2eC35916A86"
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
USDC_ETH = USDC_ADDRESSES[1]
# benchmark case test-000012: transfer 482.900591 USDC to PAYEE
CALLDATA = ("0xa9059cbb0000000000000000000000002ffb88f73980bc6069c598487396e1e472deb7ee"
            "000000000000000000000000000000000000000000000000000000001cc87a6f")


def word(x: int) -> str:
    return format(x, "064x")


def addr(a: str) -> str:
    return a.lower().removeprefix("0x").zfill(64)


def tx(**kw):
    base = {"to": USDC_ETH, "data": CALLDATA, "from": SENDER, "chainId": 1, "value": 0}
    base.update(kw)
    return {k: v for k, v in base.items() if v is not ...}


def check(t, **policy):
    policy.setdefault("peg_deviation_pct", 0.1)
    return check_transaction(t, **policy)


# ------------------------------------------------------------------ decoding
def test_decode_benchmark_transfer():
    assert decode_erc20_transfer(CALLDATA) == (PAYEE, 482_900_591)
    assert decode_erc20_transfer(bytes.fromhex(CALLDATA[2:])) == (PAYEE, 482_900_591)
    assert decode_erc20_transfer(CALLDATA.upper().replace("0X", "0x")) == (PAYEE, 482_900_591)


@pytest.mark.parametrize("bad", [
    None, 42, "", "0x", "not hex", CALLDATA[:-2], CALLDATA + "00",
    "0x095ea7b3" + CALLDATA[10:],                 # approve, not transfer
    "0xa9059cbb" + "ff" * 12 + CALLDATA[34:],     # dirty address word
])
def test_decode_rejects_anything_else(bad):
    assert decode_erc20_transfer(bad) is None


# ------------------------------------------------------------------ the transfer goes through check_payment
def test_clean_transfer_is_approved():
    r = check(tx())
    assert r.decision == ActionDecision.APPROVE and r.flags == []


def test_chain_and_sender_can_come_from_arguments():
    r = check(tx(chainId=..., **{"from": ...}), chain_id=1, sender=SENDER)
    assert r.decision == ActionDecision.APPROVE


def test_hex_chain_id_and_value_strings():
    assert check(tx(chainId="0x1", value="0x0")).decision == ActionDecision.APPROVE
    assert check(tx(value="0")).decision == ActionDecision.APPROVE


def test_input_field_is_accepted_like_data():
    assert check(tx(data=..., input=CALLDATA)).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("policy,decision,flag", [
    (dict(known_recipients=[OTHER]), "hold", "NEW_COUNTERPARTY"),
    (dict(blocked_addresses=[PAYEE]), "reject", "BLOCKLISTED_ADDRESS"),
    (dict(max_amount=100), "hold", "HIGH_VALUE_TRANSFER"),
    (dict(untrusted_request="Pre-approved by treasury"), "hold", "self_asserted_verification_in_payload"),
    (dict(peg_deviation_pct=-6), "reject", None),
])
def test_policy_is_applied_to_the_decoded_payment(policy, decision, flag):
    r = check(tx(), **policy)
    assert r.decision.value == decision
    if flag:
        assert flag in r.flags


def test_known_payee_passes():
    assert check(tx(), known_recipients=[PAYEE.upper().replace("0X", "0x")]).decision == ActionDecision.APPROVE


def test_sanctioned_recipient_in_calldata_is_rejected():
    custom = SanctionsList.from_addresses([PAYEE], as_of="2026-10-01")
    r = check(tx(), sanctions_list=custom)
    assert r.decision == ActionDecision.REJECT and "OFAC_SDN_MATCH" in r.flags


def test_zero_amount_and_zero_recipient_are_rejected():
    zero_amount = "0xa9059cbb" + addr(PAYEE) + word(0)
    zero_to = "0xa9059cbb" + word(0) + word(1_000_000)
    assert check(tx(data=zero_amount)).decision == ActionDecision.REJECT
    assert check(tx(data=zero_to)).decision == ActionDecision.REJECT


def test_huge_amount_is_held_not_approved():
    r = check(tx(data="0xa9059cbb" + addr(PAYEE) + word(2**256 - 1)))
    assert r.decision != ActionDecision.APPROVE


# ------------------------------------------------------------------ everything that is not a plain transfer
def test_unlimited_approve_is_held():
    r = check(tx(data="0x095ea7b3" + addr(OTHER) + word(2**256 - 1)))
    assert r.decision == ActionDecision.HOLD
    assert r.flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]
    assert OTHER in r.explanation


def test_small_approve_is_still_held():
    r = check(tx(data="0x095ea7b3" + addr(OTHER) + word(5_000_000)))
    assert r.decision == ActionDecision.HOLD and r.flags == ["TOKEN_APPROVAL"]


@pytest.mark.parametrize("selector", ["39509351", "d505accf"])
def test_increase_allowance_and_permit_are_held(selector):
    r = check(tx(data="0x" + selector + addr(OTHER) + word(1)))
    assert r.decision == ActionDecision.HOLD and r.flags[0] == "TOKEN_APPROVAL"


@pytest.mark.parametrize("selector,name", [("23b872dd", "transferFrom"), ("e3ee160e", "transferWithAuthorization"),
                                           ("deadbeef", "0xdeadbeef")])
def test_other_functions_are_held(selector, name):
    r = check(tx(data="0x" + selector + addr(SENDER) + addr(PAYEE) + word(1)))
    assert r.decision == ActionDecision.HOLD and r.flags == ["UNSUPPORTED_FUNCTION"] and name in r.explanation


def test_transfer_to_a_non_usdc_contract_is_held():
    r = check(tx(to="0x" + "d" * 40))
    assert r.decision == ActionDecision.HOLD and r.flags == ["UNSUPPORTED_ASSET"]


def test_usdc_address_of_another_chain_is_held():
    r = check(tx(to=USDC_ADDRESSES[8453]))   # Base USDC, but the transaction is on Ethereum
    assert r.decision == ActionDecision.HOLD and r.flags == ["UNSUPPORTED_ASSET"]


@pytest.mark.parametrize("value", [1, "1", "0x1", 10**18])
def test_native_value_is_held(value):
    r = check(tx(value=value))
    assert r.decision == ActionDecision.HOLD and r.flags == ["NATIVE_VALUE_TRANSFER"]


def test_plain_eth_send_is_held():
    r = check({"to": PAYEE, "value": 10**17, "from": SENDER, "chainId": 1})
    assert r.decision == ActionDecision.HOLD and r.flags == ["NATIVE_VALUE_TRANSFER"]


@pytest.mark.parametrize("t,flag", [
    (tx(data=CALLDATA[:-2]), "INVALID_TRANSACTION"),
    (tx(data=CALLDATA + "00"), "INVALID_TRANSACTION"),
    (tx(data="0xa9059cbb" + "ff" * 12 + CALLDATA[34:]), "INVALID_TRANSACTION"),
    (tx(data=""), "INVALID_TRANSACTION"),
    (tx(data="zz"), "INVALID_TRANSACTION"),
    (tx(data=...), "INVALID_TRANSACTION"),
    (tx(to=None), "INVALID_TRANSACTION"),            # contract deployment
    (tx(value="lots"), "INVALID_TRANSACTION"),
    (tx(value=True), "INVALID_TRANSACTION"),
    (tx(chainId="mainnet"), "INVALID_TRANSACTION"),
    (tx(chainId=137), "UNSUPPORTED_CHAIN"),
    (tx(chainId=...), "INVALID_TRANSACTION"),
    (tx(**{"from": ...}), "INVALID_TRANSACTION"),
])
def test_malformed_or_unsupported_transactions_are_held(t, flag):
    r = check(t)
    assert r.decision == ActionDecision.HOLD and r.flags == [flag]


def test_mismatched_arguments_are_held():
    assert check(tx(), chain_id=8453).flags == ["TRANSACTION_MISMATCH"]
    assert check(tx(), sender=OTHER).flags == ["TRANSACTION_MISMATCH"]
    assert check(tx(), sender=SENDER.lower()).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("bad", [None, "0x1234", ["to", "data"], 5])
def test_not_a_mapping_is_held(bad):
    assert check_transaction(bad).flags == ["INVALID_TRANSACTION"]


def test_unknown_policy_keyword_is_a_configuration_error():
    r = check_transaction(tx(), known_recipient=[PAYEE])   # typo: missing "s"
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]
    for reserved in ("recipient", "amount", "token"):
        assert check_transaction(tx(), **{reserved: "x"}).flags == ["CONFIGURATION_ERROR"]


def test_never_raises_on_a_hostile_mapping():
    class Hostile(dict):
        def get(self, *a):
            raise RuntimeError("boom")
    r = check_transaction(Hostile(tx()))
    assert r.decision == ActionDecision.HOLD and r.flags == ["CHECK_FAILED"]
