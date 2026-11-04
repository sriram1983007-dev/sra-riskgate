"""0.18.0: verify_settlement and verify_gateway_balances check what actually settled."""
import pytest

from sra_riskgate import verify_gateway_balances, verify_settlement
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.settlement import AUTHORIZATION_USED_TOPIC, TRANSFER_TOPIC

# Shaped like the Base Sepolia run of 2026-11-01 (tx 0xf12e9084…084fc, block 53339258): 0.01 USDC agent -> payee.
AGENT = "0xe542BC293D03D33445189f7E85365Be3Dc087384"
PAYEE = "0x870bcb94683cc25494cd35dd21cFC6E155f17DDc"
OTHER = "0x" + "7e57" * 10
FEE = "0x" + "fe" * 20
USDC = USDC_ADDRESSES[84532]
NONCE = "0x" + "ab" * 32


def word(addr):
    return "0x" + addr.lower()[2:].rjust(64, "0")


def transfer(frm, to, micro, token=USDC):
    return {"address": token, "topics": [TRANSFER_TOPIC, word(frm), word(to)], "data": "0x" + format(micro, "064x")}


def auth_used(frm, nonce=NONCE):
    return {"address": USDC, "topics": [AUTHORIZATION_USED_TOPIC, word(frm), nonce], "data": "0x"}


def receipt(*logs, status="0x1", block="0x32de47a"):
    return {"status": status, "blockNumber": block, "logs": list(logs)}


def verify(rc, **kw):
    kw.setdefault("chain_id", 84532)
    kw.setdefault("payer", AGENT)
    kw.setdefault("payee", PAYEE)
    kw.setdefault("amount", "0.01")
    return verify_settlement(rc, **kw)


def test_exact_payment_is_verified():
    r = verify(receipt(transfer(AGENT, PAYEE, 10_000)))
    assert r.verified and r.flags == [] and r.block_number == 53339258
    assert r.transfers == [{"from": AGENT.lower(), "to": PAYEE.lower(), "amount": "0.01", "amount_usdc": "0.01"}]
    assert "exactly 0.01 USDC" in r.explanation


@pytest.mark.parametrize("amount", [0.01, "0.01", "0.010000"])
def test_amount_forms(amount):
    assert verify(receipt(transfer(AGENT, PAYEE, 10_000)), amount=amount).verified


def test_web3_style_receipt_with_bytes_and_ints():
    lg = transfer(AGENT, PAYEE, 10_000)
    web3_log = {"address": USDC, "topics": [bytes.fromhex(t[2:]) for t in lg["topics"]],
                "data": bytes.fromhex(lg["data"][2:])}
    r = verify({"status": 1, "blockNumber": 53339258, "logs": [web3_log]})
    assert r.verified


def test_reverted_transaction_is_not_verified():
    r = verify(receipt(transfer(AGENT, PAYEE, 10_000), status="0x0"))
    assert not r.verified and r.flags == ["SETTLEMENT_FAILED"]


def test_wrong_amount():
    r = verify(receipt(transfer(AGENT, PAYEE, 9_999)))
    assert r.flags == ["SETTLEMENT_AMOUNT_MISMATCH"] and "0.009999" in r.explanation


def test_wrong_payee():
    r = verify(receipt(transfer(AGENT, OTHER, 10_000)))
    assert r.flags == ["SETTLEMENT_PAYEE_MISMATCH"] and OTHER in r.explanation


def test_no_transfer_from_payer():
    r = verify(receipt(transfer(OTHER, PAYEE, 10_000)))
    assert r.flags == ["SETTLEMENT_NOT_FOUND"]


def test_transfer_of_another_token_does_not_count():
    r = verify(receipt(transfer(AGENT, PAYEE, 10_000, token="0x" + "d" * 40)))
    assert r.flags == ["SETTLEMENT_NOT_FOUND"]


def test_duplicate_payment():
    r = verify(receipt(transfer(AGENT, PAYEE, 10_000), transfer(AGENT, PAYEE, 10_000)))
    assert r.flags == ["DUPLICATE_SETTLEMENT"]


def test_extra_transfer_is_reported_unless_allowed():
    rc = receipt(transfer(AGENT, PAYEE, 10_000), transfer(AGENT, FEE, 1_000))
    assert verify(rc).flags == ["UNEXPECTED_TRANSFER"]
    assert verify(rc, allow_other_transfers=True).verified


def test_other_payers_in_the_same_bundle_are_ignored():
    rc = receipt(transfer(OTHER, FEE, 5_000_000), transfer(AGENT, PAYEE, 10_000), transfer(FEE, OTHER, 1))
    assert verify(rc).verified


def test_authorization_nonce_must_be_used():
    paid = transfer(AGENT, PAYEE, 10_000)
    assert verify(receipt(auth_used(AGENT), paid), authorization_nonce=NONCE).verified
    assert verify(receipt(paid), authorization_nonce=NONCE).flags == ["AUTHORIZATION_NOT_USED"]
    other_nonce = "0x" + "cd" * 32
    assert verify(receipt(auth_used(AGENT, other_nonce), paid), authorization_nonce=NONCE).flags == \
        ["AUTHORIZATION_NOT_USED"]
    assert verify(receipt(auth_used(OTHER), paid), authorization_nonce=NONCE).flags == ["AUTHORIZATION_NOT_USED"]


@pytest.mark.parametrize("rc", [None, "0xabc", {}, {"status": "0x1"}, {"logs": []},
                                {"status": "yes", "logs": []},
                                {"status": "0x1", "logs": [{"address": USDC, "topics": "nope"}]}])
def test_malformed_receipts_fail_closed(rc):
    r = verify(rc)
    assert not r.verified and r.flags[0] in ("INVALID_RECEIPT", "SETTLEMENT_NOT_FOUND")


@pytest.mark.parametrize("kw,flag", [({"payee": "0x123"}, "CONFIGURATION_ERROR"),
                                     ({"amount": 0}, "CONFIGURATION_ERROR"),
                                     ({"amount": "0.0000001"}, "CONFIGURATION_ERROR"),
                                     ({"amount": "lots"}, "CONFIGURATION_ERROR"),
                                     ({"authorization_nonce": "0x12"}, "CONFIGURATION_ERROR"),
                                     ({"chain_id": 137}, "UNSUPPORTED_CHAIN")])
def test_bad_arguments(kw, flag):
    assert verify(receipt(transfer(AGENT, PAYEE, 10_000)), **kw).flags == [flag]


# Circle Gateway: balances before and after, as on Arc testnet 2026-11-01 (agent 0.09 -> 0.08, payee 0.01 -> 0.02)
def gw(**kw):
    args = dict(amount="0.01", payer_before="0.090000", payer_after="0.080000",
                payee_before="0.010000", payee_after="0.020000")
    args.update(kw)
    return verify_gateway_balances(**args)


def test_gateway_settled():
    r = gw()
    assert r.verified and "0.09 to 0.08" in r.explanation


def test_gateway_not_yet_credited():
    r = gw(payee_after="0.010000")
    assert r.flags == ["GATEWAY_PAYEE_NOT_CREDITED"] and "check again later" in r.explanation


def test_gateway_not_debited():
    assert gw(payer_after="0.085").flags == ["GATEWAY_PAYER_NOT_DEBITED"]


def test_gateway_other_activity_only_makes_it_larger():
    assert gw(payer_after="0.05", payee_after="0.05").verified


@pytest.mark.parametrize("kw", [{"amount": "-1"}, {"payer_before": "lots"}, {"payee_after": None},
                                {"payer_after": "-0.01"}])
def test_gateway_bad_input(kw):
    assert gw(**kw).flags == ["CONFIGURATION_ERROR"]


# 0.19.0: any ERC-20 by contract address and decimals, e.g. USDG on Robinhood Chain (chain 4663)
USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"
LENDER = "0x" + "be" * 20


def usdg(rc, **kw):
    kw.setdefault("chain_id", 4663)
    kw.setdefault("token", USDG)
    kw.setdefault("decimals", 6)
    kw.setdefault("symbol", "USDG")
    kw.setdefault("payee", LENDER)
    kw.setdefault("amount", "25")
    return verify(rc, **kw)


def test_other_token_on_another_chain():
    r = usdg(receipt(transfer(AGENT, LENDER, 25_000_000, token=USDG)))
    assert r.verified and "exactly 25 USDG" in r.explanation
    assert r.transfers == [{"from": AGENT.lower(), "to": LENDER, "amount": "25"}]


def test_other_token_wrong_amount_and_usdc_transfer_ignored():
    rc = receipt(transfer(AGENT, LENDER, 24_000_000, token=USDG), transfer(AGENT, LENDER, 25_000_000))
    r = usdg(rc)
    assert r.flags == ["SETTLEMENT_AMOUNT_MISMATCH"] and "24 USDG" in r.explanation


def test_other_token_decimals_matter():
    rc = receipt(transfer(AGENT, LENDER, 25 * 10**18, token=USDG))
    assert usdg(rc, decimals=18).verified
    assert usdg(rc).flags == ["SETTLEMENT_AMOUNT_MISMATCH"]


@pytest.mark.parametrize("kw", [{"decimals": None}, {"token": None}, {"decimals": -1}, {"decimals": 37},
                                {"decimals": True}, {"decimals": 6.0}, {"token": "0x123"},
                                {"amount": "0.0000001"}, {"chain_id": "4663"}])
def test_other_token_bad_arguments(kw):
    assert usdg(receipt(transfer(AGENT, LENDER, 25_000_000, token=USDG)), **kw).flags == ["CONFIGURATION_ERROR"]


def test_unknown_chain_without_token_says_how_to_check():
    r = verify(receipt(transfer(AGENT, PAYEE, 10_000)), chain_id=4663)
    assert r.flags == ["UNSUPPORTED_CHAIN"] and "token=" in r.explanation
