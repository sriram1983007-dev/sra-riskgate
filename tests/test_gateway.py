"""0.13.0: Circle Gateway batched x402 payments (domain GatewayWalletBatched) are checked, not held for validity."""
import copy

import pytest

from sra_riskgate import ActionDecision, check_authorization
from sra_riskgate.chains import GATEWAY_WALLET_ADDRESSES, USDC_ADDRESSES
from sra_riskgate.sanctions import SanctionsList

SENDER = "0x9649FbfB8121d8980F19AB8C028Eb2eC35916A86"
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
NOW = 1_790_000_000
DAY = 86400
TESTNET_WALLET = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9"
MAINNET_WALLET = "0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE"
TYPES = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]}


def gw(chain=5042002, contract=TESTNET_WALLET, days=5, **msg):
    """Circle's documented example: 0.01 USDC, valid immediately for 5 days, on Arc Testnet."""
    message = {"from": SENDER, "to": PAYEE, "value": "10000", "validAfter": "0",
               "validBefore": str(NOW + days * DAY), "nonce": "0x" + "ab" * 32}
    message.update(msg)
    return {"types": copy.deepcopy(TYPES), "primaryType": "TransferWithAuthorization",
            "domain": {"name": "GatewayWalletBatched", "version": "1", "chainId": chain,
                       "verifyingContract": contract},
            "message": message}


def check(td, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("peg_deviation_pct", 0.1)
    return check_authorization(td, **kw)


def test_documented_gateway_payment_is_approved():
    r = check(gw(), sender=SENDER, chain_id=5042002)
    assert r.decision == ActionDecision.APPROVE and r.flags == []


@pytest.mark.parametrize("chain", [1, 8453, 5042])
def test_mainnet_gateway_wallet_is_recognised(chain):
    assert check(gw(chain=chain, contract=MAINNET_WALLET)).decision == ActionDecision.APPROVE


def test_addresses_match_circle_reference():
    assert set(GATEWAY_WALLET_ADDRESSES) == set(USDC_ADDRESSES)
    assert {GATEWAY_WALLET_ADDRESSES[c] for c in (1, 8453, 5042)} == {MAINNET_WALLET}
    assert {GATEWAY_WALLET_ADDRESSES[c] for c in (84532, 5042002)} == {TESTNET_WALLET}


def test_same_validity_is_still_held_on_the_usdc_domain():
    td = gw()
    td["domain"] = {"name": "USDC", "version": "2", "chainId": 5042002, "verifyingContract": USDC_ADDRESSES[5042002]}
    r = check(td)
    assert r.decision == ActionDecision.HOLD and r.flags == ["LONG_LIVED_AUTHORIZATION"]


def test_gateway_payment_still_gets_payment_checks():
    sanctioned = sorted(SanctionsList.bundled().addresses)[0]
    assert check(gw(to=sanctioned)).decision == ActionDecision.REJECT
    assert check(gw(), known_recipients=[OTHER]).decision == ActionDecision.HOLD
    assert check(gw(value=str(20 * 10**6)), max_amount=10).decision == ActionDecision.HOLD
    assert check(gw(), sender=OTHER).flags == ["AUTHORIZATION_MISMATCH"]


@pytest.mark.parametrize("contract", [MAINNET_WALLET, USDC_ADDRESSES[5042002], OTHER])
def test_gateway_name_with_wrong_contract_is_held(contract):
    r = check(gw(contract=contract))  # testnet chain: only the testnet GatewayWallet is valid
    assert r.decision == ActionDecision.HOLD and r.flags == ["UNSUPPORTED_ASSET"]
    assert TESTNET_WALLET in r.explanation


def test_eurc_and_cirbtc_version_2_is_held():
    td = gw()
    td["domain"]["version"] = "2"
    td["domain"]["salt"] = "0x" + "0" * 24 + "e" * 40
    assert check(td).flags == ["UNSUPPORTED_ASSET"]
    td = gw()
    td["domain"]["salt"] = "0x" + "0" * 64
    assert check(td).flags == ["UNSUPPORTED_ASSET"]


@pytest.mark.parametrize("primary", ["ReceiveWithAuthorization", "Permit", "BurnIntent"])
def test_other_signatures_on_gateway_domain_are_held(primary):
    td = gw()
    td["primaryType"] = primary
    td["types"] = {primary: TYPES["TransferWithAuthorization"]}
    assert check(td).flags == ["UNSUPPORTED_SIGNATURE"]


def test_gateway_validity_limit():
    assert check(gw(days=7)).decision == ActionDecision.APPROVE
    r = check(gw(days=8))
    assert r.flags == ["LONG_LIVED_AUTHORIZATION"] and "Circle Gateway" in r.explanation
    assert check(gw(days=8), max_gateway_validity_seconds=10 * DAY).decision == ActionDecision.APPROVE
    # the one-hour limit for ordinary x402 does not apply to Gateway, and vice versa
    assert check(gw(), max_validity_seconds=60).decision == ActionDecision.APPROVE


def test_too_short_for_gateway_is_held():
    r = check(gw(days=2))
    assert r.decision == ActionDecision.HOLD and r.flags == ["GATEWAY_VALIDITY_TOO_SHORT"]


def test_expired_and_post_dated_gateway_authorizations_are_held():
    assert check(gw(days=-1)).flags == ["AUTHORIZATION_EXPIRED"]
    assert check(gw(validAfter=str(NOW + DAY))).flags == ["AUTHORIZATION_NOT_YET_VALID"]


def test_real_signature_over_gateway_typed_data():
    """The typed data shape is one eth-account can sign, so it is the shape agents will pass."""
    eth_account = pytest.importorskip("eth_account")
    acct = eth_account.Account.from_key("0x" + "11" * 32)
    td = gw(**{"from": acct.address})
    td["types"]["EIP712Domain"] = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                                   {"name": "chainId", "type": "uint256"},
                                   {"name": "verifyingContract", "type": "address"}]
    msg = {**td["message"], "value": int(td["message"]["value"]), "validAfter": 0,
           "validBefore": int(td["message"]["validBefore"])}
    signed = acct.sign_typed_data(full_message={**td, "message": msg})
    assert len(signed.signature) == 65
    assert check(td, sender=acct.address).decision == ActionDecision.APPROVE
