"""1.0.0: the checks before signing cover USDT, USDB and USDG as well as USDC, once enabled with allowed_tokens.

On-chain facts these tests rely on (read 2026-11-06, USDG re-read 2026-11-14): USDC and USDG implement EIP-3009
transferWithAuthorization; USDB implements EIP-2612 permit only; USDT implements neither.
"""
import pytest
from eth_abi import encode

from sra_riskgate import (ActionDecision, check_authorization, check_circle_request, check_payment, check_transaction,
                          check_user_operation, stablecoin_at)
from sra_riskgate.chains import STABLECOINS, USDC_ADDRESSES, parse_allowed_tokens

ME = "0x" + "a" * 40
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
ALL = ["USDC", "USDT", "USDB", "USDG"]
NOW = 1_790_000_000

USDT_ETH = STABLECOINS["USDT"][1][0]
USDB_BASE = STABLECOINS["USDB"][8453][0]
USDG_RH = STABLECOINS["USDG"][4663][0]
USDC_BASE = USDC_ADDRESSES[8453]

LISTED = [(sym, chain, addr) for sym, chains in STABLECOINS.items() for chain, (addr, _) in chains.items()]
NON_USDC = [row for row in LISTED if row[0] != "USDC"]
NO_EIP3009 = [row for row in NON_USDC if row[0] != "USDG"]
USDG_ROWS = [row for row in LISTED if row[0] == "USDG"]


def transfer_data(to, atomic):
    return "0xa9059cbb" + encode(["address", "uint256"], [to, atomic]).hex()


def approve_data(spender, atomic):
    return "0x095ea7b3" + encode(["address", "uint256"], [spender, atomic]).hex()


def pay(token, chain_id, amount=25.0, **kw):
    kw.setdefault("peg_deviation_pct", 0.0)
    return check_payment(chain_id=chain_id, sender=ME, recipient=PAYEE, amount=amount, token=token, **kw)


# ------------------------------------------------------------------ check_payment
@pytest.mark.parametrize("sym,chain,_", NON_USDC)
def test_other_stablecoins_are_off_by_default(sym, chain, _):
    r = pay(sym, chain)
    assert r.decision == ActionDecision.HOLD and r.flags == ["UNSUPPORTED_ASSET"]
    assert "allowed_tokens" in r.explanation and sym in r.explanation


@pytest.mark.parametrize("sym,chain,_", LISTED)
def test_every_listed_stablecoin_is_approved_once_enabled(sym, chain, _):
    assert pay(sym, chain, allowed_tokens=ALL).decision == ActionDecision.APPROVE


def test_default_usdc_behaviour_is_unchanged():
    assert pay("USDC", 8453).decision == ActionDecision.APPROVE
    assert pay("usdc", 1).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("sym,chain", [("USDT", 8453), ("USDG", 8453), ("USDB", 4663), ("USDC", 4663)])
def test_token_not_listed_on_that_chain_is_held(sym, chain):
    r = pay(sym, chain, allowed_tokens=ALL)
    assert r.flags == ["UNSUPPORTED_CHAIN"] and sym in r.explanation


def test_unknown_token_is_held():
    r = pay("DAI", 1, allowed_tokens=ALL)
    assert r.flags == ["UNSUPPORTED_ASSET"] and "USDT" in r.explanation


def test_limits_and_rules_apply_to_the_token_paid():
    r = pay("USDT", 1, amount=5000, allowed_tokens=ALL, max_amount=1000)
    assert r.decision == ActionDecision.HOLD and "HIGH_VALUE_TRANSFER" in r.flags
    r = pay("USDG", 4663, allowed_tokens=ALL, peg_deviation_pct=-6)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CRITICAL_DEPEG_EVENT"]
    r = pay("USDB", 8453, allowed_tokens=ALL, known_recipients=[OTHER])
    assert r.decision == ActionDecision.HOLD and "NEW_COUNTERPARTY" in r.flags
    r = pay("USDT", 1, amount=0.0000001, allowed_tokens=ALL)
    assert r.flags == ["INVALID_PAYMENT"] and "smallest USDT unit" in r.explanation


def test_round_amount_note_names_the_token():
    r = pay("USDG", 1, amount=20000, allowed_tokens=ALL, max_amount=50000)
    assert "Round amount of 20000 USDG" in r.explanation


@pytest.mark.parametrize("bad", [["DAI"], [], "nonsense", [1], 42])
def test_bad_allowed_tokens_is_a_configuration_error(bad):
    r = pay("USDC", 8453, allowed_tokens=bad)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]


def test_allowed_tokens_parsing():
    assert parse_allowed_tokens(None) == {"USDC"}
    assert parse_allowed_tokens("usdc, usdt") == {"USDC", "USDT"}
    assert parse_allowed_tokens(("usdg",)) == {"USDG"}


def test_sanctions_still_come_first():
    sanctioned = "0x0330070fd38ec3bb94f58fa55d40368271e9e54a"
    r = check_payment(chain_id=1, sender=ME, recipient=sanctioned, amount=1, token="USDT")
    assert r.decision == ActionDecision.REJECT and "OFAC_SDN_MATCH" in r.flags


# ------------------------------------------------------------------ check_transaction
def tx(to, data, chain_id, **kw):
    return check_transaction({"to": to, "data": data, "value": 0, "from": ME, "chainId": chain_id},
                             peg_deviation_pct=0.0, **kw)


@pytest.mark.parametrize("sym,chain,addr", LISTED)
def test_transfer_of_each_listed_stablecoin(sym, chain, addr):
    r = tx(addr, transfer_data(PAYEE, 25_000_000), chain, allowed_tokens=ALL)
    assert r.decision == ActionDecision.APPROVE, r.explanation


def test_usdt_transfer_held_until_enabled():
    r = tx(USDT_ETH, transfer_data(PAYEE, 25_000_000), 1)
    assert r.flags == ["UNSUPPORTED_ASSET"] and "USDT is not enabled" in r.explanation


def test_transfer_amount_uses_token_decimals_and_limit():
    r = tx(USDG_RH, transfer_data(PAYEE, 25_075_000), 4663, allowed_tokens=ALL, max_amount=25)
    assert r.decision == ActionDecision.HOLD and "HIGH_VALUE_TRANSFER" in r.flags and "25.075" in r.explanation


@pytest.mark.parametrize("sym,chain,addr", NON_USDC)
def test_approvals_are_held_for_every_listed_stablecoin_enabled_or_not(sym, chain, addr):
    for kw in ({}, {"allowed_tokens": ALL}):
        r = tx(addr, approve_data(OTHER, 2**256 - 1), chain, **kw)
        assert r.flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"] and sym in r.explanation


def test_unlisted_contract_is_held_and_names_the_listed_ones():
    r = tx(OTHER, transfer_data(PAYEE, 1_000_000), 1, allowed_tokens=ALL)
    assert r.flags == ["UNSUPPORTED_ASSET"] and "USDT 0xdAC17F958D2ee523a2206206994597C13D831ec7" in r.explanation


def test_contract_of_a_token_on_another_chain_is_not_accepted():
    # USDT's Ethereum address on Base is not USDT on Base.
    assert tx(USDT_ETH, transfer_data(PAYEE, 1_000_000), 8453, allowed_tokens=ALL).flags == ["UNSUPPORTED_ASSET"]


def test_robinhood_chain_native_value_is_held():
    r = check_transaction({"to": PAYEE, "data": "0x", "value": 10**18, "from": ME, "chainId": 4663},
                          allowed_tokens=ALL)
    assert r.flags == ["NATIVE_VALUE_TRANSFER"]


def test_stablecoin_at():
    assert stablecoin_at(1, USDT_ETH.lower()) == ("USDT", 6)
    assert stablecoin_at(8453, USDB_BASE.upper().replace("0X", "0x")) == ("USDB", 6)
    assert stablecoin_at(8453, USDT_ETH) is None and stablecoin_at(True, USDT_ETH) is None


# ------------------------------------------------------------------ check_authorization
def typed(contract, chain_id, primary="TransferWithAuthorization", name="X", version="1", **msg):
    message = {"from": ME, "to": PAYEE, "value": "250000", "validAfter": str(NOW - 600),
               "validBefore": str(NOW + 300), "nonce": "0x" + "ab" * 32}
    if primary == "Permit":
        message = {"owner": ME, "spender": OTHER, "value": str(2**256 - 1), "nonce": "0", "deadline": str(NOW + 300)}
    message.update(msg)
    return {"primaryType": primary, "domain": {"name": name, "version": version, "chainId": chain_id,
                                               "verifyingContract": contract}, "message": message}


def test_usdc_authorization_unchanged():
    r = check_authorization(typed(USDC_BASE, 8453, name="USD Coin", version="2"), now=NOW, peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.APPROVE


@pytest.mark.parametrize("sym,chain,addr", NO_EIP3009)
def test_eip3009_for_tokens_without_it_is_held(sym, chain, addr):
    r = check_authorization(typed(addr, chain), now=NOW, peg_deviation_pct=0.0, allowed_tokens=ALL)
    assert r.flags == ["UNSUPPORTED_SIGNATURE"] and "does not implement EIP-3009" in r.explanation


@pytest.mark.parametrize("sym,chain,addr", NON_USDC)
def test_permits_are_held_for_listed_stablecoins(sym, chain, addr):
    r = check_authorization(typed(addr, chain, primary="Permit"), now=NOW)
    assert r.flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"] and sym in r.explanation


@pytest.mark.parametrize("sym,chain,addr", USDG_ROWS)
def test_usdg_x402_authorization_is_checked(sym, chain, addr):
    # 1.6.0: USDG implements EIP-3009 on Ethereum and Robinhood Chain, so its x402 signatures are checked.
    r = check_authorization(typed(addr, chain, name="Global Dollar", version="1"), now=NOW, peg_deviation_pct=0.0,
                            allowed_tokens=ALL)
    assert r.decision == ActionDecision.APPROVE
    # still off unless enabled, and still subject to every payment check
    assert check_authorization(typed(addr, chain, name="Global Dollar", version="1"), now=NOW,
                               peg_deviation_pct=0.0).flags == ["UNSUPPORTED_ASSET"]
    big = check_authorization(typed(addr, chain, name="Global Dollar", version="1", value=str(5_000 * 10**6)), now=NOW,
                              peg_deviation_pct=0.0, allowed_tokens=ALL, max_amount=1000)
    assert big.decision == ActionDecision.HOLD


def test_robinhood_gateway_lookalike_is_held_not_crashed():
    r = check_authorization(typed(OTHER, 4663, name="GatewayWalletBatched"), now=NOW)
    assert r.flags == ["UNSUPPORTED_ASSET"]


# ------------------------------------------------------------------ check_user_operation
def op(calls):
    data = "0x34fcd5be" + encode(["(address,uint256,bytes)[]"],
                                 [[(to, 0, bytes.fromhex(d[2:])) for to, d in calls]]).hex()
    return {"sender": ME, "nonce": "0x0", "callData": data, "callGasLimit": "0x1", "verificationGasLimit": "0x1",
            "preVerificationGas": "0x1", "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1", "signature": "0x"}


def test_user_operation_with_usdt():
    r = check_user_operation(op([(USDT_ETH, transfer_data(PAYEE, 5_000_000))]), chain_id=1,
                             allowed_tokens=ALL, peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.APPROVE, r.explanation


def test_split_across_usdc_and_usdt_is_summed():
    calls = [(USDC_ADDRESSES[1], transfer_data(PAYEE, 600_000_000)), (USDT_ETH, transfer_data(PAYEE, 600_000_000))]
    r = check_user_operation(op(calls), chain_id=1, allowed_tokens=ALL, peg_deviation_pct=0.0, max_amount=1000)
    assert r.decision == ActionDecision.HOLD and "BATCH_TOTAL" in r.flags
    assert "1200 in USDC and USDT" in r.explanation


def test_user_operation_on_robinhood_chain():
    r = check_user_operation(op([(USDG_RH, transfer_data(PAYEE, 25_075_000))]), chain_id=4663,
                             allowed_tokens=ALL, peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.APPROVE


def test_user_operation_hidden_usdg_approval_is_held():
    calls = [(USDG_RH, transfer_data(PAYEE, 1_000_000)), (USDG_RH, approve_data(OTHER, 2**256 - 1))]
    r = check_user_operation(op(calls), chain_id=4663, allowed_tokens=ALL, peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.HOLD and "TOKEN_APPROVAL" in r.flags and "call 2 of 2" in r.explanation


# ------------------------------------------------------------------ Circle Wallets
WALLET_ID = "c4d1da72-111e-4d52-bdbf-2e74a2d803d5"


def circle(token_address, chain="ETH", **kw):
    body = {"idempotencyKey": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "entitySecretCiphertext": "x",
            "walletId": WALLET_ID, "blockchain": chain, "tokenAddress": token_address,
            "destinationAddress": PAYEE, "amounts": ["2.5"], "feeLevel": "MEDIUM"}
    return check_circle_request("transfer", body, wallets={WALLET_ID: ME}, peg_deviation_pct=0.0, **kw)


def test_circle_transfer_of_usdt_by_token_address():
    assert circle(USDT_ETH).flags == ["UNSUPPORTED_ASSET"]
    assert circle(USDT_ETH, allowed_tokens=ALL).decision == ActionDecision.APPROVE
    assert circle(OTHER, allowed_tokens=ALL).flags == ["UNSUPPORTED_ASSET"]
