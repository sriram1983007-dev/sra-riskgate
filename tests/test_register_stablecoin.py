"""1.1.0: register_stablecoin() lets the checks recognise a US-dollar stablecoin on a chain the SDK does not list."""
import pytest

from sra_riskgate import (ActionDecision, STABLECOINS, check_allowances, check_authorization, check_payment,
                          check_transaction, check_user_operation, register_stablecoin, registered_stablecoins,
                          stablecoin_at, verify_settlement)
from sra_riskgate.chains import EIP3009_TOKENS, STABLECOIN_CHAINS, USDC_ADDRESSES, _reset_registry

ME = "0x" + "a" * 40
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
CHAIN = 7777777  # a chain the SDK does not list
TOKEN = "0x" + "12" * 20
NOW = 1_790_000_000
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@pytest.fixture(autouse=True)
def clean_registry():
    _reset_registry()
    yield
    _reset_registry()


def transfer_data(to, atomic):
    return "0xa9059cbb" + to.lower()[2:].zfill(64) + format(atomic, "064x")


def approve_data(spender, atomic):
    return "0x095ea7b3" + spender.lower()[2:].zfill(64) + format(atomic, "064x")


def pay(**kw):
    args = dict(chain_id=CHAIN, sender=ME, recipient=PAYEE, amount=25.0, token="TUSD8", peg_deviation_pct=0.0)
    args.update(kw)
    return check_payment(**args)


def test_unregistered_token_is_held():
    assert pay(allowed_tokens=["USDC"]).flags == ["UNSUPPORTED_ASSET"]
    r = check_transaction({"to": TOKEN, "data": transfer_data(PAYEE, 1_000_000), "from": ME, "chainId": CHAIN})
    assert r.flags == ["UNSUPPORTED_CHAIN"]


def test_registered_token_still_needs_allowed_tokens():
    register_stablecoin("tusd8", CHAIN, TOKEN, 6)
    r = pay()
    assert r.flags == ["UNSUPPORTED_ASSET"] and "TUSD8 is not enabled" in r.explanation
    assert pay(allowed_tokens=["USDC", "TUSD8"]).decision == ActionDecision.APPROVE


def test_registered_token_gets_every_check():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6)
    on = {"allowed_tokens": ["TUSD8"]}
    assert pay(amount=5000, max_amount=1000, **on).flags == ["HIGH_VALUE_TRANSFER"]
    assert pay(known_recipients=[OTHER], **on).decision == ActionDecision.HOLD
    assert pay(peg_deviation_pct=-6, **on).decision == ActionDecision.REJECT
    assert pay(chain_id=1, **on).flags == ["UNSUPPORTED_CHAIN"]


def test_transaction_by_contract_address():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6)
    tx = {"to": TOKEN.upper().replace("0X", "0x"), "data": transfer_data(PAYEE, 25_000_000), "from": ME,
          "chainId": CHAIN}
    assert check_transaction(tx, allowed_tokens=["TUSD8"], peg_deviation_pct=0.0).decision == ActionDecision.APPROVE
    r = check_transaction({**tx, "data": approve_data(OTHER, 2**256 - 1)}, allowed_tokens=["TUSD8"])
    assert r.flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"] and "TUSD8" in r.explanation


def test_decimals_are_per_chain():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 18)
    r = check_transaction({"to": TOKEN, "data": transfer_data(PAYEE, 25 * 10**18), "from": ME, "chainId": CHAIN},
                          allowed_tokens=["TUSD8"], max_amount=10, peg_deviation_pct=0.0)
    assert r.flags == ["HIGH_VALUE_TRANSFER"] and "25" in r.explanation


def test_user_operation_on_registered_chain():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6)
    from eth_abi import encode
    calls = [(TOKEN, 0, bytes.fromhex(transfer_data(PAYEE, 600_000_000)[2:]))] * 2
    data = "0x34fcd5be" + encode(["(address,uint256,bytes)[]"], [calls]).hex()
    op = {"sender": ME, "nonce": "0x0", "callData": data, "callGasLimit": "0x1", "verificationGasLimit": "0x1",
          "preVerificationGas": "0x1", "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1", "signature": "0x"}
    r = check_user_operation(op, chain_id=CHAIN, allowed_tokens=["TUSD8"], max_amount=1000, peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.HOLD and "BATCH_TOTAL" in r.flags and "1200 TUSD8" in r.explanation


def typed(**domain):
    return {"primaryType": "TransferWithAuthorization",
            "domain": {"name": "T", "version": "1", "chainId": CHAIN, "verifyingContract": TOKEN, **domain},
            "message": {"from": ME, "to": PAYEE, "value": "1000000", "validAfter": str(NOW - 60),
                        "validBefore": str(NOW + 300), "nonce": "0x" + "ab" * 32}}


def test_eip3009_only_when_declared():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6)
    r = check_authorization(typed(), now=NOW, allowed_tokens=["TUSD8"], peg_deviation_pct=0.0)
    assert r.flags == ["UNSUPPORTED_SIGNATURE"]
    _reset_registry()
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6, eip3009=True)
    r = check_authorization(typed(), now=NOW, allowed_tokens=["TUSD8"], peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.APPROVE, r.explanation


def test_settlement_and_allowances_by_symbol():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6)
    word = lambda a: "0x" + a.lower()[2:].zfill(64)
    rc = {"status": "0x1", "blockNumber": "0x1", "logs": [
        {"address": TOKEN, "topics": [TRANSFER_TOPIC, word(ME), word(PAYEE)], "data": "0x" + format(2_500_000, "064x")}]}
    r = verify_settlement(rc, chain_id=CHAIN, payer=ME, payee=PAYEE, amount="2.5", token="TUSD8")
    assert r.verified and "2.5 TUSD8" in r.explanation
    a = check_allowances(ME, {OTHER: 2**256 - 1}, token="TUSD8", chain_id=CHAIN)
    assert a.flags == ["UNLIMITED_ALLOWANCE"] and "TUSD8" in a.explanation


def test_cannot_change_or_shadow_builtins():
    with pytest.raises(ValueError, match="built in"):
        register_stablecoin("USDC", CHAIN, TOKEN, 6)
    with pytest.raises(ValueError, match="already listed as USDC"):
        register_stablecoin("FAKE", 8453, USDC_ADDRESSES[8453], 6)
    assert stablecoin_at(8453, USDC_ADDRESSES[8453]) == ("USDC", 6)


def test_conflicts_and_idempotence():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6)
    register_stablecoin("TUSD8", CHAIN, TOKEN.upper().replace("0X", "0x"), 6)  # same details: no-op
    with pytest.raises(ValueError, match="different details"):
        register_stablecoin("TUSD8", CHAIN, TOKEN, 18)
    with pytest.raises(ValueError, match="already listed as TUSD8"):
        register_stablecoin("OTHER", CHAIN, TOKEN, 6)
    assert registered_stablecoins() == {"TUSD8": {CHAIN: (TOKEN, 6)}}


@pytest.mark.parametrize("args", [
    ("", CHAIN, TOKEN, 6), ("WAY_TOO_LONG_SYMBOL", CHAIN, TOKEN, 6), ("T-USD", CHAIN, TOKEN, 6),
    ("T", 0, TOKEN, 6), ("T", True, TOKEN, 6), ("T", "1", TOKEN, 6),
    ("T", CHAIN, "0x123", 6), ("T", CHAIN, "0x" + "0" * 40, 6), ("T", CHAIN, "0x" + "zz" * 20, 6),
    ("T", CHAIN, TOKEN, -1), ("T", CHAIN, TOKEN, 37), ("T", CHAIN, TOKEN, True), ("T", CHAIN, TOKEN, 6.0)])
def test_bad_registrations_are_refused(args):
    with pytest.raises(ValueError):
        register_stablecoin(*args)
    assert registered_stablecoins() == {}


def test_reset_restores_builtins():
    register_stablecoin("TUSD8", CHAIN, TOKEN, 6, eip3009=True)
    assert CHAIN in STABLECOIN_CHAINS and ("TUSD8", CHAIN) in EIP3009_TOKENS and "TUSD8" in STABLECOINS
    _reset_registry()
    assert CHAIN not in STABLECOIN_CHAINS and ("TUSD8", CHAIN) not in EIP3009_TOKENS and "TUSD8" not in STABLECOINS
    assert set(STABLECOINS) == {"USDC", "USDT", "USDB", "USDG"}
