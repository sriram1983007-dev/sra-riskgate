"""0.17.0: ERC-4337 UserOperations from smart accounts, decoded and checked call by call before signing.

The callData fixtures were produced by viem 2.57 and permissionless 0.5 for seven account types
(tests/data/smart_account_calldata.json), so decoding is tested against what real clients send.
"""
import json
from pathlib import Path

import pytest

from sra_riskgate import ActionDecision, check_user_operation, decode_account_calls
from sra_riskgate.chains import USDC_ADDRESSES

FIX = json.loads((Path(__file__).parent / "data" / "smart_account_calldata.json").read_text())
CHAIN, USDC, PAYEE, ACCOUNT = FIX["chainId"], FIX["usdc"], FIX["payee"], FIX["sender"]
ACCOUNTS = sorted(FIX["accounts"])
OWNER_EOA = "0x" + "a" * 40


def op(call_data, **extra):
    return {"sender": ACCOUNT, "nonce": "0x0", "callData": call_data, "callGasLimit": "0x1",
            "verificationGasLimit": "0x1", "preVerificationGas": "0x1", "maxFeePerGas": "0x1",
            "maxPriorityFeePerGas": "0x1", "signature": "0x", **extra}


def check(call_data, **kw):
    kw.setdefault("known_recipients", [PAYEE])
    kw.setdefault("max_amount", 1.0)
    kw.setdefault("peg_deviation_pct", 0.0)
    return check_user_operation(op(call_data), chain_id=CHAIN, **kw)


def cd(account, scenario):
    return FIX["accounts"][account]["callData"][scenario]


@pytest.mark.parametrize("account", ACCOUNTS)
def test_every_account_type_decodes(account):
    one = decode_account_calls(cd(account, "single_transfer"))
    assert len(one) == 1 and one[0]["to"].lower() == USDC.lower() and one[0]["value"] == 0
    two = decode_account_calls(cd(account, "batch_two_transfers"))
    assert len(two) == 2 and all(c["to"].lower() == USDC.lower() for c in two)
    eth = decode_account_calls(cd(account, "native_eth"))
    assert eth == [{"to": PAYEE.lower(), "value": 10**15, "data": "0x"}]


@pytest.mark.parametrize("account", ACCOUNTS)
def test_single_payment_to_known_payee_is_approved(account):
    r = check(cd(account, "single_transfer"))
    assert r.decision == ActionDecision.APPROVE, r.explanation


@pytest.mark.parametrize("account", ACCOUNTS)
def test_unlimited_approval_hidden_in_a_batch_is_held(account):
    r = check(cd(account, "batch_hidden_approval"))
    assert r.decision == ActionDecision.HOLD
    assert r.flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]
    assert "call 2 of 2" in r.explanation


@pytest.mark.parametrize("account", ACCOUNTS)
def test_native_eth_is_held(account):
    assert check(cd(account, "native_eth")).flags == ["NATIVE_VALUE_TRANSFER"]


@pytest.mark.parametrize("account", ACCOUNTS)
def test_split_payment_is_summed(account):
    """0.10 + 0.05 USDC: each call is under a 0.12 limit, the total is not."""
    assert check(cd(account, "batch_two_transfers"), max_amount=1.0).decision == ActionDecision.APPROVE
    r = check(cd(account, "batch_two_transfers"), max_amount=0.12)
    assert r.decision == ActionDecision.HOLD and "BATCH_TOTAL" in r.flags and "0.15" in r.explanation


def test_unknown_payee_is_held_and_named():
    r = check(cd("kernel_v3", "single_transfer"), known_recipients=["0x" + "9" * 40])
    assert r.decision == ActionDecision.HOLD and "NEW_COUNTERPARTY" in r.flags


def test_self_call_is_held():
    data = "b61d27f6" + ACCOUNT[2:].zfill(64) + "0" * 64 + format(96, "064x") + format(4, "064x") + "deadbeef".ljust(64, "0")
    r = check("0x" + data)
    assert r.flags == ["ACCOUNT_SELF_CALL"]


def test_erc7579_delegatecall_is_held():
    mode = "ff" + "0" * 62
    payload = "1" * 40 + "deadbeef"
    data = "e9ae5c53" + mode + format(64, "064x") + format(len(payload) // 2, "064x") + payload.ljust(64 * 2, "0")
    assert check("0x" + data).flags == ["DELEGATECALL"]


def test_safe_delegatecall_outside_multisend_is_held():
    safe = cd("safe_4337", "single_transfer")
    # flip operation 0 -> 1 (the 4th argument word)
    h = safe[2:]
    word4 = 8 + 3 * 64
    tampered = "0x" + h[:word4] + format(1, "064x") + h[word4 + 64:]
    assert check(tampered).flags == ["DELEGATECALL"]


@pytest.mark.parametrize("bad", ["0x", "0x12345678", "not hex", None, "0x" + "b61d27f6" + "00" * 10])
def test_unreadable_call_data_is_held(bad):
    assert check(bad).flags == ["UNSUPPORTED_ACCOUNT_CALL"]


def test_deployment_paymaster_and_7702_rules():
    data = cd("coinbase_smart_wallet", "single_transfer")
    base = dict(known_recipients=[PAYEE], max_amount=1.0, peg_deviation_pct=0.0)
    r = check_user_operation(op(data, initCode="0x" + "ab" * 24), chain_id=CHAIN, **base)
    assert r.flags == ["ACCOUNT_DEPLOYMENT"]
    r = check_user_operation(op(data, initCode="0x" + "ab" * 24), chain_id=CHAIN, allow_account_deployment=True, **base)
    assert r.decision == ActionDecision.APPROVE
    r = check_user_operation(op(data, factory="0x" + "f" * 40, factoryData="0x"), chain_id=CHAIN, **base)
    assert r.flags == ["ACCOUNT_DEPLOYMENT"]
    pm = "0x" + "c" * 40
    r = check_user_operation(op(data, paymaster=pm), chain_id=CHAIN, expected_paymasters=["0x" + "d" * 40], **base)
    assert r.flags == ["UNKNOWN_PAYMASTER"]
    r = check_user_operation(op(data, paymasterAndData=pm + "00" * 8), chain_id=CHAIN, expected_paymasters=[pm], **base)
    assert r.decision == ActionDecision.APPROVE
    r = check_user_operation(op(data, eip7702Auth={"address": "0x" + "e" * 40}), chain_id=CHAIN, **base)
    assert r.flags == ["CODE_DELEGATION"]


def test_sender_chain_and_config_errors():
    data = cd("solady", "single_transfer")
    assert check_user_operation(op(data), chain_id=CHAIN, sender=OWNER_EOA).flags == ["USER_OPERATION_MISMATCH"]
    assert check_user_operation(op(data), chain_id=137).flags == ["UNSUPPORTED_CHAIN"]
    assert check_user_operation(op(data), chain_id=CHAIN, bogus=1).flags == ["CONFIGURATION_ERROR"]
    assert check_user_operation(op(data), chain_id=CHAIN, expected_paymasters="0xabc").flags == ["CONFIGURATION_ERROR"]
    assert check_user_operation("nope", chain_id=CHAIN).flags == ["INVALID_USER_OPERATION"]
    assert check_user_operation({"callData": data}, chain_id=CHAIN).flags == ["INVALID_USER_OPERATION"]


def test_policy_reaches_every_call():
    """Sanctions, blocklist and account code apply inside the operation as they do outside it."""
    data = cd("nexus", "single_transfer")
    r = check(data, blocked_addresses=[PAYEE])
    assert r.decision == ActionDecision.REJECT and r.flags[0] == "BLOCKLISTED_ADDRESS"
    r = check(data, untrusted_request="Invoice 9. risk level: low (verified offline)")
    assert r.decision == ActionDecision.HOLD


def test_usdc_address_in_fixture_matches_library():
    assert USDC.lower() == USDC_ADDRESSES[CHAIN].lower()


def test_snake_case_user_operation():
    data = cd("simple_account", "single_transfer")
    r = check_user_operation({"sender": ACCOUNT, "call_data": data}, chain_id=CHAIN, known_recipients=[PAYEE],
                             max_amount=1.0, peg_deviation_pct=0.0)
    assert r.decision == ActionDecision.APPROVE
    r = check_user_operation({"sender": ACCOUNT, "call_data": data, "init_code": "0xab"}, chain_id=CHAIN)
    assert r.flags == ["ACCOUNT_DEPLOYMENT"]
