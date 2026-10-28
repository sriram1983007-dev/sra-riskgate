"""0.14.0: Circle Wallets (developer-controlled) requests are checked before they are sent to Circle."""
import json
import time

import pytest

from sra_riskgate import ActionDecision, CircleRequestBlocked, check_circle_request, guard_circle_wallets
from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.sanctions import SanctionsList

WALLET_ID = "c4d1da72-111e-4d52-bdbf-2e74a2d803d5"
ME = "0x" + "a" * 40
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
SANCTIONED = sorted(SanctionsList.bundled().addresses)[0]
USDC_ARC = USDC_ADDRESSES[5042002]
USDC_BASE = USDC_ADDRESSES[8453]
USDC_TOKEN_ID = "7adb2b7d-c9cd-5164-b2d4-b73b088274dc"
POLICY = dict(wallets={WALLET_ID: ME}, peg_deviation_pct=0.1)


def transfer(**kw):
    body = {"idempotencyKey": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "entitySecretCiphertext": "x",
            "walletId": WALLET_ID, "blockchain": "ARC-TESTNET", "tokenAddress": USDC_ARC,
            "destinationAddress": PAYEE, "amounts": ["2.5"], "feeLevel": "MEDIUM"}
    body.update(kw)
    return {k: v for k, v in body.items() if v is not None}


def check(op, body, **kw):
    return check_circle_request(op, body, **{**POLICY, **kw})


# ------------------------------------------------------------------ transfers
def test_usdc_transfer_by_token_address_is_approved():
    assert check("transfer", transfer()).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("op", ["transfer", "transactions/transfer", "/v1/w3s/developer/transactions/transfer",
                                "create_developer_transaction_transfer"])
def test_operation_names(op):
    assert check(op, transfer()).decision == ActionDecision.APPROVE


def test_transfer_gets_the_payment_checks():
    assert check("transfer", transfer(destinationAddress=SANCTIONED)).decision == ActionDecision.REJECT
    assert check("transfer", transfer(), known_recipients=[OTHER]).flags == ["NEW_COUNTERPARTY"]
    r = check("transfer", transfer(amounts=["20"]), max_amount=10)
    assert r.decision == ActionDecision.HOLD and "HIGH_VALUE_TRANSFER" in r.flags
    assert check("transfer", transfer(destinationAddress=ME)).decision == ActionDecision.REJECT  # self-transfer


def test_amount_is_rounded_up_so_dust_cannot_pass_a_limit():
    r = check("transfer", transfer(amounts=["10.0000000000001"]), max_amount=10)
    assert "HIGH_VALUE_TRANSFER" in r.flags


def test_native_usdc_send_on_arc_is_a_payment():
    body = transfer(tokenAddress=None)
    assert check("transfer", body).decision == ActionDecision.APPROVE
    assert check("transfer", body, max_amount=1).decision == ActionDecision.HOLD


def test_native_send_elsewhere_is_held():
    body = transfer(tokenAddress=None, blockchain="BASE")
    assert check("transfer", body).flags == ["NATIVE_VALUE_TRANSFER"]


def test_other_tokens_and_nfts_are_held():
    assert check("transfer", transfer(tokenAddress=OTHER)).flags == ["UNSUPPORTED_ASSET"]
    assert check("transfer", transfer(nftTokenIds=["1"], amounts=["1"])).flags == ["UNSUPPORTED_ASSET"]


def test_token_id_must_be_a_configured_usdc_id():
    body = transfer(tokenAddress=None, blockchain=None, tokenId=USDC_TOKEN_ID)
    assert check("transfer", body, chain="ARC-TESTNET").flags == ["UNSUPPORTED_ASSET"]
    r = check("transfer", body, chain="ARC-TESTNET", usdc_token_ids=[USDC_TOKEN_ID])
    assert r.decision == ActionDecision.APPROVE
    assert check("transfer", body, usdc_token_ids=[USDC_TOKEN_ID]).flags == ["UNKNOWN_WALLET"]  # no chain


def test_wallet_must_be_known_and_match():
    assert check_circle_request("transfer", transfer(), peg_deviation_pct=0.1).flags == ["UNKNOWN_WALLET"]
    assert check("transfer", transfer(walletAddress=OTHER)).flags == ["WALLET_MISMATCH"]
    body = transfer(walletId=None, walletAddress=ME)
    assert check_circle_request("transfer", body, peg_deviation_pct=0.1).decision == ActionDecision.APPROVE


def test_only_configured_wallets_can_be_used():
    other_wallet = "d5e2eb83-222f-4e63-ceac-3f85b3e914e6"
    assert check("transfer", transfer(walletId=other_wallet)).flags == ["UNKNOWN_WALLET"]
    assert check("transfer", transfer(walletId=other_wallet), sender=ME).flags == ["UNKNOWN_WALLET"]


def test_chain_must_match_configuration_and_be_supported():
    assert check("transfer", transfer(), chain=8453).flags == ["WALLET_MISMATCH"]
    assert check("transfer", transfer(blockchain="SOL")).flags == ["UNSUPPORTED_CHAIN"]
    assert check("transfer", transfer(blockchain="BASE", tokenAddress=USDC_BASE)).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("body", [transfer(amounts=[]), transfer(amounts=["1", "2"]), transfer(amounts=["abc"]),
                                  transfer(amounts=["NaN"]), transfer(destinationAddress=None),
                                  transfer(tokenId=USDC_TOKEN_ID)])
def test_malformed_transfers_never_approve(body):
    assert check("transfer", body).decision != ActionDecision.APPROVE


# ------------------------------------------------------------------ contract execution
def execution(**kw):
    body = {"walletId": WALLET_ID, "blockchain": "ARC-TESTNET", "contractAddress": USDC_ARC,
            "abiFunctionSignature": "transfer(address,uint256)", "abiParameters": [PAYEE, "2500000"]}
    body.update(kw)
    return {k: v for k, v in body.items() if v is not None}


def test_usdc_transfer_call_is_approved():
    assert check("contractExecution", execution()).decision == ActionDecision.APPROVE
    assert check("contractExecution", execution(abiFunctionSignature="transfer(address, uint256)")).decision \
        == ActionDecision.APPROVE


def test_transfer_call_gets_the_payment_checks():
    r = check("contractExecution", execution(abiParameters=[PAYEE, "20000000"]), max_amount=10)
    assert "HIGH_VALUE_TRANSFER" in r.flags


def test_raw_call_data_is_checked():
    data = "0xa9059cbb" + PAYEE[2:].zfill(64) + format(2_500_000, "064x")
    body = execution(abiFunctionSignature=None, abiParameters=None, callData=data)
    assert check("contractExecution", body).decision == ActionDecision.APPROVE


def test_unlimited_approve_is_held():
    body = execution(abiFunctionSignature="approve(address,uint256)", abiParameters=[OTHER, str(2**256 - 1)])
    r = check("contractExecution", body)
    assert r.decision == ActionDecision.HOLD and "TOKEN_APPROVAL" in r.flags and "UNLIMITED_APPROVAL" in r.flags


@pytest.mark.parametrize("sig,params", [("burn(uint256)", ["100"]), ("transferFrom(address,address,uint256)",
                                                                       [OTHER, PAYEE, "1"])])
def test_other_functions_are_held(sig, params):
    r = check("contractExecution", execution(abiFunctionSignature=sig, abiParameters=params))
    assert r.decision == ActionDecision.HOLD and "UNSUPPORTED_FUNCTION" in r.flags


def test_call_to_another_contract_is_held():
    assert check("contractExecution", execution(contractAddress=OTHER)).flags == ["UNSUPPORTED_ASSET"]


def test_native_value_with_a_call_is_held():
    assert check("contractExecution", execution(amount="1.0")).flags == ["NATIVE_VALUE_TRANSFER"]
    assert check("contractExecution", execution(amount="0")).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("kw", [dict(abiParameters=[PAYEE]), dict(abiParameters=["not-an-address", "1"]),
                                dict(abiParameters=[PAYEE, "-1"]), dict(callData="0xa9059cbb"),
                                dict(abiFunctionSignature=None, abiParameters=None), dict(contractAddress=None)])
def test_malformed_calls_never_approve(kw):
    assert check("contractExecution", execution(**kw)).decision != ActionDecision.APPROVE


# ------------------------------------------------------------------ signing
GATEWAY = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9"


def typed(domain, valid_for=300):
    now = int(time.time())
    return {"types": {"TransferWithAuthorization": [
        {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]},
        "primaryType": "TransferWithAuthorization", "domain": domain,
        "message": {"from": ME, "to": PAYEE, "value": "10000", "validAfter": str(now - 600),
                    "validBefore": str(now + valid_for), "nonce": "0x" + "ab" * 32}}


def sign_typed(td, **kw):
    body = {"walletId": WALLET_ID, "blockchain": "ARC-TESTNET", "data": json.dumps(td), "memo": "pay"}
    body.update(kw)
    return body


def test_x402_typed_data_is_checked():
    td = typed({"name": "USDC", "version": "2", "chainId": 5042002, "verifyingContract": USDC_ARC})
    assert check("signTypedData", sign_typed(td)).decision == ActionDecision.APPROVE
    long = typed({"name": "USDC", "version": "2", "chainId": 5042002, "verifyingContract": USDC_ARC}, 86400)
    assert check("sign/typedData", sign_typed(long)).flags == ["LONG_LIVED_AUTHORIZATION"]


def test_gateway_typed_data_uses_the_gateway_limit():
    td = typed({"name": "GatewayWalletBatched", "version": "1", "chainId": 5042002, "verifyingContract": GATEWAY},
               7 * 86400 + 100)
    assert check("signTypedData", sign_typed(td)).decision == ActionDecision.APPROVE
    assert check("signTypedData", sign_typed(td), max_gateway_validity_seconds=86400).flags \
        == ["LONG_LIVED_AUTHORIZATION"]


def test_typed_data_for_another_chain_or_wallet_is_held():
    td = typed({"name": "USDC", "version": "2", "chainId": 8453, "verifyingContract": USDC_BASE})
    assert check("signTypedData", sign_typed(td)).flags == ["AUTHORIZATION_MISMATCH"]
    td = typed({"name": "USDC", "version": "2", "chainId": 5042002, "verifyingContract": USDC_ARC})
    td["message"]["from"] = OTHER
    assert check("signTypedData", sign_typed(td)).flags == ["AUTHORIZATION_MISMATCH"]


def test_generic_evm_wallet_takes_chain_from_payload():
    td = typed({"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC_BASE})
    assert check("signTypedData", sign_typed(td, blockchain="EVM")).decision == ActionDecision.APPROVE


def test_permit_is_held():
    td = {"primaryType": "Permit", "domain": {"name": "USDC", "version": "2", "chainId": 5042002,
                                              "verifyingContract": USDC_ARC},
          "message": {"owner": ME, "spender": OTHER, "value": str(2**256 - 1), "nonce": 0, "deadline": 2**40}}
    r = check("signTypedData", sign_typed(td))
    assert "TOKEN_APPROVAL" in r.flags and "UNLIMITED_APPROVAL" in r.flags


def test_sign_transaction_is_checked():
    tx = {"to": USDC_ARC, "data": "0xa9059cbb" + PAYEE[2:].zfill(64) + format(1_000_000, "064x"),
          "value": 0, "chainId": 5042002, "nonce": "0x1", "gas": "0x186A0"}
    assert check("signTransaction", {"walletId": WALLET_ID, "transaction": json.dumps(tx)}).decision \
        == ActionDecision.APPROVE
    tx_delegation = {**tx, "type": 4, "authorizationList": [{"address": OTHER, "chainId": 0}]}
    assert check("sign/transaction", {"walletId": WALLET_ID, "transaction": json.dumps(tx_delegation)}).flags \
        == ["CODE_DELEGATION"]
    assert check("signTransaction", {"walletId": WALLET_ID, "blockchain": "BASE", "transaction": json.dumps(tx)}
                 ).flags == ["TRANSACTION_MISMATCH"]
    assert check("signTransaction", {"walletId": WALLET_ID, "rawTransaction": "0x02f8"}).flags \
        == ["UNSUPPORTED_OPERATION"]


@pytest.mark.parametrize("op,flag", [("signMessage", "UNSUPPORTED_OPERATION"), ("sign/message", "UNSUPPORTED_OPERATION"),
                                     ("walletUpgrade", "CODE_DELEGATION"), ("frobnicate", "UNSUPPORTED_OPERATION")])
def test_unsupported_operations_are_held(op, flag):
    assert check(op, {"walletId": WALLET_ID, "message": "hello"}).flags == [flag]


def test_unknown_policy_is_a_configuration_error():
    r = check_circle_request("transfer", transfer(), max_amont=5)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]


def test_never_raises_on_garbage():
    for body in (None, 42, "x", [], {"walletId": WALLET_ID, "blockchain": 7}):
        for op in ("transfer", "contractExecution", "signTypedData", "signTransaction"):
            assert check(op, body).decision != ActionDecision.APPROVE


# ------------------------------------------------------------------ guarding an API object
class FakeApi:
    def __init__(self):
        self.sent = []

    def create_developer_transaction_transfer(self, request, x_request_id=None):
        self.sent.append(request)
        return {"data": {"id": "tx-1", "state": "INITIATED"}}

    def get_transaction(self, id):
        return {"id": id}


def test_guard_sends_only_approved_requests():
    api, seen = FakeApi(), []
    guarded = guard_circle_wallets(api, on_decision=lambda **e: seen.append(e["assessment"].decision), **POLICY)
    assert guarded.create_developer_transaction_transfer(transfer())["data"]["id"] == "tx-1"
    with pytest.raises(CircleRequestBlocked) as err:
        guarded.create_developer_transaction_transfer(transfer(destinationAddress=SANCTIONED))
    assert err.value.assessment.decision == ActionDecision.REJECT and "not sent" in str(err.value)
    assert len(api.sent) == 1
    assert guarded.get_transaction("tx-1") == {"id": "tx-1"}  # read-only calls pass through
    assert seen == [ActionDecision.APPROVE, ActionDecision.REJECT]


def test_guard_rejects_a_misconfigured_policy_at_wrap_time():
    with pytest.raises(ValueError):
        guard_circle_wallets(FakeApi(), max_amont=5)


def test_with_the_official_sdk_models():
    """The SDK's request models (camelCase to_dict, enum blockchain) are read like plain dicts."""
    sdk = pytest.importorskip("circle.web3.developer_controlled_wallets")
    req = sdk.CreateTransferTransactionForDeveloperRequest.from_dict(transfer())
    assert check("create_developer_transaction_transfer", req).decision == ActionDecision.APPROVE
    req = sdk.CreateContractExecutionTransactionForDeveloperRequest.from_dict(
        {**execution(abiFunctionSignature="approve(address,uint256)", abiParameters=[OTHER, str(2**256 - 1)]),
         "idempotencyKey": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "entitySecretCiphertext": "x"})
    assert "UNLIMITED_APPROVAL" in check("create_developer_transaction_contract_execution", req).flags
    td = typed({"name": "USDC", "version": "2", "chainId": 5042002, "verifyingContract": USDC_ARC})
    req = sdk.SignTypedDataRequest.from_dict({**sign_typed(td), "entitySecretCiphertext": "x"})
    assert check("sign_typed_data", req).decision == ActionDecision.APPROVE
    api = sdk.TransactionsApi.__new__(sdk.TransactionsApi)  # no network: the guard blocks before any call
    guarded = guard_circle_wallets(api, **POLICY)
    with pytest.raises(CircleRequestBlocked):
        guarded.create_developer_transaction_transfer(
            sdk.CreateTransferTransactionForDeveloperRequest.from_dict(transfer(destinationAddress=SANCTIONED)))
