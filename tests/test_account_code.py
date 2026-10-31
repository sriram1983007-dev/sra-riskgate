"""0.16.0: an account already delegated under EIP-7702 (code 0xef0100 + delegate) is held before any payment."""
import time

import pytest

from sra_riskgate import (ActionDecision, check_account_code, check_authorization, check_circle_request,
                          check_payment, check_transaction, delegate_from_code)
from sra_riskgate.chains import USDC_ADDRESSES

ME, PAYEE = "0x" + "a" * 40, "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
DELEGATE = "0x" + "d" * 40
OK_DELEGATE = "0x" + "e" * 40
DESIGNATOR = "0xef0100" + "d" * 40


def pay(**kw):
    return check_payment(chain_id=8453, sender=ME, recipient=PAYEE, amount=5.0, peg_deviation_pct=0.1, **kw)


@pytest.mark.parametrize("code", [DESIGNATOR, DESIGNATOR.upper().replace("0X", "0x"), bytes.fromhex(DESIGNATOR[2:]),
                                  DESIGNATOR[2:]])
def test_delegated_account_is_held(code):
    r = pay(account_code=code)
    assert r.decision == ActionDecision.HOLD and r.flags == ["ACCOUNT_DELEGATED"]
    assert DELEGATE in r.explanation and "stop_signing" in r.required_actions


@pytest.mark.parametrize("code", ["0x", "", b"", "0x6080604052"])  # plain EOA, or an ordinary contract wallet
def test_plain_and_contract_accounts_pass(code):
    assert pay(account_code=code).decision == ActionDecision.APPROVE


def test_expected_delegate_passes():
    code = "0xef0100" + "e" * 40
    assert pay(account_code=code, expected_delegates=[OK_DELEGATE]).decision == ActionDecision.APPROVE
    assert pay(account_code=code, expected_delegates=[DELEGATE]).flags == ["ACCOUNT_DELEGATED"]


def test_not_given_means_not_checked():
    assert pay().decision == ActionDecision.APPROVE


@pytest.mark.parametrize("code", ["0xzz", "0x123", 42, ["0x"]])
def test_unreadable_code_is_held(code):
    r = pay(account_code=code)
    assert r.decision == ActionDecision.HOLD and r.flags == ["INVALID_ACCOUNT_CODE"]


def test_bad_expected_delegates_is_a_configuration_error():
    r = pay(account_code=DESIGNATOR, expected_delegates="0xabc")
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]


def test_sanctions_and_blocklist_still_come_first():
    assert pay(account_code=DESIGNATOR, blocked_addresses=[PAYEE]).flags[0] == "BLOCKLISTED_ADDRESS"


def test_designator_parsing_is_exact():
    assert delegate_from_code(DESIGNATOR) == DELEGATE
    assert delegate_from_code(DESIGNATOR + "00") is None          # longer than a designator: ordinary code
    assert delegate_from_code("0xef0101" + "d" * 40) is None
    assert check_account_code("0x") is None


def test_every_paying_check_takes_it():
    data = "0xa9059cbb" + PAYEE[2:].zfill(64) + format(1_000_000, "064x")
    r = check_transaction({"to": USDC_ADDRESSES[8453], "data": data, "chainId": 8453, "from": ME},
                          account_code=DESIGNATOR, peg_deviation_pct=0.1)
    assert r.flags == ["ACCOUNT_DELEGATED"]
    now = int(time.time())
    td = {"primaryType": "TransferWithAuthorization",
          "domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC_ADDRESSES[8453]},
          "message": {"from": ME, "to": PAYEE, "value": "1000000", "validAfter": str(now - 60),
                      "validBefore": str(now + 300), "nonce": "0x" + "ab" * 32}}
    assert check_authorization(td, account_code=DESIGNATOR, peg_deviation_pct=0.1).flags == ["ACCOUNT_DELEGATED"]
    body = {"walletAddress": ME, "blockchain": "BASE", "tokenAddress": USDC_ADDRESSES[8453],
            "destinationAddress": PAYEE, "amounts": ["1"]}
    assert check_circle_request("transfer", body, account_code=DESIGNATOR, peg_deviation_pct=0.1).flags \
        == ["ACCOUNT_DELEGATED"]


def test_real_designator_from_eth_account():
    """The designator an EIP-7702 authorization actually installs: 0xef0100 + the signed contract address."""
    eth_account = pytest.importorskip("eth_account")
    acct = eth_account.Account.from_key("0x" + "11" * 32)
    signed = acct.sign_authorization({"chainId": 8453, "address": DELEGATE, "nonce": 0})
    code = "0xef0100" + signed.address.hex().removeprefix("0x") if isinstance(signed.address, bytes) \
        else "0xef0100" + str(signed.address).lower().removeprefix("0x")
    assert delegate_from_code(code) == DELEGATE
    assert pay(account_code=code).flags == ["ACCOUNT_DELEGATED"]


# ---- 0.16.1: the three audit fixes -------------------------------------------------------------------------------
UNLIMITED = 2**256 - 1


def _approve_tx():
    data = "0x095ea7b3" + ("1" * 40).zfill(64) + format(UNLIMITED, "064x")
    return {"to": USDC_ADDRESSES[8453], "data": data, "chainId": 8453, "from": ME}


def _permit():
    return {"primaryType": "Permit",
            "domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC_ADDRESSES[8453]},
            "message": {"owner": ME, "spender": "0x" + "1" * 40, "value": str(UNLIMITED), "nonce": 0,
                        "deadline": 2**40}}


def test_delegated_account_outranks_approval_holds():
    """A compromised account says 'stop signing', which matters more than 'this is an approval'."""
    r = check_transaction(_approve_tx(), account_code=DESIGNATOR)
    assert r.flags == ["ACCOUNT_DELEGATED"] and "stop_signing" in r.required_actions
    r = check_authorization(_permit(), account_code=DESIGNATOR)
    assert r.flags == ["ACCOUNT_DELEGATED"] and "stop_signing" in r.required_actions
    # with a clean account the approval is still held as an approval
    assert check_transaction(_approve_tx(), account_code="0x").flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]
    assert check_authorization(_permit(), account_code="0x").flags[0] == "TOKEN_APPROVAL"


def test_reject_still_outranks_a_delegated_account():
    r = pay(account_code=DESIGNATOR, blocked_addresses=[PAYEE])
    assert r.decision == ActionDecision.REJECT


def test_account_code_can_be_bound_to_the_sender():
    assert pay(account_code={ME: "0x"}).decision == ActionDecision.APPROVE
    assert pay(account_code={ME.upper().replace("0X", "0x"): DESIGNATOR}).flags == ["ACCOUNT_DELEGATED"]
    r = pay(account_code={"0x" + "b" * 40: "0x"})            # code read from another account
    assert r.decision == ActionDecision.HOLD and r.flags == ["ACCOUNT_CODE_MISMATCH"]
    assert check_transaction(_approve_tx(), account_code={"0x" + "b" * 40: "0x"}).flags == ["ACCOUNT_CODE_MISMATCH"]
    r = pay(account_code={"not-an-address": "0x"})
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]


@pytest.mark.parametrize("bad", ["0xabc", ["0xabc"], "0x" + "e" * 40])
def test_bad_expected_delegates_is_caught_even_without_code(bad):
    """A typo in expected_delegates used to pass silently until the day code was passed in."""
    r = pay(expected_delegates=bad)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]
    r = check_authorization(_permit(), expected_delegates=bad)
    assert r.decision == ActionDecision.REJECT and r.flags == ["CONFIGURATION_ERROR"]


def test_good_expected_delegates_without_code_changes_nothing():
    assert pay(expected_delegates=[OK_DELEGATE]).decision == ActionDecision.APPROVE
