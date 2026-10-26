"""0.12.1: EIP-7702 delegations are held, in a transaction or on their own (reported by a DEV.to reader)."""
import pytest

from sra_riskgate import ActionDecision, check_delegation, check_transaction
from sra_riskgate.chains import USDC_ADDRESSES

SENDER = "0x9649FbfB8121d8980F19AB8C028Eb2eC35916A86"
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
EVIL = "0x" + "d" * 40
TRANSFER = "0xa9059cbb" + PAYEE[2:].zfill(64) + format(1_000_000, "064x")
AUTH0 = {"chainId": 0, "address": EVIL, "nonce": 0, "yParity": 0, "r": 1, "s": 1}


def clean(**kw):
    tx = {"to": USDC_ADDRESSES[8453], "data": TRANSFER, "value": 0, "from": SENDER, "chainId": 8453}
    tx.update(kw)
    return tx


def check(tx):
    return check_transaction(tx, peg_deviation_pct=0.0)


def test_clean_transfer_still_approved():
    assert check(clean()).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("key", ["authorizationList", "authorization_list", "authorizations"])
def test_clean_transfer_carrying_a_delegation_is_held(key):
    r = check(clean(type=4, **{key: [AUTH0]}))
    assert r.decision == ActionDecision.HOLD and r.flags == ["CODE_DELEGATION"]
    assert EVIL in r.explanation and "every chain" in r.explanation


@pytest.mark.parametrize("tx_type", [4, "4", "0x4", "0x04", "0X4"])
def test_type_4_is_held_even_without_a_readable_list(tx_type):
    assert check(clean(type=tx_type)).flags == ["CODE_DELEGATION"]


def test_list_without_type_is_still_held():
    assert check(clean(authorizationList=[{"chainId": 8453, "address": EVIL, "nonce": 3}])).flags == ["CODE_DELEGATION"]


@pytest.mark.parametrize("bad", ["0xdeadbeef", 5, {"address": EVIL}, [None], [[1, 2, 3]]])
def test_malformed_lists_are_held(bad):
    assert check(clean(authorizationList=bad)).flags == ["CODE_DELEGATION"]


def test_delegation_beats_every_other_rule():
    # even on an unsupported chain, with native value, the delegation is what gets reported
    assert check(clean(chainId=137, value=1, authorizationList=[AUTH0])).flags == ["CODE_DELEGATION"]


def test_ordinary_types_are_unaffected():
    for t in (0, 2, "0x2", None):
        assert check(clean(type=t)).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("auth", [AUTH0, {"chain_id": 1, "contractAddress": EVIL}, None, "junk", 7])
def test_check_delegation_always_holds(auth):
    r = check_delegation(auth)
    assert r.decision == ActionDecision.HOLD and r.flags == ["CODE_DELEGATION"]


def test_check_delegation_names_target_and_scope():
    r = check_delegation(AUTH0)
    assert EVIL in r.explanation and "every chain" in r.explanation


def test_empty_list_on_an_ordinary_transaction_is_fine():
    assert check(clean(type=2, authorizationList=[])).decision == ActionDecision.APPROVE
    assert check(clean(authorizationList=())).decision == ActionDecision.APPROVE


def test_empty_list_on_type_4_is_still_held():
    assert check(clean(type=4, authorizationList=[])).flags == ["CODE_DELEGATION"]
