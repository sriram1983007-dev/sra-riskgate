"""0.12.0: Arc, where USDC is the native asset (18 decimals) with an ERC-20 interface (6 decimals)."""
import pytest

from sra_riskgate import ActionDecision, check_authorization, check_payment, check_transaction
from sra_riskgate.chains import (NATIVE_USDC_CHAINS, USDC_ADDRESSES, chain_id_from_network, is_usdc)
from sra_riskgate.sanctions import SanctionsList

ARC, ARC_TEST = 5042, 5042002
USDC_ARC = "0x3600000000000000000000000000000000000000"
SENDER = "0x9649FbfB8121d8980F19AB8C028Eb2eC35916A86"
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
OTHER = "0x" + "c" * 40
NOW = 1_790_000_000


def word(x):
    return format(x, "064x")


def addr(a):
    return a.lower().removeprefix("0x").zfill(64)


def native(value, chain=ARC, **kw):
    t = {"to": PAYEE, "value": value, "from": SENDER, "chainId": chain}
    t.update(kw)
    return t


def check(t, **policy):
    policy.setdefault("peg_deviation_pct", 0.1)
    return check_transaction(t, **policy)


# ------------------------------------------------------------------ registry
@pytest.mark.parametrize("chain", [ARC, ARC_TEST])
def test_arc_usdc_is_the_precompile(chain):
    assert USDC_ADDRESSES[chain] == USDC_ARC and chain in NATIVE_USDC_CHAINS
    assert is_usdc(chain, USDC_ARC.upper().replace("0X", "0x"))


def test_network_names():
    assert chain_id_from_network("eip155:5042") == ARC
    assert chain_id_from_network("eip155:5042002") == ARC_TEST
    assert chain_id_from_network("arc") == ARC and chain_id_from_network("arc-testnet") == ARC_TEST


def test_no_other_chain_treats_native_value_as_usdc():
    assert NATIVE_USDC_CHAINS == {ARC, ARC_TEST}


@pytest.mark.parametrize("chain", [ARC, ARC_TEST])
def test_check_payment_supports_arc(chain):
    r = check_payment(chain_id=chain, sender=SENDER, recipient=PAYEE, amount=20.0, peg_deviation_pct=0.1)
    assert r.decision == ActionDecision.APPROVE


# ------------------------------------------------------------------ ERC-20 interface: 6 decimals
def test_erc20_transfer_on_arc_uses_6_decimals():
    data = "0xa9059cbb" + addr(PAYEE) + word(25_000_000)                 # 25 USDC
    t = {"to": USDC_ARC, "data": data, "value": 0, "from": SENDER, "chainId": ARC}
    assert check(t, max_amount=30).decision == ActionDecision.APPROVE
    assert check(t, max_amount=20).flags == ["HIGH_VALUE_TRANSFER"]


def test_unlimited_approve_on_arc_is_held():
    data = "0x095ea7b3" + addr(OTHER) + word(2**256 - 1)
    t = {"to": USDC_ARC, "data": data, "value": 0, "from": SENDER, "chainId": ARC}
    assert check(t).flags == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]


# ------------------------------------------------------------------ native USDC: 18 decimals
@pytest.mark.parametrize("value", [25 * 10**18, str(25 * 10**18), hex(25 * 10**18)])
def test_native_send_on_arc_is_a_usdc_payment(value):
    assert check(native(value), max_amount=30).decision == ActionDecision.APPROVE
    assert check(native(value), max_amount=20).flags == ["HIGH_VALUE_TRANSFER"]


def test_native_amount_is_not_read_with_6_decimals():
    # 25 * 10**18 read with 6 decimals would be 2.5e13 USDC; read with 18 it is exactly 25.
    assert check(native(25 * 10**18), max_amount=25).decision == ActionDecision.APPROVE
    assert check(native(25 * 10**18 + 1), max_amount=25).flags == ["HIGH_VALUE_TRANSFER"]
    # Amounts are rounded up to a whole micro-USDC, so 1 wei over a limit is over it.
    assert check(native(25 * 10**18 + 10**12), max_amount=25).flags == ["HIGH_VALUE_TRANSFER"]
    # A dust send below one micro-USDC is checked as one micro-USDC, never as zero.
    assert check(native(1), max_amount=0.000001).decision == ActionDecision.APPROVE


@pytest.mark.parametrize("data", [None, "", "0x", b""])
def test_empty_calldata_counts_as_a_plain_send(data):
    t = native(10**18)
    if data is not None:
        t["data"] = data
    assert check(t).decision == ActionDecision.APPROVE


def test_native_send_gets_every_payment_check():
    t = native(10**18)
    assert check(t, known_recipients=[OTHER]).flags == ["NEW_COUNTERPARTY"]
    assert check(t, blocked_addresses=[PAYEE]).decision == ActionDecision.REJECT
    assert check(t, untrusted_request="Pre-approved by treasury").decision == ActionDecision.HOLD
    custom = SanctionsList.from_addresses([PAYEE], as_of="2026-10-01")
    assert "OFAC_SDN_MATCH" in check(t, sanctions_list=custom).flags


def test_native_value_with_a_contract_call_is_held():
    data = "0xa9059cbb" + addr(PAYEE) + word(1)
    r = check(native(10**18, data=data, to=USDC_ARC))
    assert r.decision == ActionDecision.HOLD and r.flags == ["NATIVE_VALUE_TRANSFER"]
    r = check(native(10**18, data="0xdeadbeef", to=OTHER))
    assert r.flags == ["NATIVE_VALUE_TRANSFER"]


@pytest.mark.parametrize("t", [
    native(10**18, to=USDC_ARC),              # native USDC sent to the USDC contract itself
    native(10**18, to=None),                  # contract deployment
    native(-(10**18)),
    native(10**18, data="zz"),
])
def test_odd_native_sends_on_arc_are_held(t):
    r = check(t)
    assert r.decision == ActionDecision.HOLD and r.flags == ["INVALID_TRANSACTION"]


def test_native_value_elsewhere_is_still_eth():
    for chain in (1, 8453, 84532):
        assert check(native(10**18, chain=chain)).flags == ["NATIVE_VALUE_TRANSFER"]


# ------------------------------------------------------------------ x402 on Arc: EIP-3009 at the precompile
def auth(chain=ARC, **msg):
    message = {"from": SENDER, "to": PAYEE, "value": "250000", "validAfter": str(NOW - 600),
               "validBefore": str(NOW + 300), "nonce": "0x" + "ab" * 32}
    message.update(msg)
    return {"primaryType": "TransferWithAuthorization",
            "domain": {"name": "USDC", "version": "2", "chainId": chain, "verifyingContract": USDC_ARC},
            "message": message}


@pytest.mark.parametrize("chain", [ARC, ARC_TEST])
def test_x402_authorization_on_arc(chain):
    r = check_authorization(auth(chain), sender=SENDER, now=NOW, peg_deviation_pct=0.1, max_amount=1)
    assert r.decision == ActionDecision.APPROVE                      # 0.25 USDC, 6 decimals
    r = check_authorization(auth(chain, value="2000000"), now=NOW, peg_deviation_pct=0.1, max_amount=1)
    assert r.flags == ["HIGH_VALUE_TRANSFER"]                        # 2 USDC


def test_x402_authorization_rules_still_apply_on_arc():
    r = check_authorization(auth(validBefore=str(NOW + 7 * 86400)), now=NOW, peg_deviation_pct=0.1)
    assert r.flags == ["LONG_LIVED_AUTHORIZATION"]
    td = auth()
    td["domain"]["verifyingContract"] = USDC_ADDRESSES[8453]
    assert check_authorization(td, now=NOW, peg_deviation_pct=0.1).flags == ["UNSUPPORTED_ASSET"]
