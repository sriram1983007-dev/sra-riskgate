"""0.18.0: an x402 server's maxTimeoutSeconds is checked before the agent signs for it."""
import pytest

from sra_riskgate import ActionDecision, check_x402_timeout
from sra_riskgate.chains import GATEWAY_WALLET_ADDRESSES

GATEWAY_EXTRA = {"name": "GatewayWalletBatched", "version": "1", "minValiditySeconds": 604800,
                 "verifyingContract": GATEWAY_WALLET_ADDRESSES[8453].lower()}


@pytest.mark.parametrize("seconds", [60, 300, 3600, "3600", 0])
def test_ordinary_timeouts_pass(seconds):
    # 60, 300 and 3600 are what live x402 services ask for.
    assert check_x402_timeout(seconds, chain_id=8453, extra={"name": "USD Coin", "version": "2"}) is None


@pytest.mark.parametrize("seconds", [3601, 86400, 30 * 86400])
def test_long_timeouts_are_held(seconds):
    r = check_x402_timeout(seconds, chain_id=8453)
    assert r.decision == ActionDecision.HOLD and r.flags == ["LONG_TIMEOUT_REQUESTED"]
    assert str(seconds) in r.explanation


def test_gateway_requirement_gets_the_gateway_limit():
    # Circle Gateway's batched x402 option asks for 604,900 seconds (7 days + 100 s).
    assert check_x402_timeout(604900, chain_id=8453, extra=GATEWAY_EXTRA) is None
    r = check_x402_timeout(30 * 86400, chain_id=8453, extra=GATEWAY_EXTRA)
    assert r.flags == ["LONG_TIMEOUT_REQUESTED"] and "Circle Gateway" in r.explanation


def test_gateway_name_with_another_contract_is_held():
    fake = {**GATEWAY_EXTRA, "verifyingContract": "0x77777777dcc4d5a8b6e418fd04d8997ef11000ef"}
    r = check_x402_timeout(604900, chain_id=8453, extra=fake)
    assert r.flags == ["UNSUPPORTED_ASSET"]


def test_gateway_extra_does_not_lift_the_limit_without_the_name():
    r = check_x402_timeout(604900, chain_id=8453, extra={"verifyingContract": GATEWAY_EXTRA["verifyingContract"]})
    assert r.flags == ["LONG_TIMEOUT_REQUESTED"]


def test_custom_limit():
    assert check_x402_timeout(600, chain_id=8453, max_validity_seconds=300).flags == ["LONG_TIMEOUT_REQUESTED"]


@pytest.mark.parametrize("bad", ["soon", None, True, -1, 1.5, [60]])
def test_bad_values_are_held(bad):
    r = check_x402_timeout(bad, chain_id=8453)
    assert r.decision == ActionDecision.HOLD and r.flags in (["INVALID_REQUIREMENTS"], ["CHECK_FAILED"])
