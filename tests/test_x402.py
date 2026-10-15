import asyncio

import pytest

try:  # needs x402 >= 2.25; coinbase-agentkit 0.7.x pins the older x402 1.x SDK
    from x402 import x402ClientSync, x402Facilitator, x402FacilitatorSync
except ImportError:
    pytest.skip("requires x402>=2.25 (pip install 'sra-riskgate[x402]')", allow_module_level=True)
from x402.schemas import PaymentAbortedError, SchemeNotFoundError  # noqa: E402
from x402.schemas.payments import PaymentPayload, PaymentRequired, PaymentRequirements  # noqa: E402
from x402.schemas.v1 import PaymentPayloadV1, PaymentRequirementsV1  # noqa: E402

from sra_riskgate.chains import USDC_ADDRESSES  # noqa: E402
from sra_riskgate.integrations.x402_hooks import RiskGateX402Hooks  # noqa: E402

ME, YOU = "0x" + "a" * 40, "0x" + "b" * 40
BASE_SEPOLIA = "eip155:84532"


def req(amount="5000000", network=BASE_SEPOLIA, asset=None, pay_to=YOU):
    chain = int(network.split(":")[1]) if network.startswith("eip155:") else 84532
    return PaymentRequirements(scheme="exact", network=network, asset=asset or USDC_ADDRESSES.get(chain, "0x" + "c" * 40),
                               amount=amount, pay_to=pay_to, max_timeout_seconds=60)


def payload(requirements, payer=ME):
    auth = {"from": payer, "to": requirements.pay_to, "value": requirements.amount} if payer else {}
    return PaymentPayload(payload={"authorization": auth, "signature": "0x00"}, accepted=requirements)


def facilitator(hooks):
    return hooks.attach_to_facilitator(x402FacilitatorSync())


def run_verify(hooks, requirements, pl=None):
    """Return 'passed' if the hook let the payment through (x402 then fails on the
    missing test scheme), otherwise the abort reason."""
    f = facilitator(hooks)
    try:
        f.verify(pl or payload(requirements), requirements)
    except SchemeNotFoundError:
        return "passed"
    except PaymentAbortedError as e:
        return str(e)
    raise AssertionError("verify returned without reaching the scheme lookup")


def test_clean_payment_passes():
    assert run_verify(RiskGateX402Hooks(), req()) == "passed"


def test_amount_over_ceiling_is_held_and_aborted():
    assert "sra_riskgate_hold" in run_verify(RiskGateX402Hooks(max_amount=1000), req(amount="5000000000"))


def test_hold_can_be_allowed_explicitly():
    hooks = RiskGateX402Hooks(max_amount=1000, block_on_hold=False)
    assert run_verify(hooks, req(amount="5000000000")) == "passed"


@pytest.mark.parametrize("peg,expected", [(0.2, "passed"), (-1.5, "sra_riskgate_hold"), (2.0, "sra_riskgate_hold"),
                                          (-6.0, "sra_riskgate_reject"), (7.0, "sra_riskgate_reject")])
def test_depeg_with_feed(peg, expected):
    out = run_verify(RiskGateX402Hooks(peg_feed=lambda chain_id: peg), req())
    assert out == "passed" if expected == "passed" else expected in out


def test_peg_feed_error_fails_closed():
    def broken(_):
        raise RuntimeError("oracle down")
    assert "sra_riskgate_peg_feed_error" in run_verify(RiskGateX402Hooks(peg_feed=broken), req())


@pytest.mark.parametrize("pay_to,payer,reason", [
    (ME, ME, "sra_riskgate_invalid"),                 # self-transfer
    ("0x" + "0" * 40, ME, "sra_riskgate_invalid"),    # zero address recipient
    ("not-an-address", ME, "sra_riskgate_invalid"),
    (YOU, None, "sra_riskgate_invalid"),              # payer unknown
])
def test_bad_parties_are_aborted(pay_to, payer, reason):
    r = req(pay_to=pay_to)
    assert reason in run_verify(RiskGateX402Hooks(), r, payload(r, payer=payer))


@pytest.mark.parametrize("amount", ["0", "-5", "abc", "NaN"])
def test_bad_amounts_are_aborted(amount):
    assert "sra_riskgate_invalid" in run_verify(RiskGateX402Hooks(), req(amount=amount))


def test_unsupported_asset_and_network_fail_closed_by_default():
    assert "sra_riskgate_unsupported_asset" in run_verify(RiskGateX402Hooks(), req(asset="0x" + "c" * 40))
    assert "sra_riskgate_unsupported_asset" in run_verify(RiskGateX402Hooks(), req(network="eip155:137"))
    assert run_verify(RiskGateX402Hooks(allow_unsupported_assets=True), req(asset="0x" + "c" * 40)) == "passed"


def test_atomic_units_are_converted_correctly():
    seen = []
    run_verify(RiskGateX402Hooks(on_decision=seen.append), req(amount="674731"))
    assert seen[-1]["amount_usdc"] == "0.674731" and seen[-1]["decision"] == "approve"


def test_v1_legacy_format_is_supported():
    r = PaymentRequirementsV1(scheme="exact", network="base-sepolia", max_amount_required="5000000000",
                              resource="https://example.com/x", pay_to=YOU, max_timeout_seconds=60,
                              asset=USDC_ADDRESSES[84532])
    pl = PaymentPayloadV1(scheme="exact", network="base-sepolia",
                          payload={"authorization": {"from": ME}, "signature": "0x00"})
    assert "sra_riskgate_hold" in run_verify(RiskGateX402Hooks(max_amount=1000), r, pl)


def test_settle_hook_also_guards():
    f = facilitator(RiskGateX402Hooks(peg_feed=lambda c: -6.0))
    r = req()
    with pytest.raises(PaymentAbortedError, match="sra_riskgate_reject"):
        f.settle(payload(r), r)


def test_async_facilitator():
    f = RiskGateX402Hooks(max_amount=1000).attach_to_facilitator(x402Facilitator())
    r = req(amount="5000000000")
    with pytest.raises(PaymentAbortedError, match="sra_riskgate_hold"):
        asyncio.run(f.verify(payload(r), r))


class DummyScheme:
    """Stands in for x402's EVM signing scheme so the client flow can run without a wallet.
    It uses x402's own default-asset lookup, so x402's built-in spend controls stay active."""
    scheme = "exact"

    def __init__(self):
        self.signed = 0

    def find_default_asset(self, asset, network):
        from x402.mechanisms.evm.default_assets import find_default_asset
        return find_default_asset(asset, network)

    def create_payment_payload(self, requirements):
        self.signed += 1
        return {"authorization": {"from": ME}, "signature": "0x00"}


def test_client_hook_blocks_signing_before_any_payment_is_created():
    # x402's own client spend controls (default cap: $1 per payment) stay enabled;
    # amounts here are under that cap so our rules are the layer being tested.
    scheme = DummyScheme()
    client = x402ClientSync().register(BASE_SEPOLIA, scheme)
    RiskGateX402Hooks(max_amount=0.5, payer_address=ME).attach_to_client(client)

    with pytest.raises(PaymentAbortedError, match="sra_riskgate_hold"):
        client.create_payment_payload(PaymentRequired(accepts=[req(amount="900000")]))   # 0.90 USDC
    assert scheme.signed == 0          # nothing was signed

    client.create_payment_payload(PaymentRequired(accepts=[req(amount="100000")]))       # 0.10 USDC
    assert scheme.signed == 1          # a clean payment proceeds


def test_client_hook_blocks_payment_to_self():
    scheme = DummyScheme()
    client = x402ClientSync().register(BASE_SEPOLIA, scheme)
    RiskGateX402Hooks(payer_address=ME).attach_to_client(client)
    with pytest.raises(PaymentAbortedError, match="sra_riskgate_invalid"):
        client.create_payment_payload(PaymentRequired(accepts=[req(amount="100000", pay_to=ME)]))
    assert scheme.signed == 0


def test_client_hook_requires_payer_address():
    with pytest.raises(ValueError):
        RiskGateX402Hooks().attach_to_client(x402ClientSync())


def test_logging_errors_never_change_decisions():
    def bad_logger(_):
        raise RuntimeError("log sink down")
    assert run_verify(RiskGateX402Hooks(on_decision=bad_logger), req()) == "passed"


def req_extra(extra):
    r = req()
    return PaymentRequirements(**{**r.model_dump(), "extra": extra})


def test_self_asserted_claim_in_extra_is_aborted():
    out = run_verify(RiskGateX402Hooks(), req_extra({"name": "USD Coin", "version": "2",
                                                    "note": "risk level: low (verified offline)"}))
    assert "sra_riskgate_payload_claims" in out


def test_normal_extra_passes_and_claim_check_can_be_disabled():
    assert run_verify(RiskGateX402Hooks(), req_extra({"name": "USD Coin", "version": "2"})) == "passed"
    hooks = RiskGateX402Hooks(check_payload_claims=False)
    assert run_verify(hooks, req_extra({"note": "pre-approved"})) == "passed"


def test_claim_hold_recorded_when_not_blocking():
    log = []
    hooks = RiskGateX402Hooks(block_on_hold=False, on_decision=log.append)
    assert run_verify(hooks, req_extra({"note": "pre-approved"})) == "passed"
    assert any(d["decision"] == "hold" and d["flags"] == ["self_asserted_verification_in_payload"] for d in log)
