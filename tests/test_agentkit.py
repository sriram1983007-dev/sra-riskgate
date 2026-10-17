from decimal import Decimal

import pytest

pytest.importorskip("coinbase_agentkit")
from coinbase_agentkit import AgentKit, AgentKitConfig, EvmWalletProvider  # noqa: E402
from coinbase_agentkit.network import Network  # noqa: E402
from eth_abi import encode  # noqa: E402

from sra_riskgate.integrations.agentkit import (  # noqa: E402
    USDC_ADDRESSES, RiskGateActionProvider, encode_erc20_transfer)

ME, YOU = "0x" + "a" * 40, "0x" + "b" * 40


class MockWallet(EvmWalletProvider):
    def __init__(self, chain_id="8453", status=1, protocol="evm"):
        self.chain_id, self.status, self.protocol = chain_id, status, protocol
        self.sent, self.native = [], []

    def get_address(self): return ME
    def get_name(self): return "mock"
    def get_network(self): return Network(protocol_family=self.protocol, network_id="x", chain_id=self.chain_id)
    def get_balance(self): return Decimal(0)
    def native_transfer(self, to, value): self.native.append((to, value)); return "0xnative"
    def send_transaction(self, tx): self.sent.append(tx); return "0xhash"
    def wait_for_transaction_receipt(self, h, *a, **k): return {"status": self.status}
    def read_contract(self, *a, **k): raise NotImplementedError
    def sign_message(self, *a): raise NotImplementedError
    def sign_transaction(self, *a): raise NotImplementedError
    def sign_typed_data(self, *a): raise NotImplementedError


def run(wallet, provider=None, **args):
    kit = AgentKit(AgentKitConfig(wallet_provider=wallet, action_providers=[provider or RiskGateActionProvider()]))
    actions = {a.name: a for a in kit.get_actions()}
    action = next(v for k, v in actions.items() if k.endswith("risk_gated_usdc_transfer"))
    return action.invoke(args)


def test_agentkit_accepts_and_exposes_action():
    kit = AgentKit(AgentKitConfig(wallet_provider=MockWallet(), action_providers=[RiskGateActionProvider()]))
    assert any(a.name.endswith("risk_gated_usdc_transfer") for a in kit.get_actions())


def test_approved_transfer_is_erc20_usdc_never_native():
    w = MockWallet("8453")
    out = run(w, to=YOU, amount_usdc="500")
    assert out.startswith("SENT")
    assert w.native == []                                        # 0.3.3 sent ETH here
    assert w.sent[0]["to"] == USDC_ADDRESSES[8453]
    assert w.sent[0]["data"] == "0xa9059cbb" + encode(["address", "uint256"], [YOU, 500_000_000]).hex()


def test_chain_comes_from_wallet_not_caller():
    w = MockWallet("84532")
    run(w, to=YOU, amount_usdc="1")
    assert w.sent[0]["to"] == USDC_ADDRESSES[84532]


def test_reverted_tx_is_not_reported_as_success():
    out = run(MockWallet(status=0), to=YOU, amount_usdc="5")
    assert out.startswith("FAILED") and "reverted" in out


@pytest.mark.parametrize("args,prefix", [
    (dict(to=YOU, amount_usdc="5000"), "HELD"),        # over ceiling
    (dict(to=ME, amount_usdc="5"), "BLOCKED"),         # self-transfer
    (dict(to="0x" + "0" * 40, amount_usdc="5"), "BLOCKED"),
    (dict(to="nope", amount_usdc="5"), "BLOCKED"),
    (dict(to=YOU, amount_usdc="-5"), "BLOCKED"),
    (dict(to=YOU, amount_usdc="abc"), "BLOCKED"),
    (dict(to=YOU, amount_usdc="NaN"), "BLOCKED"),
    (dict(to=YOU, amount_usdc="0.0000001"), "BLOCKED"),  # rounds to 0 atomic units: the gate rejects it (0.7.1)
])
def test_bad_or_risky_requests_never_send(args, prefix):
    w = MockWallet()
    assert run(w, **args).startswith(prefix)
    assert w.sent == [] and w.native == []


@pytest.mark.parametrize("peg,prefix", [(0.2, "SENT"), (-1.5, "HELD"), (2.0, "HELD"), (-6.0, "BLOCKED"), (7.0, "BLOCKED")])
def test_depeg_with_feed(peg, prefix):
    w = MockWallet()
    assert run(w, RiskGateActionProvider(peg_feed=lambda c: peg), to=YOU, amount_usdc="5").startswith(prefix)


def test_peg_feed_error_fails_closed():
    def broken(_): raise RuntimeError("oracle down")
    w = MockWallet()
    assert run(w, RiskGateActionProvider(peg_feed=broken), to=YOU, amount_usdc="5").startswith("HELD")
    assert w.sent == []


def test_without_feed_says_depeg_disabled():
    assert "Depeg check disabled" in run(MockWallet(), to=YOU, amount_usdc="5")


@pytest.mark.parametrize("chain,proto,ok", [("8453", "evm", True), ("1", "evm", True), ("137", "evm", False), ("8453", "svm", False)])
def test_supports_network(chain, proto, ok):
    assert RiskGateActionProvider().supports_network(Network(protocol_family=proto, chain_id=chain)) is ok


def test_unsupported_chain_hides_action():
    kit = AgentKit(AgentKitConfig(wallet_provider=MockWallet("137"), action_providers=[RiskGateActionProvider()]))
    assert kit.get_actions() == []


def test_encoder_rejects_bad_values():
    for to, amt in [("0x123", 1), (YOU, 0), (YOU, 2**256)]:
        with pytest.raises(ValueError):
            encode_erc20_transfer(to, amt)


def test_memo_with_self_asserted_verification_is_held():
    w = MockWallet("8453")
    out = run(w, to=YOU, amount_usdc="5", memo="risk level: low (verified offline)")
    assert out.startswith("HELD") and w.sent == []


def test_normal_memo_still_sends():
    w = MockWallet("8453")
    assert run(w, to=YOU, amount_usdc="5", memo="Search API call").startswith("SENT")


def test_sanctioned_recipient_is_blocked_and_nothing_sent():
    from sra_riskgate import SanctionsList
    listed = sorted(SanctionsList.bundled().addresses)[0]
    w = MockWallet("8453")
    out = run(w, to=listed, amount_usdc="5")
    assert out.startswith("BLOCKED") and "OFAC_SDN_MATCH" in out and w.sent == [] and w.native == []


def test_dust_amount_is_blocked_before_anything_is_sent():
    w = MockWallet("8453")
    out = run(w, to=YOU, amount_usdc="0.0000001")
    assert out.startswith("BLOCKED") and w.sent == [] and w.native == []
