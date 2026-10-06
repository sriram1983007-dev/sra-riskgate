"""Coinbase AgentKit action provider: risk-gated USDC transfers.

Register ONLY this provider for payments. If you also register AgentKit's
wallet or ERC-20 providers, the agent can call their transfer actions and
bypass the gate entirely.
"""
from __future__ import annotations

from decimal import ROUND_DOWN, Decimal, InvalidOperation
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from sra_riskgate.client import RulePreFilter
from sra_riskgate.models import ActionDecision, TransactionPayload

try:
    from coinbase_agentkit import ActionProvider, EvmWalletProvider, create_action
    from coinbase_agentkit.network import Network
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "The AgentKit integration needs the extra: pip install 'sra-riskgate[agentkit]'"
    ) from e

USDC_ADDRESSES: dict[int, str] = {  # all 6 decimals
    1: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",      # Ethereum mainnet
    8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base mainnet
    84532: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # Base Sepolia
}
USDC_DECIMALS = 6
_TRANSFER_SELECTOR = "a9059cbb"


def encode_erc20_transfer(to_address: str, amount_atomic: int) -> str:
    """ABI-encode transfer(address,uint256)."""
    if amount_atomic <= 0 or amount_atomic >= 2**256:
        raise ValueError("amount out of range")
    addr = to_address.lower().removeprefix("0x")
    if len(addr) != 40 or any(c not in "0123456789abcdef" for c in addr):
        raise ValueError("invalid address")
    return "0x" + _TRANSFER_SELECTOR + addr.zfill(64) + format(amount_atomic, "064x")


def _chain_id(network: Network) -> Optional[int]:
    try:
        return int(network.chain_id) if network.chain_id is not None else None
    except (TypeError, ValueError):
        return None


class RiskGatedTransferInput(BaseModel):
    to: str = Field(..., description="Recipient address: 0x followed by 40 hex characters.")
    amount_usdc: str = Field(..., description="Amount of USDC in whole units, as a decimal string, e.g. '12.50'.")
    memo: str = Field("", description="What the payment is for.")


class RiskGateActionProvider(ActionProvider[EvmWalletProvider]):
    """Sends USDC only after the SRA-RiskGate pre-filter approves. Fails closed."""

    def __init__(
        self,
        max_amount: float = 1_000.0,
        depeg_hold_pct: float = 1.0,
        depeg_reject_pct: float = 5.0,
        peg_feed: Optional[Callable[[int], float]] = None,
        gate: Optional[RulePreFilter] = None,
    ):
        """peg_feed(chain_id) -> USDC peg deviation in percent (e.g. -1.2).

        Without a peg_feed, depeg checks cannot run and are reported as disabled.
        """
        super().__init__("sra-riskgate", [])
        self.gate = gate or RulePreFilter(
            max_amount=max_amount, depeg_hold_pct=depeg_hold_pct, depeg_reject_pct=depeg_reject_pct
        )
        self.peg_feed = peg_feed

    def supports_network(self, network: Network) -> bool:
        return network.protocol_family == "evm" and _chain_id(network) in USDC_ADDRESSES

    @create_action(
        name="risk_gated_usdc_transfer",
        description=(
            "Send USDC to an address. Every transfer is checked by SRA-RiskGate first "
            "(address validity, self-transfers, amount ceiling, USDC depeg) and is only "
            "sent if approved. Inputs: to (address), amount_usdc (decimal string), memo."
        ),
        schema=RiskGatedTransferInput,
    )
    def risk_gated_usdc_transfer(self, wallet_provider: EvmWalletProvider, args: dict[str, Any]) -> str:
        try:
            req = RiskGatedTransferInput(**args)
            amount = Decimal(req.amount_usdc)
        except (ValueError, InvalidOperation) as e:
            return f"BLOCKED: invalid input ({e})."

        chain_id = _chain_id(wallet_provider.get_network())
        usdc = USDC_ADDRESSES.get(chain_id)
        if usdc is None:
            return f"BLOCKED: no known USDC contract on chain {chain_id}."

        peg, peg_note = None, " Depeg check disabled (no peg_feed configured)."
        if self.peg_feed is not None:
            try:
                peg, peg_note = float(self.peg_feed(chain_id)), ""
            except Exception as e:
                return f"HELD: could not read USDC peg price ({e}). Transfer not sent."

        try:
            verdict = self.gate.inspect(TransactionPayload(
                chain_id=chain_id, token="USDC", sender=wallet_provider.get_address(),
                recipient=req.to, amount=float(amount), peg_deviation_pct=peg,
            ))
        except Exception as e:
            return f"BLOCKED: transaction failed validation ({e})."

        if verdict.decision == ActionDecision.REJECT:
            return f"BLOCKED: {verdict.explanation} Flags: {verdict.flags}."
        if verdict.decision == ActionDecision.HOLD:
            return f"HELD for human review: {verdict.explanation} Flags: {verdict.flags}. Transfer not sent."

        atomic = int((amount * 10**USDC_DECIMALS).to_integral_value(rounding=ROUND_DOWN))
        try:
            data = encode_erc20_transfer(req.to, atomic)
            tx_hash = wallet_provider.send_transaction({"to": usdc, "data": data})
            receipt = wallet_provider.wait_for_transaction_receipt(tx_hash)
        except Exception as e:
            return f"FAILED: transfer not completed ({e})."

        status = receipt.get("status") if hasattr(receipt, "get") else getattr(receipt, "status", None)
        if status != 1:
            return f"FAILED: transaction {tx_hash} reverted on-chain; no USDC was sent."
        return f"SENT: {amount} USDC to {req.to} on chain {chain_id}. tx: {tx_hash}.{peg_note}"


def risk_gate_action_provider(**kwargs: Any) -> RiskGateActionProvider:
    """Factory, matching AgentKit's naming convention."""
    return RiskGateActionProvider(**kwargs)
