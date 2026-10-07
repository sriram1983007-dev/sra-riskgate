"""x402 integration: run SRA-RiskGate rule checks inside x402 payment flows.

Works with the official ``x402`` Python SDK (x402 Foundation) through its lifecycle hooks:

- Resource servers and facilitators: ``before_verify`` and ``before_settle``
- Agent clients (the paying side): ``before_payment_creation``

Every check fails closed. A rejected, held, malformed or unknown payment is aborted with an
``AbortResult`` whose reason starts with ``sra_riskgate_``; x402 then raises its own
``PaymentAbortedError`` and no funds move.

Example (facilitator)::

    from x402 import x402FacilitatorSync
    from sra_riskgate.integrations.x402_hooks import RiskGateX402Hooks

    facilitator = x402FacilitatorSync()
    RiskGateX402Hooks(max_amount=1000).attach_to_facilitator(facilitator)
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Optional

from sra_riskgate.chains import USDC_DECIMALS, chain_id_from_network, is_usdc
from sra_riskgate.client import RulePreFilter
from sra_riskgate.models import ActionDecision, TransactionPayload

try:
    from x402.schemas.hooks import AbortResult
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "The x402 integration needs the x402 SDK version 2.25 or newer: pip install 'sra-riskgate[x402]'. "
        "Note: coinbase-agentkit 0.7.x requires the older x402 1.x, so the [agentkit] and [x402] extras "
        "cannot currently be installed in the same environment."
    ) from e

REASON_REJECT = "sra_riskgate_reject"
REASON_HOLD = "sra_riskgate_hold"
REASON_INVALID = "sra_riskgate_invalid"
REASON_UNSUPPORTED = "sra_riskgate_unsupported_asset"
REASON_PEG_FEED = "sra_riskgate_peg_feed_error"
REASON_ERROR = "sra_riskgate_internal_error"


class RiskGateX402Hooks:
    """SRA-RiskGate pre-filter rules as x402 lifecycle hooks.

    Args:
        gate: A configured ``RulePreFilter``. If omitted, one is built from the arguments below.
        max_amount: Hold payments above this many USDC.
        depeg_hold_pct / depeg_reject_pct: USDC peg-deviation thresholds, in percent.
        peg_feed: Optional ``callable(chain_id) -> deviation %``. Without it, depeg checks are skipped.
            If it raises, the payment is aborted (fail closed).
        block_on_hold: Abort payments the rules would hold (default True). For automated flows,
            "hold" means "do not proceed without a human", so aborting is the safe default.
        allow_unsupported_assets: Let non-USDC assets and unknown networks pass unchecked
            (default False: they are aborted).
        payer_address: The paying wallet, required for the client-side hook (the payment payload,
            which names the payer, does not exist yet at that point).
        on_decision: Optional ``callable(dict)`` called with every decision, for logging or audit.
    """

    def __init__(
        self,
        gate: Optional[RulePreFilter] = None,
        *,
        max_amount: float = 1_000.0,
        depeg_hold_pct: float = 1.0,
        depeg_reject_pct: float = 5.0,
        peg_feed: Optional[Callable[[int], float]] = None,
        block_on_hold: bool = True,
        allow_unsupported_assets: bool = False,
        payer_address: Optional[str] = None,
        on_decision: Optional[Callable[[dict], None]] = None,
    ):
        self.gate = gate or RulePreFilter(
            max_amount=max_amount, depeg_hold_pct=depeg_hold_pct, depeg_reject_pct=depeg_reject_pct
        )
        self.peg_feed = peg_feed
        self.block_on_hold = block_on_hold
        self.allow_unsupported_assets = allow_unsupported_assets
        self.payer_address = payer_address
        self.on_decision = on_decision

    # ------------------------------------------------------------------ hooks
    def before_verify(self, ctx: Any) -> Optional[AbortResult]:
        """Server or facilitator hook: runs before the payment is verified."""
        return self._guard("before_verify", ctx.requirements, self._payer_from_payload(ctx.payment_payload))

    def before_settle(self, ctx: Any) -> Optional[AbortResult]:
        """Server or facilitator hook: runs before the payment is settled on-chain."""
        return self._guard("before_settle", ctx.requirements, self._payer_from_payload(ctx.payment_payload))

    def before_payment_creation(self, ctx: Any) -> Optional[AbortResult]:
        """Agent client hook: runs before the agent signs a payment."""
        return self._guard("before_payment_creation", ctx.selected_requirements, self.payer_address)

    # ------------------------------------------------------------- attaching
    def attach_to_facilitator(self, facilitator: Any) -> Any:
        facilitator.on_before_verify(self.before_verify)
        facilitator.on_before_settle(self.before_settle)
        return facilitator

    def attach_to_server(self, server: Any) -> Any:
        server.on_before_verify(self.before_verify)
        server.on_before_settle(self.before_settle)
        return server

    def attach_to_client(self, client: Any) -> Any:
        if not self.payer_address:
            raise ValueError("payer_address is required for the client-side hook.")
        client.on_before_payment_creation(self.before_payment_creation)
        return client

    # --------------------------------------------------------------- internals
    @staticmethod
    def _payer_from_payload(payment_payload: Any) -> Optional[str]:
        payload = getattr(payment_payload, "payload", None)
        if isinstance(payload, dict):
            auth = payload.get("authorization")
            if isinstance(auth, dict) and auth.get("from"):
                return str(auth["from"])
        return None

    def _record(self, stage: str, decision: str, reason: Optional[str], detail: dict) -> None:
        if self.on_decision is not None:
            try:
                self.on_decision({"stage": stage, "decision": decision, "abort_reason": reason, **detail})
            except Exception:
                pass  # logging must never change a payment decision

    def _abort(self, stage: str, reason: str, message: str, detail: dict) -> AbortResult:
        self._record(stage, "abort", reason, {**detail, "message": message})
        return AbortResult(reason=reason, message=message)

    def _guard(self, stage: str, requirements: Any, payer: Optional[str]) -> Optional[AbortResult]:
        detail: dict = {}
        try:
            network = getattr(requirements, "network", None)
            asset = getattr(requirements, "asset", None)
            pay_to = getattr(requirements, "pay_to", None)
            chain_id = chain_id_from_network(network)
            detail = {"network": str(network), "asset": str(asset), "pay_to": str(pay_to), "payer": payer}

            if not is_usdc(chain_id, asset):
                if self.allow_unsupported_assets:
                    self._record(stage, "skipped", None, {**detail, "message": "unsupported asset, not checked"})
                    return None
                return self._abort(stage, REASON_UNSUPPORTED,
                                   f"Only USDC on known networks is checked; got asset {asset} on {network}.", detail)

            if not payer:
                return self._abort(stage, REASON_INVALID, "Payer address is unknown.", detail)

            try:
                atomic = Decimal(str(requirements.get_amount()))
                amount = atomic / (Decimal(10) ** USDC_DECIMALS)
            except (InvalidOperation, ValueError, TypeError, AttributeError):
                return self._abort(stage, REASON_INVALID, "Payment amount is not a number.", detail)
            if not amount.is_finite() or amount <= 0:
                return self._abort(stage, REASON_INVALID, "Payment amount must be positive.", detail)
            detail["amount_usdc"] = str(amount)

            peg = None
            if self.peg_feed is not None:
                try:
                    peg = float(self.peg_feed(chain_id))
                except Exception as e:
                    return self._abort(stage, REASON_PEG_FEED, f"Could not read USDC peg price: {e}", detail)

            try:
                verdict = self.gate.inspect(TransactionPayload(
                    chain_id=chain_id, token="USDC", sender=payer, recipient=str(pay_to),
                    amount=float(amount), peg_deviation_pct=peg,
                ))
            except Exception as e:
                return self._abort(stage, REASON_INVALID, f"Payment failed validation: {e}", detail)

            detail.update(flags=verdict.flags, explanation=verdict.explanation)
            if verdict.decision == ActionDecision.REJECT:
                return self._abort(stage, REASON_REJECT, verdict.explanation, detail)
            if verdict.decision == ActionDecision.HOLD and self.block_on_hold:
                return self._abort(stage, REASON_HOLD, verdict.explanation, detail)
            self._record(stage, verdict.decision.value, None, detail)
            return None
        except Exception as e:  # never let a bug in the gate approve a payment
            return self._abort(stage, REASON_ERROR, f"Risk gate error: {e}", detail)
