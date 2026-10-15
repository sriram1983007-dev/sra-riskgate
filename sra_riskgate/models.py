import math
import re
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

class ActionDecision(str, Enum):
    APPROVE = "approve"
    HOLD = "hold"
    REJECT = "reject"

class TransactionPayload(BaseModel):
    chain_id: int = Field(..., description="EVM Chain ID (e.g., 1 for Ethereum mainnet)")
    token: str = Field(..., description="Symbol of the stablecoin, e.g., 'USDC'")
    sender: str = Field(..., description="42-character hex Ethereum address")
    recipient: str = Field(..., description="42-character hex Ethereum address")
    amount: float = Field(..., description="Transfer amount in token units")
    peg_deviation_pct: Optional[float] = Field(0.0, description="Observed peg deviation percentage")
    peg_observed: bool = Field(
        True,
        description="False when no peg deviation was supplied, so the depeg check could not run. "
                    "Set automatically.",
    )

    @model_validator(mode="before")
    @classmethod
    def note_peg_observed(cls, data):
        if isinstance(data, dict) and "peg_observed" not in data:
            data = {**data, "peg_observed": data.get("peg_deviation_pct") is not None}
        return data

    @field_validator("peg_deviation_pct", mode="before")
    @classmethod
    def coerce_none_peg(cls, v):
        if v is None:
            return 0.0
        return v

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("Amount must be a finite numerical value.")
        if v <= 0:
            raise ValueError("Amount must be strictly greater than 0.")
        return v

    @field_validator("sender", "recipient")
    @classmethod
    def validate_eth_address(cls, v: str) -> str:
        if not re.match(r"^0x[a-fA-F0-9]{40}$", v):
            raise ValueError(f"Invalid Ethereum address format: {v}")
        addr = v.lower()
        if addr == ZERO_ADDRESS:
            raise ValueError("Zero address (0x0...0) is not permitted as sender or recipient.")
        return addr

    @model_validator(mode="after")
    def check_self_transfer(self):
        if self.sender == self.recipient:
            raise ValueError("Self-transfer detected: sender and recipient addresses cannot be identical.")
        return self

class RiskAssessment(BaseModel):
    decision: ActionDecision
    risk_score: float = Field(..., ge=0.0, le=1.0)
    flags: List[str]
    explanation: str
    required_actions: Optional[List[str]] = Field(default_factory=list)

    @field_validator("required_actions", mode="before")
    @classmethod
    def coerce_none_to_list(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return v
