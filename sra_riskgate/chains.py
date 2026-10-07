"""USDC contract addresses and network identifiers shared by the integrations."""
from __future__ import annotations

from typing import Optional

USDC_DECIMALS = 6

USDC_ADDRESSES: dict[int, str] = {
    1: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",      # Ethereum mainnet
    8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base mainnet
    84532: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # Base Sepolia
}

# Legacy (x402 v1) network names
LEGACY_NETWORKS: dict[str, int] = {
    "ethereum": 1,
    "base": 8453,
    "base-sepolia": 84532,
}


def chain_id_from_network(network: object) -> Optional[int]:
    """Parse a CAIP-2 id (``eip155:8453``) or a legacy name (``base``) into a chain id."""
    if network is None:
        return None
    s = str(network).strip().lower()
    if s.startswith("eip155:"):
        try:
            return int(s.split(":", 1)[1])
        except ValueError:
            return None
    return LEGACY_NETWORKS.get(s)


def is_usdc(chain_id: Optional[int], asset: object) -> bool:
    expected = USDC_ADDRESSES.get(chain_id) if chain_id is not None else None
    return bool(expected) and str(asset).lower() == expected.lower()
