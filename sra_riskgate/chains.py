"""USDC contract addresses and network identifiers shared by the integrations."""
from __future__ import annotations

from typing import Optional

USDC_DECIMALS = 6

USDC_ADDRESSES: dict[int, str] = {
    1: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",      # Ethereum mainnet
    8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base mainnet
    84532: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # Base Sepolia
    5042: "0x3600000000000000000000000000000000000000",   # Arc mainnet: ERC-20 interface to native USDC
    5042002: "0x3600000000000000000000000000000000000000",  # Arc testnet
}

# Chains where USDC is the native asset (Arc). A plain native send there is a USDC payment, in
# NATIVE_USDC_DECIMALS units; the ERC-20 interface above moves the same balance in USDC_DECIMALS units.
NATIVE_USDC_CHAINS: frozenset[int] = frozenset({5042, 5042002})
NATIVE_USDC_DECIMALS = 18

# Circle Gateway's GatewayWallet contract, the verifyingContract of Gateway's batched x402 payments
# (EIP-712 domain "GatewayWalletBatched"). Same address on every mainnet, and another on every testnet.
# Source: https://developers.circle.com/gateway/references/contract-addresses
_GATEWAY_MAINNET = "0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE"
_GATEWAY_TESTNET = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9"
GATEWAY_WALLET_ADDRESSES: dict[int, str] = {
    1: _GATEWAY_MAINNET, 8453: _GATEWAY_MAINNET, 5042: _GATEWAY_MAINNET,
    84532: _GATEWAY_TESTNET, 5042002: _GATEWAY_TESTNET,
}
GATEWAY_BATCHED_DOMAIN = "GatewayWalletBatched"


def is_gateway_wallet(chain_id: Optional[int], contract: object) -> bool:
    expected = GATEWAY_WALLET_ADDRESSES.get(chain_id) if chain_id is not None else None
    return bool(expected) and str(contract).lower() == expected.lower()


# Legacy (x402 v1) network names
LEGACY_NETWORKS: dict[str, int] = {
    "ethereum": 1,
    "base": 8453,
    "base-sepolia": 84532,
    "arc": 5042,
    "arc-testnet": 5042002,
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
