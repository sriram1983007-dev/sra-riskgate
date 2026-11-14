"""Stablecoin contract addresses and network identifiers shared by the checks and integrations."""
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
# Named stablecoins: symbol -> chain id -> (contract, decimals). From 1.0.0 the checks before signing cover them
# too, but only the symbols you enable with ``allowed_tokens`` (USDC alone by default).
# Each contract's symbol() and decimals() were read on chain on 2026-11-04; addresses come from the issuers:
# Tether (USDT), Bridge reserves.bridge.xyz/usdb (USDB, the Bridge/Stripe stablecoin), Paxos docs (USDG).
# USDT is deliberately absent on Base: Tether does not issue it natively there.
STABLECOINS: dict[str, dict[int, tuple[str, int]]] = {
    "USDC": {cid: (addr, USDC_DECIMALS) for cid, addr in USDC_ADDRESSES.items()},
    "USDT": {1: ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6)},
    "USDB": {1: ("0xeac4269c9a01190b1400c4dc728864e61895fdf3", 6),
             8453: ("0x100faa513ac917181eb29f73b64bf7a434a206fe", 6)},
    "USDG": {1: ("0xe343167631d89B6Ffc58B88d6b7fB0228795491D", 6),
             4663: ("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", 6)},
}


def stablecoin(symbol: object, chain_id: object) -> tuple[str, int]:
    """(contract, decimals) for a named stablecoin on a chain; ValueError if this SDK does not list it there."""
    sym = str(symbol).strip().upper()
    if sym not in STABLECOINS:
        raise ValueError(f"unknown stablecoin {symbol!r}; known: {', '.join(sorted(STABLECOINS))}")
    if chain_id not in STABLECOINS[sym]:
        chains = ", ".join(str(c) for c in sorted(STABLECOINS[sym]))
        raise ValueError(f"{sym} is not listed on chain {chain_id} (listed on {chains}); pass its contract "
                         f"address and decimals instead")
    return STABLECOINS[sym][chain_id]


DEFAULT_ALLOWED_TOKENS: tuple[str, ...] = ("USDC",)

# Every chain where at least one listed stablecoin is checked. A set, not a frozenset, so that
# register_stablecoin() can extend it in place and every module that imported it sees the change.
STABLECOIN_CHAINS: set[int] = {c for chains in STABLECOINS.values() for c in chains}

# Stablecoins that implement EIP-3009 transferWithAuthorization, the signature x402's ``exact`` scheme uses.
# A TransferWithAuthorization for any other token could never settle, so it is held. Read on chain: USDC on
# Ethereum and Base implements it (domain "USD Coin", version "2"). USDG (domain "Global Dollar", "1") implements
# it on Ethereum and Robinhood Chain: re-read on 2026-11-14, its TRANSFER_WITH_AUTHORIZATION_TYPEHASH() is the
# EIP-3009 one, authorizationState() answers, and transferWithAuthorization() with a bad signature reverts with
# InvalidSignature() (0x8baa579f). The 2026-11-06 read missed this because it searched the proxy's implementation
# code for the function selector. USDT implements neither EIP-3009 nor EIP-2612 permit; USDB (domain
# "USDBridge", "1") implements permit but not EIP-3009.
EIP3009_TOKENS: set[tuple[str, int]] = {("USDC", c) for c in USDC_ADDRESSES} | {("USDG", 1), ("USDG", 4663)}

# The built-in table, frozen: register_stablecoin() may add tokens and chains but never change these.
_BUILTIN: dict[str, dict[int, tuple[str, int]]] = {s: dict(c) for s, c in STABLECOINS.items()}
_BUILTIN_EIP3009: frozenset[tuple[str, int]] = frozenset(EIP3009_TOKENS)
_SYMBOL_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.")


def register_stablecoin(symbol: str, chain_id: int, contract: str, decimals: int, *,
                        eip3009: bool = False) -> None:
    """Add a US-dollar stablecoin the checks should recognise, on a chain this SDK does not list.

    After ``register_stablecoin("TUSD8", 1234, "0x…", 6)``, every check treats that contract like a built-in
    stablecoin: ``check_payment(token="TUSD8", ...)``, ``check_transaction`` (by contract address),
    ``check_user_operation``, ``check_authorization`` (only with ``eip3009=True``; otherwise a
    TransferWithAuthorization for it is held, since it could never settle), ``verify_settlement(token=...)``
    and ``check_allowances(token=...)``. Payments in it are still held until you enable it with
    ``allowed_tokens``, exactly like USDT, USDB and USDG.

    Amounts, ``max_amount`` and batch totals assume the token is worth one US dollar; do not register a token
    pegged to anything else. Read ``decimals()`` and the contract address from the chain yourself.

    Registration is process-wide: do it once at start-up, before any checks run. It refuses (ValueError) to
    change a built-in token, to reuse a symbol with different details on the same chain, or to give one
    contract two symbols, so a registration can never redirect USDC, USDT, USDB or USDG to another address.
    Registering the same details again is a no-op.
    """
    if not isinstance(symbol, str) or not symbol.strip():
        raise ValueError("symbol must be a non-empty string")
    sym = symbol.strip().upper()
    if len(sym) > 11 or not set(sym) <= _SYMBOL_OK:
        raise ValueError(f"symbol {symbol!r} must be at most 11 letters, digits or dots")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise ValueError(f"chain_id must be a positive integer, got {chain_id!r}")
    if (not isinstance(contract, str) or len(contract) != 42 or not contract.startswith(("0x", "0X"))
            or any(ch not in "0123456789abcdefABCDEF" for ch in contract[2:]) or int(contract, 16) == 0):
        raise ValueError(f"contract must be a non-zero 0x-prefixed 20-byte address, got {contract!r}")
    if isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 36:
        raise ValueError(f"decimals must be an integer from 0 to 36, got {decimals!r}")
    if not isinstance(eip3009, bool):
        raise ValueError("eip3009 must be True or False")
    if sym in _BUILTIN:
        raise ValueError(f"{sym} is built in and cannot be registered or changed")
    addr = "0x" + contract[2:].lower()
    listed = stablecoin_at(chain_id, addr)
    current = STABLECOINS.get(sym, {}).get(chain_id)
    if current is not None:
        if current[0].lower() == addr and current[1] == decimals and ((sym, chain_id) in EIP3009_TOKENS) == eip3009:
            return
        raise ValueError(f"{sym} is already registered on chain {chain_id} with different details")
    if listed is not None:
        raise ValueError(f"{addr} on chain {chain_id} is already listed as {listed[0]}")
    STABLECOINS.setdefault(sym, {})[chain_id] = (addr, decimals)
    STABLECOIN_CHAINS.add(chain_id)
    if eip3009:
        EIP3009_TOKENS.add((sym, chain_id))


def registered_stablecoins() -> dict[str, dict[int, tuple[str, int]]]:
    """The tokens added with register_stablecoin(), as symbol -> chain id -> (contract, decimals)."""
    return {s: dict(c) for s, c in STABLECOINS.items() if s not in _BUILTIN}


def _reset_registry() -> None:
    """Remove every registered token (for tests)."""
    for s in [s for s in STABLECOINS if s not in _BUILTIN]:
        del STABLECOINS[s]
    STABLECOIN_CHAINS.clear()
    STABLECOIN_CHAINS.update(c for chains in _BUILTIN.values() for c in chains)
    EIP3009_TOKENS.clear()
    EIP3009_TOKENS.update(_BUILTIN_EIP3009)


def stablecoin_at(chain_id: object, contract: object) -> Optional[tuple[str, int]]:
    """(symbol, decimals) of the listed stablecoin at ``contract`` on ``chain_id``, or None."""
    if not isinstance(contract, str) or isinstance(chain_id, bool):
        return None
    c = contract.strip().lower()
    for sym, chains in STABLECOINS.items():
        listed = chains.get(chain_id)  # type: ignore[call-overload]
        if listed and listed[0].lower() == c:
            return sym, listed[1]
    return None


def listed_on(chain_id: object) -> str:
    """'USDC 0x…, USDT 0x…' for the stablecoins listed on a chain, for error messages."""
    out = [f"{sym} {chains[chain_id][0]}" for sym, chains in STABLECOINS.items()
           if not isinstance(chain_id, bool) and chain_id in chains]  # type: ignore[operator]
    return ", ".join(out) or "none"


def parse_allowed_tokens(allowed: object) -> frozenset[str]:
    """Validate ``allowed_tokens``: None means USDC only; otherwise listed symbols, case-insensitive."""
    if allowed is None:
        return frozenset(DEFAULT_ALLOWED_TOKENS)
    if isinstance(allowed, str):
        allowed = [p for p in allowed.replace(",", " ").split() if p]
    try:
        items = list(allowed)  # type: ignore[call-overload]
    except TypeError:
        raise ValueError("allowed_tokens must be a list of stablecoin symbols")
    out = set()
    for t in items:
        sym = str(t).strip().upper() if isinstance(t, str) else None
        if sym not in STABLECOINS:
            raise ValueError(f"allowed_tokens: unknown stablecoin {t!r}; known: {', '.join(sorted(STABLECOINS))}")
        out.add(sym)
    if not out:
        raise ValueError("allowed_tokens is empty, so no payment could ever be approved")
    return frozenset(out)


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
