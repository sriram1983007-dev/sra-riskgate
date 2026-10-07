# Changelog

## 0.4.0
- New x402 integration (`sra-riskgate[x402]`): `RiskGateX402Hooks` runs the rule checks inside x402
  payment flows through the official SDK's lifecycle hooks: `before_verify` and `before_settle` for
  resource servers and facilitators, `before_payment_creation` for paying agents. Fails closed.
- USDC addresses and network parsing moved to `sra_riskgate.chains`, shared by all integrations.
- Note: `coinbase-agentkit` 0.7.x pins `x402<2`, so the `[agentkit]` and `[x402]` extras must be installed separately.

## 0.3.5
- AgentKit integration rewritten as a real `ActionProvider` with `@create_action`.
- Sends USDC as an ERC-20 transfer (0.3.3 sent the native token; 0.3.4 was not accepted by AgentKit).
- Chain read from the wallet; reverted transactions reported as failures; optional `peg_feed`.
- `solana` pinned so the `[agentkit]` extra imports cleanly.

## 0.3.2
- Restored the `pydantic` dependency (missing in 0.3.1).

## 0.3.1
- Unknown constructor arguments raise `TypeError`; legacy `max_allowed_deviation_pct` maps to the hold threshold.
- Non-finite thresholds rejected; license and author metadata restored.

## 0.3.0
- Depeg checks use `abs()`, so upward depegs are caught; thresholds validated.

Yanked releases: 0.1.0, 0.2.1, 0.2.2, 0.2.3, 0.3.1, 0.3.3, 0.3.4.
