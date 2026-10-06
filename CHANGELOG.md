# Changelog

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
