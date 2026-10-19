# Changelog

## 0.7.2
- New informational flag `ROUND_AMOUNT`: a whole-number amount at or above 10,000 USDC is flagged.
  Large round-number transfers are a common transaction-monitoring signal; the 10,000 default mirrors
  the US currency transaction report threshold for cash (CTRs themselves do not apply to stablecoin
  transfers).
- **It never changes the decision.** An approve stays approve and a hold stays hold; the explanation says
  the flag is informational and that many such payments (payroll, settlements) are legitimate.
- Configure with `RulePreFilter(round_amount_threshold=...)`, or pass `None` to turn it off.
- Because `check_payment`'s default ceiling is 1,000 USDC, the flag appears there only alongside
  `HIGH_VALUE_TRANSFER` unless you raise `max_amount`. `RulePreFilter`'s default ceiling is 50,000, so
  round amounts from 10,000 to 50,000 now approve with the flag instead of with no flags.
- README: the decision table now lists the dust rule (below 0.000001 USDC) and the round-amount flag.
- Suggested by an external review.

## 0.7.1
- Fix: a USDC amount below one atomic unit (0.000001 USDC) is now rejected with `INVALID_PAYMENT`
  ("below the smallest USDC unit"). Such an amount rounds to zero on-chain and can never execute, but
  0.7.0 and earlier approved it (for example `amount=1e-7`). The check lives in `TransactionPayload`
  validation, so `check_payment`, `RulePreFilter`, the AgentKit provider and the MCP rule tools all
  reject it; the AgentKit provider now blocks it before sending instead of failing at encoding.
- Amounts of at least 0.000001 USDC decide exactly as before; a remainder below one unit (e.g.
  1.0000001) is still rounded down on-chain as before. Non-USDC tokens are unaffected.
- Reported by an external review of 0.6.1.

## 0.7.0
- **New: offline OFAC SDN address match.** `check_payment` and `RulePreFilter` now **reject** a payment
  whose sender or recipient is on the US Treasury OFAC SDN list, with flags `OFAC_SDN_MATCH` and
  `SANCTIONED_RECIPIENT` / `SANCTIONED_SENDER` and required actions `reject_payment`,
  `refer_to_compliance`. The package bundles 124 Ethereum-format addresses (as of 2026-10-01), taken
  from the open-source ofac-sanctioned-digital-currency-addresses extraction of OFAC's list. No network
  call or API key.
- In `check_payment` the sanctions match runs first, so a sanctioned counterparty is a reject even on an
  unsupported chain or token.
- New `SanctionsList` (`from_file`, `from_addresses`, `bundled`) and `is_sanctioned()`. Pass
  `sanctions_list=` to use a fresher list, or `check_sanctions=False` to turn the match off (results then
  carry `SANCTIONS_NOT_CHECKED`).
- The x402 hooks and the AgentKit action provider get the same check through `RulePreFilter`.
- Fails closed: if the list cannot be loaded, `check_payment` returns `hold` (`CHECK_FAILED`).
- **Behaviour change:** payments to or from listed addresses that were approved before are now rejected.
  Everything else decides exactly as in 0.6.1.
- It is an exact match against a dated snapshot, not a sanctions screening service or a compliance
  determination; the README says so.

## 0.6.1
- Fix: `check_payment` rejects a boolean `amount` with `INVALID_PAYMENT` (`True` was read as 1 USDC).
- PyPI page: model results are now described as measured by the author in two identical full runs,
  not "independently reproduced" (the 0.6.0 page still had the old wording).
- README: links to the free Kaggle notebook and the Kaggle copy of the benchmark.

## 0.6.0
- New `check_payment()`: one fail-closed call before every payment. It checks the asset and chain
  (USDC on Ethereum, Base, Base Sepolia), validates addresses and amount, runs `RulePreFilter` and scans
  the untrusted request text for self-asserted verification claims. Invalid payments and bad
  configuration are rejected; unsupported chains or tokens and any internal error become `hold`. It
  never raises on bad payment data, so callers cannot accidentally fail open. Default per-payment
  ceiling is 1,000 USDC.
- README: quick start for `check_payment` and a link to the
  [agent-payment-guard](https://github.com/sriram1983007-dev/agent-payment-guard) Agent Skill.
- No change to existing APIs or decisions.
- README wording (GitHub copy): model results are described as measured by the author in two runs, not
  "independently reproduced". The PyPI page for 0.6.0 still shows the old wording until the next release.

## 0.5.1
- `scan_payload_claims` hardened after a code audit:
  - text is normalised before matching (Unicode compatibility forms, zero-width characters, Cyrillic and
    Greek look-alike letters), so "ｒｉｓｋ level: low" or "pre-vеrified" no longer slip through;
  - "System:" / "Assistant:" only match at the start of a line, so ordinary text such as
    "Billing system: invoice 42" is no longer held;
  - payloads too large (over 10,000 text fields) or too deeply nested to scan now return a
    `payload_too_large_to_scan` claim (hold) instead of being partly skipped.
- `RulePreFilter`: when no peg deviation is supplied, the assessment now carries the flag `PEG_NOT_CHECKED`
  and says the depeg check was skipped, instead of looking like a perfect peg. Decisions are unchanged.
  `TransactionPayload` gains a read-only-in-spirit `peg_observed` field, set automatically.

## 0.5.0
- New `scan_payload_claims()`: detects self-asserted verification claims in untrusted payment text
  (for example "risk level: low (verified offline)", "sanctions screening passed", "pre-approved",
  "ignore previous instructions"). Use it to hold a payment, never to reject it.
  On sra-stablecoin-risk-bench it flags all 4 of SRA-RiskGate-4B's unsafe approvals on the held-out
  test set with 0 false holds on 3,358 legitimate payments (test + train). The rules were written after
  those failures were identified, so this fixes a known weakness and is not an independent evaluation.
- x402 hooks: payment requirements whose `extra` contains such claims are aborted with
  `sra_riskgate_payload_claims` (disable with `check_payload_claims=False`).
- AgentKit action provider: a transfer whose memo contains such claims is held, not sent.

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
