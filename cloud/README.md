# SRA-RiskGate Cloud

The hosted service behind `sra_riskgate.cloud` (sra-riskgate 2.0.0+). The library stays free, offline and open
source. The cloud adds what one machine cannot do alone:

| Feature | What it does |
| --- | --- |
| Shared budgets | One spend ledger for every machine an organisation's agents run on. The budget check and its ledger entry happen together, so eight workers racing for the last $30 of a budget cannot all win. |
| Threat feed | Look-alike addresses reported by poisoning scans. An address enters everyone's feed only when at least two organisations report it (`SRA_CLOUD_FEED_MIN_ORGS`, never below 2) or an operator approves it, so no single customer can block an address for everyone. |
| Receipt vault | Every cloud decision is signed with the organisation's own key, chained to the one before and stored. `GET /v1/report` builds the audit report. |
| Pay per check (x402) | `POST /v1/x402/check`: agents with no account pay per check in USDC, through the official x402 SDK and a facilitator. Stateless: no shared ledger, since there is no account. |
| Dashboard | `GET /`: plan, usage, verified receipts, feed size and recent decisions. The API key stays in the browser tab. |

The payment's free text never reaches the service: `CloudClient.check_payment` checks it locally first and sends
only the payment fields.

## API

All `/v1` routes except `/v1/x402/check` need `Authorization: Bearer sra_live_...`.

| Route | |
| --- | --- |
| `POST /v1/check` | `{chain_id, sender, recipient, amount, token?, peg_deviation_pct?, payment_id?, known_recipients?}`: the decision, flags, signed `receipt`, `usage`. 429 when the plan's monthly limit is reached. |
| `POST /v1/ledger/release` | `{payment_id}`: give back the budget of an approved payment that was never sent. |
| `GET /v1/policy`, `PUT /v1/policy` | The organisation's policy, in the library's [policy format](../README.md); `ledger` and `screening` are refused. |
| `GET /v1/feed`, `POST /v1/feed/report` | The threat feed; report `{address, imitates?, chain_id?, tx?}`. |
| `GET /v1/receipts?after=&limit=`, `GET /v1/report?format=json\|md` | The vault and its audit report. |
| `GET /v1/usage` | Checks used this month and the plan's limit. |
| `POST /v1/x402/check` | Pay-per-check (when configured). |
| `GET /healthz`, `GET /` | Health and dashboard. |

## Run it locally

```bash
pip install -e . -e "./cloud[x402]"          # from the repository root
export SRA_CLOUD_DB=./sra-cloud.db
sra-cloud create-org "My team" --plan free     # prints org id, API key and receipt key: save them
sra-cloud serve --port 8080
```

```python
from sra_riskgate import CloudClient
cloud = CloudClient(api_key="sra_live_...", base_url="http://localhost:8080")
cloud.set_policy({"version": 1, "budgets": {"window_hours": 24, "total": 500}})
r = cloud.check_payment(chain_id=8453, sender=agent, recipient=payee, amount=25, peg_deviation_pct=0.0)
```

## Deploy on Fly.io

From the repository root, with [flyctl](https://fly.io/docs/flyctl/install/) installed and `fly auth login` done:

```bash
fly apps create YOUR-APP-NAME                        # then set app = "YOUR-APP-NAME" in cloud/fly.toml
fly volumes create sra_data --size 1 --region iad --config cloud/fly.toml
fly deploy --config cloud/fly.toml --dockerfile cloud/Dockerfile
fly ssh console --config cloud/fly.toml -C 'sra-cloud create-org "First customer" --plan free'
```

Optional settings (`fly secrets set NAME=value --config cloud/fly.toml`):

| Variable | Default | |
| --- | --- | --- |
| `SRA_CLOUD_PLANS` | `{"free": 1000, "team": 100000, "scale": 2000000}` | Monthly check limit per plan |
| `SRA_CLOUD_FEED_MIN_ORGS` | `2` | Organisations that must report an address before it enters the feed (2 or more) |
| `SRA_CLOUD_X402_PAY_TO` | unset | Your USDC address: turns on pay-per-check |
| `SRA_CLOUD_X402_RECEIPT_KEY` | unset | Hex key that signs pay-per-check receipts (required with the above): `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SRA_CLOUD_X402_PRICE` | `$0.002` | Price per check |
| `SRA_CLOUD_X402_NETWORK` | `eip155:8453` | Base mainnet. `eip155:84532` for Base Sepolia while testing |
| `SRA_CLOUD_FACILITATOR_URL` | x402 SDK default | Facilitator for verify and settle |

## Operate it

```bash
sra-cloud orgs                                   # list organisations
sra-cloud new-key ORG_ID --label ci              # another key; revoke with: sra-cloud revoke-key sra_live_XXXXXXX
sra-cloud set-plan ORG_ID team
sra-cloud feed --pending                         # reports not yet in the feed
sra-cloud feed-approve 0x...  /  sra-cloud feed-reject 0x... --note "false positive"
```

Back up `/data/sra-cloud.db` (Fly volume snapshots are on by default; copy it off-site too). It holds API key
hashes, organisation receipt keys, the ledger and the vault.

## Limits of this version (0.1.0)

- **One instance.** Atomic budgets rely on one process and one SQLite file. Keep `min_machines_running = 1` and do
  not scale out until the ledger moves to Postgres.
- **No self-serve signup or card billing yet.** You create organisations with `sra-cloud create-org` and invoice by
  hand; x402 pay-per-check needs no account.
- **Receipt keys are held by the service** so it can sign; the organisation gets a copy at creation to verify
  receipts independently. Treat the database as secret.
- **Get an independent security review before taking money**: the service holds budgets, keys and decision records.
