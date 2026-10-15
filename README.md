# ContractScan

ContractScan checks single-file Solidity contracts before deployment. It is aimed at AI-written ("vibe-coded") contracts. It runs [Slither](https://github.com/crytic/slither) and [Aderyn](https://github.com/Cyfrin/aderyn) static analysis plus a small set of rug-pull and centralization heuristics. It then gives a verdict of **Deployable**, **Fix first** or **Do not deploy**, with plain-language explanations.

Hosted version: https://contract-scan.dev

> **ContractScan is NOT an audit.** It is static analysis plus pattern heuristics. It misses economic and logic bugs and produces false positives. A "Deployable" verdict only means no high- or medium-severity issue was found by these tools.

## How the verdict works

- The verdict is computed from tool findings only. The optional LLM explainer writes explanation text and patches, but it cannot change the verdict.
- A single high-severity finding blocks deployment only if one of these holds:
  - it comes from a high-precision Slither detector (`reentrancy-eth`, `arbitrary-send-eth`, `suicidal`, `controlled-delegatecall`);
  - another tool or a heuristic flags overlapping lines;
  - the owner can take funds that users deposited;
  - anyone can mint tokens, anyone can burn another account's tokens, or a self-transfer inflates the balance (token-logic heuristics).
- Otherwise the result is "fix first" with low confidence.
- Each report includes `verdict_confidence` and `verdict_reasons`. Every finding has a `why` field (which detector or pattern fired, on what code), and every report has a `not_analyzed` list: business logic, price/oracle manipulation, cross-contract interactions, economic/MEV and off-chain risk are not checked.
- Token-logic heuristics (`token:*`) target root causes seen in real exploits: self-transfer balance inflation, unguarded mint, unguarded burn of another account, rewriting the AMM pair balance plus `sync()`, extra burns on pool transfers, and pricing from `address(this).balance` during a payable call.
- The heuristic thresholds were tuned on a small public experiment: https://github.com/contractscan-dev/ai-solidity-experiment-2026-10

## Run locally

Requirements: Linux, Python 3.11+, `bwrap` (bubblewrap, optional but recommended), Slither, Aderyn, and solc via solc-select.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
for v in $(seq 0 30); do solc-select install 0.8.$v; done   # scanner only uses pre-installed compilers
CS_ALLOW_PREWARM=1 python scripts/prewarm_compilers.py      # one-time: cache compilers for Aderyn (no downloads at scan time)
# install aderyn: https://github.com/Cyfrin/aderyn#installation
cp config.env.example config.env                       # edit values
CS_VENV=$VIRTUAL_ENV uvicorn app:app --host 127.0.0.1 --port 8787
```

- Web UI: http://127.0.0.1:8787/
- API: `POST /api/scan` with JSON `{"source": "<solidity>"}`
- Tests: `pytest -q tests`. The end-to-end regression tests are skipped when the analysis tools are not installed.

Each scan runs in a fresh temporary directory inside bubblewrap. The sandbox has no network and a read-only root, and runs under memory, CPU and time limits. Contract code is only compiled and analyzed, never executed.

Limits: single file (flattened is fine), 2,000 lines, 250 KB, solc 0.8.0-0.8.30 (pre-installed only). The only imports allowed are `@openzeppelin/contracts/...`. They resolve to pinned vendored copies in `vendor/` (v4.9.6 and v5.7.0, MIT, sha256 in `vendor/README.md`), and nothing is fetched at scan time. Findings inside OpenZeppelin code are not reported.

## MCP

ContractScan includes a stdio MCP server exposing one tool, `scan_contract`:

```json
{ "mcpServers": { "contractscan": { "command": "/path/to/.venv/bin/python", "args": ["/path/to/contractscan/mcp_server.py"] } } }
```

The server enforces a per-caller daily limit (`CS_MCP_PER_DAY`).

## Data retention

- **Contract source is not stored.** It is written to a temporary directory for the duration of a scan, and that directory is deleted when the scan finishes. The hosted service never keeps source longer than 24 hours.
- If an LLM explainer is configured (`DEEPSEEK_API_KEY`), the source and findings are sent to that provider to generate explanations.
- The SQLite database (`data/`) holds anonymous usage counters, payment records (transaction hashes and redeem codes) and optional feedback.

## Payments (hosted service)

The hosted service accepts plain USDC transfers on Base, which the server verifies on-chain. It never asks for wallet signatures and never holds keys. x402 support is experimental. See `payments.py`.

## License

MIT. See [LICENSE](LICENSE).
