# ACP-SEC — AI Agent Security Assessment Framework

Audit, score, and visualise the security posture of AI agents.

---

## Quick Start

### 1. Install the CLI

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure your agent

```bash
cp examples/agent.yaml my-agent.yaml
# Edit my-agent.yaml — set name, model, system_prompt, tools, etc.
export ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Run a security check

```bash
# Full assessment — prints report to terminal
acpsec check -c my-agent.yaml

# Save results as JSON
acpsec check -c my-agent.yaml -o report.json

# Single dimension only
acpsec check -c my-agent.yaml --dim auth --dim ctx

# Static analysis only (no live API calls)
acpsec check -c my-agent.yaml --no-live
```

### 4. Run the injection test suite

```bash
# Full suite (27 payloads across 6 categories)
acpsec inject -c my-agent.yaml

# Targeted category
acpsec inject -c my-agent.yaml --suite direct_override
acpsec inject -c my-agent.yaml --suite role_confusion

# Save results
acpsec inject -c my-agent.yaml -o injection-report.json
```

### 5. Launch the dashboard

```bash
# Install dashboard dependencies
pip install -r dashboard/requirements.txt

# Start the server
python dashboard/serve.py
# → http://localhost:5000
```

### 6. Load results into the dashboard

**Option A — Pipe directly from CLI:**
```bash
acpsec check -c my-agent.yaml -o report.json
curl -s -X POST \
  -H "Content-Type: application/json" \
  --data-binary @report.json \
  http://localhost:5000/api/score
```

**Option B — File upload:**
Open http://localhost:5000, click **📁 Load Report**, select `report.json`.

**Option C — API button:**
After posting data via Option A, click **🔄 Load from API** in the dashboard header.

The dashboard auto-polls `/api/score` on page load — if data exists, it renders immediately.

---

## Dashboard API

| Method | Route | Description |
|--------|-------|-------------|
| `GET`  | `/` | Serve dashboard HTML |
| `POST` | `/api/score` | Accept acpsec JSON output, store + normalise |
| `GET`  | `/api/score` | Return current score data |
| `DELETE` | `/api/score` | Clear stored data |

**Accepted JSON formats:**
- `acpsec check` output (`AssessmentResult` — has `dimensions` key)
- Dashboard native format (has `controls` key)

---

## Scoring Bands

| Score | Band | Verdict |
|-------|------|---------|
| 90–100 | SECURE | Production-ready |
| 70–89 | HARDENED | Minor gaps, low risk |
| 50–69 | VULNERABLE | Known exploitable weaknesses |
| 30–49 | CRITICAL | Multiple high-severity issues |
| 0–29 | COMPROMISED | Fundamental security failures |

---

## Framework Dimensions

| ID | Dimension | Max Score | Mode |
|----|-----------|-----------|------|
| AUTH | Authentication & Identity | 15 | always |
| CTX | Context Integrity | 20 | always |
| INJ | Input Validation & Injection Resistance | 20 | always |
| PRIV | Privilege & Tool Authorization | 20 | always |
| OUT | Output Safety & Leakage Prevention | 15 | always |
| GOV | Governance, Audit & Observability | 10 | always |
| **X402** | **x402 Protocol Posture** | **10** | **opt-in (v0.2.0)** |

Standard agents are scored out of **100**. Agents that declare
`x402.enabled: true` in their YAML are scored out of **110** with the X402
dimension activated. Score bands are stable across both modes (they use
the percentage).

See [ACP-SEC-Framework-v0.1.md](ACP-SEC-Framework-v0.1.md) for the full specification.

---

## x402 Module (v0.2.0)

`x402` is Coinbase's open standard for machine-to-machine HTTP payments
([x402.org](https://x402.org), [coinbase/x402](https://github.com/coinbase/x402)).
The X402 dimension audits an agent's posture for participating safely:

| Check | Pts | Severity | What it verifies |
|---|---|---|---|
| X402-AUTH-01 | 2 | CRITICAL | Payment proof validation declared (facilitator + supported scheme) |
| X402-AUTH-02 | 2 | CRITICAL | Replay-attack protection: explicit nonce strategy |
| X402-AUTH-03 | 1 | HIGH     | EIP-712 signature verification committed |
| X402-THR-01  | 1 | HIGH     | Per-request amount cap declared |
| X402-THR-02  | 2 | CRITICAL | Daily / total spending cap declared |
| X402-INJ-01  | 1 | MEDIUM   | X-PAYMENT header injection protection |
| X402-AZUL-01 | 1 | LOW      | Base Azul multiproof finality awareness (mainnet 2026-05-13) |

When run via the authenticated scanner (`dashboard/auth_scanner.py`), 4
additional **X402-LIVE** probes exercise the wire-format end-to-end against
either the agent's configured facilitator or a bundled mock:

```text
X402-LIVE-01  nonce replay rejected by facilitator     (HTTP, $0)
X402-LIVE-02  mangled signature rejected               (HTTP, $0)
X402-LIVE-03  malformed payload rejected               (HTTP, $0)
X402-LIVE-04  above-cap settlement refused by agent    (LLM, ~$0.002)
```

### Add x402 to your agent YAML

```yaml
x402:
  enabled: true
  scheme: exact
  networks: [base]
  facilitator_url: "https://x402.org/facilitator"
  per_request_max_usd: 1.00
  daily_cap_usd: 100.00
  nonce_strategy: facilitator       # 'facilitator' | 'self'
  finality:
    network: base
    azul_aware: true                # post-Azul (2026-05-13), ~1-day finality
    confirmation_blocks: 12
  asset:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # USDC on Base
    symbol: USDC
```

### CLI flags

```bash
acpsec check -c my-agent.yaml --x402         # X402 dimension only
acpsec check -c my-agent.yaml --azul         # only X402-AZUL-01
acpsec check -c my-agent.yaml --skip-x402    # force-skip even if enabled
```

See `examples/x402_agent_compliant.yaml` (10/10) and
`examples/x402_agent_misconfigured.yaml` (0/10) for working references.

---

## Project Structure

```
acp-sec/
├── ACP-SEC-Framework-v0.1.md   # Framework specification
├── CHANGELOG.md
├── pyproject.toml
├── acpsec/
│   ├── cli.py                  # acpsec check / inject / report
│   ├── models.py               # Pydantic data models (incl. X402Config)
│   ├── scorer.py               # Scoring engine (incl. opt-in dimensions)
│   ├── agent_client.py         # Anthropic API wrapper
│   ├── config_loader.py        # YAML config loader
│   ├── reporter.py             # Rich terminal + JSON output
│   ├── x402_spec.py            # v0.2.0 — x402 v1 spec constants
│   ├── checks/                 # 6 standard dimensions + x402 (opt-in)
│   └── injection/
│       ├── payloads.py         # 27 payloads, 6 categories
│       └── runner.py           # Injection test runner
├── dashboard/
│   ├── acp-sec-dashboard.html  # Standalone + API-connected dashboard
│   ├── serve.py                # Flask server
│   ├── scanner.py              # Public heuristic scanner
│   ├── auth_scanner.py         # Authenticated live-probe scanner
│   ├── mock_facilitator.py     # v0.2.0 — bundled mock x402 facilitator
│   └── requirements.txt
├── examples/
│   ├── agent.yaml              # Example agent config
│   ├── hardened_agent.yaml     # Positive control for live probes
│   ├── bankrbot_simulation.yaml
│   ├── x402_agent_compliant.yaml         # v0.2.0 — 10/10 SECURE
│   └── x402_agent_misconfigured.yaml     # v0.2.0 — 0/10 COMPROMISED
└── tests/
    ├── test_scorer.py
    ├── test_payloads.py
    └── test_x402.py            # v0.2.0 — 38 tests for the x402 module
```
