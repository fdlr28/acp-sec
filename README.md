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

| ID | Dimension | Max Score |
|----|-----------|-----------|
| AUTH | Authentication & Identity | 15 |
| CTX | Context Integrity | 20 |
| INJ | Input Validation & Injection Resistance | 20 |
| PRIV | Privilege & Tool Authorization | 20 |
| OUT | Output Safety & Leakage Prevention | 15 |
| GOV | Governance, Audit & Observability | 10 |

See [ACP-SEC-Framework-v0.1.md](ACP-SEC-Framework-v0.1.md) for the full specification.

---

## Project Structure

```
acp-sec/
├── ACP-SEC-Framework-v0.1.md   # Framework specification
├── pyproject.toml
├── acpsec/
│   ├── cli.py                  # acpsec check / inject / report
│   ├── models.py               # Pydantic data models
│   ├── scorer.py               # Scoring engine
│   ├── agent_client.py         # Anthropic API wrapper
│   ├── config_loader.py        # YAML config loader
│   ├── reporter.py             # Rich terminal + JSON output
│   ├── checks/                 # 6 dimension check modules
│   └── injection/
│       ├── payloads.py         # 27 payloads, 6 categories
│       └── runner.py           # Injection test runner
├── dashboard/
│   ├── acp-sec-dashboard.html  # Standalone + API-connected dashboard
│   ├── serve.py                # Flask server
│   └── requirements.txt
├── examples/
│   └── agent.yaml              # Example agent config
└── tests/
    ├── test_scorer.py
    └── test_payloads.py
```
