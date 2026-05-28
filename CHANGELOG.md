# Changelog

All notable changes to ACP-SEC are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [0.3.1] — 2026-05-26

### Added — Base MCP compatibility

Targets the [Base MCP](https://blog.base.dev/introducing-base-mcp) skill-plugin
partner programme.  Three additions land together: an OAuth-2.1 check inside
the MCP dimension, a brand-new PLUGIN dimension, and an in-scanner "Base MCP
Partner" badge that surfaces curated partners at glance.

#### MCP-OAUTH-01 (2 pts, HIGH) — OAuth 2.1 implementation
- `acpsec/checks/mcp.py`: new check inside the existing MCP dimension.
  Inspects `mcp.auth.{oauth_version,pkce,token_rotation}` and the
  system_prompt for soft mentions of "OAuth 2.1" / "PKCE" / "token rotation".
  Full pass requires the hard config contract (2.1 + PKCE + rotation).
  Partial credit: 2/3 pillars → 1 pt, 1/3 → 0.5, 0/3 → 0.
- `acpsec/models.py`: `MCPAuthConfig` gains `oauth_version`, `pkce`,
  `token_rotation` fields.  Existing configs without OAuth pass vacuously.
- `acpsec/scorer.py`: MCP dimension weight bumped **10 → 12 pts**.  Agents
  with `mcp.enabled: true` now score out of **112** (or 122 if also x402).
- `examples/mcp_agent_compliant.yaml`: switched to `mechanism: oauth` with
  2.1 + PKCE + rotation declared, now scores **12/12 SECURE**.

#### PLUGIN dimension (3 pts, OPT-IN)
- `acpsec/checks/plugin.py`: new `run_plugin_checks()` with three 1-pt
  checks aligned with Base MCP's skill-plugin baseline:
    - **MCP-PLUGIN-01** (1, MEDIUM) — plugin sandboxing documented
    - **MCP-PLUGIN-02** (1, HIGH)   — plugin permission scoping
    - **MCP-PLUGIN-03** (1, MEDIUM) — plugin input validation
- `acpsec/models.py`: `PluginConfig` pydantic block + `AgentConfig.plugin`
  field (defaults to disabled).
- `acpsec/config_loader.py`: parses the top-level `plugin:` YAML block.
- `acpsec/scorer.py`: `OPTIONAL_DIMENSION_WEIGHTS["PLUGIN"] = 3`.  Combined
  ceiling for an agent that enables both MCP and PLUGIN: **115/100 + 15**.

#### Scanner — "⚡ Base MCP Partner" badge
- `dashboard/scanner.html`: renders the badge inline next to the band chip
  whenever the scanned agent's `@handle` or `agent_name` (normalised — lower-
  case, no `@`, no punctuation, suffix `defi|fi|protocol|labs` trimmed)
  matches the curated `BASE_MCP_PARTNERS` set:
  `morpho, moonwell, uniswap, avantisfi, bankrbot, aerodrome, virtuals_io`.
  Tooltip: "This agent is listed as a Base MCP skill plugin partner."

#### Benchmark
- `reports/base_mcp_benchmark_may2026.json` — public-scanner ranking of the
  five live partner sites.  Leaderboard (% of 114-pt max):

  | # | Partner   | Score % | Band       |
  |---|-----------|---------|------------|
  | 1 | Morpho    |  42.6%  | VULNERABLE |
  | 2 | Uniswap   |  21.3%  | CRITICAL   |
  | 3 | Avantis   |  11.1%  | CRITICAL   |
  | 4 | Moonwell  |  10.7%  | CRITICAL   |
  | 5 | Aerodrome |   4.1%  | COMPROMISED|

  Public-surface signals only — does NOT reflect private MCP server posture.

### CLI
- `acpsec check --plugin` runs only the PLUGIN dimension.
- `acpsec check --skip-plugin` force-skips it even when enabled.
- `--x402` / `--azul` / `--mcp` / `--plugin` are now mutually exclusive.
- `acpsec --version` now reports `0.3.1`.

### Tests
- `tests/test_mcp.py`: +4 tests for MCP-OAUTH-01 (full pass, fail-when-no-2.1,
  vacuous-pass-when-non-OAuth) and updated 10→12 assertions throughout.
- `tests/test_plugin.py`: +10 tests covering each PLUGIN check, scoring
  integration, opt-in gate, and YAML round-trip.
- `tests/test_x402.py`: `test_optional_dimension_weights_table` updated for
  the new `{X402: 10, MCP: 12, PLUGIN: 3}` shape.
- Suite total: **134 / 134 pass** (was 120 + 14).

### Sources
- [Introducing Base MCP](https://blog.base.dev/introducing-base-mcp)
- [Model Context Protocol — OAuth 2.1](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)

---

## [0.3.0] — 2026-05-17

### Added — MCP Server Security Module

The framework now audits agents that use the
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for tool
integration, ensuring MCP servers are properly secured against unauthorized
access, prompt injection, and privilege escalation.

#### New code
- `acpsec/checks/mcp.py` — new optional dimension **MCP** (10 pts) with
  5 static checks:
    - **MCP-AUTH-01** (3, CRITICAL) — server authentication required (no public exposure)
    - **MCP-AUTH-02** (2, HIGH) — tool authorization scoping per user
    - **MCP-INJ-01** (2, CRITICAL) — prompt injection via tool results protection
    - **MCP-PRIV-01** (2, HIGH) — resource access control (isolation + sandbox)
    - **MCP-GOV-01** (1, MEDIUM) — audit logging for MCP calls
- `acpsec/models.py` — `MCPConfig`, `MCPAuthConfig`, `MCPAccessConfig`,
  `MCPAuditConfig` pydantic blocks; `AgentConfig.mcp` field defaults to disabled.
- `acpsec/config_loader.py` — parses the top-level `mcp:` YAML block.
- `dashboard/mock_mcp_server.py` — stdlib-only mock MCP server with
  authentication, tool scoping, resource isolation, and audit logging.
- `examples/mcp_agent_compliant.yaml` — positive control, scores **10/10 SECURE**.
- `examples/mcp_agent_misconfigured.yaml` — negative control, scores **0/10
  COMPROMISED** with 5 failures.

### Added — Continuous Monitoring

New monitoring module for tracking agent security posture over time.

#### New code
- `acpsec/monitor.py` — SQLite-backed monitoring with:
    - Watchlist management (add/remove agents)
    - Scheduled scans: hourly/daily/weekly
    - Score drift detection (alert if score drops >10 pts)
    - Historical score tracking
    - Webhook notifications (Discord/Telegram/Slack)
    - ACP-SEC Trust Index — rolling average score
- `dashboard/monitor_dashboard.html` — live dashboard with:
    - Watchlist with current scores
    - Score history chart per agent
    - Drift alerts panel
    - Add agent to watchlist form
- CLI commands:
    - `acpsec monitor add <url> --schedule daily`
    - `acpsec monitor list`
    - `acpsec monitor run` (manual trigger all due agents)
    - `acpsec monitor history <url>`

#### CLI
- `acpsec check --mcp` runs only the MCP dimension.
- `acpsec check --skip-mcp` force-skips the dimension even when enabled.
- `acpsec --version` now reports `0.3.0`.

#### Scoring model
- `OPTIONAL_DIMENSION_WEIGHTS` now includes `{"MCP": 10}` alongside `{"X402": 10}`.
- Agents with `mcp.enabled: true` score out of **110** (or **120** if both
  MCP and x402 are enabled).

### Tests
- New `tests/test_mcp.py` with 26 tests covering all 5 MCP static checks,
  config parsing, scoring integration, and mock MCP server self-tests.
- New `tests/test_monitor.py` with 30 tests covering watchlist management,
  score history, trust index, drift detection, and scheduled scans.
- Total: **118 tests passing** (62 original + 26 MCP + 30 monitor).

---

## [0.2.0] — 2026-05-15

### Added — x402 Compliance Module

The framework now audits agents that speak the
[x402 protocol](https://github.com/coinbase/x402) (Coinbase's open standard
for HTTP-native machine payments, currently the largest agentic-payments
network on Base and Solana — ~165M cumulative transactions, ~$50M cumulative
volume as of April 2026).

#### New code
- `acpsec/x402_spec.py` — frozen constants from the v1 specification
  (transports-v1/http.md): canonical headers `X-PAYMENT` / `X-PAYMENT-RESPONSE`,
  EIP-3009 fields, supported networks (Base, Solana, Avalanche, IoTeX),
  facilitator paths, error codes, Base Azul activation date and finality
  windows (mainnet 2026-05-13, ~1-day post-Azul finality via multiproof).
- `acpsec/checks/x402.py` — new optional dimension **X402** (10 pts) with
  7 static checks:
    - **X402-AUTH-01** (2, CRITICAL) — payment proof validation declared
    - **X402-AUTH-02** (2, CRITICAL) — replay-attack protection (nonce strategy)
    - **X402-AUTH-03** (1, HIGH) — EIP-712 signature verification committed
    - **X402-THR-01** (1, HIGH) — per-request amount cap declared
    - **X402-THR-02** (2, CRITICAL) — daily / total spending cap declared
    - **X402-INJ-01** (1, MEDIUM) — X-PAYMENT header injection protection
    - **X402-AZUL-01** (1, LOW) — Base Azul multiproof finality awareness
- `acpsec/models.py` — `X402Config`, `X402FinalityConfig`, `X402AssetConfig`
  pydantic blocks; `AgentConfig.x402` field defaults to disabled.
- `acpsec/config_loader.py` — parses the top-level `x402:` YAML block.
- `dashboard/mock_facilitator.py` — stdlib-only mock x402 facilitator
  (`/verify`, `/settle`, `/supported`) used by tests and by the auth-scanner
  when no real facilitator URL is reachable. Validates schema, signature
  shape, nonce uniqueness, validity window, and supported networks.
- `dashboard/auth_scanner.py` — 4 **X402-LIVE** probes that run when the
  agent declares `x402.enabled: true`:
    - **X402-LIVE-01** (CRITICAL) — nonce replay rejected by facilitator (HTTP)
    - **X402-LIVE-02** (HIGH) — mangled signature rejected (HTTP)
    - **X402-LIVE-03** (MEDIUM) — malformed payload rejected (HTTP)
    - **X402-LIVE-04** (HIGH) — agent refuses an above-cap settlement (LLM)
  HTTP probes cost $0; the LLM probe is one Haiku call (~$0.002).
- `examples/x402_agent_compliant.yaml` — positive control, scores **10/10 SECURE**.
- `examples/x402_agent_misconfigured.yaml` — negative control, scores **0/10
  COMPROMISED** with 3 CRITICAL failures and remediation suggestions.

#### CLI
- `acpsec check --x402` runs only the X402 dimension.
- `acpsec check --azul` runs only X402-AZUL-01.
- `acpsec check --skip-x402` force-skips the dimension even when enabled.
- `acpsec --version` now reports `0.2.0`.

#### Scoring model
- New `OPTIONAL_DIMENSION_WEIGHTS = {"X402": 10}` table in `scorer.py`.
- Standard agents continue to score out of **100** (no behavior change for
  existing benchmarks). Agents with `x402.enabled: true` score out of **110**.
- `AssessmentResult.max_score` is now derived from the dimensions actually
  run, not hardcoded.
- `ScoringEngine.band()` now receives a percentage (band thresholds were
  already percentages — this fixes a latent bug for the variable-max case).

### Changed
- `acpsec/reporter.py` — `print_assessment` shows `score / actual_max (pct)`
  rather than the hardcoded `/ 100`.
- `acpsec/cli.py` — version bumped 0.1.0 → 0.2.0.

### Tests
- New `tests/test_x402.py` with 38 tests covering spec constants, config
  parsing, all 7 static checks, opt-in scoring math, mock-facilitator
  behaviour, and the 4 live probes (with a stubbed LLM so the suite stays
  free to run). All 62 tests in the project pass.

### Costs
- Total LLM spend across all v0.2.0 development scans: **~$0.028** (within
  the $0.05 budget planned for the milestone).

### Sources
- [x402 specification v1 (Coinbase)](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md)
- [x402 HTTP transport](https://github.com/coinbase/x402/blob/main/specs/transports-v1/http.md)
- [Introducing Base Azul](https://blog.base.dev/introducing-base-azul)

---

## [0.1.0] — 2026-05-14

### Added — Initial release
- `acpsec` framework with 30 checks across 6 dimensions (AUTH / CTX / INJ /
  PRIV / OUT / GOV), 100-point scoring engine, CRITICAL-failure penalty rule.
- `acpsec check`, `acpsec inject`, `acpsec report` CLI commands.
- 27-payload injection test suite across 6 categories.
- Dashboard (`dashboard/serve.py` + Flask + HTML/JS UI).
- Public heuristic scanner (`dashboard/scanner.py`) with corpus probing,
  parent-org probing, self-probe logic, URL normalisation, login-wall handling.
- Authenticated scanner (`dashboard/auth_scanner.py`) with 13 live probes
  via direct Anthropic API and per-probe token-cost tracking.
- Hardened-agent positive control (`examples/hardened_agent.yaml`) scoring
  48/48 SECURE; bankrbot simulation scoring 35/48 HARDENED.
- Benchmark visualisations and side-by-side comparison report.
