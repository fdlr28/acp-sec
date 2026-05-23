# ACP-SEC v0.3.0 Polish & Cloud Deployment Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Polish ACP-SEC v0.3.0 codebase for production readiness, improve dashboard UI, and prepare for cloud deployment.

**Architecture:** Flask backend (`serve.py`) serves three HTML dashboards (main, scanner, monitor). The `acpsec` Python package provides CLI, scoring engine, checks, and monitoring. We'll add monitor API endpoints, unify the UI, fix the version mismatch, and add deployment configs.

**Tech Stack:** Python 3.11+, Flask 3.0+, Chart.js 3.9 (CDN), SQLite (monitor), Pydantic, Click, Rich

---

## File Map

### Files to Modify
- `acpsec/__init__.py` — fix version from "0.1.0" to "0.3.0"
- `dashboard/serve.py` — add CORS, health endpoint, monitor API endpoints, env var handling
- `dashboard/scanner.html` — version badge, add-to-watchlist button, loading animation, nav
- `dashboard/monitor_dashboard.html` — connect to API endpoints, live data, nav
- `dashboard/acp-sec-dashboard.html` — unified nav
- `README.md` — full rewrite with MCP/monitor docs
- `dashboard/requirements.txt` — pin versions, add flask-cors

### Files to Create
- `Procfile` — Railway/Render deployment
- `vercel.json` — Vercel static deployment
- `requirements.txt` (root) — pinned production dependencies

---

## Phase 1: Code Cleanup & Polish

### Task 1: Fix Version Mismatch

**Files:**
- Modify: `acpsec/__init__.py:3`

- [ ] **Step 1: Fix `__init__.py` version**

Change line 3 of `acpsec/__init__.py`:
```python
__version__ = "0.3.0"
```

- [ ] **Step 2: Verify version consistency**

Run: `cd /Users/fadhlan/sentrak/acp-sec && python -c "import acpsec; print(acpsec.__version__)"`
Expected: `0.3.0`

- [ ] **Step 3: Commit**

```bash
cd /Users/fadhlan/sentrak/acp-sec
git add acpsec/__init__.py
git commit -m "fix: align __init__.py version to 0.3.0 with pyproject.toml"
```

---

### Task 2: Add Docstrings to Public Functions

All public functions in `acpsec/` modules need docstrings. The `dashboard/` files already have docstrings on their public functions.

**Files:**
- Modify: `acpsec/models.py` — add docstrings to all Pydantic model classes and their properties
- Modify: `acpsec/scorer.py` — add docstrings to `ScoringEngine` methods, `make_check`, `total_max_score`
- Modify: `acpsec/cli.py` — add docstrings to all Click commands
- Modify: `acpsec/agent_client.py` — add docstrings to `AgentClient` class and methods
- Modify: `acpsec/config_loader.py` — add docstrings to `load_config`, `_expand_env_vars`
- Modify: `acpsec/reporter.py` — add docstrings to `print_assessment`, `print_injection_report`, `save_json`
- Modify: `acpsec/catalogue.py` — add docstrings to `get_check_catalogue`, `get_dimension_catalogue`
- Modify: `acpsec/monitor.py` — add docstrings to `Monitor` class and all public methods
- Modify: `acpsec/injection/runner.py` — add docstrings to `InjectionRunner` class and `run`
- Modify: `acpsec/injection/payloads.py` — add docstrings to `Payload` dataclass and `ALL_PAYLOADS`
- Modify: `acpsec/checks/*.py` — add docstrings to all `run_*_checks` functions

- [ ] **Step 1: Add docstrings to `acpsec/models.py`**

Add class-level docstrings to each Pydantic model and property docstrings to computed properties. Example for `CheckResult`:

```python
class CheckResult(BaseModel):
    """Result of a single security check."""

    check_id: str
    name: str
    dimension: str
    status: CheckStatus = CheckStatus.FAIL
    score: float = 0.0
    max_score: float = 0.0
    severity: Severity = Severity.MEDIUM
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Whether the check passed."""
        return self.status == CheckStatus.PASS

    @property
    def score_pct(self) -> float:
        """Score as a percentage of max possible."""
        return (self.score / self.max_score * 100) if self.max_score > 0 else 0.0
```

Repeat for all models: `DimensionResult`, `AssessmentResult`, `InjectionResult`, `InjectionSuiteResult`, `X402Config`, `MCPConfig`, `AgentConfig`, and all nested config models.

- [ ] **Step 2: Add docstrings to `acpsec/scorer.py`**

```python
def total_max_score(active_optional: set[str] | None = None) -> int:
    """Compute the maximum possible score for a scan run."""

class ScoringEngine:
    """Aggregates dimension scores, applies penalties, and assigns bands."""

    def score_dimension(self, results: list[CheckResult]) -> float:
        """Sum earned points across all checks in a dimension."""

    def apply_penalties(self, score: float, checks: list[CheckResult]) -> float:
        """Deduct CRITICAL_PENALTY for each unmitigated CRITICAL failure."""

    def band(self, score: float) -> tuple[str, str]:
        """Return (band_name, verdict) for a given 0-100 score percentage."""

    def build_assessment(self, ...) -> AssessmentResult:
        """Aggregate dimension results into a full AssessmentResult."""

def make_check(...) -> CheckResult:
    """Helper to construct a CheckResult with pass/fail/warn logic."""
```

- [ ] **Step 3: Add docstrings to `acpsec/agent_client.py`**

```python
class AgentClient:
    """Thin wrapper around the Anthropic API for agent communication."""

    def __init__(self, config: AgentConfig):
        """Initialize client from agent configuration."""

    def send(self, user_message: str, ...) -> str:
        """Send a message to the agent and return the text response."""

    def health_check(self) -> bool:
        """Verify the agent endpoint is reachable."""
```

- [ ] **Step 4: Add docstrings to remaining modules**

Apply the same pattern to `config_loader.py`, `reporter.py`, `catalogue.py`, `monitor.py`, `injection/runner.py`, `injection/payloads.py`, and all `checks/*.py` files. Each public function gets a one-line summary docstring.

- [ ] **Step 5: Verify no import errors**

Run: `cd /Users/fadhlan/sentrak/acp-sec && python -c "import acpsec; from acpsec.checks import run_auth_checks"`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add acpsec/
git commit -m "docs: add docstrings to all public functions in acpsec package"
```

---

### Task 3: Add Type Hints Where Missing

**Files:**
- Modify: `acpsec/reporter.py` — return types on `print_assessment`, `print_injection_report`, `save_json`
- Modify: `acpsec/config_loader.py` — return type on `load_config`
- Modify: `acpsec/monitor.py` — return types on `Monitor` methods
- Modify: `acpsec/injection/runner.py` — param/return types on `InjectionRunner` methods

- [ ] **Step 1: Add return types to `reporter.py`**

```python
def print_assessment(result: AssessmentResult) -> None:
def print_injection_report(result: InjectionSuiteResult) -> None:
def save_json(data: Any, output: str | None) -> None:
```

- [ ] **Step 2: Add return types to `config_loader.py`**

```python
def load_config(path: str | Path) -> AgentConfig:
```

- [ ] **Step 3: Add return types to `monitor.py`**

```python
def add_agent(self, url: str, schedule: str) -> None:
def remove_agent(self, url: str) -> None:
def list_agents(self) -> list[WatchlistEntry]:
def get_agent(self, url: str) -> WatchlistEntry | None:
def record_score(self, url: str, score: float, max_score: float, band: str) -> None:
def get_history(self, url: str, limit: int = 50) -> list[ScoreRecord]:
def get_trust_index(self, url: str, window: int = 5) -> float | None:
def get_alerts(self, url: str | None = None, limit: int = 20) -> list[DriftAlert]:
def get_due_agents(self) -> list[WatchlistEntry]:
```

- [ ] **Step 4: Add return types to `injection/runner.py`**

```python
async def run(self, categories: list[str] | None = None, delay_seconds: float = 0.5) -> InjectionSuiteResult:
async def _run_payload(self, payload: Payload) -> InjectionResult:
```

- [ ] **Step 5: Run tests to verify**

Run: `cd /Users/fadhlan/sentrak/acp-sec && PYTHONPATH=. /opt/homebrew/bin/python3 -m pytest tests/ -q`
Expected: 116+ passed

- [ ] **Step 6: Commit**

```bash
git add acpsec/
git commit -m "type: add missing type hints to acpsec package"
```

---

### Task 4: Remove Dead Code & Unused Imports

**Files:**
- Modify: all `acpsec/*.py` and `dashboard/*.py` files as needed

- [ ] **Step 1: Run ruff to find unused imports**

Run: `cd /Users/fadhlan/sentrak/acp-sec && python -m ruff check acpsec/ dashboard/ --select F401,F811`
Expected: list of any unused imports

- [ ] **Step 2: Fix any issues found**

Remove unused imports. If ruff finds none, this step is a no-op.

- [ ] **Step 3: Run ruff full check**

Run: `cd /Users/fadhlan/sentrak/acp-sec && python -m ruff check acpsec/ dashboard/`
Expected: clean or only pre-existing style warnings

- [ ] **Step 4: Commit (if changes made)**

```bash
git add acpsec/ dashboard/
git commit -m "chore: remove dead code and unused imports"
```

---

### Task 5: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite README.md**

Replace the entire README with:

```markdown
# ACP-SEC

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![Tests](https://img.shields.io/badge/tests-116+-brightgreen)
![License](https://img.shields.io/badge/license-MIT-gray)

**AI Agent Communication Protocol Security Assessment Framework**

ACP-SEC evaluates AI agent security across 7 dimensions: Authentication, Context Integrity, Injection Resistance, Privilege Control, Output Safety, Governance, and x402 Payment Security.

## Quick Start

```bash
# 1. Install
pip install -e .

# 2. Configure your agent
cp examples/agent.yaml my-agent.yaml
# Edit my-agent.yaml with your agent details

# 3. Run security assessment
acpsec check -c my-agent.yaml
```

## Features

- **30+ security checks** across 7 dimensions (6 mandatory + 2 opt-in)
- **Injection testing** with 27 attack payloads across 6 categories
- **Web dashboard** with real-time scoring and visualizations
- **Agent scanner** for heuristic website security analysis
- **Continuous monitoring** with drift detection and alerts
- **x402 payment security** module for agent commerce
- **MCP (Model Context Protocol)** security assessment
- **CLI-first** with rich terminal output and JSON export

## Installation

```bash
# Clone and install
git clone https://github.com/fdlr28/acp-sec.git
cd acp-sec
pip install -e .

# Install dashboard dependencies (optional)
pip install -r dashboard/requirements.txt
```

## Usage

### CLI Assessment

```bash
# Run all checks
acpsec check -c agent.yaml

# Run specific dimensions
acpsec check -c agent.yaml --dim auth --dim inj

# Enable x402 payment checks
acpsec check -c agent.yaml --x402

# Enable MCP checks
acpsec check -c agent.yaml --mcp

# Run injection suite
acpsec inject -c agent.yaml

# Export results
acpsec check -c agent.yaml -o results.json
```

### Dashboard

```bash
# Launch web dashboard
python dashboard/serve.py
# Open http://localhost:5001

# Scanner page
# Open http://localhost:5001/scanner

# Monitor page
# Open http://localhost:5001/monitor
```

### Continuous Monitoring

```bash
# Add agent to watchlist
acpsec monitor add https://agent.example.com --schedule daily

# List watched agents
acpsec monitor list

# Run due scans
acpsec monitor run

# View score history
acpsec monitor history https://agent.example.com
```

## Security Dimensions

| Dimension | Weight | Checks | Description |
|-----------|--------|--------|-------------|
| AUTH | 15 pts | 5 | Authentication & Identity |
| CTX | 20 pts | 5 | Context Integrity |
| INJ | 20 pts | 5 | Input Validation & Injection Resistance |
| PRIV | 20 pts | 5 | Privilege & Tool Authorization |
| OUT | 15 pts | 5 | Output Safety & Leakage Prevention |
| GOV | 10 pts | 5 | Governance, Audit & Observability |
| X402 | 10 pts | 7 | Payment Security (opt-in) |
| MCP | 10 pts | 5 | Model Context Protocol (opt-in) |

## Score Bands

| Band | Range | Verdict |
|------|-------|---------|
| SECURE | 90-100 | Production-ready with active monitoring |
| HARDENED | 70-89 | Minor gaps present, low overall risk |
| VULNERABLE | 50-69 | Known exploitable weaknesses |
| CRITICAL | 30-49 | Multiple high-severity issues |
| COMPROMISED | 0-29 | Fundamental security failures |

## Project Structure

```
acp-sec/
├── acpsec/                 # Python package
│   ├── cli.py              # Click CLI
│   ├── scorer.py           # Scoring engine
│   ├── models.py           # Pydantic models
│   ├── monitor.py          # Continuous monitoring
│   ├── checks/             # Security check modules
│   │   ├── auth.py         # AUTH dimension
│   │   ├── context.py      # CTX dimension
│   │   ├── input_validation.py  # INJ dimension
│   │   ├── privilege.py    # PRIV dimension
│   │   ├── output_safety.py # OUT dimension
│   │   ├── governance.py   # GOV dimension
│   │   ├── x402.py         # X402 dimension
│   │   └── mcp.py          # MCP dimension
│   └── injection/          # Injection test suite
│       ├── payloads.py     # 27 attack payloads
│       └── runner.py       # Injection executor
├── dashboard/              # Web dashboard
│   ├── serve.py            # Flask server
│   ├── acp-sec-dashboard.html  # Main dashboard
│   ├── scanner.html        # Agent scanner
│   ├── monitor_dashboard.html  # Monitor dashboard
│   └── scanner.py          # Heuristic scanner
├── tests/                  # Test suite (116+ tests)
└── examples/               # Example agent configs
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main dashboard |
| GET | `/scanner` | Agent scanner |
| GET | `/monitor` | Monitor dashboard |
| GET | `/api/health` | Health check |
| POST | `/api/scanner/lookup` | X profile lookup |
| POST | `/api/scanner/scan` | Heuristic scan |
| GET | `/api/score` | Get current score |
| POST | `/api/score` | Post score data |
| DELETE | `/api/score` | Clear score |
| GET | `/api/monitor/agents` | List watchlist |
| POST | `/api/monitor/agents` | Add to watchlist |
| DELETE | `/api/monitor/agents` | Remove from watchlist |
| POST | `/api/monitor/scan` | Trigger scan |
| GET | `/api/monitor/history` | Score history |
| GET | `/api/monitor/alerts` | Drift alerts |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`PYTHONPATH=. pytest tests/ -q`)
4. Commit your changes (`git commit -m 'feat: add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README with MCP/monitor docs, badges, and quick start"
```

---

## Phase 2: Dashboard UI Improvements

### Task 6: Add Monitor API Endpoints to serve.py

The monitor dashboard currently uses localStorage. We need API endpoints backed by `acpsec.monitor.Monitor` (SQLite).

**Files:**
- Modify: `dashboard/serve.py`

- [ ] **Step 1: Add monitor imports and initialization**

Add after line 66 in `serve.py`:

```python
# ---------------------------------------------------------------------------
# Optional monitor integration
# ---------------------------------------------------------------------------
MONITOR_HTML = Path(__file__).parent / "monitor_dashboard.html"

try:
    from acpsec.monitor import Monitor  # type: ignore[import]
    _monitor_db = os.environ.get("ACPSEC_MONITOR_DB", str(Path(__file__).parent / "acpsec_monitor.db"))
    _monitor = Monitor(_monitor_db)
    MONITOR_AVAILABLE = True
except ImportError:
    _monitor = None
    MONITOR_AVAILABLE = False
```

- [ ] **Step 2: Add health check endpoint**

Add before the scanner routes (around line 240):

```python
@app.get("/api/health")
def health_check():
    """Health check endpoint for deployment platforms."""
    return jsonify({
        "status": "ok",
        "version": "0.3.0",
        "acpsec_available": ACPSEC_AVAILABLE,
        "monitor_available": MONITOR_AVAILABLE,
    }), 200
```

- [ ] **Step 3: Add monitor page route**

```python
@app.get("/monitor")
def monitor_page():
    """Serve the continuous monitoring dashboard."""
    return send_file(MONITOR_HTML)
```

- [ ] **Step 4: Add monitor API endpoints**

```python
@app.get("/api/monitor/agents")
def monitor_list_agents():
    """List all agents on the watchlist."""
    if not MONITOR_AVAILABLE:
        return jsonify({"error": "monitor module not available"}), 503
    agents = _monitor.list_agents()
    return jsonify({
        "ok": True,
        "agents": [
            {
                "url": a.url,
                "schedule": a.schedule,
                "added_at": a.added_at,
                "last_scan": a.last_scan,
                "last_score": a.last_score,
                "last_max_score": a.last_max_score,
                "last_band": a.last_band,
            }
            for a in agents
        ],
    }), 200


@app.post("/api/monitor/agents")
def monitor_add_agent():
    """Add an agent to the watchlist."""
    if not MONITOR_AVAILABLE:
        return jsonify({"error": "monitor module not available"}), 503
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload = request.get_json(force=True)
    url = (payload.get("url") or "").strip()
    schedule = (payload.get("schedule") or "daily").strip().lower()
    if not url:
        return jsonify({"error": "'url' is required"}), 422
    if schedule not in ("hourly", "daily", "weekly"):
        return jsonify({"error": "'schedule' must be hourly, daily, or weekly"}), 422
    _monitor.add_agent(url, schedule)
    return jsonify({"ok": True}), 200


@app.delete("/api/monitor/agents")
def monitor_remove_agent():
    """Remove an agent from the watchlist."""
    if not MONITOR_AVAILABLE:
        return jsonify({"error": "monitor module not available"}), 503
    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify({"error": "'url' query param is required"}), 422
    _monitor.remove_agent(url)
    return jsonify({"ok": True}), 200


@app.post("/api/monitor/scan")
def monitor_scan_agent():
    """Trigger a scan for a specific agent."""
    if not MONITOR_AVAILABLE:
        return jsonify({"error": "monitor module not available"}), 503
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload = request.get_json(force=True)
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": "'url' is required"}), 422

    # Use the heuristic scanner to get a real score
    sc = _get_scanner()
    if sc is None:
        return jsonify({"error": "scanner module not available"}), 503

    result = sc.analyze_agent(url, url, scan_mode="root")
    if not result["ok"]:
        return jsonify(result), 422

    data = result["data"]
    score = data.get("final_score", 0)
    max_score = data.get("max_score", 100)
    band = data.get("band", "UNKNOWN")

    _monitor.record_score(url, score, max_score, band)
    return jsonify({"ok": True, "data": data}), 200


@app.get("/api/monitor/history")
def monitor_get_history():
    """Get score history for an agent."""
    if not MONITOR_AVAILABLE:
        return jsonify({"error": "monitor module not available"}), 503
    url = (request.args.get("url") or "").strip()
    limit = int(request.args.get("limit", 50))
    if not url:
        return jsonify({"error": "'url' query param is required"}), 422
    history = _monitor.get_history(url, limit=limit)
    return jsonify({
        "ok": True,
        "history": [
            {"score": r.score, "max_score": r.max_score, "band": r.band, "timestamp": r.timestamp}
            for r in history
        ],
    }), 200


@app.get("/api/monitor/alerts")
def monitor_get_alerts():
    """Get drift alerts."""
    if not MONITOR_AVAILABLE:
        return jsonify({"error": "monitor module not available"}), 503
    url = request.args.get("url")
    limit = int(request.args.get("limit", 20))
    alerts = _monitor.get_alerts(url=url or None, limit=limit)
    return jsonify({
        "ok": True,
        "alerts": [
            {
                "url": a.url,
                "old_score": a.old_score,
                "new_score": a.new_score,
                "delta": a.delta,
                "timestamp": a.timestamp,
            }
            for a in alerts
        ],
    }), 200
```

- [ ] **Step 5: Update serve.py module docstring**

Add the new routes to the docstring at the top of the file.

- [ ] **Step 6: Test the new endpoints**

Run: `cd /Users/fadhlan/sentrak/acp-sec && python -c "from dashboard.serve import app; print('OK')"`
Expected: `OK`

- [ ] **Step 7: Commit**

```bash
git add dashboard/serve.py
git commit -m "feat: add monitor API endpoints and health check to serve.py"
```

---

### Task 7: Add CORS Headers to serve.py

**Files:**
- Modify: `dashboard/serve.py`
- Modify: `dashboard/requirements.txt`

- [ ] **Step 1: Add flask-cors to requirements.txt**

Update `dashboard/requirements.txt`:
```
flask>=3.0,<4.0
flask-cors>=4.0,<5.0
requests>=2.31.0,<3.0
beautifulsoup4>=4.12.0,<5.0
```

- [ ] **Step 2: Add CORS to serve.py**

Add after the Flask app creation (line 31):

```python
from flask_cors import CORS

CORS(app)  # Enable CORS for all routes
```

- [ ] **Step 3: Install and verify**

Run: `cd /Users/fadhlan/sentrak/acp-sec/dashboard && pip install flask-cors>=4.0`
Run: `cd /Users/fadhlan/sentrak/acp-sec && python -c "from dashboard.serve import app; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add dashboard/serve.py dashboard/requirements.txt
git commit -m "feat: add CORS headers via flask-cors for cross-origin requests"
```

---

### Task 8: Update scanner.html — Version Badge & Loading Animation

**Files:**
- Modify: `dashboard/scanner.html`

- [ ] **Step 1: Update version badge**

Change line 629:
```html
<div class="hero-badge">v0.3.0</div>
```

- [ ] **Step 2: Add loading animation during scan**

Find the `startScan()` function (around line 1024). Add a loading overlay that shows during the scan. Insert before the fetch call:

```javascript
// Show loading overlay
const loadingOverlay = document.getElementById('loading-overlay');
loadingOverlay.style.display = 'flex';
```

And after the scan completes (both success and error paths):
```javascript
loadingOverlay.style.display = 'none';
```

Add the loading overlay HTML before the closing `</body>` tag (or in the step-3 section):

```html
<!-- Loading overlay -->
<div id="loading-overlay" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:9999; justify-content:center; align-items:center;">
  <div style="background:var(--bg-secondary); border-radius:12px; padding:2rem 3rem; text-align:center; box-shadow:var(--shadow);">
    <div class="spinner" style="width:48px; height:48px; border:4px solid var(--border); border-top-color:var(--accent-purple); border-radius:50%; animation:spin 0.8s linear infinite; margin:0 auto 1rem;"></div>
    <p style="font-weight:600; color:var(--text-primary);">Scanning agent...</p>
    <p id="loading-status" style="font-size:0.85rem; color:var(--text-secondary); margin-top:0.5rem;">Analyzing security posture</p>
  </div>
</div>
<style>@keyframes spin { to { transform: rotate(360deg); } }</style>
```

- [ ] **Step 3: Add "Add to Watchlist" button after scan results**

In the results section (step 3, around line 769), add a button next to the existing "Send to Dashboard" and "Download" buttons:

```html
<button id="btn-watchlist" class="btn btn-outline" onclick="addToWatchlist()" style="display:none;">
  <span style="margin-right:0.3rem;">+</span> Add to Watchlist
</button>
```

Add the JavaScript function:

```javascript
async function addToWatchlist() {
  const agentName = document.getElementById('result-agent-name')?.textContent || '';
  const agentUrl = document.getElementById('agent-url-input')?.value || '';
  if (!agentUrl) return;

  try {
    const resp = await fetch('/api/monitor/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: agentUrl, schedule: 'daily' })
    });
    const data = await resp.json();
    if (data.ok) {
      const btn = document.getElementById('btn-watchlist');
      btn.textContent = 'Added to Watchlist';
      btn.disabled = true;
      btn.style.opacity = '0.6';
    } else {
      alert(data.error || 'Failed to add to watchlist');
    }
  } catch (e) {
    alert('Failed to add to watchlist: ' + e.message);
  }
}
```

Show the button when scan results are displayed (in the function that renders step 3 results):
```javascript
document.getElementById('btn-watchlist').style.display = 'inline-flex';
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/scanner.html
git commit -m "feat: update scanner version badge to v0.3.0, add loading animation and watchlist button"
```

---

### Task 9: Connect monitor_dashboard.html to API Endpoints

**Files:**
- Modify: `dashboard/monitor_dashboard.html`

- [ ] **Step 1: Replace localStorage data loading with API calls**

Replace the `loadData()` function (line 415) with:

```javascript
async function loadData() {
  try {
    const [agentsResp, alertsResp] = await Promise.all([
      fetch('/api/monitor/agents'),
      fetch('/api/monitor/alerts')
    ]);
    const agentsData = await agentsResp.json();
    const alertsData = await alertsResp.json();

    if (agentsData.ok) {
      watchlist = agentsData.agents.map(a => ({
        url: a.url,
        schedule: a.schedule,
        addedAt: a.added_at ? new Date(a.added_at).getTime() : Date.now(),
        lastScan: a.last_scan ? new Date(a.last_scan).getTime() : null,
        lastScore: a.last_score,
        lastMaxScore: a.last_max_score,
        lastBand: a.last_band,
      }));
    }
    if (alertsData.ok) {
      alerts = alertsData.alerts.map(a => ({
        url: a.url,
        oldScore: a.old_score,
        newScore: a.new_score,
        delta: a.delta,
        timestamp: new Date(a.timestamp).getTime(),
      }));
    }

    // Load history for chart
    for (const agent of watchlist) {
      const histResp = await fetch(`/api/monitor/history?url=${encodeURIComponent(agent.url)}&limit=50`);
      const histData = await histResp.json();
      if (histData.ok) {
        scoreHistory[agent.url] = histData.history.map(h => ({
          score: h.score,
          timestamp: new Date(h.timestamp).getTime(),
        }));
      }
    }
  } catch (e) {
    console.warn('API unavailable, falling back to localStorage:', e);
    // Fallback to localStorage
    const stored = localStorage.getItem('acpsec_monitor');
    if (stored) {
      const data = JSON.parse(stored);
      watchlist = data.watchlist || [];
      alerts = data.alerts || [];
      scoreHistory = data.scoreHistory || {};
    }
  }
}
```

- [ ] **Step 2: Replace `addAgent()` with API call**

```javascript
async function addAgent() {
  const url = document.getElementById('agent-url').value.trim();
  const schedule = document.getElementById('agent-schedule').value;
  if (!url) return;

  try {
    const resp = await fetch('/api/monitor/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, schedule })
    });
    const data = await resp.json();
    if (!data.ok) {
      alert(data.error || 'Failed to add agent');
      return;
    }
    document.getElementById('agent-url').value = '';
    await loadData();
    render();
  } catch (e) {
    alert('Failed to add agent: ' + e.message);
  }
}
```

- [ ] **Step 3: Replace `removeAgent()` with API call**

```javascript
async function removeAgent(url) {
  try {
    await fetch(`/api/monitor/agents?url=${encodeURIComponent(url)}`, { method: 'DELETE' });
    await loadData();
    render();
  } catch (e) {
    alert('Failed to remove agent: ' + e.message);
  }
}
```

- [ ] **Step 4: Replace `scanAgent()` with real API scan**

```javascript
async function scanAgent(url) {
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }

  try {
    const resp = await fetch('/api/monitor/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await resp.json();
    if (!data.ok) {
      alert(data.error || 'Scan failed');
      return;
    }
    await loadData();
    render();
  } catch (e) {
    alert('Scan failed: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan'; }
  }
}
```

- [ ] **Step 5: Update `saveData()` to also sync to localStorage as fallback**

Keep `saveData()` but make it a backup:
```javascript
function saveData() {
  localStorage.setItem('acpsec_monitor', JSON.stringify({ watchlist, alerts, scoreHistory }));
}
```

- [ ] **Step 6: Commit**

```bash
git add dashboard/monitor_dashboard.html
git commit -m "feat: connect monitor dashboard to API endpoints for live data"
```

---

### Task 10: Unify Navigation Across All Dashboards

**Files:**
- Modify: `dashboard/scanner.html`
- Modify: `dashboard/monitor_dashboard.html`
- Modify: `dashboard/acp-sec-dashboard.html`

- [ ] **Step 1: Add unified nav to scanner.html**

Replace the header content in scanner.html (lines 48-80) with a unified nav that includes links to all three pages. Add after the logo:

```html
<nav class="header-nav">
  <a href="/" class="nav-link">Dashboard</a>
  <a href="/scanner" class="nav-link active">Scanner</a>
  <a href="/monitor" class="nav-link">Monitor</a>
</nav>
```

Add CSS for the nav:
```css
.header-nav { display: flex; gap: 0.25rem; }
.nav-link {
  padding: 0.4rem 0.75rem;
  border-radius: 6px;
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--text-secondary);
  text-decoration: none;
  transition: all 0.15s;
}
.nav-link:hover { background: var(--bg-tertiary); color: var(--text-primary); }
.nav-link.active { background: rgba(127,119,221,.12); color: var(--accent-purple); }
```

- [ ] **Step 2: Add unified nav to monitor_dashboard.html**

Add the same nav pattern to monitor_dashboard.html header (after the h1):
```html
<nav class="header-nav">
  <a href="/" class="nav-link">Dashboard</a>
  <a href="/scanner" class="nav-link">Scanner</a>
  <a href="/monitor" class="nav-link active">Monitor</a>
</nav>
```

- [ ] **Step 3: Add unified nav to acp-sec-dashboard.html**

Add the same nav pattern to acp-sec-dashboard.html header (after the logo):
```html
<nav class="header-nav">
  <a href="/" class="nav-link active">Dashboard</a>
  <a href="/scanner" class="nav-link">Scanner</a>
  <a href="/monitor" class="nav-link">Monitor</a>
</nav>
```

- [ ] **Step 4: Ensure dark mode toggle is consistent on all pages**

Verify each page has a dark mode toggle button in the header. All three already do (scanner has it, monitor has it, dashboard has it). Ensure they all use the same style class.

- [ ] **Step 5: Commit**

```bash
git add dashboard/scanner.html dashboard/monitor_dashboard.html dashboard/acp-sec-dashboard.html
git commit -m "feat: unify navigation and dark mode across all dashboard pages"
```

---

## Phase 3: Cloud Deployment Preparation

### Task 11: Create Deployment Configuration Files

**Files:**
- Create: `Procfile`
- Create: `vercel.json`
- Create: `requirements.txt` (root level)

- [ ] **Step 1: Create Procfile**

```Procfile
web: cd dashboard && gunicorn serve:app --bind 0.0.0.0:$PORT --workers 2
```

- [ ] **Step 2: Create vercel.json**

```json
{
  "version": 2,
  "builds": [
    {
      "src": "dashboard/serve.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    { "src": "/(.*)", "dest": "dashboard/serve.py" }
  ]
}
```

- [ ] **Step 3: Create root requirements.txt**

```
# ACP-SEC Production Dependencies
# Core package
anthropic>=0.40.0,<1.0
click>=8.1,<9.0
pyyaml>=6.0,<7.0
rich>=13.0,<14.0
httpx>=0.27,<1.0
pydantic>=2.0,<3.0
jinja2>=3.1,<4.0

# Dashboard
flask>=3.0,<4.0
flask-cors>=4.0,<5.0
requests>=2.31.0,<3.0
beautifulsoup4>=4.12.0,<5.0

# Production server
gunicorn>=22.0,<23.0
```

- [ ] **Step 4: Add gunicorn to dashboard/requirements.txt**

Update `dashboard/requirements.txt`:
```
flask>=3.0,<4.0
flask-cors>=4.0,<5.0
requests>=2.31.0,<3.0
beautifulsoup4>=4.12.0,<5.0
gunicorn>=22.0,<23.0
```

- [ ] **Step 5: Commit**

```bash
git add Procfile vercel.json requirements.txt dashboard/requirements.txt
git commit -m "feat: add deployment configs for Railway, Render, and Vercel"
```

---

### Task 12: Environment Variable Handling in serve.py

**Files:**
- Modify: `dashboard/serve.py`

- [ ] **Step 1: Update serve.py to use env vars for all paths**

Replace the hardcoded paths section (lines 37-42) with:

```python
PORT = int(os.environ.get("PORT", 5001))

_base = Path(__file__).parent
DASHBOARD_HTML = Path(os.environ.get("ACPSEC_DASHBOARD_HTML", _base / "acp-sec-dashboard.html"))
SCANNER_HTML   = Path(os.environ.get("ACPSEC_SCANNER_HTML", _base / "scanner.html"))
MONITOR_HTML   = Path(os.environ.get("ACPSEC_MONITOR_HTML", _base / "monitor_dashboard.html"))
STORE_FILE     = Path(os.environ.get("ACPSEC_STORE_FILE", _base / "score_store.json"))
SCAN_STORE     = Path(os.environ.get("ACPSEC_SCAN_STORE", _base / "scan_store.json"))
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/serve.py
git commit -m "feat: make all file paths configurable via environment variables"
```

---

### Task 13: Run Full Test Suite & Final Verification

- [ ] **Step 1: Install all dependencies**

```bash
cd /Users/fadhlan/sentrak/acp-sec
pip install -e ".[dev]"
pip install -r dashboard/requirements.txt
```

- [ ] **Step 2: Run ruff lint**

```bash
python -m ruff check acpsec/ dashboard/
```
Expected: clean or only pre-existing warnings

- [ ] **Step 3: Run full test suite**

```bash
cd /Users/fadhlan/sentrak/acp-sec
PYTHONPATH=. /opt/homebrew/bin/python3 -m pytest tests/ -v
```
Expected: 116+ tests passing

- [ ] **Step 4: Verify dashboard starts**

```bash
cd /Users/fadhlan/sentrak/acp-sec
timeout 5 python dashboard/serve.py || true
```
Expected: Flask startup messages, no errors

- [ ] **Step 5: Verify health endpoint**

```bash
cd /Users/fadhlan/sentrak/acp-sec
python -c "
from dashboard.serve import app
with app.test_client() as c:
    r = c.get('/api/health')
    print(r.get_json())
"
```
Expected: `{'status': 'ok', 'version': '0.3.0', ...}`

- [ ] **Step 6: Commit any remaining fixes**

```bash
git add -A
git commit -m "chore: final cleanup and verification for v0.3.0 polish"
```

---

### Task 14: Push to GitHub

- [ ] **Step 1: Check git status**

```bash
cd /Users/fadhlan/sentrak/acp-sec
git status
```

- [ ] **Step 2: Push to GitHub**

```bash
git push origin main
```

- [ ] **Step 3: Show final git log**

```bash
git log --oneline -15
```
