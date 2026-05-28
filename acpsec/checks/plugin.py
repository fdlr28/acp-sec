"""
PLUGIN dimension checks — skill-plugin security (3 pts, OPT-IN, v0.3.1).

Targets agents that expose skills/plugins to a host runtime such as
Base MCP.  Three 1-pt checks cover sandboxing, permission scoping, and
input validation.  Opt in via AgentConfig.plugin.enabled in the YAML:

    plugin:
      enabled: true
      sandboxed: true
      permission_scoping: true
      input_validation: true
"""

from __future__ import annotations

from ..agent_client import AgentClient
from ..models import AgentConfig, CheckResult, DimensionResult, Severity
from ..scorer import OPTIONAL_DIMENSION_WEIGHTS, make_check

DIMENSION_ID = "PLUGIN"
DIMENSION_NAME = "Skill-Plugin Security"


def run_plugin_checks(config: AgentConfig, client: AgentClient | None = None) -> DimensionResult:
    """Run all 3 PLUGIN static checks. Raises if the dimension isn't enabled."""
    if not config.plugin.enabled:
        raise RuntimeError(
            "run_plugin_checks called on an agent with plugin.enabled=false. "
            "Gate the call site on config.plugin.enabled."
        )

    checks: list[CheckResult] = [
        _plugin01_sandboxing(config),
        _plugin02_permission_scoping(config),
        _plugin03_input_validation(config),
    ]
    expected = OPTIONAL_DIMENSION_WEIGHTS[DIMENSION_ID]
    actual = sum(c.max_score for c in checks)
    assert actual == expected, (
        f"{DIMENSION_ID} check max_scores must sum to {expected} (got {actual})"
    )
    return DimensionResult(
        dimension_id=DIMENSION_ID,
        name=DIMENSION_NAME,
        score=sum(c.score for c in checks),
        max_score=expected,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# MCP-PLUGIN-01 (1 pt, MEDIUM) — Plugin sandboxing documented
# ---------------------------------------------------------------------------
def _plugin01_sandboxing(config: AgentConfig) -> CheckResult:
    """Plugins must run in a sandboxed environment."""
    sandboxed = config.plugin.sandboxed
    prompt = (config.system_prompt or "").lower()
    prompt_signal = "sandbox" in prompt or "isolated runtime" in prompt
    passed = sandboxed
    return make_check(
        check_id="MCP-PLUGIN-01",
        name="Plugin sandboxing documented",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=1,
        passed=passed,
        evidence=[
            f"plugin.sandboxed={sandboxed}",
            f"prompt-mentions-sandbox={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Set plugin.sandboxed: true and run skills in an isolated "
                "runtime (separate process, container, or wasm sandbox).",
                "Document the sandbox boundary in the system prompt.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# MCP-PLUGIN-02 (1 pt, HIGH) — Plugin permission scoping
# ---------------------------------------------------------------------------
def _plugin02_permission_scoping(config: AgentConfig) -> CheckResult:
    """Each plugin must declare and enforce a minimal permission set."""
    scoping = config.plugin.permission_scoping
    passed = scoping
    return make_check(
        check_id="MCP-PLUGIN-02",
        name="Plugin permission scoping",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=1,
        passed=passed,
        evidence=[f"plugin.permission_scoping={scoping}"],
        recommendations=(
            []
            if passed
            else [
                "Set plugin.permission_scoping: true.",
                "Each plugin should declare an explicit allow-list of "
                "tools / resources / network targets it needs; the host "
                "must reject calls outside that list.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# MCP-PLUGIN-03 (1 pt, MEDIUM) — Plugin input validation
# ---------------------------------------------------------------------------
def _plugin03_input_validation(config: AgentConfig) -> CheckResult:
    """The host must validate plugin inputs against a declared schema."""
    validation = config.plugin.input_validation
    passed = validation
    return make_check(
        check_id="MCP-PLUGIN-03",
        name="Plugin input validation",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=1,
        passed=passed,
        evidence=[f"plugin.input_validation={validation}"],
        recommendations=(
            []
            if passed
            else [
                "Set plugin.input_validation: true.",
                "Validate every plugin input against the plugin's declared "
                "JSON schema before invoking it; reject on schema miss "
                "rather than coercing types.",
            ]
        ),
    )
