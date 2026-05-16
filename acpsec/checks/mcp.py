"""
MCP dimension checks — Model Context Protocol server security (10 pts, OPT-IN).

This dimension is only evaluated when AgentConfig.mcp.enabled is True.
Total budget: 10 points across 5 checks.  2 of 5 are CRITICAL; under the
standard CRITICAL_PENALTY (-5) rule, a single CRITICAL failure floors the
dimension at 0.
"""

from __future__ import annotations

from ..agent_client import AgentClient
from ..models import AgentConfig, CheckResult, DimensionResult, Severity
from ..scorer import OPTIONAL_DIMENSION_WEIGHTS, make_check

DIMENSION_ID = "MCP"
DIMENSION_NAME = "MCP Server Security"


def run_mcp_checks(config: AgentConfig, client: AgentClient | None = None) -> DimensionResult:
    """Run all 5 MCP static checks. Raises if the dimension isn't enabled."""
    if not config.mcp.enabled:
        raise RuntimeError(
            "run_mcp_checks called on an agent with mcp.enabled=false. "
            "Gate the call site on config.mcp.enabled."
        )

    checks: list[CheckResult] = [
        _mcp_auth01_server_authentication(config),
        _mcp_auth02_tool_authorization_scoping(config),
        _mcp_inj01_prompt_injection_protection(config),
        _mcp_priv01_resource_access_control(config),
        _mcp_gov01_audit_logging(config),
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
# MCP-AUTH-01 (3 pts, CRITICAL) — server authentication required
# ---------------------------------------------------------------------------
def _mcp_auth01_server_authentication(config: AgentConfig) -> CheckResult:
    """The MCP server must require authentication — no public exposure."""
    mcp = config.mcp
    auth_required = mcp.auth.required
    has_url = bool(mcp.server_url and mcp.server_url.strip())
    valid_mechanism = mcp.auth.mechanism in {"bearer", "api_key", "oauth", "mtls"}
    passed = auth_required and has_url and valid_mechanism
    return make_check(
        check_id="MCP-AUTH-01",
        name="Server authentication required",
        dimension=DIMENSION_ID,
        severity=Severity.CRITICAL,
        max_score=3,
        passed=passed,
        evidence=[
            f"auth.required={auth_required}",
            f"server_url='{mcp.server_url}'",
            f"auth.mechanism='{mcp.auth.mechanism}'",
        ],
        recommendations=(
            []
            if passed
            else [
                "Set mcp.auth.required: true to enforce authentication.",
                "Configure a valid auth mechanism (bearer, api_key, oauth, mtls).",
                "Set mcp.server_url to the MCP server endpoint.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# MCP-AUTH-02 (2 pts, HIGH) — tool authorization scoping per user
# ---------------------------------------------------------------------------
def _mcp_auth02_tool_authorization_scoping(config: AgentConfig) -> CheckResult:
    """MCP tools must be scoped per user — no shared global tool access."""
    scoping = config.mcp.auth.tool_scoping
    passed = scoping
    return make_check(
        check_id="MCP-AUTH-02",
        name="Tool authorization scoping per user",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"auth.tool_scoping={scoping}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Enable per-user tool authorization scoping.",
                "Each user should only access tools relevant to their role.",
                "Set mcp.auth.tool_scoping: true.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# MCP-INJ-01 (2 pts, CRITICAL) — prompt injection via tool results
# ---------------------------------------------------------------------------
def _mcp_inj01_prompt_injection_protection(config: AgentConfig) -> CheckResult:
    """MCP tool results must be sanitized to prevent prompt injection."""
    protected = config.mcp.prompt_injection_protection
    passed = protected
    return make_check(
        check_id="MCP-INJ-01",
        name="Prompt injection via tool results protection",
        dimension=DIMENSION_ID,
        severity=Severity.CRITICAL,
        max_score=2,
        passed=passed,
        evidence=[
            f"prompt_injection_protection={protected}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Enable prompt injection protection for MCP tool results.",
                "Sanitize tool outputs before passing to the LLM context.",
                "Set mcp.prompt_injection_protection: true.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# MCP-PRIV-01 (2 pts, HIGH) — resource access control
# ---------------------------------------------------------------------------
def _mcp_priv01_resource_access_control(config: AgentConfig) -> CheckResult:
    """MCP tools must enforce resource-level access control."""
    isolation = config.mcp.access.resource_isolation
    sandbox = config.mcp.access.sandbox_mode
    passed = isolation and sandbox
    return make_check(
        check_id="MCP-PRIV-01",
        name="Resource access control",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"access.resource_isolation={isolation}",
            f"access.sandbox_mode={sandbox}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Enable resource isolation: mcp.access.resource_isolation: true.",
                "Enable sandbox mode: mcp.access.sandbox_mode: true.",
                "Tools should only access resources the user owns.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# MCP-GOV-01 (1 pt, MEDIUM) — audit logging for MCP calls
# ---------------------------------------------------------------------------
def _mcp_gov01_audit_logging(config: AgentConfig) -> CheckResult:
    """MCP server must log tool invocations for audit trail."""
    audit = config.mcp.audit
    passed = audit.enabled and audit.log_tool_calls
    return make_check(
        check_id="MCP-GOV-01",
        name="Audit logging for MCP calls",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=1,
        passed=passed,
        evidence=[
            f"audit.enabled={audit.enabled}",
            f"audit.log_tool_calls={audit.log_tool_calls}",
            f"audit.log_results={audit.log_results}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Enable audit logging: mcp.audit.enabled: true.",
                "Log tool calls: mcp.audit.log_tool_calls: true.",
                "Consider logging results for forensic analysis.",
            ]
        ),
    )
