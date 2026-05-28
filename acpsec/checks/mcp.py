"""
MCP dimension checks — Model Context Protocol server security (12 pts, OPT-IN).

This dimension is only evaluated when AgentConfig.mcp.enabled is True.
Total budget: 12 points across 6 checks.  2 of 6 are CRITICAL; under the
standard CRITICAL_PENALTY (-5) rule, a single CRITICAL failure floors the
dimension at 0.

v0.3.1 adds MCP-OAUTH-01 (2 pts, HIGH) to align with the Base MCP partner
program's OAuth 2.1 + PKCE + token-rotation requirements.
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
        _mcp_oauth01_oauth_2_1_implementation(config),
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
# MCP-OAUTH-01 (2 pts, HIGH) — OAuth 2.1 implementation
# ---------------------------------------------------------------------------
def _mcp_oauth01_oauth_2_1_implementation(config: AgentConfig) -> CheckResult:
    """
    When the MCP server's auth mechanism is `oauth`, verify the deployment
    meets the Base MCP partner baseline:

      - OAuth 2.1 (not 2.0)
      - PKCE (RFC 7636) enabled
      - Refresh-token rotation on use

    System prompt mention of "OAuth 2.1" / "PKCE" / "token rotation" is
    accepted as a soft signal — the config booleans are the hard contract.
    Agents using non-OAuth mechanisms (bearer/api_key/mtls) pass vacuously
    since OAuth isn't applicable.
    """
    mcp = config.mcp
    mechanism = (mcp.auth.mechanism or "").lower()
    prompt = (config.system_prompt or "").lower()

    if mechanism != "oauth":
        # Not applicable — pass vacuously, but flag in evidence so
        # reviewers can see WHY the score landed full.
        return make_check(
            check_id="MCP-OAUTH-01",
            name="OAuth 2.1 implementation",
            dimension=DIMENSION_ID,
            severity=Severity.HIGH,
            max_score=2,
            passed=True,
            evidence=[
                f"auth.mechanism='{mechanism}' — OAuth not in use, N/A.",
            ],
            recommendations=[],
        )

    is_2_1 = (mcp.auth.oauth_version or "").strip() == "2.1"
    pkce = bool(mcp.auth.pkce)
    rotation = bool(mcp.auth.token_rotation)

    # Soft prompt signals — only matter when a config flag is missing.
    prompt_mentions_2_1     = "oauth 2.1" in prompt or "oauth2.1" in prompt
    prompt_mentions_pkce    = "pkce" in prompt
    prompt_mentions_rotation = (
        "token rotation"   in prompt
        or "rotate refresh" in prompt
        or "refresh rotation" in prompt
    )

    # Full pass requires the hard config contract.  Partial credit when
    # SOME of the three pillars are present.
    pillars_passed = sum([
        is_2_1 or prompt_mentions_2_1,
        pkce  or prompt_mentions_pkce,
        rotation or prompt_mentions_rotation,
    ])
    passed = (pillars_passed == 3) and (is_2_1 and pkce and rotation)

    evidence = [
        f"auth.oauth_version='{mcp.auth.oauth_version}'  (need '2.1')",
        f"auth.pkce={pkce}",
        f"auth.token_rotation={rotation}",
        f"prompt signals: 2.1={prompt_mentions_2_1}, "
        f"pkce={prompt_mentions_pkce}, rotation={prompt_mentions_rotation}",
    ]

    if passed:
        return make_check(
            check_id="MCP-OAUTH-01",
            name="OAuth 2.1 implementation",
            dimension=DIMENSION_ID,
            severity=Severity.HIGH,
            max_score=2,
            passed=True,
            evidence=evidence,
            recommendations=[],
        )

    # Partial credit: 2/3 pillars → 1 pt warn, 1/3 → 0.5, 0/3 → 0 fail.
    partial = {3: 2.0, 2: 1.0, 1: 0.5, 0: 0.0}[pillars_passed]
    return make_check(
        check_id="MCP-OAUTH-01",
        name="OAuth 2.1 implementation",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=False,
        partial_score=partial,
        evidence=evidence,
        recommendations=[
            "Set mcp.auth.oauth_version: '2.1' (PKCE is mandatory in 2.1).",
            "Set mcp.auth.pkce: true.",
            "Set mcp.auth.token_rotation: true and rotate refresh tokens on use.",
            "Document OAuth 2.1 + PKCE + rotation in the agent's system prompt.",
        ],
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
