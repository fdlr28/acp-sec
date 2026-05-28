"""Core data models for ACP-SEC."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity level of a security finding."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckStatus(str, Enum):
    """Outcome of a single security check."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


class ToolTier(int, Enum):
    """Risk tier of a tool, from read-only to critical."""
    READ_ONLY = 0
    WRITE = 1
    DESTRUCTIVE = 2
    CRITICAL = 3


class FindingStatus(str, Enum):
    """Lifecycle status of a security finding."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class CheckResult(BaseModel):
    """Result of a single security check."""
    check_id: str
    name: str
    dimension: str
    status: CheckStatus
    score: float
    max_score: float
    severity: Severity
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Whether the check passed."""
        return self.status == CheckStatus.PASS

    @property
    def score_pct(self) -> float:
        """Score as a percentage of maximum possible."""
        if self.max_score == 0:
            return 0.0
        return round(self.score / self.max_score * 100, 1)


class DimensionResult(BaseModel):
    """Aggregated results for a single security dimension."""
    dimension_id: str
    dimension_id: str
    name: str
    score: float
    max_score: float
    checks: list[CheckResult] = Field(default_factory=list)

    @property
    def score_pct(self) -> float:
        """Dimension score as a percentage of maximum possible."""
        if self.max_score == 0:
            return 0.0
        return round(self.score / self.max_score * 100, 1)

    @property
    def critical_failures(self) -> list[CheckResult]:
        """All CRITICAL-severity checks that failed."""
        return [
            c for c in self.checks
            if c.severity == Severity.CRITICAL and c.status == CheckStatus.FAIL
        ]


class AssessmentResult(BaseModel):
    """Complete security assessment for an agent."""
    agent_name: str
    agent_version: str
    timestamp: str
    final_score: float
    max_score: float = 100.0
    band: str
    verdict: str
    dimensions: list[DimensionResult] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def score_pct(self) -> float:
        """Final score as a percentage of maximum possible."""
        return round(self.final_score / self.max_score * 100, 1)

    @property
    def all_checks(self) -> list[CheckResult]:
        """Flatten all checks across all dimensions."""
        return [c for d in self.dimensions for c in d.checks]

    @property
    def critical_failures(self) -> list[CheckResult]:
        """All CRITICAL-severity checks that failed."""
        return [c for c in self.all_checks if c.severity == Severity.CRITICAL and not c.passed]


class InjectionResult(BaseModel):
    """Result of a single injection test."""
    test_id: str
    test_id: str
    category: str
    payload: str
    payload_encoding: str = "plain"
    injected: bool
    confidence: float  # 0.0 - 1.0
    response_snippet: str
    evidence: list[str] = Field(default_factory=list)
    severity: Severity = Severity.CRITICAL


class InjectionSuiteResult(BaseModel):
    """Aggregate results of an injection test suite."""
    agent_name: str
    timestamp: str
    total_tests: int
    injected_count: int
    resistance_score: float  # 0-100
    results: list[InjectionResult] = Field(default_factory=list)

    @property
    def injection_rate(self) -> float:
        """Percentage of tests that resulted in injection."""
        if self.total_tests == 0:
            return 0.0
        return round(self.injected_count / self.total_tests * 100, 1)


class X402FinalityConfig(BaseModel):
    """Finality posture for the agent's primary settlement network."""
    network: str = "base"
    confirmation_blocks: int = 12
    azul_aware: bool = False        # multiproof (TEE+ZK) → ~1-day Ethereum withdrawal
    pre_azul: bool = False          # explicit opt-in for pre-Azul 7-day behaviour


class X402AssetConfig(BaseModel):
    """Token used to settle x402 invoices (EIP-3009 ERC-20 or SPL)."""
    address: str = ""               # contract / mint address
    symbol: str = "USDC"


class X402Config(BaseModel):
    """
    x402 protocol posture declared by the agent.

    When `enabled=true`, ACP-SEC runs the X402 dimension (10 pts) on top of
    the standard 100-pt scoring budget.  When disabled (or absent), the
    dimension is skipped entirely and total score stays at /100.
    """
    enabled: bool = False
    scheme: str = "exact"
    networks: list[str] = Field(default_factory=list)
    facilitator_url: str = ""
    per_request_max_usd: float = 0.0
    daily_cap_usd: float = 0.0
    nonce_strategy: str = "facilitator"   # "facilitator" | "self" | "none"
    finality: X402FinalityConfig = Field(default_factory=X402FinalityConfig)
    asset: X402AssetConfig = Field(default_factory=X402AssetConfig)


class MCPAuthConfig(BaseModel):
    """Authentication posture for an MCP server."""
    required: bool = True                 # MCP-AUTH-01: server must require auth
    mechanism: str = "bearer"             # bearer | api_key | oauth | mtls
    tool_scoping: bool = False            # MCP-AUTH-02: per-user tool authorization

    # v0.3.1 — OAuth 2.1 posture (MCP-OAUTH-01).  Only inspected when
    # mechanism == "oauth".  Aligned with Base MCP's OAuth 2.1 + PKCE
    # requirements for skill-plugin partners.
    oauth_version: str = ""               # "2.1" expected for full score
    pkce: bool = False                    # PKCE (RFC 7636) — required for 2.1
    token_rotation: bool = False          # refresh-token rotation on use


class MCPAccessConfig(BaseModel):
    """Resource access control for MCP tools."""
    resource_isolation: bool = False      # MCP-PRIV-01: tools scoped to user resources
    sandbox_mode: bool = False            # tools run in sandboxed environment


class MCPAuditConfig(BaseModel):
    """Audit logging posture for MCP calls."""
    enabled: bool = False                 # MCP-GOV-01: audit logging active
    log_tool_calls: bool = False          # log every tool invocation
    log_results: bool = False             # log tool return values


class MCPConfig(BaseModel):
    """
    MCP (Model Context Protocol) server posture declared by the agent.

    When `enabled=true`, ACP-SEC runs the MCP dimension (12 pts as of
    v0.3.1) on top of the standard 100-pt scoring budget.  When disabled
    (or absent), the dimension is skipped entirely and total score stays
    at /100.
    """
    enabled: bool = False
    server_url: str = ""
    auth: MCPAuthConfig = Field(default_factory=MCPAuthConfig)
    access: MCPAccessConfig = Field(default_factory=MCPAccessConfig)
    audit: MCPAuditConfig = Field(default_factory=MCPAuditConfig)
    prompt_injection_protection: bool = False  # MCP-INJ-01


class PluginConfig(BaseModel):
    """
    Skill-plugin posture (v0.3.1).

    For agents that expose skills/plugins to a host runtime such as Base
    MCP.  Three booleans drive three checks (1 pt each) and the dimension
    is opt-in via `enabled`.
    """
    enabled: bool = False
    sandboxed: bool = False             # MCP-PLUGIN-01: plugin sandboxing documented
    permission_scoping: bool = False    # MCP-PLUGIN-02: plugin permission scoping
    input_validation: bool = False      # MCP-PLUGIN-03: plugin input validation


class AgentConfig(BaseModel):
    """Configuration for an AI agent under assessment."""
    name: str
    version: str = "1.0"
    provider_type: str = Field(alias="provider_type", default="anthropic")
    model: str = "claude-sonnet-4-6"
    api_key: str | None = None
    endpoint: str | None = None
    system_prompt: str = ""
    tools: list[dict[str, Any]] = Field(default_factory=list)
    auth_type: str = "bearer"
    session_isolation: bool = True
    output_filtering: bool = False
    hitl_tiers: list[int] = Field(default_factory=list)
    environment: str = "staging"
    owner: str = ""
    x402: X402Config = Field(default_factory=X402Config)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    plugin: PluginConfig = Field(default_factory=PluginConfig)

    model_config = {"populate_by_name": True}
