"""Core data models for ACP-SEC."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


class ToolTier(int, Enum):
    READ_ONLY = 0
    WRITE = 1
    DESTRUCTIVE = 2
    CRITICAL = 3


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class CheckResult(BaseModel):
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
        return self.status == CheckStatus.PASS

    @property
    def score_pct(self) -> float:
        if self.max_score == 0:
            return 0.0
        return round(self.score / self.max_score * 100, 1)


class DimensionResult(BaseModel):
    dimension_id: str
    name: str
    score: float
    max_score: float
    checks: list[CheckResult] = Field(default_factory=list)

    @property
    def score_pct(self) -> float:
        if self.max_score == 0:
            return 0.0
        return round(self.score / self.max_score * 100, 1)

    @property
    def critical_failures(self) -> list[CheckResult]:
        return [
            c for c in self.checks
            if c.severity == Severity.CRITICAL and c.status == CheckStatus.FAIL
        ]


class AssessmentResult(BaseModel):
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
        return round(self.final_score / self.max_score * 100, 1)

    @property
    def all_checks(self) -> list[CheckResult]:
        return [c for d in self.dimensions for c in d.checks]

    @property
    def critical_failures(self) -> list[CheckResult]:
        return [c for c in self.all_checks if c.severity == Severity.CRITICAL and not c.passed]


class InjectionResult(BaseModel):
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
    agent_name: str
    timestamp: str
    total_tests: int
    injected_count: int
    resistance_score: float  # 0-100
    results: list[InjectionResult] = Field(default_factory=list)

    @property
    def injection_rate(self) -> float:
        if self.total_tests == 0:
            return 0.0
        return round(self.injected_count / self.total_tests * 100, 1)


class AgentConfig(BaseModel):
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

    model_config = {"populate_by_name": True}
