"""
Tests for the MCP module (v0.3.0).

Layout:
  - Static checks: MCP-AUTH-01, MCP-AUTH-02, MCP-INJ-01, MCP-PRIV-01, MCP-GOV-01
  - Config parsing: YAML loading with MCP block
  - Scoring integration: OPTIONAL_DIMENSION_WEIGHTS, compliant vs misconfigured
  - Mock MCP server: self-tests for the test server
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import pytest

# dashboard/ is a sibling of acpsec/, not a package — add it to sys.path.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "dashboard"))

from acpsec.checks.mcp import run_mcp_checks
from acpsec.config_loader import load_config
from acpsec.models import (
    AgentConfig,
    CheckStatus,
    MCPAccessConfig,
    MCPAuditConfig,
    MCPAuthConfig,
    MCPConfig,
    Severity,
)
from acpsec.scorer import (
    OPTIONAL_DIMENSION_WEIGHTS,
    ScoringEngine,
    total_max_score,
)

from mock_mcp_server import MockMCPServer


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _compliant_mcp() -> MCPConfig:
    return MCPConfig(
        enabled=True,
        server_url="https://mcp.example.com:8443",
        prompt_injection_protection=True,
        auth=MCPAuthConfig(
            required=True,
            mechanism="bearer",
            tool_scoping=True,
        ),
        access=MCPAccessConfig(
            resource_isolation=True,
            sandbox_mode=True,
        ),
        audit=MCPAuditConfig(
            enabled=True,
            log_tool_calls=True,
            log_results=True,
        ),
    )


def _compliant_agent() -> AgentConfig:
    return AgentConfig(
        name="MCP Compliant Agent",
        version="0.3",
        mcp=_compliant_mcp(),
    )


def _misconfigured_mcp() -> MCPConfig:
    return MCPConfig(
        enabled=True,
        server_url="",
        prompt_injection_protection=False,
        auth=MCPAuthConfig(
            required=False,
            mechanism="none",
            tool_scoping=False,
        ),
        access=MCPAccessConfig(
            resource_isolation=False,
            sandbox_mode=False,
        ),
        audit=MCPAuditConfig(
            enabled=False,
            log_tool_calls=False,
            log_results=False,
        ),
    )


def _misconfigured_agent() -> AgentConfig:
    return AgentConfig(
        name="MCP Misconfigured Agent",
        version="0.3",
        mcp=_misconfigured_mcp(),
    )


# ---------------------------------------------------------------------------
# Static checks — compliant agent should pass all (10/10)
# ---------------------------------------------------------------------------

class TestMCPChecksCompliant:
    """All checks pass for a fully configured MCP agent."""

    def test_all_checks_pass(self):
        result = run_mcp_checks(_compliant_agent())
        assert result.score == 10.0
        assert result.max_score == 10.0
        assert all(c.status == CheckStatus.PASS for c in result.checks)

    def test_auth01_server_authentication(self):
        result = run_mcp_checks(_compliant_agent())
        auth01 = next(c for c in result.checks if c.check_id == "MCP-AUTH-01")
        assert auth01.status == CheckStatus.PASS
        assert auth01.score == 3.0
        assert auth01.severity == Severity.CRITICAL

    def test_auth02_tool_scoping(self):
        result = run_mcp_checks(_compliant_agent())
        auth02 = next(c for c in result.checks if c.check_id == "MCP-AUTH-02")
        assert auth02.status == CheckStatus.PASS
        assert auth02.score == 2.0
        assert auth02.severity == Severity.HIGH

    def test_inj01_prompt_injection(self):
        result = run_mcp_checks(_compliant_agent())
        inj01 = next(c for c in result.checks if c.check_id == "MCP-INJ-01")
        assert inj01.status == CheckStatus.PASS
        assert inj01.score == 2.0
        assert inj01.severity == Severity.CRITICAL

    def test_priv01_resource_access(self):
        result = run_mcp_checks(_compliant_agent())
        priv01 = next(c for c in result.checks if c.check_id == "MCP-PRIV-01")
        assert priv01.status == CheckStatus.PASS
        assert priv01.score == 2.0
        assert priv01.severity == Severity.HIGH

    def test_gov01_audit_logging(self):
        result = run_mcp_checks(_compliant_agent())
        gov01 = next(c for c in result.checks if c.check_id == "MCP-GOV-01")
        assert gov01.status == CheckStatus.PASS
        assert gov01.score == 1.0
        assert gov01.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Static checks — misconfigured agent should fail all (0/10)
# ---------------------------------------------------------------------------

class TestMCPChecksMisconfigured:
    """All checks fail for a misconfigured MCP agent."""

    def test_all_checks_fail(self):
        result = run_mcp_checks(_misconfigured_agent())
        assert result.score == 0.0
        assert result.max_score == 10.0
        assert all(c.status == CheckStatus.FAIL for c in result.checks)

    def test_auth01_requires_auth(self):
        result = run_mcp_checks(_misconfigured_agent())
        auth01 = next(c for c in result.checks if c.check_id == "MCP-AUTH-01")
        assert auth01.status == CheckStatus.FAIL
        assert "auth.required=False" in auth01.evidence[0]

    def test_auth02_requires_scoping(self):
        result = run_mcp_checks(_misconfigured_agent())
        auth02 = next(c for c in result.checks if c.check_id == "MCP-AUTH-02")
        assert auth02.status == CheckStatus.FAIL

    def test_inj01_requires_protection(self):
        result = run_mcp_checks(_misconfigured_agent())
        inj01 = next(c for c in result.checks if c.check_id == "MCP-INJ-01")
        assert inj01.status == CheckStatus.FAIL

    def test_priv01_requires_isolation(self):
        result = run_mcp_checks(_misconfigured_agent())
        priv01 = next(c for c in result.checks if c.check_id == "MCP-PRIV-01")
        assert priv01.status == CheckStatus.FAIL

    def test_gov01_requires_audit(self):
        result = run_mcp_checks(_misconfigured_agent())
        gov01 = next(c for c in result.checks if c.check_id == "MCP-GOV-01")
        assert gov01.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Static checks — disabled MCP raises RuntimeError
# ---------------------------------------------------------------------------

class TestMCPDisabled:
    """run_mcp_checks must raise if mcp.enabled is false."""

    def test_raises_when_disabled(self):
        agent = AgentConfig(name="No MCP", mcp=MCPConfig(enabled=False))
        with pytest.raises(RuntimeError, match="mcp.enabled=false"):
            run_mcp_checks(agent)


# ---------------------------------------------------------------------------
# Scoring integration
# ---------------------------------------------------------------------------

class TestMCPScoreIntegration:
    """MCP dimension plugs into the scoring engine correctly."""

    def test_mcp_optional_weight(self):
        assert OPTIONAL_DIMENSION_WEIGHTS["MCP"] == 10

    def test_total_max_score_with_mcp(self):
        assert total_max_score(("MCP",)) == 110

    def test_total_score_110_for_compliant(self):
        from acpsec.checks import run_auth_checks, run_context_checks
        from acpsec.checks import run_input_validation_checks as run_inj
        from acpsec.checks import run_output_safety_checks as run_out
        from acpsec.checks import run_privilege_checks as run_priv
        from acpsec.checks import run_governance_checks as run_gov

        agent = _compliant_agent()
        dims = [
            run_auth_checks(agent, None),
            run_context_checks(agent, None),
            run_inj(agent, None),
            run_priv(agent, None),
            run_out(agent, None),
            run_gov(agent, None),
            run_mcp_checks(agent),
        ]
        engine = ScoringEngine()
        assessment = engine.build_assessment("MCP Agent", "0.3", dims)
        # Max is 100 (base) + 10 (MCP) = 110
        assert assessment.max_score == 110.0


# ---------------------------------------------------------------------------
# YAML config parsing
# ---------------------------------------------------------------------------

class TestMCPConfigParsing:
    """Load YAML files and verify MCP config is parsed correctly."""

    def test_compliant_yaml_loads(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        path = _REPO_ROOT / "examples" / "mcp_agent_compliant.yaml"
        cfg = load_config(path)
        assert cfg.mcp.enabled is True
        assert cfg.mcp.server_url == "https://mcp.example.com:8443"
        assert cfg.mcp.auth.required is True
        assert cfg.mcp.auth.tool_scoping is True
        assert cfg.mcp.prompt_injection_protection is True
        assert cfg.mcp.access.resource_isolation is True
        assert cfg.mcp.access.sandbox_mode is True
        assert cfg.mcp.audit.enabled is True
        assert cfg.mcp.audit.log_tool_calls is True

    def test_misconfigured_yaml_loads(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        path = _REPO_ROOT / "examples" / "mcp_agent_misconfigured.yaml"
        cfg = load_config(path)
        assert cfg.mcp.enabled is True
        assert cfg.mcp.server_url == ""
        assert cfg.mcp.auth.required is False
        assert cfg.mcp.auth.tool_scoping is False

    def test_compliant_scores_10_of_10(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        path = _REPO_ROOT / "examples" / "mcp_agent_compliant.yaml"
        cfg = load_config(path)
        result = run_mcp_checks(cfg)
        assert result.score == 10.0
        assert result.max_score == 10.0

    def test_misconfigured_scores_0_of_10(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        path = _REPO_ROOT / "examples" / "mcp_agent_misconfigured.yaml"
        cfg = load_config(path)
        result = run_mcp_checks(cfg)
        assert result.score == 0.0
        assert result.max_score == 10.0


# ---------------------------------------------------------------------------
# Mock MCP server self-tests
# ---------------------------------------------------------------------------

class TestMockMCPServer:
    """Verify the mock MCP server works as expected."""

    def test_health_endpoint(self):
        with MockMCPServer() as mcp:
            with urllib.request.urlopen(f"{mcp.url}/health") as r:
                data = json.loads(r.read().decode())
                assert data["status"] == "ok"
                assert r.status == 200

    def test_login_returns_token(self):
        with MockMCPServer() as mcp:
            body = json.dumps({"username": "user1", "password": "pass1"}).encode()
            req = urllib.request.Request(
                f"{mcp.url}/auth/login",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read().decode())
                assert "token" in data
                assert data["user"] == "user1"

    def test_unauthenticated_tool_access_rejected(self):
        with MockMCPServer() as mcp:
            body = json.dumps({"tool": "read_document"}).encode()
            req = urllib.request.Request(
                f"{mcp.url}/tools/invoke",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 401

    def test_authenticated_tool_invocation(self):
        with MockMCPServer() as mcp:
            # Login
            login_body = json.dumps({"username": "user1", "password": "pass1"}).encode()
            login_req = urllib.request.Request(
                f"{mcp.url}/auth/login",
                data=login_body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(login_req) as r:
                token = json.loads(r.read().decode())["token"]

            # Invoke tool
            tool_body = json.dumps({"tool": "read_document"}).encode()
            tool_req = urllib.request.Request(
                f"{mcp.url}/tools/invoke",
                data=tool_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
            )
            with urllib.request.urlopen(tool_req) as r:
                data = json.loads(r.read().decode())
                assert "result" in data
                assert data["result"]["status"] == "ok"

    def test_tool_scoping_enforced(self):
        with MockMCPServer() as mcp:
            # Login as user2 (only has read_document)
            login_body = json.dumps({"username": "user1", "password": "pass1"}).encode()
            login_req = urllib.request.Request(
                f"{mcp.url}/auth/login",
                data=login_body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(login_req) as r:
                token = json.loads(r.read().decode())["token"]

            # Try to invoke a tool not in scope
            tool_body = json.dumps({"tool": "delete_file"}).encode()
            tool_req = urllib.request.Request(
                f"{mcp.url}/tools/invoke",
                data=tool_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(tool_req)
            assert exc_info.value.code == 403

    def test_audit_log_recorded(self):
        with MockMCPServer() as mcp:
            # Login
            login_body = json.dumps({"username": "user1", "password": "pass1"}).encode()
            login_req = urllib.request.Request(
                f"{mcp.url}/auth/login",
                data=login_body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(login_req) as r:
                token = json.loads(r.read().decode())["token"]

            # Invoke tool
            tool_body = json.dumps({"tool": "read_document"}).encode()
            tool_req = urllib.request.Request(
                f"{mcp.url}/tools/invoke",
                data=tool_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
            )
            with urllib.request.urlopen(tool_req):
                pass

            assert len(mcp.audit_log) == 1
            assert mcp.audit_log[0]["tool"] == "read_document"
            assert mcp.audit_log[0]["status"] == "success"
