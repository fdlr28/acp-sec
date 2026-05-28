"""
Tests for the PLUGIN dimension (v0.3.1, skill-plugin security).

Covers:
  - The 3 static checks (MCP-PLUGIN-01/02/03)
  - Opt-in gate via plugin.enabled
  - Scoring integration (dimension weight, total_max_score arithmetic)
  - YAML config parsing
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from acpsec.checks.plugin import run_plugin_checks
from acpsec.config_loader import load_config
from acpsec.models import (
    AgentConfig,
    CheckStatus,
    PluginConfig,
    Severity,
)
from acpsec.scorer import (
    OPTIONAL_DIMENSION_WEIGHTS,
    ScoringEngine,
    total_max_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _compliant_plugin_agent() -> AgentConfig:
    return AgentConfig(
        name="Plugin Compliant Agent",
        version="0.3.1",
        system_prompt="Skills run in a sandboxed runtime with strict input validation.",
        plugin=PluginConfig(
            enabled=True,
            sandboxed=True,
            permission_scoping=True,
            input_validation=True,
        ),
    )


def _misconfigured_plugin_agent() -> AgentConfig:
    return AgentConfig(
        name="Plugin Misconfigured Agent",
        version="0.3.1",
        plugin=PluginConfig(
            enabled=True,
            sandboxed=False,
            permission_scoping=False,
            input_validation=False,
        ),
    )


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------

class TestPluginChecksCompliant:
    def test_all_three_pass(self):
        result = run_plugin_checks(_compliant_plugin_agent())
        assert result.score == 3.0
        assert result.max_score == 3.0
        assert all(c.status == CheckStatus.PASS for c in result.checks)
        assert [c.check_id for c in result.checks] == [
            "MCP-PLUGIN-01", "MCP-PLUGIN-02", "MCP-PLUGIN-03",
        ]

    def test_plugin02_severity_high(self):
        result = run_plugin_checks(_compliant_plugin_agent())
        plugin02 = next(c for c in result.checks if c.check_id == "MCP-PLUGIN-02")
        # Permission scoping is the privilege-escalation guard → HIGH.
        assert plugin02.severity == Severity.HIGH


class TestPluginChecksMisconfigured:
    def test_all_three_fail(self):
        result = run_plugin_checks(_misconfigured_plugin_agent())
        assert result.score == 0.0
        assert result.max_score == 3.0
        assert all(c.status == CheckStatus.FAIL for c in result.checks)

    def test_plugin01_recommends_sandbox(self):
        result = run_plugin_checks(_misconfigured_plugin_agent())
        c = next(x for x in result.checks if x.check_id == "MCP-PLUGIN-01")
        assert any("sandboxed: true" in r for r in c.recommendations)


class TestPluginGate:
    def test_raises_when_disabled(self):
        agent = AgentConfig(name="No plugin", plugin=PluginConfig(enabled=False))
        with pytest.raises(RuntimeError, match="plugin.enabled=false"):
            run_plugin_checks(agent)


# ---------------------------------------------------------------------------
# Scoring integration
# ---------------------------------------------------------------------------

class TestPluginScoring:
    def test_optional_weight_is_three(self):
        assert OPTIONAL_DIMENSION_WEIGHTS["PLUGIN"] == 3

    def test_total_max_with_plugin(self):
        assert total_max_score(("PLUGIN",)) == 103

    def test_total_max_with_mcp_and_plugin(self):
        # 100 (base) + 12 (MCP) + 3 (PLUGIN) = 115
        assert total_max_score(("MCP", "PLUGIN")) == 115

    def test_assessment_max_score_reflects_plugin(self):
        dim = run_plugin_checks(_compliant_plugin_agent())
        engine = ScoringEngine()
        result = engine.build_assessment("Plugin Agent", "0.3.1", [dim])
        assert result.max_score == 3.0
        assert result.final_score == 3.0
        assert result.score_pct == 100.0


# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------

class TestPluginYaml:
    def _yaml(self, body: str) -> AgentConfig:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(body)
            path = f.name
        try:
            return load_config(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_full_plugin_block_round_trips(self):
        cfg = self._yaml("""
name: PluginAgent
version: "0.3.1"
plugin:
  enabled: true
  sandboxed: true
  permission_scoping: true
  input_validation: true
""")
        assert cfg.plugin.enabled is True
        assert cfg.plugin.sandboxed is True
        assert cfg.plugin.permission_scoping is True
        assert cfg.plugin.input_validation is True

    def test_missing_plugin_block_defaults_disabled(self):
        cfg = self._yaml("name: NoPluginAgent\nversion: '1.0'\n")
        assert cfg.plugin.enabled is False
        assert cfg.plugin.sandboxed is False
