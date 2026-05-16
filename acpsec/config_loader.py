"""Load and validate agent configuration from YAML."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from .models import (
    AgentConfig,
    MCPAccessConfig,
    MCPAuditConfig,
    MCPAuthConfig,
    MCPConfig,
    X402AssetConfig,
    X402Config,
    X402FinalityConfig,
)


_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def _expand_env_vars(value: str) -> str:
    """Expand ${VAR_NAME} references to environment variables."""
    def replacer(match: re.Match) -> str:
        var = match.group(1)
        resolved = os.environ.get(var)
        if resolved is None:
            raise ValueError(f"Environment variable '{var}' is not set.")
        return resolved

    return _ENV_VAR_RE.sub(replacer, value)


def _expand_recursive(obj: object) -> object:
    if isinstance(obj, str):
        return _expand_env_vars(obj)
    if isinstance(obj, dict):
        return {k: _expand_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_recursive(item) for item in obj]
    return obj


def load_config(path: str | Path) -> AgentConfig:
    """Load an agent YAML config and return an AgentConfig."""
    raw = Path(path).read_text()
    data: dict = yaml.safe_load(raw)
    data = _expand_recursive(data)

    # Flatten nested sections into AgentConfig fields
    provider = data.pop("provider", {})
    security = data.pop("security", {})
    metadata = data.pop("metadata", {})
    x402_raw = data.pop("x402", {}) or {}
    mcp_raw = data.pop("mcp", {}) or {}

    flat = {
        "name": data.get("name", "unknown"),
        "version": data.get("version", "1.0"),
        "provider_type": provider.get("type", data.get("provider_type", "anthropic")),
        "model": provider.get("model", data.get("model", "claude-sonnet-4-6")),
        "api_key": provider.get("api_key", data.get("api_key")),
        "endpoint": provider.get("endpoint", data.get("endpoint")),
        "system_prompt": data.get("system_prompt", ""),
        "tools": data.get("tools", []),
        "auth_type": security.get("auth_type", data.get("auth_type", "bearer")),
        "session_isolation": security.get("session_isolation", data.get("session_isolation", True)),
        "output_filtering": security.get("output_filtering", data.get("output_filtering", False)),
        "hitl_tiers": security.get("hitl_tiers", data.get("hitl_tiers", [])),
        "environment": metadata.get("environment", data.get("environment", "staging")),
        "owner": metadata.get("owner", data.get("owner", "")),
        "x402": _build_x402_config(x402_raw),
        "mcp": _build_mcp_config(mcp_raw),
    }

    return AgentConfig(**flat)


def _build_x402_config(raw: dict) -> X402Config:
    """Build an X402Config from the YAML `x402:` block (or defaults if empty)."""
    finality_raw = raw.get("finality", {}) or {}
    asset_raw = raw.get("asset", {}) or {}
    return X402Config(
        enabled=bool(raw.get("enabled", False)),
        scheme=raw.get("scheme", "exact"),
        networks=list(raw.get("networks", []) or []),
        facilitator_url=raw.get("facilitator_url", ""),
        per_request_max_usd=float(raw.get("per_request_max_usd", 0.0)),
        daily_cap_usd=float(raw.get("daily_cap_usd", 0.0)),
        nonce_strategy=raw.get("nonce_strategy", "facilitator"),
        finality=X402FinalityConfig(
            network=finality_raw.get("network", "base"),
            confirmation_blocks=int(finality_raw.get("confirmation_blocks", 12)),
            azul_aware=bool(finality_raw.get("azul_aware", False)),
            pre_azul=bool(finality_raw.get("pre_azul", False)),
        ),
        asset=X402AssetConfig(
            address=asset_raw.get("address", ""),
            symbol=asset_raw.get("symbol", "USDC"),
        ),
    )


def _build_mcp_config(raw: dict) -> MCPConfig:
    """Build an MCPConfig from the YAML `mcp:` block (or defaults if empty)."""
    auth_raw = raw.get("auth", {}) or {}
    access_raw = raw.get("access", {}) or {}
    audit_raw = raw.get("audit", {}) or {}
    return MCPConfig(
        enabled=bool(raw.get("enabled", False)),
        server_url=raw.get("server_url", ""),
        auth=MCPAuthConfig(
            required=bool(auth_raw.get("required", True)),
            mechanism=auth_raw.get("mechanism", "bearer"),
            tool_scoping=bool(auth_raw.get("tool_scoping", False)),
        ),
        access=MCPAccessConfig(
            resource_isolation=bool(access_raw.get("resource_isolation", False)),
            sandbox_mode=bool(access_raw.get("sandbox_mode", False)),
        ),
        audit=MCPAuditConfig(
            enabled=bool(audit_raw.get("enabled", False)),
            log_tool_calls=bool(audit_raw.get("log_tool_calls", False)),
            log_results=bool(audit_raw.get("log_results", False)),
        ),
        prompt_injection_protection=bool(raw.get("prompt_injection_protection", False)),
    )
