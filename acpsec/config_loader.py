"""Load and validate agent configuration from YAML."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from .models import AgentConfig


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
    }

    return AgentConfig(**flat)
