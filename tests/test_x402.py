"""
Tests for the x402 module (commits 1-4).

Layout grows as commits land:
  - Commit 1: config parsing + spec constants
  - Commit 2: 7 static checks + opt-in scoring
  - Commit 3: mock facilitator self-tests
  - Commit 4: live probes against the mock facilitator
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from acpsec import x402_spec
from acpsec.config_loader import load_config
from acpsec.models import AgentConfig, X402Config


# ---------------------------------------------------------------------------
# Commit 1 — spec constants + config parsing
# ---------------------------------------------------------------------------

class TestSpecConstants:
    def test_protocol_version_is_1(self):
        assert x402_spec.X402_VERSION == 1

    def test_canonical_http_headers(self):
        # transports-v1/http.md §3, §5 — verbatim
        assert x402_spec.X402_HEADER_CLIENT == "X-PAYMENT"
        assert x402_spec.X402_HEADER_SERVER == "X-PAYMENT-RESPONSE"

    def test_base_networks_present(self):
        assert "base" in x402_spec.SUPPORTED_NETWORKS
        assert "base-sepolia" in x402_spec.SUPPORTED_NETWORKS

    def test_solana_supported(self):
        assert "solana" in x402_spec.SUPPORTED_NETWORKS

    def test_eip3009_fields_match_spec(self):
        # spec §6.1.1
        assert x402_spec.EIP3009_FIELDS == (
            "from", "to", "value", "validAfter", "validBefore", "nonce",
        )

    def test_facilitator_paths(self):
        assert x402_spec.FACILITATOR_VERIFY_PATH == "/verify"
        assert x402_spec.FACILITATOR_SETTLE_PATH == "/settle"

    def test_known_error_codes(self):
        assert "insufficient_funds" in x402_spec.X402_ERROR_CODES
        assert "invalid_exact_evm_payload_signature" in x402_spec.X402_ERROR_CODES
        assert "invalid_payload" in x402_spec.X402_ERROR_CODES

    def test_azul_activation_date_is_2026_05_13(self):
        assert x402_spec.BASE_AZUL_ACTIVATION == "2026-05-13"
        assert x402_spec.BASE_FINALITY_AZUL_DAYS == 1
        assert x402_spec.BASE_FINALITY_PRE_AZUL_DAYS == 7


class TestConfigParsing:
    """The YAML loader must produce a fully-typed X402Config block."""

    def _yaml(self, body: str) -> AgentConfig:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(body)
            path = f.name
        try:
            return load_config(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_x402_block_defaults_disabled(self):
        cfg = self._yaml("""
name: NoX402
version: "1.0"
""")
        assert isinstance(cfg.x402, X402Config)
        assert cfg.x402.enabled is False
        assert cfg.x402.networks == []
        assert cfg.x402.finality.azul_aware is False

    def test_full_x402_block_round_trips(self):
        cfg = self._yaml("""
name: X402Agent
version: "0.1"
x402:
  enabled: true
  scheme: exact
  networks: [base]
  facilitator_url: "http://127.0.0.1:8402"
  per_request_max_usd: 1.5
  daily_cap_usd: 200.0
  nonce_strategy: facilitator
  finality:
    network: base
    confirmation_blocks: 12
    azul_aware: true
  asset:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    symbol: USDC
""")
        x = cfg.x402
        assert x.enabled is True
        assert x.scheme == "exact"
        assert x.networks == ["base"]
        assert x.facilitator_url == "http://127.0.0.1:8402"
        assert x.per_request_max_usd == pytest.approx(1.5)
        assert x.daily_cap_usd == pytest.approx(200.0)
        assert x.nonce_strategy == "facilitator"
        assert x.finality.azul_aware is True
        assert x.finality.confirmation_blocks == 12
        assert x.asset.symbol == "USDC"
        assert x.asset.address.startswith("0x833589")

    def test_legacy_yaml_without_x402_still_loads(self):
        """Existing v0.1 configs must keep working unchanged."""
        cfg = self._yaml("""
name: LegacyAgent
version: "1.0"
provider:
  type: anthropic
  model: claude-haiku-4-5-20251001
system_prompt: |
  You are helpful.
security:
  auth_type: bearer
  session_isolation: true
""")
        assert cfg.name == "LegacyAgent"
        assert cfg.session_isolation is True
        assert cfg.x402.enabled is False
