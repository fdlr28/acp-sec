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
from acpsec.checks.x402 import run_x402_checks
from acpsec.config_loader import load_config
from acpsec.models import (
    AgentConfig,
    CheckStatus,
    Severity,
    X402AssetConfig,
    X402Config,
    X402FinalityConfig,
)
from acpsec.scorer import (
    OPTIONAL_DIMENSION_WEIGHTS,
    ScoringEngine,
    total_max_score,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _compliant_x402() -> X402Config:
    return X402Config(
        enabled=True,
        scheme="exact",
        networks=["base"],
        facilitator_url="http://127.0.0.1:8402",
        per_request_max_usd=1.00,
        daily_cap_usd=100.00,
        nonce_strategy="facilitator",
        finality=X402FinalityConfig(
            network="base",
            confirmation_blocks=12,
            azul_aware=True,
            pre_azul=False,
        ),
        asset=X402AssetConfig(
            address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            symbol="USDC",
        ),
    )


def _compliant_agent() -> AgentConfig:
    return AgentConfig(
        name="Compliant",
        version="0.1",
        system_prompt="Verify the signature on every X-PAYMENT header.",
        x402=_compliant_x402(),
    )


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


# ---------------------------------------------------------------------------
# Commit 2 — 7 static checks + opt-in scoring
# ---------------------------------------------------------------------------

class TestX402Checks:
    """One unit test per static check, plus aggregate scoring tests."""

    def test_run_x402_raises_when_disabled(self):
        cfg = AgentConfig(name="X", x402=X402Config(enabled=False))
        with pytest.raises(RuntimeError, match="enabled=false"):
            run_x402_checks(cfg)

    def test_fully_compliant_agent_scores_10_of_10(self):
        result = run_x402_checks(_compliant_agent())
        assert result.dimension_id == "X402"
        assert result.max_score == 10
        assert result.score == 10, [
            (c.check_id, c.status, c.score) for c in result.checks
        ]
        assert all(c.status == CheckStatus.PASS for c in result.checks)

    # -- per-check tests ----------------------------------------------------

    def test_auth01_fails_without_facilitator(self):
        cfg = _compliant_agent()
        cfg.x402.facilitator_url = ""
        r = run_x402_checks(cfg)
        c = next(x for x in r.checks if x.check_id == "X402-AUTH-01")
        assert c.status == CheckStatus.FAIL
        assert c.severity == Severity.CRITICAL

    def test_auth01_fails_with_unsupported_scheme(self):
        cfg = _compliant_agent()
        cfg.x402.scheme = "wishful"
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-AUTH-01")
        assert c.status == CheckStatus.FAIL

    def test_auth02_fails_with_nonce_strategy_none(self):
        cfg = _compliant_agent()
        cfg.x402.nonce_strategy = "none"
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-AUTH-02")
        assert c.status == CheckStatus.FAIL
        assert c.severity == Severity.CRITICAL

    def test_auth02_passes_with_self_strategy(self):
        cfg = _compliant_agent()
        cfg.x402.nonce_strategy = "self"
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-AUTH-02")
        assert c.status == CheckStatus.PASS

    def test_auth03_fails_when_no_facilitator_and_silent_prompt(self):
        cfg = AgentConfig(
            name="Silent",
            system_prompt="",   # no mention of signatures
            x402=X402Config(
                enabled=True, scheme="exact", networks=["base"],
                facilitator_url="",          # no facilitator
                nonce_strategy="self",
                per_request_max_usd=1.0, daily_cap_usd=10.0,
                finality=X402FinalityConfig(azul_aware=True, confirmation_blocks=12),
            ),
        )
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-AUTH-03")
        assert c.status == CheckStatus.FAIL

    def test_thr01_fails_with_zero_cap(self):
        cfg = _compliant_agent()
        cfg.x402.per_request_max_usd = 0.0
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-THR-01")
        assert c.status == CheckStatus.FAIL

    def test_thr02_fails_with_zero_daily_cap(self):
        cfg = _compliant_agent()
        cfg.x402.daily_cap_usd = 0.0
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-THR-02")
        assert c.status == CheckStatus.FAIL
        assert c.severity == Severity.CRITICAL

    def test_inj01_passes_when_facilitator_configured(self):
        c = next(x for x in run_x402_checks(_compliant_agent()).checks
                 if x.check_id == "X402-INJ-01")
        assert c.status == CheckStatus.PASS

    def test_inj01_fails_when_no_facilitator_and_silent_prompt(self):
        cfg = _compliant_agent()
        cfg.x402.facilitator_url = ""
        cfg.system_prompt = "Hello world"
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-INJ-01")
        assert c.status == CheckStatus.FAIL

    def test_azul01_passes_post_azul(self):
        c = next(x for x in run_x402_checks(_compliant_agent()).checks
                 if x.check_id == "X402-AZUL-01")
        assert c.status == CheckStatus.PASS

    def test_azul01_fails_on_base_without_explicit_posture(self):
        cfg = _compliant_agent()
        cfg.x402.finality.azul_aware = False
        cfg.x402.finality.pre_azul = False
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-AZUL-01")
        assert c.status == CheckStatus.FAIL

    def test_azul01_skips_when_not_on_base(self):
        cfg = _compliant_agent()
        cfg.x402.networks = ["avalanche"]
        c = next(x for x in run_x402_checks(cfg).checks if x.check_id == "X402-AZUL-01")
        assert c.status == CheckStatus.PASS  # N/A — vacuously passes


class TestOptInScoring:
    def test_optional_dimension_weights_table(self):
        assert OPTIONAL_DIMENSION_WEIGHTS == {"X402": 10}

    def test_total_max_score_without_optional(self):
        assert total_max_score() == 100

    def test_total_max_score_with_x402(self):
        assert total_max_score(("X402",)) == 110

    def test_assessment_max_score_tracks_dimensions_run(self):
        """An x402 agent's assessment must report max_score=110."""
        from acpsec.models import DimensionResult, CheckResult

        # Synthesise two dimensions: AUTH (15 max, all pass) + X402 (10 max, all pass)
        auth_dim = DimensionResult(
            dimension_id="AUTH", name="Authentication & Identity",
            score=15.0, max_score=15.0,
            checks=[CheckResult(
                check_id="AUTH-01", name="x", dimension="AUTH",
                status=CheckStatus.PASS, score=15.0, max_score=15.0,
                severity=Severity.HIGH,
            )],
        )
        x402_dim = run_x402_checks(_compliant_agent())
        engine = ScoringEngine()
        result = engine.build_assessment("X", "0.1", [auth_dim, x402_dim])

        assert result.max_score == 25.0     # 15 + 10
        assert result.final_score == 25.0
        assert result.score_pct == 100.0
        assert result.band == "SECURE"
