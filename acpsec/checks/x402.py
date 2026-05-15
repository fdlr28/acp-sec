"""
X402 dimension checks — x402 protocol posture (10 pts, OPT-IN).

This dimension is only evaluated when AgentConfig.x402.enabled is True.
Total budget: 10 points across 7 checks.  3 of 7 are CRITICAL; under the
standard CRITICAL_PENALTY (−5) rule, a single CRITICAL failure floors the
dimension at 0.
"""

from __future__ import annotations

from ..agent_client import AgentClient
from ..models import AgentConfig, CheckResult, DimensionResult, Severity
from ..scorer import OPTIONAL_DIMENSION_WEIGHTS, make_check
from ..x402_spec import (
    BASE_FINALITY_AZUL_DAYS,
    BASE_MIN_CONFIRMATIONS_AZUL,
    SUPPORTED_NETWORKS,
    SUPPORTED_SCHEMES,
)

DIMENSION_ID = "X402"
DIMENSION_NAME = "x402 Protocol Posture"


def run_x402_checks(config: AgentConfig, client: AgentClient | None = None) -> DimensionResult:
    """Run all 7 x402 static checks. Raises if the dimension isn't enabled."""
    if not config.x402.enabled:
        raise RuntimeError(
            "run_x402_checks called on an agent with x402.enabled=false. "
            "Gate the call site on config.x402.enabled."
        )

    checks: list[CheckResult] = [
        _x402_auth01_payment_proof_declared(config),
        _x402_auth02_replay_nonce_strategy(config),
        _x402_auth03_signature_verification(config),
        _x402_thr01_per_request_cap(config),
        _x402_thr02_daily_cap(config),
        _x402_inj01_header_injection_posture(config),
        _x402_azul01_finality_awareness(config),
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
# X402-AUTH-01 (2 pts, CRITICAL) — payment proof validation declared
# ---------------------------------------------------------------------------
def _x402_auth01_payment_proof_declared(config: AgentConfig) -> CheckResult:
    """The agent must route payment proofs through a configured facilitator."""
    x = config.x402
    has_facilitator = bool(x.facilitator_url and x.facilitator_url.strip())
    scheme_ok = x.scheme in SUPPORTED_SCHEMES
    passed = has_facilitator and scheme_ok
    return make_check(
        check_id="X402-AUTH-01",
        name="Payment proof validation declared",
        dimension=DIMENSION_ID,
        severity=Severity.CRITICAL,
        max_score=2,
        passed=passed,
        evidence=[
            f"facilitator_url='{x.facilitator_url}'",
            f"scheme='{x.scheme}' (supported={sorted(SUPPORTED_SCHEMES)})",
        ],
        recommendations=(
            []
            if passed
            else [
                "Declare `x402.facilitator_url` pointing to a trusted verifier.",
                "Use scheme='exact' (the only v1-spec scheme).",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# X402-AUTH-02 (2 pts, CRITICAL) — replay-attack protection (nonce)
# ---------------------------------------------------------------------------
def _x402_auth02_replay_nonce_strategy(config: AgentConfig) -> CheckResult:
    """A nonce strategy must be declared. 'none' is an explicit fail."""
    strategy = (config.x402.nonce_strategy or "").lower()
    valid = {"facilitator", "self"}
    passed = strategy in valid
    return make_check(
        check_id="X402-AUTH-02",
        name="Replay-attack protection (nonce strategy)",
        dimension=DIMENSION_ID,
        severity=Severity.CRITICAL,
        max_score=2,
        passed=passed,
        evidence=[
            f"nonce_strategy='{strategy}'",
            "EIP-3009 nonces are burned on-chain; off-chain agents must also "
            "enforce uniqueness pre-settlement to prevent double-spend windows.",
        ],
        recommendations=(
            []
            if passed
            else [
                "Set x402.nonce_strategy to 'facilitator' (delegate) or 'self' "
                "(maintain a server-side nonce ledger).",
                "Never use 'none' in production — it disables replay defence.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# X402-AUTH-03 (1 pt, HIGH) — signature verification posture
# ---------------------------------------------------------------------------
def _x402_auth03_signature_verification(config: AgentConfig) -> CheckResult:
    """
    The agent must commit (via facilitator OR self) to verifying EIP-712
    signatures. We check that a facilitator is reachable OR system_prompt
    explicitly mentions signature verification.
    """
    x = config.x402
    via_facilitator = bool(x.facilitator_url and x.nonce_strategy == "facilitator")
    prompt = (config.system_prompt or "").lower()
    via_prompt = "eip-712" in prompt or "signature verification" in prompt \
        or "verify the signature" in prompt
    passed = via_facilitator or via_prompt
    return make_check(
        check_id="X402-AUTH-03",
        name="EIP-712 signature verification committed",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=1,
        passed=passed,
        evidence=[
            f"facilitator-handled={via_facilitator}",
            f"prompt-mentioned={via_prompt}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Either route /verify through a trusted facilitator, or add "
                "an explicit clause to the system prompt committing to "
                "EIP-712 signature verification before accepting payment.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# X402-THR-01 (1 pt, HIGH) — per-request amount cap
# ---------------------------------------------------------------------------
def _x402_thr01_per_request_cap(config: AgentConfig) -> CheckResult:
    """The agent must declare a finite per-request cap (>0)."""
    cap = config.x402.per_request_max_usd
    passed = cap > 0.0
    return make_check(
        check_id="X402-THR-01",
        name="Per-request amount cap declared",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=1,
        passed=passed,
        evidence=[f"per_request_max_usd={cap}"],
        recommendations=(
            []
            if passed
            else [
                "Set x402.per_request_max_usd to a finite positive value. "
                "Common values: 0.01–10.00 for content APIs, ≤100 for "
                "compute-heavy services.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# X402-THR-02 (2 pts, CRITICAL) — daily / total spending cap
# ---------------------------------------------------------------------------
def _x402_thr02_daily_cap(config: AgentConfig) -> CheckResult:
    """A finite daily cap is mandatory to bound autonomous spend."""
    cap = config.x402.daily_cap_usd
    passed = cap > 0.0
    return make_check(
        check_id="X402-THR-02",
        name="Daily / total spending cap declared",
        dimension=DIMENSION_ID,
        severity=Severity.CRITICAL,
        max_score=2,
        passed=passed,
        evidence=[f"daily_cap_usd={cap}"],
        recommendations=(
            []
            if passed
            else [
                "Set x402.daily_cap_usd to a finite positive value. "
                "Unbounded daily spend on autonomous agents = unbounded blast "
                "radius if compromised.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# X402-INJ-01 (1 pt, MEDIUM) — header injection posture
# ---------------------------------------------------------------------------
def _x402_inj01_header_injection_posture(config: AgentConfig) -> CheckResult:
    """
    Agent must commit to validating the X-PAYMENT header before forwarding
    it. We accept either: facilitator-routed (the facilitator parses it)
    OR system_prompt mentions header validation.
    """
    via_facilitator = bool(config.x402.facilitator_url)
    prompt = (config.system_prompt or "").lower()
    via_prompt = "header injection" in prompt or "x-payment" in prompt or \
        "validate the header" in prompt or "crlf" in prompt
    passed = via_facilitator or via_prompt
    return make_check(
        check_id="X402-INJ-01",
        name="X-PAYMENT header injection protection",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=1,
        passed=passed,
        evidence=[
            f"facilitator-parsed={via_facilitator}",
            f"prompt-mentioned={via_prompt}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Validate the X-PAYMENT header value (reject CRLF, oversize, "
                "non-base64) before decode; OR delegate parsing to the "
                "facilitator and never echo the raw header back.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# X402-AZUL-01 (1 pt, LOW) — multiproof finality awareness
# ---------------------------------------------------------------------------
def _x402_azul01_finality_awareness(config: AgentConfig) -> CheckResult:
    """
    If the agent settles on Base mainnet, it must acknowledge finality
    semantics: post-Azul (azul_aware=true, ~1-day) or pre-Azul (pre_azul=true).
    Silent settles on Base without an explicit posture = fail.
    """
    networks = [n.lower() for n in (config.x402.networks or [])]
    on_base = "base" in networks
    fin = config.x402.finality
    if not on_base:
        passed = True
        evidence = ["Agent does not settle on Base mainnet — Azul N/A"]
    else:
        explicit_post_azul = fin.azul_aware and not fin.pre_azul
        explicit_pre_azul = fin.pre_azul and not fin.azul_aware
        confirmations_ok = fin.confirmation_blocks >= BASE_MIN_CONFIRMATIONS_AZUL
        passed = (explicit_post_azul and confirmations_ok) or explicit_pre_azul
        evidence = [
            f"on_base=True, azul_aware={fin.azul_aware}, pre_azul={fin.pre_azul}",
            f"confirmation_blocks={fin.confirmation_blocks} "
            f"(min={BASE_MIN_CONFIRMATIONS_AZUL} post-Azul)",
            f"Azul activated mainnet 2026-05-13; finality ~{BASE_FINALITY_AZUL_DAYS} day.",
        ]
    return make_check(
        check_id="X402-AZUL-01",
        name="Base Azul multiproof finality awareness",
        dimension=DIMENSION_ID,
        severity=Severity.LOW,
        max_score=1,
        passed=passed,
        evidence=evidence,
        recommendations=(
            []
            if passed
            else [
                "Set x402.finality.azul_aware: true and confirmation_blocks: 12 "
                "if you settle on Base mainnet post-Azul (2026-05-13).",
                "If still on pre-Azul behaviour, set pre_azul: true explicitly "
                "to acknowledge ~7-day withdrawal finality.",
            ]
        ),
    )
