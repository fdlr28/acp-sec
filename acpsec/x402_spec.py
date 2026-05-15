"""
x402 Protocol — frozen constants from the v1 specification.

Source: github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md
        github.com/coinbase/x402/blob/main/specs/transports-v1/http.md
Spec version: v0.2 (2025-10-3, transport-agnostic redesign)

These constants exist so that the rest of acpsec can reference the spec
in one place.  If the upstream spec changes, only this module needs to
be updated.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Protocol version
# ---------------------------------------------------------------------------
X402_VERSION = 1

# ---------------------------------------------------------------------------
# HTTP transport (transports-v1/http.md §3, §5)
# ---------------------------------------------------------------------------
# Client → server. Value is base64(JSON PaymentPayload).
X402_HEADER_CLIENT: str = "X-PAYMENT"
# Server → client (settlement). Value is base64(JSON SettlementResponse).
X402_HEADER_SERVER: str = "X-PAYMENT-RESPONSE"

# ---------------------------------------------------------------------------
# Networks (spec §11.1 — reference implementation)
# ---------------------------------------------------------------------------
# Note: the protocol is chain-agnostic; this is the v1 reference set.
SUPPORTED_NETWORKS: frozenset[str] = frozenset({
    "base",
    "base-sepolia",
    "avalanche",
    "avalanche-fuji",
    "iotex",
    # SVM (specs/schemes/exact/scheme_exact_svm.md)
    "solana",
    "solana-devnet",
})

# Chain IDs for the EVM networks above.
EVM_CHAIN_IDS: dict[str, int] = {
    "base":           8453,
    "base-sepolia":   84532,
    "avalanche":      43114,
    "avalanche-fuji": 43113,
    "iotex":          4689,
}

# ---------------------------------------------------------------------------
# Payment schemes (spec §6)
# ---------------------------------------------------------------------------
SUPPORTED_SCHEMES: frozenset[str] = frozenset({"exact"})

# EIP-3009 typed-data fields signed by the payer (spec §6.1.1).
EIP3009_FIELDS: tuple[str, ...] = (
    "from", "to", "value", "validAfter", "validBefore", "nonce",
)

# ---------------------------------------------------------------------------
# Facilitator interface (spec §7)
# ---------------------------------------------------------------------------
FACILITATOR_VERIFY_PATH   = "/verify"
FACILITATOR_SETTLE_PATH   = "/settle"
FACILITATOR_SUPPORTED_PATH = "/supported"
FACILITATOR_DISCOVERY_PATH = "/discovery/resources"

# ---------------------------------------------------------------------------
# Error codes (spec §9)
# ---------------------------------------------------------------------------
X402_ERROR_CODES: frozenset[str] = frozenset({
    "insufficient_funds",
    "invalid_exact_evm_payload_authorization_valid_after",
    "invalid_exact_evm_payload_authorization_valid_before",
    "invalid_exact_evm_payload_authorization_value",
    "invalid_exact_evm_payload_signature",
    "invalid_exact_evm_payload_recipient_mismatch",
    "invalid_network",
    "invalid_payload",
    "invalid_payment_requirements",
    "invalid_scheme",
    "unsupported_scheme",
    "invalid_x402_version",
    "invalid_transaction_state",
    "unexpected_verify_error",
    "unexpected_settle_error",
})

# ---------------------------------------------------------------------------
# Base Azul (mainnet activation 2026-05-13)
# Source: blog.base.dev/introducing-base-azul
# Multiproof = TEE proof + ZK proof. Either can finalize alone; matching
# proofs cut Ethereum withdrawal finality to ~1 day (vs. ~7 days pre-Azul).
# ---------------------------------------------------------------------------
BASE_AZUL_ACTIVATION       = "2026-05-13"
BASE_FINALITY_PRE_AZUL_DAYS = 7
BASE_FINALITY_AZUL_DAYS     = 1

# Minimum confirmation blocks recommended for high-value settlement on Base.
# 12 blocks ≈ 24s; production agents waiting on Ethereum L1 finality should
# instead track the multiproof status from the bridge.
BASE_MIN_CONFIRMATIONS_AZUL = 12

# ---------------------------------------------------------------------------
# Schema fragments — useful for static structural validation
# ---------------------------------------------------------------------------
PAYMENT_REQUIREMENTS_REQUIRED_FIELDS: tuple[str, ...] = (
    "scheme", "network", "maxAmountRequired", "asset",
    "payTo", "resource", "description", "maxTimeoutSeconds",
)

PAYMENT_PAYLOAD_REQUIRED_FIELDS: tuple[str, ...] = (
    "x402Version", "scheme", "network", "payload",
)

SETTLEMENT_RESPONSE_REQUIRED_FIELDS: tuple[str, ...] = (
    "success", "transaction", "network", "payer",
)
