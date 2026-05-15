"""
Mock x402 facilitator — stdlib-only (no FastAPI dependency).

Implements the v1 facilitator surface (/verify, /settle, /supported) with
just enough fidelity to exercise the X402-LIVE-* probes in auth_scanner.py.

It is NOT a real facilitator:
  - Signatures are sanity-checked by regex, not cryptographically.
  - "Settlement" returns a synthetic tx hash; no real chain interaction.
  - Nonce store is in-memory and resets when the process exits.

Used as a context manager:

    with MockFacilitator() as fac:
        # fac.url is e.g. "http://127.0.0.1:54231"
        # fac.nonce_store has the {nonce: timestamp} map for assertions
        ...
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from acpsec.x402_spec import (
    FACILITATOR_SETTLE_PATH,
    FACILITATOR_SUPPORTED_PATH,
    FACILITATOR_VERIFY_PATH,
    SUPPORTED_NETWORKS,
    X402_VERSION,
)

# 65 hex chars after 0x = standard EIP-712 sig length (r,s,v).
_SIG_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")
_NONCE_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


class MockFacilitator:
    """
    Stand-alone facilitator on a free localhost port.

    State:
      - nonce_store: dict[str, float]  — nonce → first-seen unix timestamp
      - request_log: list[dict]        — every inbound request, for asserts
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port = _free_port()
        self.url = f"http://{host}:{self.port}"
        self.nonce_store: dict[str, float] = {}
        self.request_log: list[dict[str, Any]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> "MockFacilitator":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def start(self) -> None:
        facilitator = self
        handler = _make_handler(facilitator)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        # Wait until the socket is actually accepting connections.
        for _ in range(50):
            try:
                with socket.create_connection((self.host, self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def reset(self) -> None:
        """Clear nonce store and request log between probes."""
        self.nonce_store.clear()
        self.request_log.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Ask the kernel for an unused TCP port (bind to :0)."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_handler(facilitator: MockFacilitator):
    """Build a BaseHTTPRequestHandler subclass closed over `facilitator`."""

    class Handler(BaseHTTPRequestHandler):
        # Silence stderr access-log spam during tests
        def log_message(self, format: str, *args: Any) -> None:
            return

        # -------- helpers --------
        def _json(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _read_json(self) -> dict | None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length == 0:
                return None
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode())
            except Exception:
                return None

        # -------- routes --------
        def do_GET(self) -> None:                       # noqa: N802
            if self.path == FACILITATOR_SUPPORTED_PATH:
                return self._json(200, {
                    "kinds": [
                        {"x402Version": X402_VERSION, "scheme": "exact", "network": n}
                        for n in sorted(SUPPORTED_NETWORKS) if "sepolia" not in n
                    ]
                })
            return self._json(404, {"error": "not found"})

        def do_POST(self) -> None:                      # noqa: N802
            body = self._read_json()
            facilitator.request_log.append({
                "path": self.path, "headers": dict(self.headers),
                "body": body, "ts": time.time(),
            })
            if self.path == FACILITATOR_VERIFY_PATH:
                return self._handle_verify(body)
            if self.path == FACILITATOR_SETTLE_PATH:
                return self._handle_settle(body)
            return self._json(404, {"error": "not found"})

        # -------- /verify --------
        def _handle_verify(self, body: dict | None) -> None:
            err = _validate_payment(body, facilitator)
            if err is not None:
                return self._json(200, {
                    "isValid": False,
                    "invalidReason": err,
                    "payer": _payer(body),
                })
            return self._json(200, {
                "isValid": True,
                "payer": _payer(body),
            })

        # -------- /settle --------
        def _handle_settle(self, body: dict | None) -> None:
            err = _validate_payment(body, facilitator)
            if err is not None:
                return self._json(200, {
                    "success": False,
                    "errorReason": err,
                    "transaction": "",
                    "network": _network(body),
                    "payer": _payer(body),
                })
            # Record nonce on successful settle (real on-chain nonce burn).
            auth = _auth(body)
            if auth and auth.get("nonce"):
                facilitator.nonce_store[auth["nonce"]] = time.time()
            return self._json(200, {
                "success": True,
                "transaction": "0x" + "ab" * 32,
                "network": _network(body),
                "payer": _payer(body),
            })

    return Handler


def _payment_payload(body: dict | None) -> dict | None:
    if not body or not isinstance(body, dict):
        return None
    return body.get("paymentPayload") if isinstance(body.get("paymentPayload"), dict) else None


def _auth(body: dict | None) -> dict | None:
    p = _payment_payload(body)
    if not p:
        return None
    payload = p.get("payload")
    if not isinstance(payload, dict):
        return None
    auth = payload.get("authorization")
    return auth if isinstance(auth, dict) else None


def _payer(body: dict | None) -> str:
    a = _auth(body)
    return (a or {}).get("from", "") or ""


def _network(body: dict | None) -> str:
    p = _payment_payload(body)
    return (p or {}).get("network", "") or ""


def _validate_payment(body: dict | None, facilitator: MockFacilitator) -> str | None:
    """Return an x402 error code if invalid, else None."""
    if not body or not isinstance(body, dict):
        return "invalid_payload"

    pp = _payment_payload(body)
    if not pp:
        return "invalid_payload"
    if pp.get("x402Version") != X402_VERSION:
        return "invalid_x402_version"
    if pp.get("scheme") != "exact":
        return "invalid_scheme"
    if pp.get("network") not in SUPPORTED_NETWORKS:
        return "invalid_network"

    payload = pp.get("payload")
    if not isinstance(payload, dict):
        return "invalid_payload"

    sig = payload.get("signature", "")
    if not isinstance(sig, str) or not _SIG_RE.match(sig):
        return "invalid_exact_evm_payload_signature"

    auth = payload.get("authorization")
    if not isinstance(auth, dict):
        return "invalid_payload"

    for f in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
        if f not in auth:
            return "invalid_payload"

    nonce = auth["nonce"]
    if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
        return "invalid_payload"

    # Replay defence — second appearance of the same nonce is rejected.
    if nonce in facilitator.nonce_store:
        return "invalid_payload"          # spec §9: "invalid_payload" covers reuse

    # Time window
    try:
        va = int(auth["validAfter"])
        vb = int(auth["validBefore"])
    except (TypeError, ValueError):
        return "invalid_payload"
    now = int(time.time())
    if now < va:
        return "invalid_exact_evm_payload_authorization_valid_after"
    if now > vb:
        return "invalid_exact_evm_payload_authorization_valid_before"

    return None


# ---------------------------------------------------------------------------
# Helpers used by callers/tests for building well-formed payloads
# ---------------------------------------------------------------------------

def build_payment_payload(
    *,
    network: str = "base-sepolia",
    value: str = "10000",
    from_addr: str = "0x857b06519E91e3A54538791bDbb0E22373e36b66",
    to_addr: str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    signature: str | None = None,
    nonce: str | None = None,
    valid_after: int | None = None,
    valid_before: int | None = None,
) -> dict:
    """Construct a well-formed v1 PaymentPayload."""
    now = int(time.time())
    return {
        "x402Version": X402_VERSION,
        "scheme": "exact",
        "network": network,
        "payload": {
            "signature": signature or ("0x" + "a" * 130),
            "authorization": {
                "from": from_addr,
                "to": to_addr,
                "value": value,
                "validAfter": str(valid_after if valid_after is not None else now - 60),
                "validBefore": str(valid_before if valid_before is not None else now + 300),
                "nonce": nonce or ("0x" + "b" * 64),
            },
        },
    }


def build_payment_requirements(
    *,
    network: str = "base-sepolia",
    max_amount: str = "10000",
    pay_to: str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    asset: str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
) -> dict:
    """Construct a v1 PaymentRequirements object."""
    return {
        "scheme": "exact",
        "network": network,
        "maxAmountRequired": max_amount,
        "resource": "https://api.example.com/premium-data",
        "description": "mock resource",
        "mimeType": "application/json",
        "payTo": pay_to,
        "maxTimeoutSeconds": 60,
        "asset": asset,
        "extra": {"name": "USDC", "version": "2"},
    }


def encode_x_payment_header(payment_payload: dict) -> str:
    """Base64-encode a PaymentPayload for use as the X-PAYMENT header value."""
    return base64.b64encode(json.dumps(payment_payload).encode()).decode()


if __name__ == "__main__":
    # Smoke test — start, hit /supported, stop.
    import urllib.request
    with MockFacilitator() as fac:
        print(f"mock facilitator listening at {fac.url}")
        with urllib.request.urlopen(f"{fac.url}/supported") as r:
            print("/supported →", r.status, r.read().decode())
