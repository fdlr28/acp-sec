"""
Mock MCP server — stdlib-only (no FastAPI dependency).

Implements a minimal MCP server surface with authentication, tool scoping,
resource isolation, and audit logging to exercise the MCP-* probes in
acpsec/checks/mcp.py.

It is NOT a real MCP server:
  - Authentication is token-based with a hardcoded test token.
  - Tool results are canned responses.
  - Audit log is in-memory and resets when the process exits.

Used as a context manager:

    with MockMCPServer() as mcp:
        # mcp.url is e.g. "http://127.0.0.1:54231"
        # mcp.audit_log has the list of tool invocations for assertions
        ...
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# Test tokens for authentication
VALID_TOKENS = {"test-token-123", "admin-token-456"}

# Tool registry with scoping (user -> allowed tools)
TOOL_REGISTRY = {
    "user1": ["read_document", "list_files"],
    "user2": ["read_document"],
    "admin": ["read_document", "list_files", "write_file", "delete_file"],
}

# Canned tool results
TOOL_RESULTS = {
    "read_document": {"content": "This is a test document.", "status": "ok"},
    "list_files": {"files": ["doc1.txt", "doc2.pdf"], "status": "ok"},
    "write_file": {"status": "ok", "message": "File written successfully."},
    "delete_file": {"status": "ok", "message": "File deleted."},
}


class MockMCPServer:
    """
    Stand-alone MCP server on a free localhost port.

    State:
      - audit_log: list[dict] — every tool invocation, for assertions
      - active_sessions: dict[str, str] — token -> user mapping
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port = _free_port()
        self.url = f"http://{host}:{self.port}"
        self.audit_log: list[dict[str, Any]] = []
        self.active_sessions: dict[str, str] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> "MockMCPServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def start(self) -> None:
        mcp_server = self
        handler = _make_handler(mcp_server)
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
        """Clear audit log and sessions between probes."""
        self.audit_log.clear()
        self.active_sessions.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Ask the kernel for an unused TCP port (bind to :0)."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_handler(mcp_server: MockMCPServer):
    """Build a BaseHTTPRequestHandler subclass closed over `mcp_server`."""

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

        def _get_token(self) -> str | None:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return auth[7:]
            return self.headers.get("X-API-Key")

        def _authenticate(self) -> str | None:
            """Return username if authenticated, else None."""
            token = self._get_token()
            if not token:
                return None
            return mcp_server.active_sessions.get(token)

        # -------- routes --------
        def do_GET(self) -> None:                       # noqa: N802
            if self.path == "/health":
                return self._json(200, {"status": "ok", "server": "mock-mcp"})
            if self.path == "/tools":
                user = self._authenticate()
                if not user:
                    return self._json(401, {"error": "authentication_required"})
                tools = TOOL_REGISTRY.get(user, [])
                return self._json(200, {"tools": tools})
            return self._json(404, {"error": "not found"})

        def do_POST(self) -> None:                      # noqa: N802
            body = self._read_json()

            # Login endpoint (no auth required)
            if self.path == "/auth/login":
                return self._handle_login(body)

            # All other endpoints require authentication
            user = self._authenticate()
            if not user:
                return self._json(401, {"error": "authentication_required"})

            if self.path == "/tools/invoke":
                return self._handle_tool_invoke(body, user)
            return self._json(404, {"error": "not found"})

        # -------- /auth/login --------
        def _handle_login(self, body: dict | None) -> None:
            if not body:
                return self._json(400, {"error": "invalid_request"})
            username = body.get("username")
            password = body.get("password")
            # Simple auth check
            if username == "user1" and password == "pass1":
                token = "test-token-123"
            elif username == "admin" and password == "admin":
                token = "admin-token-456"
            else:
                return self._json(401, {"error": "invalid_credentials"})

            mcp_server.active_sessions[token] = username
            return self._json(200, {"token": token, "user": username})

        # -------- /tools/invoke --------
        def _handle_tool_invoke(self, body: dict | None, user: str) -> None:
            if not body:
                return self._json(400, {"error": "invalid_request"})

            tool_name = body.get("tool")
            if not tool_name:
                return self._json(400, {"error": "missing_tool_name"})

            # Check tool scoping
            allowed_tools = TOOL_REGISTRY.get(user, [])
            if tool_name not in allowed_tools:
                mcp_server.audit_log.append({
                    "user": user,
                    "tool": tool_name,
                    "status": "denied",
                    "reason": "tool_not_in_scope",
                    "ts": time.time(),
                })
                return self._json(403, {
                    "error": "tool_not_authorized",
                    "message": f"Tool '{tool_name}' not in scope for user '{user}'",
                })

            # Execute tool (canned response)
            result = TOOL_RESULTS.get(tool_name, {"error": "unknown_tool"})

            # Audit logging
            mcp_server.audit_log.append({
                "user": user,
                "tool": tool_name,
                "status": "success",
                "ts": time.time(),
            })

            return self._json(200, {"result": result})

    return Handler


if __name__ == "__main__":
    # Smoke test — start, login, invoke tool, stop.
    import urllib.request
    with MockMCPServer() as mcp:
        print(f"mock MCP server listening at {mcp.url}")

        # Login
        login_data = json.dumps({"username": "user1", "password": "pass1"}).encode()
        req = urllib.request.Request(
            f"{mcp.url}/auth/login",
            data=login_data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            resp = json.loads(r.read().decode())
            token = resp["token"]
            print(f"/auth/login → {r.status}, token={token}")

        # Invoke tool
        tool_data = json.dumps({"tool": "read_document"}).encode()
        req = urllib.request.Request(
            f"{mcp.url}/tools/invoke",
            data=tool_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        with urllib.request.urlopen(req) as r:
            print(f"/tools/invoke → {r.status}, {r.read().decode()}")

        print(f"Audit log: {mcp.audit_log}")
