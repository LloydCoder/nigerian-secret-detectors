from __future__ import annotations

import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .policy import ScanPolicy
from .providers import PROVIDERS
from .registry import REGISTRY
from .scanner import scan

SCAN_ROOT = Path(os.environ.get("NIGERIAN_SCAN_ROOT", ".")).expanduser().resolve()
MAX_BODY = 64 * 1024
RATE_LIMIT = 60
RATE_WINDOW = 60.0
MAX_RATE_CLIENTS = 4096
API_KEY = os.environ.get("NIGERIAN_API_KEY")
_RATE_STATE: dict[str, list[float]] = {}


def _safe_target(value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("target must be a relative path without parent traversal")
    target = (SCAN_ROOT / candidate).resolve()
    if not target.is_relative_to(SCAN_ROOT):
        raise ValueError("target must remain inside NIGERIAN_SCAN_ROOT")
    return target


def _policy_from_payload(value: object) -> ScanPolicy:
    if value is None:
        return ScanPolicy()
    if not isinstance(value, dict):
        raise ValueError("policy must be a JSON object")
    return ScanPolicy(
        fail_on=str(value.get("fail_on", "high")),
        max_file_size=int(value.get("max_file_size", 2 * 1024 * 1024)),
        max_files=int(value.get("max_files", 10_000)),
        excluded_dirs=frozenset(value.get("excluded_dirs", ScanPolicy().excluded_dirs)),
    )


def _allow_request(client: str) -> bool:
    now = time.monotonic()
    recent = [stamp for stamp in _RATE_STATE.get(client, []) if now - stamp < RATE_WINDOW]
    if len(recent) >= RATE_LIMIT:
        _RATE_STATE[client] = recent
        return False
    if client not in _RATE_STATE and len(_RATE_STATE) >= MAX_RATE_CLIENTS:
        oldest = min(_RATE_STATE, key=lambda key: _RATE_STATE[key][-1])
        del _RATE_STATE[oldest]
    recent.append(now)
    _RATE_STATE[client] = recent
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "NigerianSecretsAPI/0.4"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def _write(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        client = self.client_address[0]
        if not _allow_request(client):
            self._write(429, {"error": "rate_limited"})
            return False
        if client in {"127.0.0.1", "::1"} and API_KEY is None:
            return True
        supplied = self.headers.get("X-API-Key", "")
        if API_KEY is None or not hmac.compare_digest(supplied, API_KEY):
            self._write(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        path = urlparse(self.path).path
        if path == "/healthz":
            return self._write(200, {"status": "ok", "version": "0.4"})
        if path == "/v1/providers":
            return self._write(200, {"providers": [p.id for p in PROVIDERS]})
        if path == "/v1/detectors":
            return self._write(200, {"detectors": [r.id for r in REGISTRY.rules]})
        return self._write(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        if urlparse(self.path).path != "/v1/scan":
            return self._write(404, {"error": "not_found"})
        try:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                return self._write(411, {"error": "content_length_required"})
            length = int(length_header)
            if length < 0 or length > MAX_BODY:
                return self._write(413, {"error": "request_too_large"})
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            target = payload.get("target")
            if not isinstance(target, str) or not target:
                raise ValueError("target must be a non-empty relative path")
            policy = _policy_from_payload(payload.get("policy"))
            findings = scan(
                _safe_target(target),
                excluded_dirs=set(policy.excluded_dirs),
                max_file_size=policy.max_file_size,
                max_files=policy.max_files,
            )
            return self._write(200, {"findings": [f.to_dict() for f in findings], "count": len(findings)})
        except (TypeError, ValueError, OSError, json.JSONDecodeError, TimeoutError) as exc:
            return self._write(400, {"error": str(exc)})

    def log_message(self, *_args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"} and API_KEY is None:
        raise RuntimeError("NIGERIAN_API_KEY is required when binding the API remotely")
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    serve()
