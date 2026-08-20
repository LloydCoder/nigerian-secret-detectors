from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .providers import PROVIDERS
from .registry import REGISTRY
from .scanner import scan

SCAN_ROOT = Path(os.environ.get("NIGERIAN_SCAN_ROOT", ".")).expanduser().resolve()


def _safe_target(value: str) -> Path:
    target = (SCAN_ROOT / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    if not target.is_relative_to(SCAN_ROOT):
        raise ValueError("target must remain inside NIGERIAN_SCAN_ROOT")
    return target


class Handler(BaseHTTPRequestHandler):
    server_version = "NigerianSecretsAPI/0.4"

    def _write(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            return self._write(200, {"status": "ok"})
        if path == "/v1/providers":
            return self._write(200, {"providers": [p.id for p in PROVIDERS]})
        if path == "/v1/detectors":
            return self._write(200, {"detectors": [r.id for r in REGISTRY.rules]})
        return self._write(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/v1/scan":
            return self._write(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 64 * 1024:
                return self._write(413, {"error": "request_too_large"})
            payload = json.loads(self.rfile.read(length) or b"{}")
            target = payload["target"]
            if not isinstance(target, str) or not target:
                raise ValueError("target must be a non-empty path")
            findings = scan(_safe_target(target))
            return self._write(200, {"findings": [f.__dict__ for f in findings], "count": len(findings)})
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
            return self._write(400, {"error": str(exc)})

    def log_message(self, *_args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()
