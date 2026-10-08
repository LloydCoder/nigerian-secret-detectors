# API security model

The HTTP API is a local control boundary, not a public internet service.

## Defaults

- Bind: `127.0.0.1:8787`
- Authentication: loopback access is permitted without an API key; non-loopback access requires `NIGERIAN_API_KEY`.
- Remote transport: non-loopback access also requires `NIGERIAN_TLS_CERTFILE` and `NIGERIAN_TLS_KEYFILE`.
- Request body: 64 KiB maximum.
- Connection timeout: 10 seconds.
- Rate limit: 60 requests per client per 60 seconds with bounded client state.
- Scan root: `NIGERIAN_SCAN_ROOT`.

Targets must be relative paths without parent traversal and must resolve inside the configured scan root. The scanner independently applies file-size, file-count, symlink, binary, and excluded-directory controls.

Responses use `Cache-Control: no-store` and security headers. Findings contain only redacted matches and never raw credential material.

Remote plaintext HTTP is deliberately rejected by `serve()`. Deployments behind a trusted reverse proxy should keep the scanner on a private network boundary.
