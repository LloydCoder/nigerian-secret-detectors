# Architecture

## Detection path

`scanner.py` performs bounded filesystem traversal, decodes UTF-8 safely, skips binary blobs, applies the immutable `DetectorRegistry`, scores provider context, redacts findings, and returns stable ordering.

`rules.py` contains native detector grammars. Each rule explicitly declares a detection type:

- `provider-specific` — provider credential grammar is explicit in the rule.
- `provider-context` — credential-shaped material is associated with provider aliases/context.
- `generic` — provider-independent heuristic.
- `cryptographic` — cryptographic material such as private keys.
- `token` — token grammar such as JWT-shaped values.
- `heuristic` — general heuristic behavior.

This distinction is part of the product's evidence discipline.

## Correlation

The scanner can optionally produce an HMAC-SHA-256 fingerprint for a matched value. The raw match remains transient and is not stored in the `Finding`. A caller must provide the HMAC key explicitly.

## Git intelligence

`git.py` walks a bounded set of reachable commits and changed blobs. Deleted files are inspected from the parent revision when possible. Reports contain commit/path/line metadata, redaction, and HMAC fingerprints. Raw secret material is never serialized by the history API.

## Verification boundary

`verification.py` contains an explicit adapter registry. Verification is opt-in and unregistered providers return `unsupported`. Provider adapters are responsible for their own provider-approved transport, timeout, retry, rate-limit, and secret-handling controls. No adapter is enabled by default.

## API boundary

The HTTP API is local-only by default. Remote binding requires API-key authentication and application-level TLS. Path targets are constrained to `NIGERIAN_SCAN_ROOT`, request bodies are bounded, and the scanner remains subject to file-size and file-count limits.

## External integrations

Gitleaks, TruffleHog, Semgrep, Nuclei, and Slither remain interoperable integration surfaces. They are not coupled into the native detection path.
