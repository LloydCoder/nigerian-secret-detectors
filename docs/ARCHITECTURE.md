# Architecture

`scanner.py` performs bounded filesystem traversal, safe UTF-8 decoding, binary skipping, detector evaluation, context scoring, redaction, optional HMAC fingerprinting, and stable result ordering.

`rules.py` declares detector grammars. Every rule has an explicit detection type: `provider-specific`, `provider-context`, `generic`, `cryptographic`, `token`, or `heuristic`.

`registry.py` validates detector uniqueness, provider coverage, severities, and detection types before exposing rules.

`git.py` scans a bounded set of reachable commits and changed blobs. Deleted-file content is inspected from the parent revision when available. Only redacted metadata and HMAC fingerprints leave the history scanner.

`verification.py` is an explicit opt-in adapter boundary. Unregistered providers are `unsupported`, and no provider adapter is enabled by default.

`api.py` is local-first. Remote binding requires API-key authentication and TLS; request size and scanner resource limits remain enforced.

Gitleaks, TruffleHog, Semgrep, Nuclei, and Slither remain interoperable integrations rather than replacements for the native Nigerian/African financial-infrastructure detector.
