# Git history scanning

`nigerian-git-scan` provides bounded historical detection without storing raw credentials.

```bash
export NIGERIAN_FINGERPRINT_KEY='use-a secret-management system'
nigerian-git-scan /path/to/repository --max-commits 200 --max-files-per-commit 200
```

The scanner examines changed blobs in reachable history. Added and modified blobs are read from the commit; deleted-file content is read from the parent revision when available.

Findings contain commit/parent, change type, path, detector/provider, severity, confidence, line/column, redacted match, and HMAC-SHA-256 fingerprint. The HMAC key stays outside the repository and raw secret values are not serialized.

History limits are deliberate resource-exhaustion controls. Increase them only when the repository size and execution budget justify it.
