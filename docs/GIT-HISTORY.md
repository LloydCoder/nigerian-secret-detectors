# Git history scanning

The `nigerian-git-scan` command provides bounded historical secret detection without storing raw credentials.

```bash
export NIGERIAN_FINGERPRINT_KEY='use-a-secret-management-system'
nigerian-git-scan /path/to/repository --max-commits 200 --max-files-per-commit 200
```

The scanner examines changed blobs in reachable history. Added and modified blobs are read from the commit; deleted-file content is read from the parent revision when available.

Each finding contains:

- commit
- parent commit when available
- change type
- path
- detector
- provider
- severity
- confidence
- line/column
- redacted match
- HMAC-SHA-256 fingerprint

The fingerprint enables correlation of the same secret across locations and commits without storing the raw value. The HMAC key must remain outside the repository and should be rotated according to the trust boundary of the deployment.

History scanning is bounded by default because unbounded Git histories can create predictable resource-exhaustion risks. Increase limits deliberately for larger repositories.
