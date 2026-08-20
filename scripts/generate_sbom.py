#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]

entries = []
for path in sorted(FILES):
    data = path.read_bytes()
    entries.append({"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})

sbom = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "lloydcoder-nigerian-secret-detectors-source",
    "documentNamespace": "https://github.com/LloydCoder/nigerian-secret-detectors/sbom",
    "creationInfo": {"creators": ["Tool: nigerian-secret-detectors-sbom"]},
    "files": [
        {"SPDXID": f"SPDXRef-File-{i}", "fileName": e["path"], "checksums": [{"algorithm": "SHA256", "checksumValue": e["sha256"]}], "fileSize": e["size"]}
        for i, e in enumerate(entries, 1)
    ],
}
Path("sbom.spdx.json").write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
