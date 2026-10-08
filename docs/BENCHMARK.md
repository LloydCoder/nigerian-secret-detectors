# Benchmark methodology

The benchmark is intentionally synthetic and deterministic. It is a regression, coverage, and performance instrument, not a real-world prevalence or recall study.

## Corpus

`benchmarks/corpus.jsonl` is a compact seed catalog. `nigerian_secrets.benchmark` expands it deterministically into 660 cases:

- 360 positives: 10 cases for each of the 30 registered providers plus 60 generic cryptographic/JWT/token cases.
- 300 negatives: UUIDs, hashes, timestamps, public keys, checksums, high-entropy values, documentation-like values, malformed JWT-like strings, base64-like blobs, and database IDs.
- Multiple language/context labels are represented in the provider cases.
- Credential-shaped values are generated only in a temporary benchmark directory and are never stored in Git.

## Metrics

The benchmark reports true positives, false positives, true negatives, false negatives, precision, recall, F1, elapsed time, files/second, and MB/second.

A published result should include the repository revision and benchmark implementation version. The corpus is synthetic and must not be presented as a production recall estimate.

## Adversarial coverage

Adversarial transformations are tested separately when they represent behavior the scanner is not designed to normalize, such as literal splitting, Unicode escapes, URL encoding, and token truncation. A limitation is recorded as a capability gap rather than silently relabeled as a negative case.
