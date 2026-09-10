# Benchmark methodology

The benchmark is intentionally synthetic and deterministic. It is a regression, coverage, and performance instrument, not a real-world prevalence or recall study.

## Corpus

`benchmarks/corpus.jsonl` is a compact seed catalog. `nigerian_secrets.benchmark` expands it deterministically into 660 cases:

- 360 positives: 10 cases for each of the 30 registered providers plus 60 generic cryptographic/JWT/token cases.
- 300 negatives: UUIDs, hashes, timestamps, public keys, checksums, high-entropy values, documentation-like values, malformed JWT-like strings, base64-like blobs, and database IDs.
- Multiple language/context labels are represented in the provider cases.
- Credential-shaped values are generated only in a temporary benchmark directory and are never stored in Git.

## Metrics

The benchmark reports:

- true positives
- false positives
- true negatives
- false negatives
- precision
- recall
- F1
- elapsed time
- files/second
- MB/second

The corpus version is the repository revision containing the seed catalog and benchmark implementation. Published numbers must include that revision and the benchmark tool version.

## Interpretation

A high score on this corpus means the current detector behavior is stable against the controlled fixtures. It does **not** establish production recall across arbitrary repositories, provider account populations, encodings, obfuscation techniques, or secret formats.

Real-world validation requires legally obtained and appropriately sanitized data. Raw customer or production credentials must never be added to the corpus.

## Adversarial coverage

Adversarial transformations are tracked separately from the core regression gate when they represent behavior the scanner is not designed to normalize, such as literal splitting, Unicode confusables, or encoded wrappers. A failure there is recorded as a capability gap rather than silently relabeled as a negative case.
