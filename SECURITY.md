# Security Policy

## Supported versions

Security fixes are provided for the latest release and the default branch.

## Reporting a vulnerability

Do not open a public issue containing credential material or exploit details. Report suspected vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting channel when enabled.

Never submit real credentials to the repository, its fixtures, CI logs, or issue tracker. Synthetic values only.

## Secret-handling principles

- Detection output redacts matched material.
- Verification is opt-in and disabled by default.
- The local API binds to `127.0.0.1` by default and is not an internet-facing service.
- CI scans intentionally exclude synthetic benchmark fixtures from exposure gates.
- Credentials must never be used in tests or examples.

## Release security

Release artifacts are built in GitHub Actions. The release workflow generates an SPDX-compatible SBOM and publishes checksums for artifacts.
