#!/usr/bin/env python3
"""Backward-compatible entrypoint for the native detector engine."""

from nigerian_secrets.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
