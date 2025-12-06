#!/usr/bin/env python3
import subprocess
import os
import sys
from pathlib import Path

def run_nuclei(target):
    subprocess.run(["nuclei", "-t", "detectors/nuclei/", "-u", target])

def run_trufflehog(target):
    subprocess.run(["trufflehog", "filesystem", target, "--only-verified"])

def run_semgrep(target):
    subprocess.run(["semgrep", "scan", "--config", "detectors/semgrep/", target])

def run_gitleaks(target):
    subprocess.run(["gitleaks", "detect", "--source", target, "--config", "detectors/gitleaks/config/gitleaks.toml"])

def run_slither(target):
    subprocess.run(["slither", target, "--detect", "hardcoded-nigerian-secrets"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python runner.py <target_dir_or_file>")
        sys.exit(1)
    target = sys.argv[1]
    print("🛡️ Scanning for Nigerian secrets...")
    run_nuclei(target)
    run_trufflehog(target)
    run_semgrep(target)
    run_gitleaks(target)
    run_slither(target)  # For .sol files
    print("✅ Scan complete!")
