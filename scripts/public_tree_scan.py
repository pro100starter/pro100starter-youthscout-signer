#!/usr/bin/env python3
"""Reject accidental sensitive material in this public repository."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bbot\d{6,}:[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"-100\d{6,20}"),
)


def main() -> None:
    violations: list[str] = []
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or ".git" in path.parts
            or "__pycache__" in path.parts
            or ".pytest_cache" in path.parts
            or path.resolve() == SELF
            or path.name.endswith(".sealed.json")
        ):
            continue
        data = path.read_bytes()
        if any(pattern.search(data) for pattern in PATTERNS):
            violations.append(str(path.relative_to(ROOT)))
    if violations:
        raise SystemExit("sensitive material found: " + ", ".join(sorted(violations)))
    print("public tree scan passed")


if __name__ == "__main__":
    main()
