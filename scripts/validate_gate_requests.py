#!/usr/bin/env python3
"""Validate narrowly scoped, unsigned YouthScout gate requests before signing."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUESTS = ROOT / "requests" / "pending"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
REVIEW_KEYS = {"reviewed_at", "reviewer", "verdict"}
COMMON_KEYS = {
    "authorized_action",
    "commit_sha",
    "config_sha256",
    "demo_rollout_limit",
    "fixture_manifest_sha256",
    "independent_review",
    "legacy_cases_passed",
    "legacy_cases_total",
    "schema_version",
    "v3_cases_passed",
    "v3_cases_total",
    "workbook_sha256",
    "xlsx_version",
}
SCHEMAS = {
    "AUDIT_FILTER_GATE.unsigned.json": {
        "action": "audit_filter_only",
        "target_key": "audit_target_chat_id",
        "keys": COMMON_KEYS | {"audit_max_records_per_cycle", "audit_target_chat_id"},
    },
    "MAIN_DEMO_GATE.unsigned.json": {
        "action": "main_demo_only",
        "target_key": "main_target_chat_id",
        "keys": COMMON_KEYS | {"main_target_chat_id"},
    },
}


def fail(name: str, detail: str) -> None:
    raise ValueError(f"{name}: {detail}")


def positive_int(name: str, field: str, value: object, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        fail(name, f"invalid {field}")


def validate_review(name: str, review: object) -> None:
    if not isinstance(review, dict) or set(review) != REVIEW_KEYS:
        fail(name, "invalid independent_review")
    if review["verdict"] != "PASS":
        fail(name, "independent_review verdict must be PASS")
    if not isinstance(review["reviewer"], str) or not review["reviewer"].strip():
        fail(name, "independent_review reviewer required")
    reviewed_at = review["reviewed_at"]
    if not isinstance(reviewed_at, str) or not reviewed_at.endswith("Z"):
        fail(name, "invalid reviewed_at")
    try:
        parsed = datetime.fromisoformat(reviewed_at[:-1] + "+00:00")
    except ValueError:
        fail(name, "invalid reviewed_at")
    if parsed.tzinfo != timezone.utc:
        fail(name, "invalid reviewed_at")


def load(requests_dir: Path, name: str, schema: dict[str, object]) -> dict[str, object]:
    path = requests_dir / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name}: unreadable JSON") from exc
    if not isinstance(data, dict):
        fail(name, "JSON object required")
    expected_keys = schema["keys"]
    assert isinstance(expected_keys, set)
    if set(data) != expected_keys:
        extras = sorted(set(data) - expected_keys)
        missing = sorted(expected_keys - set(data))
        fail(name, f"unexpected or missing keys (extra={extras}, missing={missing})")
    if data["schema_version"] != 2 or data["xlsx_version"] != "v3":
        fail(name, "unsupported gate schema")
    if data["authorized_action"] != schema["action"]:
        fail(name, "wrong authorized_action")
    target_key = schema["target_key"]
    assert isinstance(target_key, str)
    target = data[target_key]
    if not isinstance(target, str) or not re.fullmatch(r"-100[0-9]{6,20}", target):
        fail(name, f"invalid {target_key}")
    commit_sha = data["commit_sha"]
    if not isinstance(commit_sha, str) or not SHA_RE.fullmatch(commit_sha):
        fail(name, "invalid commit_sha")
    for key in ("config_sha256", "workbook_sha256", "fixture_manifest_sha256"):
        if not isinstance(data[key], str) or not HASH_RE.fullmatch(data[key]):
            fail(name, f"invalid {key}")
    for key, expected in (
        ("legacy_cases_total", 37),
        ("legacy_cases_passed", 37),
        ("v3_cases_total", 43),
        ("v3_cases_passed", 43),
    ):
        if data[key] != expected:
            fail(name, f"invalid {key}")
    positive_int(name, "demo_rollout_limit", data["demo_rollout_limit"], 1_000_000)
    if name == "AUDIT_FILTER_GATE.unsigned.json":
        positive_int(name, "audit_max_records_per_cycle", data["audit_max_records_per_cycle"], 1_000)
    validate_review(name, data["independent_review"])
    return data


def main(requests_dir: Path | None = None) -> None:
    requests_dir = requests_dir or REQUESTS
    actual = {path.name for path in requests_dir.iterdir() if path.is_file()}
    expected = set(SCHEMAS)
    if actual != expected:
        raise ValueError(f"unexpected request file set (extra={sorted(actual - expected)}, missing={sorted(expected - actual)})")
    requests = {name: load(requests_dir, name, schema) for name, schema in SCHEMAS.items()}
    audit = requests["AUDIT_FILTER_GATE.unsigned.json"]
    demo = requests["MAIN_DEMO_GATE.unsigned.json"]
    for key in ("commit_sha", "config_sha256", "workbook_sha256", "fixture_manifest_sha256"):
        if audit[key] != demo[key]:
            raise ValueError(f"gate requests disagree on {key}")
    print("validated gate request pair")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-dir", type=Path, default=REQUESTS)
    args = parser.parse_args()
    try:
        main(args.request_dir)
    except ValueError as exc:
        print(f"gate request validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
