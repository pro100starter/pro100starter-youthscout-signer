from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_gate_requests.py"

spec = importlib.util.spec_from_file_location("gate_validator", SCRIPT)
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


@pytest.fixture
def request_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    destination = tmp_path / "pending"
    destination.mkdir()
    common = {
        "commit_sha": "2d01e9242992210a881e6065cc90fd5ae2682475",
        "config_sha256": "6fe881c06599010d1f46639b983181dd91219e6c56beec05ab20cd25bd50f197",
        "workbook_sha256": "5bcd016e426cf27043882dc5089b54dcab0c692fe0c9ff868e7b43c05cc92120",
        "fixture_manifest_sha256": "e238fd8da113ba3c8f90e107712fdeb60cef8e7b80c27dc90c732dbfe3ea328d",
        "demo_rollout_limit": 100,
        "independent_review": {"reviewed_at": "2026-08-15T10:55:37.599138Z", "reviewer": "test reviewer", "verdict": "PASS"},
        "legacy_cases_total": 37,
        "legacy_cases_passed": 37,
        "v3_cases_total": 43,
        "v3_cases_passed": 43,
        "schema_version": 2,
        "xlsx_version": "v3",
    }
    audit = common | {"authorized_action": "audit_filter_only", "audit_target_chat_id": "-100" + "1" * 10, "audit_max_records_per_cycle": 68}
    demo = common | {"authorized_action": "main_demo_only", "main_target_chat_id": "-100" + "2" * 10}
    save(destination, "AUDIT_FILTER_GATE.unsigned.json", audit)
    save(destination, "MAIN_DEMO_GATE.unsigned.json", demo)
    monkeypatch.setattr(validator, "REQUESTS", destination)
    return destination


def payload(directory: Path, name: str) -> dict:
    return json.loads((directory / name).read_text())


def save(directory: Path, name: str, data: dict) -> None:
    (directory / name).write_text(json.dumps(data, sort_keys=True))


def test_accepts_valid_request_pair(request_dir: Path) -> None:
    validator.main()


def test_rejects_unknown_payload_field(request_dir: Path) -> None:
    name = "AUDIT_FILTER_GATE.unsigned.json"
    data = payload(request_dir, name)
    data["unconstrained_attestation_claim"] = "must not be signed"
    save(request_dir, name, data)
    with pytest.raises(ValueError, match="unexpected"):
        validator.main()


def test_rejects_negative_demo_rollout_limit(request_dir: Path) -> None:
    name = "MAIN_DEMO_GATE.unsigned.json"
    data = payload(request_dir, name)
    data["demo_rollout_limit"] = -1
    save(request_dir, name, data)
    with pytest.raises(ValueError, match="demo_rollout_limit"):
        validator.main()


def test_rejects_extra_pending_request_file(request_dir: Path) -> None:
    (request_dir / "UNREVIEWED.unsigned.json").write_text("{}")
    with pytest.raises(ValueError, match="unexpected request file"):
        validator.main()


def test_rejects_non_utc_review_timestamp(request_dir: Path) -> None:
    name = "AUDIT_FILTER_GATE.unsigned.json"
    data = payload(request_dir, name)
    data["independent_review"]["reviewed_at"] = "2026-08-15 10:55:37"
    save(request_dir, name, data)
    with pytest.raises(ValueError, match="reviewed_at"):
        validator.main()


def test_rejects_incomplete_test_case_results(request_dir: Path) -> None:
    name = "MAIN_DEMO_GATE.unsigned.json"
    data = payload(request_dir, name)
    data["v3_cases_passed"] = data["v3_cases_total"] - 1
    save(request_dir, name, data)
    with pytest.raises(ValueError, match="v3_cases_passed"):
        validator.main()
