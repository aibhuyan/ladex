"""The `ladex scan` CLI surface: JSON shape and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ladex.cli import main

REPO = str(Path(__file__).parent.parent / "fixtures" / "sample_repo")


def test_scan_json_shape(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["scan", REPO, "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_scanned"] == 5
    assert payload["files_with_findings"] >= 3
    assert payload["summary"]["by_component_type"]["inference_api"] >= 2
    first = payload["detections"][0]
    assert {"rule_id", "component_type", "path", "line", "column"} <= first.keys()


def test_scan_human_report_runs(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["scan", REPO])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Summary:" in out
    assert "openai.client" in out


def test_scan_missing_path_errors() -> None:
    assert main(["scan", "does/not/exist"]) == 2


def test_scan_defaults_to_cwd(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["scan", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "files_scanned" in payload
