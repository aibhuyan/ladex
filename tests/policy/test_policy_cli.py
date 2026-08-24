"""The `ladex policy` CLI surface: check, list, JSON, and project-fact flags."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ladex.cli import main

REPO = str(Path(__file__).parent.parent / "fixtures" / "sample_repo")


def test_policy_list(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["policy", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "eu-ai-act-art-50" in out
    assert "Art. 50(1)" in out


def test_policy_check_json_potential(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["policy", "check", REPO, "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["potential"] >= 1
    ob = next(
        o for o in payload["obligations"] if o["rule_id"] == "art-50-1-ai-interaction-disclosure"
    )
    assert ob["status"] == "potentially_applies"
    assert "user_facing" in ob["unresolved"]
    assert ob["is_gap"] is True


def test_policy_check_json_applies_when_declared(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["policy", "check", REPO, "--user-facing", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["applies"] >= 1
    assert payload["summary"]["gaps"] >= 1


def test_policy_check_human_report(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["policy", "check", REPO, "--user-facing"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Art. 50(1)" in out
    assert "attestation" in out


def test_policy_check_missing_path() -> None:
    assert main(["policy", "check", "no/such/path"]) == 2
