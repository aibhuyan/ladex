"""Step 0 smoke tests: the package imports and the CLI entrypoint runs."""

from __future__ import annotations

import pytest

import ladex
from ladex.cli import main


def test_version_is_defined() -> None:
    assert ladex.__version__ == "0.1.3"


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--version"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.strip() == "ladex 0.1.3"


def test_cli_default_runs(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([])
    assert rc == 0
    assert "bill of lading" in capsys.readouterr().out
