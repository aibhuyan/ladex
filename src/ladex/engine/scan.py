"""Directory scanning: run detection across a tree and aggregate the results.

This lives in the engine, not the CLI, because every surface (CLI, LSP, PR check) must
scan identically — forking this logic would let the editor and the PR gate disagree.
"""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ladex.engine.detect import Detection, PythonDetector

# Directories never worth scanning. Hidden directories (".*") are pruned as well.
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        ".eggs",
        "site-packages",
    }
)


#: Extensions that may contain IaC we can parse (Terraform + Kubernetes manifests).
IAC_SUFFIXES: frozenset[str] = frozenset({".tf", ".yaml", ".yml"})


def _iter_files(
    root: Path, suffixes: frozenset[str], ignore_dirs: frozenset[str]
) -> Iterator[Path]:
    if root.is_file():
        if root.suffix in suffixes:
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignore_dirs and not d.startswith("."))
        for name in sorted(filenames):
            if Path(name).suffix in suffixes:
                yield Path(dirpath) / name


def iter_python_files(
    root: Path, ignore_dirs: frozenset[str] = DEFAULT_IGNORE_DIRS
) -> Iterator[Path]:
    """Yield every ``.py`` file under ``root``, sorted, skipping ignored/hidden dirs."""
    yield from _iter_files(root, frozenset({".py"}), ignore_dirs)


def iter_iac_files(root: Path, ignore_dirs: frozenset[str] = DEFAULT_IGNORE_DIRS) -> Iterator[Path]:
    """Yield every Terraform/Kubernetes candidate file under ``root``."""
    yield from _iter_files(root, IAC_SUFFIXES, ignore_dirs)


def iter_notebook_files(
    root: Path, ignore_dirs: frozenset[str] = DEFAULT_IGNORE_DIRS
) -> Iterator[Path]:
    """Yield every Jupyter notebook under ``root``."""
    yield from _iter_files(root, frozenset({".ipynb"}), ignore_dirs)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The outcome of scanning a path: all detections plus summary counts."""

    root: Path
    files_scanned: int
    detections: tuple[Detection, ...] = field(default_factory=tuple)

    @property
    def files_with_findings(self) -> int:
        return len({d.path for d in self.detections})

    def counts_by_component_type(self) -> dict[str, int]:
        counter = Counter(d.component_type.value for d in self.detections)
        return dict(sorted(counter.items()))

    def counts_by_provider(self) -> dict[str, int]:
        counter = Counter(d.provider or "unknown" for d in self.detections)
        return dict(sorted(counter.items()))

    def detections_by_file(self) -> dict[str, list[Detection]]:
        grouped: dict[str, list[Detection]] = {}
        for det in self.detections:
            grouped.setdefault(det.path, []).append(det)
        return grouped


def scan_path(
    root: Path,
    detector: PythonDetector | None = None,
    *,
    scan_iac: bool = True,
    scan_notebooks: bool = True,
) -> ScanResult:
    """Scan a file or directory and return an aggregated, deterministically-ordered result.

    Covers Python (tree-sitter), Jupyter notebooks, and Terraform/Kubernetes IaC — all
    producing the same ``Detection`` records ("one engine").
    """
    det = detector if detector is not None else PythonDetector()
    detections: list[Detection] = []
    files_scanned = 0
    for py_file in iter_python_files(root):
        files_scanned += 1
        detections.extend(det.detect_file(py_file))
    if scan_notebooks:
        from ladex.engine.detect.notebook import detect_notebook_file

        for nb_file in iter_notebook_files(root):
            files_scanned += 1
            detections.extend(detect_notebook_file(nb_file, det))
    if scan_iac:
        from ladex.engine.detect.iac import detect_iac_file

        for iac_file in iter_iac_files(root):
            files_scanned += 1
            detections.extend(detect_iac_file(iac_file))
    detections.sort(key=Detection.sort_key)
    return ScanResult(root=root, files_scanned=files_scanned, detections=tuple(detections))
