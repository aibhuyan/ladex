"""Ladex command-line interface.

Step 0 stub: a trivial entrypoint so `ladex` is runnable from the first commit.
The real `ladex scan` command lands in Step 3.
"""

from __future__ import annotations

import sys

from ladex import __version__


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `ladex` console script."""
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in {"--version", "-V", "version"}:
        print(f"ladex {__version__}")
        return 0
    print(f"ladex {__version__} — a bill of lading for AI")
    print("No commands yet. `ladex scan` arrives in Step 3.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
