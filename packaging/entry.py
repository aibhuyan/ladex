"""Frozen-binary entry point for PyInstaller.

PyInstaller needs a concrete script to analyse; this just calls the real CLI so the single
binary behaves exactly like the ``ladex`` console script.
"""

import sys

from ladex.cli import main

if __name__ == "__main__":
    sys.exit(main())
