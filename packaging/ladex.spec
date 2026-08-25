# PyInstaller spec — single-file `ladex` binary.
#
# The engine loads its taxonomy/policy/IaC packs as package data via importlib.resources and
# uses the native tree-sitter Python grammar, so those must be collected explicitly — a bare
# PyInstaller run would omit the .yaml packs and the grammar and the binary would fail at
# runtime. Build with:  pyinstaller packaging/ladex.spec  (from the repo root).

from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

datas = []
datas += collect_data_files("ladex")  # packs/**/*.yaml, py.typed
datas += collect_data_files("tree_sitter_python")  # the compiled Python grammar

binaries = []
binaries += collect_dynamic_libs("tree_sitter")
binaries += collect_dynamic_libs("tree_sitter_python")

hiddenimports = []
hiddenimports += collect_submodules("ladex")

# Packages that load their own data files / grammars at runtime and need full collection,
# or PyInstaller silently omits pieces (hcl2's lark grammar, cyclonedx's schemas).
for _pkg in ("hcl2", "lark", "lark_cython", "cyclonedx", "license_expression"):
    try:
        _d, _b, _h = collect_all(_pkg)
    except Exception:  # noqa: BLE001 - optional deps (e.g. lark_cython) may be absent
        continue
    datas += _d
    binaries += _b
    hiddenimports += _h

a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pyinstaller"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ladex",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
