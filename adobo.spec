# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single self-contained ADOBO.exe."""

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

PROJECT = Path(SPECPATH).resolve()

hiddenimports = (
    collect_submodules("adobo")
    + [
        "pydantic",
        "pydantic.deprecated.decorator",
        "scapy",
        "scapy.all",
        "scapy.layers",
        "scapy.layers.inet",
        "scapy.layers.dns",
        "scapy.layers.ntp",
        "scapy.layers.l2",
        "scapy.contrib",
        "scapy.contrib.ntp",
    ]
)

excludes = [
    "tkinter",
    "matplotlib",
    "pandas",
    "numpy",
    "PIL",
    "pytest",
    "sphinx",
    # yaml and psutil are declared runtime dependencies (pyproject.toml) and are
    # imported at module level by adobo.config / adobo.defenses and
    # adobo.monitor. Excluding them produced a bundle that could not read its
    # own config or sample the target.
    "fastapi",
    "uvicorn",
    "colorama",
]

a = Analysis(
    [str(PROJECT / "adobo" / "__main__.py")],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ADOBO",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Deliberately not requesting elevation. With uac_admin=True the manifest
    # triggers a UAC prompt, and in a non-interactive context (a service account,
    # a CI runner, a piped shell) the elevation is denied and the bundle exits
    # before it can print anything - a silent failure with no error to act on.
    #
    # Raw-socket profiles genuinely do need an elevated terminal, but that is
    # checked at runtime by adobo.transports.raw_capability(), which refuses
    # with an actionable message instead of dying without one. Failing there is
    # strictly better than failing before the process starts.
    #
    # However, the manifest elevation is the *only* way an executable launched
    # by double-click or from a non-elevated shell can become Administrator.
    # Without it, raw-capable profiles silently send nothing and the tool
    # reports zero with no explanation. The egress probe in
    # adobo.transports.scapy_transport now catches that and refuses with a
    # clear message, but that still means "runs and sends nothing" instead of
    # "runs and actually sends". Enabling the manifest elevation restores the
    # user's expectation: double-click → UAC prompt → raw profiles work.
    uac_admin=True,
)