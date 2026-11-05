#!/usr/bin/env python3
"""Build the FoundryGuard desktop console as one standalone executable with PyInstaller.

    python build_installer.py              build dist/FoundryGuard (dist/FoundryGuard.exe on Windows)
    python build_installer.py --dry-run    print the PyInstaller command and the asset map, build nothing
    python build_installer.py --console    keep a console window (for debugging a build that will not start)

The binary is ``--onefile --noconsole``: double-clicking it opens the dark customtkinter window and nothing
else. ``FoundryGuard --cli ARGS`` runs the command line from the same file (the window uses that for the
dynamic pass), so ``FoundryGuard --cli score .`` works where Python is not installed.

PyInstaller does not cross-compile. Run this script on Windows for a Windows ``.exe``, on macOS for a macOS
binary, on Linux for a Linux one. It needs Python with Tk, plus ``pip install pyinstaller customtkinter``
(and ``tomli`` on Python 3.9 / 3.10).

After the build, the binary is smoke-tested headless: ``--cli score`` on the safe signature fixture must
write a report with a score of 100. ``--no-smoke`` skips that.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "cli"
ENTRY = SRC / "launcher.py"
NAME = "FoundryGuard"
SMOKE_TARGET = ROOT / "tests" / "foundryguard" / "fixtures" / "signatures" / "safe"

# Files the frozen app reads from disk at run time, as (source relative to the repo, folder inside the bundle).
# The HTML report, the findings log and the foundryguard.toml template are generated from code
# (reporter.py, scoring.py, foundryguard.py) and travel inside the compiled modules.
ASSETS: list[tuple[str, str]] = [
    ("intel/foundryguard-rules.json", "intel"),  # default rule pack, used offline before the first sync
    ("README.md", "."),
    ("pyproject.toml", "."),
]

# Third-party packages whose data files (themes, fonts, icons) PyInstaller would otherwise leave out.
COLLECT_DATA = ["customtkinter"]


def version() -> str:
    for line in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "0"


def modules() -> list[str]:
    """Every FoundryGuard module, so lazily imported ones (gui -> scoring -> injector -> blueprints) are bundled."""
    names = sorted(p.stem for p in SRC.glob("*.py") if p.stem not in ("__init__", "__main__", "launcher"))
    names += sorted(f"blueprints.{p.stem}" for p in (SRC / "blueprints").glob("*.py") if p.stem != "__init__")
    names.append("blueprints")
    if sys.version_info < (3, 11):
        names.append("tomli")
    return names


def exe_path(dist: Path) -> Path:
    return dist / (NAME + (".exe" if os.name == "nt" else ""))


def pyinstaller_args(dist: Path, work: Path, console: bool = False) -> list[str]:
    args = [
        str(ENTRY),
        "--name", NAME,
        "--onefile",
        "--console" if console else "--noconsole",
        "--noconfirm",
        "--clean",
        "--distpath", str(dist),
        "--workpath", str(work),
        "--specpath", str(work),
        "--paths", str(SRC),
    ]
    for src, dest in ASSETS:
        args += ["--add-data", f"{ROOT / src}{os.pathsep}{dest}"]
    for pkg in COLLECT_DATA:
        args += ["--collect-data", pkg]
    for mod in modules():
        args += ["--hidden-import", mod]
    return args


def check_prereqs() -> list[str]:
    missing = []
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        missing.append("pyinstaller (pip install pyinstaller)")
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        missing.append("customtkinter (pip install customtkinter)")
    try:
        import tkinter  # noqa: F401
    except ImportError:
        missing.append("Tk for this Python (Debian/Ubuntu: apt install python3-tk; python.org installers include it)")
    if sys.version_info < (3, 11):
        try:
            import tomli  # noqa: F401
        except ImportError:
            missing.append("tomli (pip install tomli)")
    for src, _ in ASSETS:
        if not (ROOT / src).is_file():
            missing.append(f"asset {src}")
    return missing


def smoke(exe: Path) -> str | None:
    """Run the built binary headless. Returns an error, or None when it scored the safe fixture at 100."""
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, FOUNDRYGUARD_INTEL_CACHE=str(Path(tmp) / "intel.json"))
        cmd = [str(exe), "--cli", "score", str(SMOKE_TARGET), "--out", tmp, "--presets", "none"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"{' '.join(cmd)}: {exc}"
        score_json = Path(tmp) / "foundryguard-score.json"
        report = Path(tmp) / "foundryguard-report.html"
        if proc.returncode != 0 or not score_json.is_file() or not report.is_file():
            return f"{' '.join(cmd)} exited {proc.returncode}\n{proc.stdout[-2000:]}{proc.stderr[-2000:]}"
        score = json.loads(score_json.read_text(encoding="utf-8")).get("score")
        if score != 100:
            return f"safe fixture scored {score}, expected 100"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dist", default=str(ROOT / "dist"), help="output folder (default: dist/)")
    ap.add_argument("--work", default=str(ROOT / "build" / "pyinstaller"), help="PyInstaller work folder")
    ap.add_argument("--console", action="store_true", help="keep a console window (debug builds)")
    ap.add_argument("--dry-run", action="store_true", help="print the command and asset map, build nothing")
    ap.add_argument("--no-smoke", action="store_true", help="skip the headless test of the built binary")
    args = ap.parse_args(argv)

    dist, work = Path(args.dist).resolve(), Path(args.work).resolve()
    pi_args = pyinstaller_args(dist, work, args.console)
    print(f"FoundryGuard {version()} -> {exe_path(dist)}")
    for src, dest in ASSETS:
        print(f"  asset  {src}  ->  {dest}/")
    for pkg in COLLECT_DATA:
        print(f"  data   {pkg} (package data)")
    if args.dry_run:
        print("pyinstaller " + " ".join(pi_args))
        return 0

    missing = check_prereqs()
    if missing:
        print("missing:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 2
    if work.exists():
        shutil.rmtree(work)

    import PyInstaller.__main__
    PyInstaller.__main__.run(pi_args)

    exe = exe_path(dist)
    if not exe.is_file():
        print(f"build failed: {exe} was not written", file=sys.stderr)
        return 1
    print(f"built {exe} ({exe.stat().st_size / 1e6:.1f} MB)")
    if args.no_smoke:
        return 0
    err = smoke(exe)
    if err:
        print(f"smoke test failed: {err}", file=sys.stderr)
        return 1
    print("smoke test: safe fixture scored 100")
    return 0


if __name__ == "__main__":
    sys.exit(main())
