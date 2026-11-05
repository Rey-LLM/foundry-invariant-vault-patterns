"""0.19: standalone executable (build_installer.py, src/cli/launcher.py).

The PyInstaller build itself takes a minute and needs pyinstaller and Tk, so it only runs with
FOUNDRYGUARD_BUILD_EXE=1. Everything around it (argument list, asset map, the --cli dispatch, the frozen
forge command, the bundled intel pack) is tested here without building.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "cli"
sys.path.insert(0, str(SRC))

import foundryguard  # noqa: E402
import gui  # noqa: E402
import intel_sync  # noqa: E402
import launcher  # noqa: E402
import scoring  # noqa: E402


def _load_build_installer():
    spec = importlib.util.spec_from_file_location("build_installer", REPO / "build_installer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bi = _load_build_installer()


class Frozen:
    """Pretend to be a PyInstaller onefile process unpacked into ``meipass``."""

    def __init__(self, meipass: str | None = None, executable: str = "/opt/FoundryGuard"):
        self.meipass, self.executable = meipass, executable

    def __enter__(self):
        self._patches = [mock.patch.object(sys, "frozen", True, create=True),
                         mock.patch.object(sys, "executable", self.executable)]
        if self.meipass:
            self._patches.append(mock.patch.object(sys, "_MEIPASS", self.meipass, create=True))
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()


class TestInstallerArgs(unittest.TestCase):
    def setUp(self):
        self.args = bi.pyinstaller_args(Path("/tmp/d"), Path("/tmp/w"))

    def _values(self, flag: str) -> list[str]:
        return [self.args[i + 1] for i, a in enumerate(self.args) if a == flag]

    def test_onefile_noconsole(self):
        self.assertEqual(self.args[0], str(SRC / "launcher.py"))
        self.assertIn("--onefile", self.args)
        self.assertIn("--noconsole", self.args)
        self.assertNotIn("--console", self.args)
        self.assertEqual(self._values("--name"), ["FoundryGuard"])

    def test_console_debug_build(self):
        args = bi.pyinstaller_args(Path("/tmp/d"), Path("/tmp/w"), console=True)
        self.assertIn("--console", args)
        self.assertNotIn("--noconsole", args)

    def test_assets_mapped(self):
        data = self._values("--add-data")
        self.assertEqual(len(data), len(bi.ASSETS))
        for (src, dest), arg in zip(bi.ASSETS, data):
            self.assertTrue((REPO / src).is_file(), src)
            self.assertEqual(arg, f"{REPO / src}{os.pathsep}{dest}")
        self.assertIn(("intel/foundryguard-rules.json", "intel"), bi.ASSETS)
        self.assertIn("customtkinter", self._values("--collect-data"))

    def test_every_module_is_bundled(self):
        hidden = set(self._values("--hidden-import"))
        for p in SRC.glob("*.py"):
            if p.stem not in ("__init__", "__main__", "launcher"):
                self.assertIn(p.stem, hidden)
        for p in (SRC / "blueprints").glob("*.py"):
            if p.stem != "__init__":
                self.assertIn(f"blueprints.{p.stem}", hidden)
        self.assertEqual(self._values("--paths"), [str(SRC)])

    def test_exe_name(self):
        name = bi.exe_path(Path("dist")).name
        self.assertEqual(name, "FoundryGuard.exe" if os.name == "nt" else "FoundryGuard")

    def test_version_from_pyproject(self):
        self.assertRegex(bi.version(), r"^\d+\.\d+\.\d+$")
        self.assertIn(f'version = "{bi.version()}"', (REPO / "pyproject.toml").read_text())

    def test_dry_run_builds_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = bi.main(["--dry-run", "--dist", tmp, "--work", tmp + "/w"])
            self.assertEqual(rc, 0)
            self.assertIn("pyinstaller ", out.getvalue())
            self.assertIn("--onefile --noconsole", out.getvalue())
            self.assertEqual(os.listdir(tmp), [])


class TestLauncher(unittest.TestCase):
    def test_no_args_opens_window(self):
        with mock.patch.object(gui, "main", return_value=0) as g, mock.patch.object(foundryguard, "main") as c:
            self.assertEqual(launcher.main([]), 0)
        g.assert_called_once_with([])
        c.assert_not_called()

    def test_target_goes_to_window(self):
        with mock.patch.object(gui, "main", return_value=0) as g:
            launcher.main(["/some/project"])
        g.assert_called_once_with(["/some/project"])

    def test_cli_flag_runs_command_line(self):
        with mock.patch.object(foundryguard, "main", return_value=3) as c, mock.patch.object(gui, "main") as g:
            self.assertEqual(launcher.main(["--cli", "score", ".", "--json"]), 3)
        c.assert_called_once_with(["score", ".", "--json"])
        g.assert_not_called()

    def test_missing_stdio_is_replaced(self):
        with mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", None):
            launcher._quiet_stdio()
            self.assertIsNotNone(sys.stdout)
            self.assertIsNotNone(sys.stderr)
            print("goes nowhere")
            sys.stdout.close()
            sys.stderr.close()

    def test_child_consoles_hidden_on_windows_only(self):
        orig = subprocess.Popen
        try:
            with mock.patch.object(launcher.os, "name", "posix"):
                launcher._hide_child_consoles()
            self.assertIs(subprocess.Popen, orig)
            with mock.patch.object(launcher.os, "name", "nt"):
                launcher._hide_child_consoles()
                patched = subprocess.Popen
                self.assertIsNot(patched, orig)
                launcher._hide_child_consoles()  # idempotent
                self.assertIs(subprocess.Popen, patched)
            seen = {}

            def fake_init(self, *args, **kwargs):
                seen.update(kwargs)

            with mock.patch.object(orig, "__init__", fake_init):
                patched(["forge", "build"], creationflags=0x200)
            self.assertEqual(seen["creationflags"], 0x200 | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        finally:
            subprocess.Popen = orig


class TestFrozenForgeCommand(unittest.TestCase):
    def test_source_checkout(self):
        cmd = scoring.forge_command(Path("/p"), Path("/p/r.md"))
        self.assertEqual(cmd[:2], [sys.executable, str(SRC / "foundryguard.py")])
        self.assertEqual(cmd[2:5], ["run", "--root", "/p"])

    def test_frozen_runs_itself_with_cli(self):
        with Frozen():
            cmd = scoring.forge_command(Path("/p"), Path("/p/r.md"))
        self.assertEqual(cmd[:3], ["/opt/FoundryGuard", launcher.CLI_FLAG, "run"])
        self.assertIn("--test", cmd)
        self.assertEqual(cmd[-2:], ["--report", "/p/r.md"])


class Offline:
    def __call__(self, url, body=None):
        raise OSError("offline")


class TestBundledPack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.addCleanup(intel_sync.activate, intel_sync.SyncResult(source="idle"))
        (Path(self.tmp) / "intel").mkdir()
        shutil.copy(REPO / "intel" / "foundryguard-rules.json", Path(self.tmp) / "intel")
        self.cache = Path(self.tmp) / "cache" / "intel.json"

    def test_not_used_outside_a_build(self):
        self.assertIsNone(intel_sync.bundled_pack_path())
        res = intel_sync.sync(intel_sync.IntelConfig(), Offline(), self.cache)
        self.assertEqual(res.source, "none")

    def test_offline_first_start_uses_bundled_pack(self):
        pack = json.loads((REPO / "intel" / "foundryguard-rules.json").read_text())
        with Frozen(self.tmp):
            self.assertEqual(intel_sync.bundled_pack_path(), Path(self.tmp) / "intel" / "foundryguard-rules.json")
            res = intel_sync.sync(intel_sync.IntelConfig(), Offline(), self.cache)
        self.assertEqual(res.source, "bundled")
        self.assertEqual(len(res.rules), len(pack["rules"]))
        self.assertIn("(offline, bundled pack)", res.label())
        self.assertTrue(res.errors)  # the failed fetches are still reported
        self.assertFalse(self.cache.exists())  # a fallback never overwrites the cache

    def test_cache_beats_bundled_pack(self):
        intel_sync.sync(intel_sync.IntelConfig(osv=False), lambda u, b=None: (REPO / "intel" / "foundryguard-rules.json").read_bytes(), self.cache)
        with Frozen(self.tmp):
            res = intel_sync.sync(intel_sync.IntelConfig(), Offline(), self.cache, force=True)
        self.assertEqual(res.source, "cache")

    def test_broken_bundled_pack_is_ignored(self):
        (Path(self.tmp) / "intel" / "foundryguard-rules.json").write_text("{not json")
        with Frozen(self.tmp):
            res = intel_sync.sync(intel_sync.IntelConfig(), Offline(), self.cache)
        self.assertEqual(res.source, "none")


@unittest.skipUnless(os.environ.get("FOUNDRYGUARD_BUILD_EXE") == "1", "set FOUNDRYGUARD_BUILD_EXE=1 to run PyInstaller")
class TestRealBuild(unittest.TestCase):
    def test_build_and_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = bi.main(["--dist", tmp + "/dist", "--work", tmp + "/work"])
            self.assertEqual(rc, 0)
            self.assertTrue(bi.exe_path(Path(tmp) / "dist").is_file())


if __name__ == "__main__":
    unittest.main()
