#!/usr/bin/env python3
"""Entry point of the standalone FoundryGuard executable (``build_installer.py``).

Double-clicking the binary opens the desktop console. The same binary also runs the command line when its
first argument is ``--cli``; the console uses that for the dynamic pass, since a frozen app has no Python
interpreter and no ``foundryguard.py`` to hand to one.

    FoundryGuard                 open the window
    FoundryGuard PATH_OR_URL     open the window with the target filled in
    FoundryGuard --cli score .   same as ``foundryguard score .``

Built with ``--noconsole``, Windows gives the process no stdout or stderr, and every console program it starts
(forge, solc, git) would open a terminal window of its own. Both are handled here, before anything else runs.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

CLI_FLAG = "--cli"


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _quiet_stdio() -> None:
    # pythonw / --noconsole on Windows: print() to None raises, so send it nowhere instead
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def _hide_child_consoles() -> None:
    """Start console programs without a window when the app itself has none (Windows only)."""
    if os.name != "nt" or getattr(subprocess.Popen, "_fg_no_window", False):
        return
    flag = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    base = subprocess.Popen

    class Popen(base):  # type: ignore[misc, valid-type]
        _fg_no_window = True

        def __init__(self, *args, **kwargs):
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | flag
            super().__init__(*args, **kwargs)

    subprocess.Popen = Popen  # type: ignore[misc]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    _quiet_stdio()
    if frozen():
        _hide_child_consoles()
    if argv and argv[0] == CLI_FLAG:
        if __package__:
            from . import foundryguard
        else:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import foundryguard  # type: ignore
        return foundryguard.main(argv[1:])
    if __package__:
        from . import gui
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import gui  # type: ignore
    return gui.main(argv)


if __name__ == "__main__":
    sys.exit(main())
