#!/usr/bin/env python3
"""Layer 10: FoundryGuard desktop window (``foundryguard-gui``).

One target bar takes a local path (a Solidity project, a single contract, backend or site code) or an
http(s) URL. Eight toggles pick the preset vectors (01-08). LAUNCH SECURITY SIMULATION runs
``scoring.simulate`` in a background thread: static pass and score, preset matrix from the solc AST,
and, when ``forge`` is on PATH and the target is a Foundry project, the generated invariant suites.
When it finishes, ``foundryguard-report.html`` opens in the browser with the score at the top.

A URL gets one passive GET (headers and the returned HTML); nothing is fuzzed against a remote host.

The window needs Tk (``python3-tk`` on Debian/Ubuntu, included with the python.org installers).
Everything except ``App`` works without it, so the logic is unit-tested headless.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

if __package__:
    from . import scoring
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scoring  # type: ignore

TITLE = "FoundryGuard"
LAUNCH_LABEL = "LAUNCH SECURITY SIMULATION"

# Flat monochrome palette.
BG = "#f2f2f2"
PANEL = "#ffffff"
INK = "#111111"
MUTED = "#666666"
LINE = "#c8c8c8"
ACTIVE = "#333333"


# --------------------------------------------------------------------------- #
# Headless logic
# --------------------------------------------------------------------------- #


def describe_target(text: str) -> tuple[bool, str]:
    """(ready, one-line description) for what the target bar holds."""
    text = text.strip()
    if not text:
        return False, "Enter a project folder, a file, or an http(s) URL."
    if scoring.is_url(text):
        return True, "URL: one passive GET; headers and returned HTML are scored, no requests beyond that."
    if text.lower().startswith(("http:", "https:", "ftp:", "file:", "ws:", "wss:")):
        return False, "Not a valid http(s) URL."
    p = Path(text).expanduser()
    if not p.exists():
        return False, f"Not found: {p}"
    if p.is_file():
        if p.suffix.lower() not in scoring.SCANNED_EXT:
            return False, f"Unsupported file type {p.suffix or '(none)'}; use .sol .py .js .ts .html .php or a folder."
        return True, f"File: {p.name}"
    files = scoring.discover(p)
    if not files:
        return False, "Folder has no .sol/.py/.js/.ts/.html/.php files outside test, lib and node_modules."
    sol = sum(f.suffix == ".sol" for f in files)
    foundry = " (Foundry project)" if (p / "foundry.toml").is_file() else ""
    capped = "+" if len(files) >= scoring.MAX_FILES else ""
    return True, f"Folder{foundry}: {len(files)}{capped} file(s), {sol} Solidity"


@dataclass
class Event:
    kind: str  # log | done | error
    text: str = ""
    result: "scoring.ScoreResult | None" = None
    report: Path | None = None


@dataclass
class Job:
    """One simulation in a worker thread. Events go to ``events``; the window polls it from the Tk loop."""

    target: str
    presets: frozenset[int]
    run_forge: bool = True
    out_dir: str | None = None
    runner: Callable = scoring.simulate  # injectable for tests
    events: "queue.Queue[Event]" = field(default_factory=queue.Queue)
    _cancel: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None

    def start(self) -> "Job":
        self.thread = threading.Thread(target=self._run, name="foundryguard-simulation", daemon=True)
        self.thread.start()
        return self

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def _run(self) -> None:
        try:
            result, page = self.runner(self.target, self.presets, run_forge=self.run_forge, out_dir=self.out_dir,
                                       progress=lambda m: self.events.put(Event("log", m)), cancel=self._cancel.is_set)
            self.events.put(Event("done", f"{result.score}/100 {result.verdict}", result, page))
        except scoring.Cancelled as exc:
            self.events.put(Event("error", f"Stopped: {exc}"))
        except Exception as exc:  # shown in the window, never swallowed
            self.events.put(Event("error", f"{exc.__class__.__name__}: {exc}"))

    def drain(self) -> list[Event]:
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out


def open_report(path: Path, opener: Callable[[str], bool] = webbrowser.open) -> bool:
    return bool(opener(path.resolve().as_uri()))


# --------------------------------------------------------------------------- #
# Window
# --------------------------------------------------------------------------- #


def _mono() -> tuple:
    return ("Menlo", 11) if sys.platform == "darwin" else ("Consolas", 10) if os.name == "nt" else ("DejaVu Sans Mono", 10)


def _style(ttk, root) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    mono = _mono()
    root.configure(background=BG)
    style.configure(".", background=BG, foreground=INK, font=mono, borderwidth=1, focuscolor=INK)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL, relief="solid", bordercolor=LINE)
    style.configure("TLabel", background=BG, foreground=INK)
    style.configure("Panel.TLabel", background=PANEL)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("Head.TLabel", background=BG, foreground=INK, font=(mono[0], mono[1], "bold"))
    style.configure("Score.TLabel", background=INK, foreground="#ffffff", font=(mono[0], 26, "bold"), padding=(18, 8))
    style.configure("TEntry", fieldbackground=PANEL, foreground=INK, bordercolor=INK, lightcolor=INK, darkcolor=INK,
                    insertcolor=INK, padding=6)
    style.configure("TCheckbutton", background=BG, foreground=INK, indicatorbackground=PANEL,
                    indicatorforeground=INK, padding=(0, 3))
    style.map("TCheckbutton", background=[("active", BG)], indicatorbackground=[("selected", INK), ("active", PANEL)],
              indicatorforeground=[("selected", "#ffffff")])
    style.configure("TButton", background=PANEL, foreground=INK, bordercolor=INK, lightcolor=PANEL, darkcolor=PANEL,
                    relief="flat", padding=(10, 5))
    style.map("TButton", background=[("active", "#e6e6e6"), ("disabled", BG)], foreground=[("disabled", "#9a9a9a")])
    style.configure("Launch.TButton", background=INK, foreground="#ffffff", bordercolor=INK, lightcolor=INK,
                    darkcolor=INK, padding=(14, 10), font=(mono[0], mono[1] + 1, "bold"))
    style.map("Launch.TButton", background=[("active", ACTIVE), ("disabled", "#9a9a9a")],
              foreground=[("disabled", "#eeeeee")])
    style.configure("Horizontal.TProgressbar", background=INK, troughcolor=PANEL, bordercolor=LINE,
                    lightcolor=INK, darkcolor=INK)


class App:
    """The Tk window. Created only by ``main()`` (needs a display)."""

    POLL_MS = 100

    def __init__(self, root, initial: str = "") -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk, self.root = tk, ttk, root
        self.job: Job | None = None
        self.runner: Callable = scoring.simulate
        self.last_report: Path | None = None
        root.title(f"{TITLE} - Security Simulation")
        root.geometry("920x680")
        root.minsize(720, 520)
        _style(ttk, root)

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)

        head = ttk.Frame(outer)
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        ttk.Label(head, text="FOUNDRYGUARD  /  SECURITY SIMULATION", style="Head.TLabel").grid(row=0, column=0, sticky="w")
        self.score_var = tk.StringVar(value="--/100")
        ttk.Label(head, textvariable=self.score_var, style="Score.TLabel").grid(row=0, column=1, rowspan=2, sticky="e")
        ttk.Label(head, text="Static score 1-100, preset matrix, invariant fuzzing when forge is installed.",
                  style="Muted.TLabel").grid(row=1, column=0, sticky="w")

        # Target bar
        ttk.Label(outer, text="TARGET  (path or http(s) URL)", style="Head.TLabel").grid(row=1, column=0, sticky="w", pady=(16, 4))
        bar = ttk.Frame(outer)
        bar.grid(row=2, column=0, sticky="ew")
        bar.columnconfigure(0, weight=1)
        self.target_var = tk.StringVar(value=initial)
        self.entry = ttk.Entry(bar, textvariable=self.target_var)
        self.entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(bar, text="Folder", command=self.pick_folder).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(bar, text="File", command=self.pick_file).grid(row=0, column=2, padx=(6, 0))
        self.hint_var = tk.StringVar()
        ttk.Label(outer, textvariable=self.hint_var, style="Muted.TLabel").grid(row=3, column=0, sticky="w", pady=(4, 0))
        self.target_var.trace_add("write", lambda *_: self._schedule_hint())
        self._hint_after = None

        # Presets
        ttk.Label(outer, text="PRESET VECTORS", style="Head.TLabel").grid(row=4, column=0, sticky="w", pady=(16, 4))
        grid = ttk.Frame(outer)
        grid.grid(row=5, column=0, sticky="ew")
        self.preset_vars: dict[int, object] = {}
        for i, (pid, name) in enumerate(scoring.PRESETS.items()):
            var = tk.BooleanVar(value=True)
            self.preset_vars[pid] = var
            ttk.Checkbutton(grid, text=f"{pid:02d}  {name}", variable=var).grid(
                row=i % 4, column=i // 4, sticky="w", padx=(0, 36))
        opts = ttk.Frame(outer)
        opts.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        self.forge_var = tk.BooleanVar(value=True)
        self.open_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Run forge fuzzing when available", variable=self.forge_var).pack(side="left")
        ttk.Checkbutton(opts, text="Open report when done", variable=self.open_var).pack(side="left", padx=(24, 0))
        ttk.Button(opts, text="All", command=lambda: self.set_presets(True)).pack(side="right")
        ttk.Button(opts, text="None", command=lambda: self.set_presets(False)).pack(side="right", padx=(0, 6))

        # Launch
        actions = ttk.Frame(outer)
        actions.grid(row=7, column=0, sticky="ew", pady=(16, 8))
        actions.columnconfigure(0, weight=1)
        self.launch_btn = ttk.Button(actions, text=LAUNCH_LABEL, style="Launch.TButton", command=self.launch)
        self.launch_btn.grid(row=0, column=0, sticky="ew")
        self.cancel_btn = ttk.Button(actions, text="Stop", command=self.stop, state="disabled")
        self.cancel_btn.grid(row=0, column=1, padx=(8, 0), sticky="ns")
        self.report_btn = ttk.Button(actions, text="Open report", command=self.reopen, state="disabled")
        self.report_btn.grid(row=0, column=2, padx=(6, 0), sticky="ns")
        self.progress = ttk.Progressbar(outer, mode="indeterminate")
        self.progress.grid(row=8, column=0, sticky="ew")

        # Log
        log_frame = ttk.Frame(outer, style="Panel.TFrame")
        log_frame.grid(row=9, column=0, sticky="nsew", pady=(8, 0))
        outer.rowconfigure(9, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = tk.Text(log_frame, height=12, wrap="word", relief="flat", borderwidth=0, background=PANEL,
                           foreground=INK, insertbackground=INK, font=_mono(), highlightthickness=0, padx=10, pady=8, state="disabled")
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(outer, textvariable=self.status_var, style="Muted.TLabel").grid(row=10, column=0, sticky="w", pady=(6, 0))

        root.bind("<Return>", lambda _e: self.launch())
        self.entry.focus_set()
        self.update_hint()

    # -- actions ------------------------------------------------------------
    def pick_folder(self) -> None:
        from tkinter import filedialog
        d = filedialog.askdirectory(title="Project folder")
        if d:
            self.target_var.set(d)

    def pick_file(self) -> None:
        from tkinter import filedialog
        f = filedialog.askopenfilename(title="Source file", filetypes=[
            ("Source", "*.sol *.py *.js *.jsx *.ts *.tsx *.html *.htm *.php"), ("All files", "*")])
        if f:
            self.target_var.set(f)

    def set_presets(self, on: bool) -> None:
        for v in self.preset_vars.values():
            v.set(on)

    def selected_presets(self) -> frozenset[int]:
        return frozenset(p for p, v in self.preset_vars.items() if v.get())

    def _schedule_hint(self) -> None:
        if self._hint_after:
            self.root.after_cancel(self._hint_after)
        self._hint_after = self.root.after(250, self.update_hint)

    def update_hint(self) -> bool:
        self._hint_after = None
        ok, text = describe_target(self.target_var.get())
        self.hint_var.set(text)
        if not (self.job and self.job.running()):
            self.launch_btn.configure(state="normal" if ok else "disabled")
        return ok

    def write(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def launch(self) -> None:
        if self.job and self.job.running():
            return
        if not self.update_hint():
            return
        target = self.target_var.get().strip()
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.score_var.set("../100")
        self.status_var.set("Running...")
        self.launch_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.write(f"Target: {target}")
        self.write("Presets: " + (", ".join(f"{p:02d}" for p in sorted(self.selected_presets())) or "none"))
        self.job = Job(target, self.selected_presets(), bool(self.forge_var.get()), runner=self.runner).start()
        self.root.after(self.POLL_MS, self.poll)

    def stop(self) -> None:
        if self.job:
            self.job.cancel()
            self.status_var.set("Stopping...")

    def reopen(self) -> None:
        if self.last_report and self.last_report.exists():
            open_report(self.last_report)

    def poll(self) -> None:
        job = self.job
        if job is None:
            return
        for ev in job.drain():
            if ev.kind == "log":
                self.write(ev.text)
            elif ev.kind == "done":
                self.finish(ev)
            else:
                self.write(ev.text)
                self.finish(ev)
        if job.running() or not job.events.empty():
            self.root.after(self.POLL_MS, self.poll)

    def finish(self, ev: Event) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.cancel_btn.configure(state="disabled")
        self.launch_btn.configure(state="normal")
        if ev.kind == "done" and ev.result is not None and ev.report is not None:
            r = ev.result
            self.score_var.set(f"{r.score}/100")
            c = r.counts()
            self.status_var.set(f"{r.verdict}: {len(r.findings)} deduction(s), {c['CRITICAL']} critical, "
                                f"{c['HIGH']} high. Report: {ev.report}")
            self.last_report = ev.report
            self.report_btn.configure(state="normal")
            if self.open_var.get():
                open_report(ev.report)
        else:
            self.score_var.set("--/100")
            self.status_var.set(ev.text)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-h", "--help"):
        print("usage: foundryguard-gui [TARGET]\n\nOpen the FoundryGuard simulation window, optionally with TARGET "
              "(a path or http(s) URL) filled in.")
        return 0
    try:
        import tkinter as tk
    except ImportError:
        print("foundryguard-gui: Tk is not available in this Python. Install it (Debian/Ubuntu: "
              "`sudo apt install python3-tk`, Fedora: `sudo dnf install python3-tkinter`, macOS: the python.org "
              "installer or `brew install python-tk`), or use `foundryguard score TARGET`.", file=sys.stderr)
        return 2
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"foundryguard-gui: cannot open a window ({exc}). Use `foundryguard score TARGET` on headless machines.",
              file=sys.stderr)
        return 2
    App(root, argv[0] if argv else "")
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
