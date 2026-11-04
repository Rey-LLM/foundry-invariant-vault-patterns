#!/usr/bin/env python3
"""Layer 10: FoundryGuard desktop window (``foundryguard-gui``).

One target bar takes a local path (a Solidity project, a single contract, backend or site code) or an
http(s) URL. Eight toggles pick the preset vectors (01-08). LAUNCH SECURITY SIMULATION runs
``scoring.simulate`` in a background thread: static pass and score, preset matrix from the solc AST,
and, when ``forge`` is on PATH and the target is a Foundry project, the generated invariant suites.
When it finishes, ``foundryguard-report.html`` opens in the browser with the score at the top.

A URL gets one passive GET (headers and the returned HTML); nothing is fuzzed against a remote host.

The window is built on customtkinter (dark theme, flat rounded widgets) and needs Tk underneath
(``python3-tk`` on Debian/Ubuntu, included with the python.org installers). Everything except ``App`` and
``make_root`` works without either, so the logic is unit-tested headless.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
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

PLACEHOLDER = "Enter Local Project Path or Target Web URL..."

# Dark palette: charcoal background, slate cards, white text, one muted green accent.
BG = "#1a1a1a"
CARD = "#2a2a2a"
FIELD = "#222222"
HOVER = "#333333"
BORDER = "#363636"
BORDER_STRONG = "#4a4a4a"
TEXT = "#f2f2f2"
MUTED = "#a0a0a0"
FAINT = "#6e6e6e"
ACCENT = "#4e9a6a"
ACCENT_HOVER = "#5aad78"
DISABLED = "#3a3a3a"
AMBER = "#c9a227"
RED = "#c95b5b"


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

MISSING_CTK = ("foundryguard-gui: the window needs customtkinter. Install it with `pip install customtkinter` "
               "(`pip install foundryguard` pulls it in), or use `foundryguard score TARGET`.")


def _fonts() -> tuple[str, str]:
    """(sans, mono) family names that exist on each platform."""
    if sys.platform == "darwin":
        return "Helvetica Neue", "Menlo"
    if os.name == "nt":
        return "Segoe UI", "Consolas"
    return "DejaVu Sans", "DejaVu Sans Mono"


def make_root():
    """A dark customtkinter root window. Raises ImportError without Tk or customtkinter."""
    import customtkinter as ctk

    ctk.set_appearance_mode("dark")
    root = ctk.CTk(fg_color=BG)
    return root


def score_color(score: int) -> str:
    if score >= 75:
        return ACCENT
    if score >= 50:
        return AMBER
    return RED


class App:
    """The customtkinter window. Created only by ``main()`` (needs a display)."""

    POLL_MS = 100
    DIGEST_LIMIT = 300  # findings printed into the log box when a run ends; the HTML report has all of them

    def __init__(self, root, initial: str = "") -> None:
        import tkinter as tk
        import customtkinter as ctk

        ctk.set_appearance_mode("dark")
        self.tk, self.ctk, self.root = tk, ctk, root
        self.job: Job | None = None
        self.runner: Callable = scoring.simulate
        self.last_report: Path | None = None
        self._started = 0.0
        self._syncing = False
        self._hint_after = None
        root.title(f"{TITLE} - Security Simulation")
        root.geometry("980x760")
        root.minsize(820, 640)
        try:
            root.configure(fg_color=BG)
        except Exception:  # plain tk.Tk root
            root.configure(background=BG)

        sans, mono = _fonts()
        f = self.fonts = {
            "brand": ctk.CTkFont(sans, 18, "bold"),
            "sub": ctk.CTkFont(sans, 12),
            "label": ctk.CTkFont(sans, 11, "bold"),
            "body": ctk.CTkFont(sans, 13),
            "small": ctk.CTkFont(sans, 12),
            "mono": ctk.CTkFont(mono, 12),
            "entry": ctk.CTkFont(mono, 13),
            "score": ctk.CTkFont(mono, 34, "bold"),
            "launch": ctk.CTkFont(sans, 14, "bold"),
        }

        outer = ctk.CTkFrame(root, fg_color=BG, corner_radius=0)
        outer.pack(fill="both", expand=True, padx=20, pady=18)
        outer.columnconfigure(0, weight=1)

        # Header: brand on the left, score card on the right.
        head = ctk.CTkFrame(outer, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="FoundryGuard", font=f["brand"], text_color=TEXT, anchor="w").grid(
            row=0, column=0, sticky="w")
        ctk.CTkLabel(head, text="Static score, preset matrix, and invariant fuzzing when forge is installed.",
                     font=f["sub"], text_color=MUTED, anchor="w").grid(row=1, column=0, sticky="w")
        score_card = self._card(head)
        score_card.grid(row=0, column=1, rowspan=2, sticky="e")
        self.score_var = tk.StringVar(value="--/100")
        self.verdict_var = tk.StringVar(value="NOT RUN")
        self.score_label = ctk.CTkLabel(score_card, textvariable=self.score_var, font=f["score"], text_color=TEXT,
                                        width=150)
        self.score_label.pack(padx=22, pady=(10, 0))
        self.verdict_label = ctk.CTkLabel(score_card, textvariable=self.verdict_var, font=f["label"],
                                          text_color=MUTED)
        self.verdict_label.pack(padx=22, pady=(0, 10))

        # Target bar.
        target = self._card(outer)
        target.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        target.columnconfigure(0, weight=1)
        self._section(target, "TARGET").grid(row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 6))
        self.target_var = tk.StringVar(value=initial)
        self.entry = ctk.CTkEntry(target, placeholder_text=PLACEHOLDER, height=40, corner_radius=8, border_width=1,
                                  fg_color=FIELD, border_color=BORDER, text_color=TEXT,
                                  placeholder_text_color=FAINT, font=f["entry"])
        self.entry.grid(row=1, column=0, sticky="ew", padx=(16, 8))
        if initial:
            self.entry.insert(0, initial)
        self._ghost(target, "Folder", self.pick_folder).grid(row=1, column=1, padx=(0, 6))
        self._ghost(target, "File", self.pick_file).grid(row=1, column=2, padx=(0, 16))
        self.hint_var = tk.StringVar()
        self.hint_label = ctk.CTkLabel(target, textvariable=self.hint_var, font=f["small"], text_color=MUTED,
                                       anchor="w")
        self.hint_label.grid(row=2, column=0, columnspan=3, sticky="w", padx=16, pady=(4, 10))
        for seq in ("<KeyRelease>", "<<Paste>>", "<<Cut>>", "<FocusOut>"):
            self.entry.bind(seq, self._entry_changed, add="+")
        self.target_var.trace_add("write", self._var_changed)

        # Preset matrix: 4 x 2 borderless grid.
        matrix = self._card(outer)
        matrix.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        for c in range(4):
            matrix.columnconfigure(c, weight=1, uniform="preset")
        self._section(matrix, "PRESET MATRIX").grid(row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 6))
        toggles = ctk.CTkFrame(matrix, fg_color="transparent")
        toggles.grid(row=0, column=2, columnspan=2, sticky="e", padx=16, pady=(12, 6))
        self._ghost(toggles, "All", lambda: self.set_presets(True), width=52, height=26).pack(side="right")
        self._ghost(toggles, "None", lambda: self.set_presets(False), width=52, height=26).pack(side="right",
                                                                                                 padx=(0, 6))
        self.preset_vars: dict[int, object] = {}
        for i, (pid, name) in enumerate(scoring.PRESETS.items()):
            var = tk.BooleanVar(value=True)
            self.preset_vars[pid] = var
            cell = ctk.CTkFrame(matrix, fg_color=FIELD, corner_radius=8)
            cell.grid(row=1 + i // 4, column=i % 4, sticky="nsew", padx=(16 if i % 4 == 0 else 4, 16 if i % 4 == 3 else 4),
                      pady=4)
            ctk.CTkCheckBox(cell, text=f"{pid:02d}  {name}", variable=var, onvalue=True, offvalue=False,
                            font=f["small"], text_color=TEXT, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                            border_color=BORDER_STRONG, border_width=2, corner_radius=4, checkbox_width=18,
                            checkbox_height=18, checkmark_color=BG).pack(anchor="w", padx=10, pady=9)
        opts = ctk.CTkFrame(matrix, fg_color="transparent")
        opts.grid(row=3, column=0, columnspan=4, sticky="ew", padx=16, pady=(8, 12))
        self.forge_var = tk.BooleanVar(value=True)
        self.open_var = tk.BooleanVar(value=True)
        for text, var in (("Run forge fuzzing when available", self.forge_var),
                          ("Open report when done", self.open_var)):
            ctk.CTkSwitch(opts, text=text, variable=var, onvalue=True, offvalue=False, font=f["small"],
                          text_color=MUTED, progress_color=ACCENT, button_color=TEXT, button_hover_color="#ffffff",
                          fg_color=BORDER_STRONG, switch_width=34, switch_height=16).pack(side="left", padx=(0, 24))

        # Action row.
        actions = ctk.CTkFrame(outer, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", pady=(14, 0))
        actions.columnconfigure(0, weight=1)
        self.launch_btn = ctk.CTkButton(actions, text=LAUNCH_LABEL, command=self.launch, height=48, corner_radius=8,
                                        font=f["launch"], fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                        text_color="#ffffff", text_color_disabled=FAINT)
        self.launch_btn.grid(row=0, column=0, sticky="ew")
        self.cancel_btn = self._ghost(actions, "Stop", self.stop, height=48, width=84)
        self.cancel_btn.grid(row=0, column=1, padx=(8, 0))
        self.report_btn = self._ghost(actions, "Open report", self.reopen, height=48, width=120)
        self.report_btn.grid(row=0, column=2, padx=(6, 0))
        self.cancel_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")

        # Live progress.
        prog = self._card(outer)
        prog.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        prog.columnconfigure(0, weight=1)
        self.phase_var = tk.StringVar(value="Idle")
        self.elapsed_var = tk.StringVar(value="")
        ctk.CTkLabel(prog, textvariable=self.phase_var, font=f["small"], text_color=MUTED, anchor="w").grid(
            row=0, column=0, sticky="w", padx=16, pady=(10, 4))
        ctk.CTkLabel(prog, textvariable=self.elapsed_var, font=f["mono"], text_color=MUTED, anchor="e").grid(
            row=0, column=1, sticky="e", padx=16, pady=(10, 4))
        self.progress = ctk.CTkProgressBar(prog, mode="determinate", height=6, corner_radius=3, fg_color=FIELD,
                                           progress_color=ACCENT, indeterminate_speed=1.2)
        self.progress.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 14))
        self.progress.set(0)

        # Log.
        self.log = ctk.CTkTextbox(outer, height=180, corner_radius=10, border_width=1, border_color=BORDER,
                                  fg_color=CARD, text_color=TEXT, font=f["mono"], wrap="word",
                                  scrollbar_button_color=BORDER_STRONG, scrollbar_button_hover_color=FAINT)
        self.log.grid(row=5, column=0, sticky="nsew", pady=(12, 0))
        self.log.configure(state="disabled")
        outer.rowconfigure(5, weight=1)

        self.status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(outer, textvariable=self.status_var, font=f["small"], text_color=MUTED, anchor="w").grid(
            row=6, column=0, sticky="ew", pady=(8, 0))

        root.bind("<Return>", lambda _e: self.launch())
        if initial:  # an empty bar keeps its placeholder visible until clicked
            self.entry.focus_set()
        self.update_hint()

    # -- building blocks ----------------------------------------------------
    def _card(self, parent):
        return self.ctk.CTkFrame(parent, fg_color=CARD, corner_radius=10, border_width=1, border_color=BORDER)

    def _section(self, parent, text: str):
        return self.ctk.CTkLabel(parent, text=text, font=self.fonts["label"], text_color=FAINT, anchor="w")

    def _ghost(self, parent, text: str, command, width: int = 76, height: int = 40):
        return self.ctk.CTkButton(parent, text=text, command=command, width=width, height=height, corner_radius=8,
                                  fg_color="transparent", hover_color=HOVER, border_width=1,
                                  border_color=BORDER_STRONG, text_color=TEXT, text_color_disabled=FAINT,
                                  font=self.fonts["small"])

    # -- target bar <-> target_var ------------------------------------------
    # CTkEntry hides its placeholder when bound to a textvariable, so the two are kept in sync by hand.
    def _entry_changed(self, _event=None) -> None:
        value = self.entry.get()
        if value != self.target_var.get():
            self._syncing = True
            try:
                self.target_var.set(value)
            finally:
                self._syncing = False

    def _var_changed(self, *_args) -> None:
        value = self.target_var.get()
        if not self._syncing and self.entry.get() != value:
            self.entry.delete(0, "end")
            if value:
                self.entry.insert(0, value)
        self._schedule_hint()

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
        if self._hint_after:
            self.root.after_cancel(self._hint_after)
        self._hint_after = None
        ok, text = describe_target(self.target_var.get())
        self.hint_var.set(text)
        self.hint_label.configure(text_color=MUTED if ok or not self.target_var.get().strip() else RED)
        self.entry.configure(border_color=ACCENT if ok else BORDER)
        if not (self.job and self.job.running()):
            self.launch_btn.configure(state="normal" if ok else "disabled",
                                      fg_color=ACCENT if ok else DISABLED)
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
        self.verdict_var.set("RUNNING")
        self.score_label.configure(text_color=TEXT)
        self.verdict_label.configure(text_color=ACCENT)
        self.status_var.set("Running...")
        forge = bool(self.forge_var.get())
        cores = os.cpu_count() or 1
        self.phase_var.set(f"Simulation running in a worker thread"
                           + (f"; forge fuzz runs may use up to {cores} local cores" if forge else "; forge off"))
        self.launch_btn.configure(state="disabled", fg_color=DISABLED)
        self.cancel_btn.configure(state="normal")
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self._started = time.monotonic()
        self.write(f"Target: {target}")
        self.write("Presets: " + (", ".join(f"{p:02d}" for p in sorted(self.selected_presets())) or "none"))
        self.job = Job(target, self.selected_presets(), forge, runner=self.runner).start()
        self.root.after(self.POLL_MS, self.poll)

    def stop(self) -> None:
        if self.job:
            self.job.cancel()
            self.status_var.set("Stopping...")
            self.phase_var.set("Stopping after the current step")

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
                self.phase_var.set(ev.text[:110])
            elif ev.kind == "done":
                self.finish(ev)
            else:
                self.write(ev.text)
                self.finish(ev)
        if job.running() or not job.events.empty():
            self.elapsed_var.set(f"{time.monotonic() - self._started:5.1f}s")
            self.root.after(self.POLL_MS, self.poll)

    def finish(self, ev: Event) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.cancel_btn.configure(state="disabled")
        self.update_hint()
        self.elapsed_var.set(f"{time.monotonic() - self._started:5.1f}s")
        if ev.kind == "done" and ev.result is not None and ev.report is not None:
            r = ev.result
            self.progress.set(1)
            self.score_var.set(f"{r.score}/100")
            self.verdict_var.set(r.verdict)
            color = score_color(r.score)
            self.score_label.configure(text_color=color)
            self.verdict_label.configure(text_color=color)
            c = r.counts()
            self.phase_var.set("Finished")
            self.status_var.set(f"{r.verdict}: {len(r.findings)} deduction(s), {c['CRITICAL']} critical, "
                                f"{c['HIGH']} high. Report: {ev.report}")
            self.last_report = ev.report
            self.report_btn.configure(state="normal")
            self.write("")
            for line in scoring.finding_digest(r, limit=self.DIGEST_LIMIT):
                self.write(line)
            if self.open_var.get():
                open_report(ev.report)
        else:
            self.progress.set(0)
            self.score_var.set("--/100")
            self.verdict_var.set("STOPPED" if ev.text.startswith("Stopped") else "ERROR")
            self.score_label.configure(text_color=TEXT)
            self.verdict_label.configure(text_color=RED)
            self.phase_var.set("Idle")
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
        import customtkinter  # noqa: F401
    except ImportError:
        print(MISSING_CTK, file=sys.stderr)
        return 2
    try:
        root = make_root()
    except tk.TclError as exc:
        print(f"foundryguard-gui: cannot open a window ({exc}). Use `foundryguard score TARGET` on headless machines.",
              file=sys.stderr)
        return 2
    App(root, argv[0] if argv else "")
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
