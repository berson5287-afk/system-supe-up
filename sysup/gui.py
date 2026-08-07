"""The desktop interface.

Tkinter, so it double-clicks from the desktop with nothing to install, and so
it sits alongside AI Chat Lab rather than dragging in a second UI stack.

**The sampler runs on its own thread, and that is not an optimisation.** The
stall detector works by measuring how late its own one-second tick arrives —
so if sampling were driven from Tkinter's `after()` loop, every slow redraw,
every dragged window and every opened menu would delay the tick and the app
would cheerfully report itself as a whole-system freeze. The sampling thread
keeps honest time; the UI polls a queue and is free to be as slow as it likes.

Everything expensive (diagnosis, the model, web research) also runs off the
main thread, because the machine being diagnosed is by definition already
struggling and a frozen diagnostic tool is a bad joke.
"""

from __future__ import annotations

import queue
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from dataclasses import dataclass
from tkinter import messagebox, ttk

from . import diagnose as diagnose_mod, knowledge, report as report_mod, rules
from .collect import History, ProcRow, Sample, Sampler
from .incidents import IncidentRecorder
from .config import REPORT_DIR, Settings

# ------------------------------------------------------------------- palette

BG = "#12141a"
PANEL = "#1a1d25"
PANEL_ALT = "#20242e"
RAISED = "#262b36"
BORDER = "#2a2f3a"
TEXT = "#e6e9ef"
DIM = "#8b93a7"
FAINT = "#5c6478"

ACCENT = "#4f8ef7"          # kept from AI Chat Lab, so the two look related
ACCENT_DARK = "#3b76d9"
OK = "#3ecf8e"
WARN = "#e0a03a"
DANGER = "#f2565a"
CRIT = "#ff3b5c"

SEVERITY_COLOUR = {5: CRIT, 4: DANGER, 3: WARN, 2: ACCENT, 1: DIM}
SEVERITY_TEXT = {5: "CRITICAL", 4: "SERIOUS", 3: "MODERATE", 2: "MINOR",
                 1: "INFO"}

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_TINY = ("Segoe UI", 8)
FONT_TITLE = ("Segoe UI", 15, "bold")
FONT_HUGE = ("Segoe UI", 20, "bold")
FONT_MONO = ("Consolas", 9)


def humanise(value: float, unit: str = "B") -> str:
    for suffix in ("", "K", "M", "G", "T"):
        if abs(value) < 1024:
            return f"{value:.0f} {suffix}{unit}".replace("  ", " ")
        value /= 1024
    return f"{value:.0f} P{unit}"


def flat_button(parent, text, command, primary=False, danger=False, **kwargs):
    background = ACCENT if primary else (RAISED if not danger else "#3a2126")
    foreground = "white" if primary else (DANGER if danger else TEXT)
    return tk.Button(
        parent, text=text, command=command,
        font=FONT_BOLD if primary else FONT,
        bg=background, fg=foreground,
        activebackground=ACCENT_DARK if primary else "#303644",
        activeforeground="white" if primary else foreground,
        relief="flat", cursor="hand2", padx=14, pady=6, bd=0,
        highlightthickness=0, disabledforeground=FAINT, **kwargs)


# -------------------------------------------------------------------- gauge

class Gauge(tk.Canvas):
    """A headline number, a bar, and the last minute of history.

    The sparkline is the reason this is a canvas rather than three labels: a
    number alone cannot distinguish "steady at 80%" from "spiking to 80%", and
    those two mean completely different things when someone is trying to
    explain a stutter that happens every few seconds.
    """

    HEIGHT = 78

    def __init__(self, parent, label: str, colour: str, unit: str = "%") -> None:
        super().__init__(parent, height=self.HEIGHT, bg=PANEL,
                         highlightthickness=0, bd=0)
        self.label = label
        self.colour = colour
        self.unit = unit
        self._value = 0.0
        self._fraction = 0.0
        self._series: list[float] = []
        self._note = ""
        self.bind("<Configure>", lambda _e: self._draw())

    def update_values(self, value: float, fraction: float,
                      series: list[float], note: str = "") -> None:
        self._value = value
        self._fraction = max(0.0, min(1.0, fraction))
        self._series = series
        self._note = note
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        width = self.winfo_width() or 200
        if width < 20:
            return

        self.create_text(2, 4, anchor="nw", text=self.label.upper(),
                         fill=DIM, font=FONT_TINY)
        shown = (f"{self._value:.0f}{self.unit}" if self.unit == "%"
                 else f"{self._value:,.0f}{self.unit}")
        self.create_text(2, 15, anchor="nw", text=shown, fill=TEXT,
                         font=FONT_HUGE)
        if self._note:
            self.create_text(width - 2, 8, anchor="ne", text=self._note,
                             fill=DIM, font=FONT_SMALL)

        # bar
        top = 46
        self.create_rectangle(2, top, width - 2, top + 6, fill=PANEL_ALT,
                              outline="")
        filled = max(0, int((width - 4) * self._fraction))
        colour = self.colour
        if self._fraction > 0.9:
            colour = CRIT
        elif self._fraction > 0.75:
            colour = WARN
        if filled > 0:
            self.create_rectangle(2, top, 2 + filled, top + 6, fill=colour,
                                  outline="")

        # sparkline
        if len(self._series) > 1:
            spark_top, spark_bottom = 58, self.HEIGHT - 4
            peak = max(max(self._series), 1e-9)
            window = self._series[-90:]
            step = (width - 4) / max(1, len(window) - 1)
            points = []
            for index, item in enumerate(window):
                x = 2 + index * step
                y = spark_bottom - (item / peak) * (spark_bottom - spark_top)
                points += [x, y]
            if len(points) >= 4:
                self.create_line(*points, fill=colour, width=1, smooth=True)


# ------------------------------------------------------------------ threads

@dataclass
class Tick:
    sample: Sample
    stall: dict | None
    incident: object = None


class SamplerThread(threading.Thread):
    """Keeps honest time, whatever the interface is doing."""

    def __init__(self, settings: Settings, history: History,
                 out: queue.Queue) -> None:
        super().__init__(daemon=True, name="sampler")
        self.settings = settings
        self.history = history
        self.out = out
        self.interval = float(settings.get("sample_interval", 1.0))
        self.threshold = float(settings.get("stall_threshold_s", 2.5))
        self.paused = threading.Event()
        self.stopped = threading.Event()
        self.sampler = Sampler()
        # Preserves the telemetry either side of every stall, so an
        # intermittent freeze can be examined after the fact instead of only
        # while somebody happens to be watching the gauges.
        self.recorder = IncidentRecorder(history)

    def resume(self) -> None:
        """Come back from a pause without inventing a freeze.

        The sampler must forget its previous reading first. Otherwise the next
        sample differences against a baseline from before the pause and reports
        the entire paused period as scheduler lateness — a five-second pause
        becomes a five-second "the whole machine stopped" alert. The
        continuity guard in `Sampler.sample` catches long gaps, but a pause
        shorter than that limit and longer than the stall threshold would slip
        straight through it.
        """
        self.sampler.reset()
        self.paused.clear()

    def run(self) -> None:
        self.sampler.sample()                      # prime; no rates yet
        next_tick = time.monotonic() + self.interval
        while not self.stopped.is_set():
            now = time.monotonic()
            if now < next_tick:
                # Wait on the stop event rather than sleeping, so quitting is
                # immediate instead of up to a second late.
                self.stopped.wait(min(0.05, next_tick - now))
                continue
            next_tick += self.interval
            if next_tick < now:
                next_tick = now + self.interval
            if self.paused.is_set():
                continue
            try:
                sample = self.sampler.sample(self.interval)
            except Exception:
                continue
            stall = self.history.add(sample, self.threshold)
            try:
                incident = self.recorder.on_sample(sample, stall)
            except Exception:
                incident = None
            try:
                self.out.put_nowait(Tick(sample, stall, incident))
            except queue.Full:
                pass


# --------------------------------------------------------------------- app

class App(tk.Tk):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.history = History(size=int(settings.get("history_samples", 300)))
        self.queue: queue.Queue = queue.Queue(maxsize=8)
        self.findings: list[rules.Finding] = []
        self.selected_finding: rules.Finding | None = None
        self._rebuilding = False
        self.busy = False
        self.last_report = None
        self.last_incident = None
        self.started_at = time.time()
        self._ticks = 0
        self._sort_column = "cpu"
        self._sort_reverse = True

        self.title("System Supe-Up")
        self.configure(bg=BG)
        self.geometry("1300x860")
        self.minsize(1060, 680)

        self._style()
        self._build()

        self.sampler = SamplerThread(settings, self.history, self.queue)
        self.sampler.start()

        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.after(120, self._drain)

    # ------------------------------------------------------------- chrome
    def _style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")     # the only built-in theme that recolours
        style.configure("Treeview",
                        background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, borderwidth=0, rowheight=23,
                        font=FONT_SMALL)
        style.configure("Treeview.Heading", background=PANEL_ALT,
                        foreground=DIM, borderwidth=0, font=FONT_TINY,
                        relief="flat", padding=(6, 5))
        style.map("Treeview.Heading",
                  background=[("active", RAISED)], foreground=[("active", TEXT)])
        style.map("Treeview", background=[("selected", ACCENT_DARK)],
                  foreground=[("selected", "white")])
        style.configure("Vertical.TScrollbar", background=RAISED,
                        troughcolor=PANEL, borderwidth=0, arrowcolor=DIM)
        style.configure("TPanedwindow", background=BG)
        style.configure("Sash", sashthickness=6, background=BG)

    def _build(self) -> None:
        self._build_header()
        self._build_gauges()

        # The alert strip is packed and unpacked rather than always present,
        # so a healthy machine shows no empty red box waiting for trouble.
        self.alert = tk.Frame(self, bg="#3a1d22")
        self.alert_label = tk.Label(
            self.alert, text="", bg="#3a1d22", fg="#ffc9cd", font=FONT_BOLD,
            anchor="w", padx=14, pady=8, justify="left")
        self.alert_label.pack(side="left", fill="x", expand=True)

        panes = ttk.Panedwindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=12, pady=(8, 0))
        panes.add(self._build_processes(panes), weight=3)
        panes.add(self._build_findings(panes), weight=2)

        self._build_footer()

    def _build_header(self) -> None:
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=16, pady=(14, 6))

        left = tk.Frame(bar, bg=BG)
        left.pack(side="left")
        tk.Label(left, text="System Supe-Up", bg=BG, fg=TEXT,
                 font=FONT_TITLE).pack(side="left")
        self.status_dot = tk.Label(left, text="●", bg=BG, fg=OK,
                                   font=("Segoe UI", 11))
        self.status_dot.pack(side="left", padx=(12, 4))
        self.status_label = tk.Label(left, text="starting…", bg=BG, fg=DIM,
                                     font=FONT_SMALL)
        self.status_label.pack(side="left")

        right = tk.Frame(bar, bg=BG)
        right.pack(side="right")
        self.diagnose_button = flat_button(
            right, "Diagnose now", self._diagnose, primary=True)
        self.diagnose_button.pack(side="left", padx=(0, 6))
        flat_button(right, "Snapshot", self._snapshot).pack(side="left",
                                                           padx=(0, 6))
        flat_button(right, "Reports", self._open_reports).pack(side="left",
                                                              padx=(0, 6))
        self.pause_button = flat_button(right, "Pause", self._toggle_pause)
        self.pause_button.pack(side="left", padx=(0, 6))
        flat_button(right, "⚙", self._open_settings).pack(side="left")

    def _build_gauges(self) -> None:
        frame = tk.Frame(self, bg=PANEL, highlightbackground=BORDER,
                         highlightthickness=1)
        frame.pack(fill="x", padx=12, pady=(4, 8))
        # Kept so the alert strip can be packed directly beneath it; pack has
        # no concept of "third from the top" once things start hiding.
        self.gauge_frame = frame
        inner = tk.Frame(frame, bg=PANEL)
        inner.pack(fill="x", padx=14, pady=10)

        self.gauges = {}
        for key, label, colour, unit in (
                ("cpu", "Processor", ACCENT, "%"),
                ("memory", "Memory", "#a78bfa", "%"),
                ("disk", "Disk wait", WARN, " ms"),
                ("faults", "Hard page faults", DANGER, "/s")):
            gauge = Gauge(inner, label, colour, unit)
            gauge.pack(side="left", fill="x", expand=True, padx=(0, 22))
            self.gauges[key] = gauge

    def _build_processes(self, parent) -> tk.Widget:
        wrapper = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                           highlightthickness=1)
        head = tk.Frame(wrapper, bg=PANEL)
        head.pack(fill="x", padx=12, pady=(9, 4))
        tk.Label(head, text="PROCESSES", bg=PANEL, fg=DIM,
                 font=FONT_TINY).pack(side="left")
        self.process_note = tk.Label(head, text="", bg=PANEL, fg=FAINT,
                                     font=FONT_TINY)
        self.process_note.pack(side="right")

        columns = ("name", "pid", "cpu", "memory", "io", "faults", "threads",
                   "state")
        headings = {"name": "Process", "pid": "PID", "cpu": "CPU",
                    "memory": "Memory", "io": "Disk I/O", "faults": "Faults/s",
                    "threads": "Threads", "state": "What it is doing"}
        widths = {"name": 210, "pid": 58, "cpu": 62, "memory": 78, "io": 78,
                  "faults": 66, "threads": 62, "state": 170}

        holder = tk.Frame(wrapper, bg=PANEL)
        holder.pack(fill="both", expand=True, padx=(10, 2), pady=(0, 10))
        self.tree = ttk.Treeview(holder, columns=columns, show="headings",
                                 selectmode="browse")
        for column in columns:
            self.tree.heading(
                column, text=headings[column],
                command=lambda c=column: self._sort_by(c))
            self.tree.column(
                column, width=widths[column], stretch=(column in ("name", "state")),
                anchor="w" if column in ("name", "state") else "e")

        scroll = ttk.Scrollbar(holder, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.tree.tag_configure("hung", foreground="#ffb3b8",
                                background="#2e1a1e")
        self.tree.tag_configure("stuck", foreground=WARN)
        self.tree.tag_configure("system", foreground=DIM)
        self.tree.tag_configure("normal", foreground=TEXT)
        self.tree.bind("<Double-1>", self._explain_process)
        return wrapper

    def _build_findings(self, parent) -> tk.Widget:
        wrapper = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                           highlightthickness=1)
        head = tk.Frame(wrapper, bg=PANEL)
        head.pack(fill="x", padx=12, pady=(9, 4))
        self.findings_title = tk.Label(head, text="FINDINGS", bg=PANEL,
                                       fg=DIM, font=FONT_TINY)
        self.findings_title.pack(side="left")

        self.findings_box = tk.Frame(wrapper, bg=PANEL, height=190)
        self.findings_box.pack(fill="x", padx=10, pady=(0, 6))
        self.findings_box.pack_propagate(False)

        detail_head = tk.Frame(wrapper, bg=PANEL)
        detail_head.pack(fill="x", padx=12, pady=(2, 2))
        tk.Label(detail_head, text="DETAIL", bg=PANEL, fg=DIM,
                 font=FONT_TINY).pack(side="left")
        self.fix_button = flat_button(detail_head, "Investigate & fix",
                                      self._investigate_finding, primary=True)
        self.fix_button.configure(font=FONT_SMALL, padx=10, pady=2)
        self.fix_button.pack(side="right")
        self.explain_button = flat_button(detail_head, "Ask the model",
                                          self._explain_finding)
        self.explain_button.configure(font=FONT_SMALL, padx=9, pady=2)
        self.explain_button.pack(side="right", padx=(0, 6))
        self.copy_button = flat_button(detail_head, "Copy fix",
                                       self._copy_fix)
        self.copy_button.configure(font=FONT_SMALL, padx=9, pady=2)
        self.copy_button.pack(side="right", padx=(0, 6))

        holder = tk.Frame(wrapper, bg=PANEL)
        holder.pack(fill="both", expand=True, padx=(10, 2), pady=(0, 10))
        self.detail = tk.Text(holder, bg=PANEL_ALT, fg=TEXT, font=FONT_SMALL,
                              wrap="word", bd=0, highlightthickness=0,
                              padx=12, pady=10, relief="flat",
                              insertbackground=TEXT, cursor="arrow")
        scroll = ttk.Scrollbar(holder, orient="vertical",
                               command=self.detail.yview)
        self.detail.configure(yscrollcommand=scroll.set)
        self.detail.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.detail.tag_configure("h", font=("Segoe UI", 11, "bold"),
                                  foreground=TEXT, spacing3=6)
        self.detail.tag_configure("body", foreground="#c9cfdb", spacing1=2,
                                  spacing3=8, lmargin1=0, lmargin2=0)
        self.detail.tag_configure("label", font=FONT_TINY, foreground=DIM,
                                  spacing1=8, spacing3=3)
        self.detail.tag_configure("bullet", foreground="#aab2c3",
                                  lmargin1=10, lmargin2=22, spacing3=3)
        self.detail.tag_configure("fix", font=FONT_BOLD, foreground=OK,
                                  spacing1=8, spacing3=2)
        self.detail.tag_configure("cmd", font=FONT_MONO, foreground="#9ecbff",
                                  background="#171b23", lmargin1=10,
                                  lmargin2=10, spacing1=3, spacing3=3)
        self.detail.tag_configure("risk", font=FONT_TINY, foreground=WARN)
        self.detail.configure(state="disabled")
        self._show_placeholder()
        return wrapper

    def _build_footer(self) -> None:
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=16, pady=(6, 12))
        self.progress = tk.Label(bar, text="", bg=BG, fg=ACCENT,
                                 font=FONT_SMALL, anchor="w")
        self.progress.pack(side="left", fill="x", expand=True)
        tk.Label(bar, text=f"reports → {REPORT_DIR}", bg=BG, fg=FAINT,
                 font=FONT_TINY).pack(side="right")

    # -------------------------------------------------------------- updates
    def _drain(self) -> None:
        """Pull whatever the sampler produced and redraw once."""
        latest = None
        stalled = False
        incident = None
        try:
            while True:
                tick = self.queue.get_nowait()
                latest = tick.sample
                stalled = stalled or tick.stall is not None
                incident = tick.incident or incident
        except queue.Empty:
            pass

        if incident is not None:
            self._incident_ready(incident)

        if latest is not None:
            self._ticks += 1
            self._refresh_gauges(latest)
            self._refresh_processes(latest)
            self._refresh_alerts(latest, stalled)
            # Re-running every rule each second is wasted work; findings do
            # not meaningfully change that fast.
            if self._ticks % 5 == 0 and not self.busy:
                threading.Thread(target=self._recompute_findings,
                                 daemon=True).start()
            minutes = (time.time() - self.started_at) / 60
            state = "paused" if self.sampler.paused.is_set() else "watching"
            self.status_label.configure(
                text=f"{state} · {minutes:.0f} min · "
                     f"{self.history.count} samples")
            self.status_dot.configure(
                fg=WARN if self.sampler.paused.is_set() else OK)

        self.after(150, self._drain)

    def _incident_ready(self, incident) -> None:
        """A freeze finished being recorded — offer the forensics."""
        self.last_incident = incident
        self.progress.configure(
            text=f"⚠  Freeze recorded: {incident.lateness:.1f}s — "
                 f"{incident.verdict()[0][:70]}")
        window = tk.Toplevel(self)
        window.title("Freeze recorded")
        window.configure(bg=BG)
        window.geometry("760x560")

        tk.Label(window, text=f"System stall — {incident.lateness:.2f} seconds",
                 bg=BG, fg=TEXT, font=FONT_TITLE, anchor="w").pack(
            fill="x", padx=18, pady=(16, 2))
        tk.Label(window,
                 text="The telemetry from either side of this freeze has been "
                      "kept, so it can be examined now rather than guessed at "
                      "later.",
                 bg=BG, fg=DIM, font=FONT_SMALL, anchor="w", justify="left",
                 wraplength=700).pack(fill="x", padx=18, pady=(0, 8))

        holder = tk.Frame(window, bg=BG)
        holder.pack(fill="both", expand=True, padx=18, pady=4)
        text = tk.Text(holder, bg=PANEL, fg="#d5dae4", font=FONT_MONO,
                       wrap="word", bd=0, highlightthickness=0, padx=14,
                       pady=12, cursor="arrow")
        scroll = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("end", incident.summary())
        text.configure(state="disabled")

        buttons = tk.Frame(window, bg=BG)
        buttons.pack(fill="x", padx=18, pady=(6, 16))
        flat_button(buttons, "Open incident folder",
                    self._open_incidents, primary=True).pack(side="left")
        flat_button(buttons, "Close", window.destroy).pack(side="right")

    def _open_incidents(self) -> None:
        from .incidents import INCIDENT_DIR
        INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["explorer", str(INCIDENT_DIR)])
        except OSError:
            webbrowser.open(INCIDENT_DIR.as_uri())

    def _refresh_gauges(self, sample: Sample) -> None:
        self.gauges["cpu"].update_values(
            sample.cpu, sample.cpu / 100, self.history.series("cpu", 90))
        self.gauges["memory"].update_values(
            sample.memory_percent, sample.memory_percent / 100,
            self.history.series("memory_percent", 90),
            f"{sample.memory_available / 1e9:.1f} GB free")
        # Latency rather than percent-busy: an NVMe absorbing 120 MB/s reads
        # as under 1% busy, so the percentage looks idle exactly when the
        # drive is the thing everything is waiting for.
        latency = sample.disk_latency_ms
        self.gauges["disk"].update_values(
            latency, min(1.0, latency / 40.0),
            self.history.series("disk_latency_ms", 90),
            f"{(sample.disk_read_bps + sample.disk_write_bps) / 1e6:.0f} MB/s"
            f" · {sample.disk_busy:.0f}% busy")
        self.gauges["faults"].update_values(
            sample.hard_faults, min(1.0, sample.hard_faults / 500),
            self.history.series("hard_faults", 90))

    def _refresh_processes(self, sample: Sample) -> None:
        key = self._sort_column
        rows = sorted(sample.processes,
                      key=lambda r: self._sort_value(r, key),
                      reverse=self._sort_reverse)[:40]

        # Tk hands values back as strings or ints depending on the version, so
        # the selected pid has to be coerced before it can be compared.
        selected = self.tree.selection()
        keep = None
        if selected:
            try:
                keep = int(self.tree.item(selected[0])["values"][1])
            except (ValueError, IndexError, TypeError):
                keep = None

        self.tree.delete(*self.tree.get_children())
        for row in rows:
            fact = knowledge.lookup(row.name)
            if row.hung:
                tag, state = "hung", "NOT RESPONDING"
            elif row.waits.dominant:
                tag = "stuck"
                state = row.waits.describe()
            elif fact and fact.essential:
                tag = "system"
                state = f"{row.waits.running} running" if row.waits.running \
                    else "idle"
            else:
                tag = "normal"
                state = f"{row.waits.running} running" if row.waits.running \
                    else "idle"

            item = self.tree.insert("", "end", tags=(tag,), values=(
                row.name, row.pid, f"{row.cpu:.1f}%", humanise(row.memory),
                (humanise(row.io_bps) + "/s") if row.io_bps > 1e5 else "—",
                f"{row.hard_faults:.0f}" if row.hard_faults else "—",
                row.threads, state))
            if keep is not None and row.pid == keep:
                self.tree.selection_set(item)

        self.process_note.configure(
            text=f"{len(sample.processes)} running · top 40 by "
                 f"{self._sort_column}")

    @staticmethod
    def _sort_value(row: ProcRow, column: str):
        return {"name": row.name.lower(), "pid": row.pid, "cpu": row.cpu,
                "memory": row.memory, "io": row.io_bps,
                "faults": row.hard_faults, "threads": row.threads,
                "state": row.waits.stuck}.get(column, 0)

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = column != "name"
        sample = self.history.latest()
        if sample is not None:
            self._refresh_processes(sample)

    def _refresh_alerts(self, sample: Sample, stalled: bool) -> None:
        lines = []
        recent = [s for s in self.history.stalls
                  if time.time() - s["at"] < 120]
        if recent:
            worst = max(recent, key=lambda s: s["lateness"])
            lines.append(f"⚠  The whole machine stopped responding for "
                         f"{worst['lateness']:.1f}s  "
                         f"({len(recent)} in the last two minutes)")
        for window in sample.hung_windows[:3]:
            row = sample.find(window.pid)
            why = f" — {row.waits.describe()}" if row and row.waits.dominant \
                else ""
            lines.append(f"⛔  Not responding: {window.title[:70]}{why}")

        if lines:
            self.alert_label.configure(text="\n".join(lines))
            if not self.alert.winfo_ismapped():
                self.alert.pack(fill="x", padx=12, pady=(0, 4),
                                after=self.gauge_frame)
        elif self.alert.winfo_ismapped():
            self.alert.pack_forget()

    # ------------------------------------------------------------- findings
    def _recompute_findings(self) -> None:
        try:
            found = rules.analyse(self.history)
        except Exception:
            return
        self.after(0, lambda: self._set_findings(found))

    def _set_findings(self, found: list[rules.Finding]) -> None:
        self.findings = found
        self.findings_title.configure(text=f"FINDINGS ({len(found)})")
        self._rebuilding = True
        try:
            self._build_finding_rows(found)
        finally:
            self._rebuilding = False

    def _build_finding_rows(self, found: list[rules.Finding]) -> None:
        for child in self.findings_box.winfo_children():
            child.destroy()

        if not found:
            tk.Label(self.findings_box,
                     text="Nothing wrong found yet.\nLeave it watching.",
                     bg=PANEL, fg=DIM, font=FONT_SMALL,
                     justify="left").pack(anchor="w", padx=4, pady=8)
            return

        canvas = tk.Canvas(self.findings_box, bg=PANEL, highlightthickness=0,
                           bd=0)
        scroll = ttk.Scrollbar(self.findings_box, orient="vertical",
                               command=canvas.yview)
        strip = tk.Frame(canvas, bg=PANEL)
        strip.bind("<Configure>", lambda _e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=strip, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        for finding in found:
            self._finding_row(strip, finding)

        if self.selected_finding is None or not any(
                f.id == self.selected_finding.id for f in found):
            self._select_finding(found[0])
        else:
            current = next(f for f in found
                           if f.id == self.selected_finding.id)
            self._select_finding(current)

    def _finding_row(self, parent, finding: rules.Finding) -> None:
        colour = SEVERITY_COLOUR.get(finding.severity, DIM)
        selected = (self.selected_finding is not None
                    and self.selected_finding.id == finding.id)
        background = RAISED if selected else PANEL

        row = tk.Frame(parent, bg=background, cursor="hand2")
        row.pack(fill="x", pady=1)
        tk.Frame(row, bg=colour, width=3).pack(side="left", fill="y")

        body = tk.Frame(row, bg=background)
        body.pack(side="left", fill="x", expand=True, padx=8, pady=5)
        tk.Label(body, text=SEVERITY_TEXT.get(finding.severity, "?"),
                 bg=background, fg=colour, font=FONT_TINY,
                 anchor="w").pack(anchor="w")
        tk.Label(body, text=finding.title, bg=background, fg=TEXT,
                 font=FONT_SMALL, anchor="w", justify="left",
                 wraplength=340).pack(anchor="w")

        for widget in (row, body, *body.winfo_children()):
            widget.bind("<Button-1>",
                        lambda _e, f=finding: self._select_finding(f))

    def _select_finding(self, finding: rules.Finding) -> None:
        changed = (self.selected_finding is None
                   or self.selected_finding.id != finding.id)
        self.selected_finding = finding
        self._render_detail(finding)
        # Repaint the strip so the highlight moves — but not while _set_findings
        # is the thing that called us, or the two bounce off each other and
        # rebuild the list twice for every click.
        if changed and not self._rebuilding:
            self._set_findings(self.findings)

    def _render_detail(self, finding: rules.Finding) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", finding.title + "\n", "h")
        self.detail.insert("end", finding.explanation + "\n", "body")

        if finding.evidence:
            self.detail.insert("end", "EVIDENCE\n", "label")
            for item in finding.evidence:
                self.detail.insert("end", f"•  {item}\n", "bullet")

        if finding.fixes:
            self.detail.insert("end", "WHAT TO DO\n", "label")
            for fix in finding.fixes:
                flags = []
                if fix.risk != "low":
                    flags.append(f"{fix.risk} risk")
                if fix.needs_admin:
                    flags.append("needs admin")
                self.detail.insert("end", f"{fix.title}", "fix")
                if flags:
                    self.detail.insert("end", f"   ({', '.join(flags)})",
                                       "risk")
                self.detail.insert("end", f"\n{fix.detail}\n", "bullet")
                if fix.command:
                    self.detail.insert("end", f"{fix.command}\n", "cmd")

        self.detail.configure(state="disabled")

    def _show_placeholder(self) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "Watching the machine\n", "h")
        self.detail.insert(
            "end",
            "Findings appear here as they are detected. Nothing is changed on "
            "your PC — fixes are shown, never run.\n\n"
            "Press Diagnose now for a full report with a written explanation "
            "from your local model.\n", "body")
        self.detail.configure(state="disabled")

    # -------------------------------------------------------------- actions
    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.busy = busy
        self.progress.configure(text=message)
        self.diagnose_button.configure(state="disabled" if busy else "normal")
        self.explain_button.configure(state="disabled" if busy else "normal")
        self.fix_button.configure(state="disabled" if busy else "normal")

    def _diagnose(self) -> None:
        if self.busy:
            return
        if self.history.count < 5:
            messagebox.showinfo("System Supe-Up",
                                "Give it a few more seconds of data first.")
            return
        self._set_busy(True, "starting…")

        def work() -> None:
            try:
                def progress(message: str) -> None:
                    self.after(0, lambda: self.progress.configure(
                        text=f"⋯  {message}"))

                diagnosis = diagnose_mod.diagnose(
                    self.history, self.settings, on_progress=progress)
                paths = report_mod.save(diagnosis)
                self.last_report = paths["html"]
                self.after(0, lambda: self._diagnosis_done(diagnosis, paths))
            except Exception as error:
                self.after(0, lambda: self._failed(error))

        threading.Thread(target=work, daemon=True).start()

    def _diagnosis_done(self, diagnosis, paths) -> None:
        self._set_busy(False, f"report saved · {paths['html'].name}")
        self._set_findings(diagnosis.findings)
        if diagnosis.narrative:
            self._show_narrative(diagnosis)
        else:
            messagebox.showinfo(
                "System Supe-Up",
                "Report written, but no model was reachable so it has no "
                "written explanation. The findings and evidence are all "
                "there.")

    def _show_narrative(self, diagnosis) -> None:
        window = tk.Toplevel(self)
        window.title("What is going on")
        window.configure(bg=BG)
        window.geometry("820x680")

        head = tk.Frame(window, bg=BG)
        head.pack(fill="x", padx=18, pady=(16, 8))
        tk.Label(head, text=diagnosis.headline(), bg=BG, fg=TEXT,
                 font=FONT_TITLE, wraplength=640, justify="left",
                 anchor="w").pack(fill="x")
        tk.Label(head,
                 text=f"{len(diagnosis.findings)} findings · written by "
                      f"{diagnosis.model or 'no model'} · "
                      f"{diagnosis.duration_s:.0f}s",
                 bg=BG, fg=DIM, font=FONT_SMALL, anchor="w").pack(fill="x")

        holder = tk.Frame(window, bg=BG)
        holder.pack(fill="both", expand=True, padx=18, pady=6)
        text = tk.Text(holder, bg=PANEL, fg="#d5dae4", font=("Segoe UI", 10),
                       wrap="word", bd=0, highlightthickness=0, padx=18,
                       pady=14, spacing1=2, spacing3=8, cursor="arrow")
        scroll = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        text.tag_configure("h", font=("Segoe UI", 12, "bold"), foreground=TEXT,
                           spacing1=10, spacing3=4)
        for line in (diagnosis.narrative or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                text.insert("end", stripped.lstrip("# ") + "\n", "h")
            else:
                text.insert("end", line.replace("**", "") + "\n")
        text.configure(state="disabled")

        buttons = tk.Frame(window, bg=BG)
        buttons.pack(fill="x", padx=18, pady=(6, 16))
        flat_button(buttons, "Open full report", self._open_last_report,
                    primary=True).pack(side="left")
        flat_button(buttons, "Close", window.destroy).pack(side="right")

    def _open_settings(self) -> None:
        from .settings_dialog import SettingsDialog
        SettingsDialog(self, self.settings, on_saved=self._settings_saved)

    def _settings_saved(self, settings: Settings) -> None:
        self.settings = settings
        # Sampling cadence is owned by the thread, so a changed interval only
        # takes effect on a restart of the app; say so rather than silently
        # ignoring it.
        interval = float(settings.get("sample_interval", 1.0))
        threshold = float(settings.get("stall_threshold_s", 2.5))
        self.sampler.threshold = threshold
        if abs(interval - self.sampler.interval) > 1e-6:
            self.progress.configure(
                text="Settings saved. The new sample interval applies next "
                     "time the app starts.")
        else:
            self.progress.configure(text="Settings saved.")

    def _investigate_finding(self) -> None:
        """Research the selected finding and offer a plan of real actions."""
        if self.selected_finding is None:
            messagebox.showinfo("System Supe-Up",
                                "Select a finding on the left first.")
            return
        from .fix_dialog import FixDialog
        from . import sysinfo

        finding = self.selected_finding
        sample = self.history.latest()
        # Machine facts are cheap (about a tenth of a second) and give the
        # investigator the OS build and drive state to reason with.
        try:
            facts = sysinfo.gather(include_events=False)
        except Exception:
            facts = None
        FixDialog(self, finding, self.settings, facts=facts, sample=sample)

    def _explain_finding(self) -> None:
        if self.busy or self.selected_finding is None:
            return
        finding = self.selected_finding
        self._set_busy(True, f"asking about “{finding.title[:44]}”…")

        def work() -> None:
            try:
                answer = diagnose_mod.triage(finding, self.settings)
                self.after(0, lambda: self._show_triage(finding, answer))
            except Exception as error:
                self.after(0, lambda: self._failed(error))

        threading.Thread(target=work, daemon=True).start()

    def _show_triage(self, finding: rules.Finding, answer: str) -> None:
        self._set_busy(False, "")
        self.detail.configure(state="normal")
        self.detail.insert("end", "\nWHAT THE MODEL SAYS\n", "label")
        self.detail.insert("end", answer.strip() + "\n", "body")
        self.detail.configure(state="disabled")
        self.detail.see("end")

    def _explain_process(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0])["values"]
        name = str(values[0])
        fact = knowledge.lookup(name)
        if fact is None:
            messagebox.showinfo(
                name, f"{name} is not in the built-in table.\n\n"
                      f"Run a full diagnosis and it will be looked up on the "
                      f"web through your SearXNG instance.")
            return
        causes = "\n".join(f"  •  {c}" for c in fact.common_causes) or "  —"
        messagebox.showinfo(
            fact.display,
            f"{fact.role}\n\n"
            f"Vendor: {fact.vendor or 'unknown'}\n"
            f"Safe to end: {'no — essential to Windows' if fact.essential else ('yes' if fact.killable else 'not recommended')}\n\n"
            f"Common reasons it misbehaves:\n{causes}")

    def _copy_fix(self) -> None:
        finding = self.selected_finding
        if finding is None:
            return
        commands = [f.command for f in finding.fixes if f.command]
        if not commands:
            messagebox.showinfo("System Supe-Up",
                                "This finding has no command to copy — its "
                                "fixes are things to change by hand.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(commands))
        self.progress.configure(
            text=f"copied {len(commands)} command(s) to the clipboard")

    def _snapshot(self) -> None:
        if self.busy:
            return
        self._set_busy(True, "writing snapshot…")

        def work() -> None:
            try:
                diagnosis = diagnose_mod.diagnose(
                    self.history, self.settings, use_model=False)
                paths = report_mod.save(diagnosis)
                self.last_report = paths["html"]
                self.after(0, lambda: self._set_busy(
                    False, f"snapshot saved · {paths['html'].name}"))
            except Exception as error:
                self.after(0, lambda: self._failed(error))

        threading.Thread(target=work, daemon=True).start()

    def _failed(self, error: Exception) -> None:
        self._set_busy(False, "")
        messagebox.showerror("System Supe-Up", f"That did not work:\n\n{error}")

    def _open_last_report(self) -> None:
        if self.last_report is not None:
            webbrowser.open(self.last_report.as_uri())
        else:
            self._open_reports()

    def _open_reports(self) -> None:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["explorer", str(REPORT_DIR)])
        except OSError:
            webbrowser.open(REPORT_DIR.as_uri())

    def _toggle_pause(self) -> None:
        if self.sampler.paused.is_set():
            self.sampler.resume()
            self.pause_button.configure(text="Pause")
        else:
            self.sampler.paused.set()
            self.pause_button.configure(text="Resume")

    def _quit(self) -> None:
        self.sampler.stopped.set()
        self.destroy()


def main(settings: Settings | None = None) -> int:
    App(settings or Settings.load()).mainloop()
    return 0
