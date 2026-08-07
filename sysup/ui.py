"""The live terminal dashboard.

Two things drive the design.

First, the sampling loop must keep near-perfect time, because its lateness *is*
the stall detector.  So the loop targets absolute wake-up times rather than
sleeping for a fixed interval, and rendering is never allowed to push the next
sample late — a dashboard that stutters would report itself as a system freeze.

Second, a diagnosis takes minutes on a 32B model, and the machine being
diagnosed is by definition already struggling.  So it runs on a background
thread and the live view keeps sampling throughout: the freeze you are trying
to catch may well happen *while* the report is being written, and that is
exactly when the evidence is worth having.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import diagnose as diagnose_mod, knowledge, report as report_mod, rules
from .collect import History, ProcRow, Sampler
from .config import Settings

SPARK = "▁▂▃▄▅▆▇█"

SORTS = {
    "c": ("cpu", "CPU"),
    "m": ("memory", "memory"),
    "i": ("io_bps", "disk I/O"),
    "f": ("hard_faults", "page faults"),
    "t": ("threads", "threads"),
}

SEVERITY_STYLE = {5: "bold white on red", 4: "bold red", 3: "yellow",
                  2: "cyan", 1: "dim"}


def sparkline(values: list[float], width: int = 28,
              ceiling: float | None = None) -> str:
    if not values:
        return " " * width
    window = values[-width:]
    top = ceiling if ceiling is not None else max(window)
    if not top:
        return SPARK[0] * len(window)
    return "".join(
        SPARK[min(len(SPARK) - 1, int(value / top * (len(SPARK) - 1)))]
        for value in window)


def bar(fraction: float, width: int = 18) -> Text:
    fraction = max(0.0, min(1.0, fraction))
    filled = int(fraction * width)
    style = "red" if fraction > 0.9 else "yellow" if fraction > 0.75 else "green"
    text = Text()
    text.append("█" * filled, style=style)
    text.append("░" * (width - filled), style="dim")
    return text


def humanise(value: float, unit: str = "B") -> str:
    for suffix in ("", "K", "M", "G", "T"):
        if abs(value) < 1024:
            return f"{value:.0f}{suffix}{unit}" if suffix else f"{value:.0f}{unit}"
        value /= 1024
    return f"{value:.0f}P{unit}"


@dataclass
class UIState:
    sort_key: str = "cpu"
    sort_label: str = "CPU"
    paused: bool = False
    show_findings: bool = True
    #: Set while a diagnosis is running on its own thread.
    diagnosing: bool = False
    progress: str = ""
    last_report: str = ""
    message: str = ""
    message_until: float = 0.0
    findings: list[rules.Finding] = field(default_factory=list)
    selected: int = 0

    def say(self, text: str, seconds: float = 6.0) -> None:
        self.message = text
        self.message_until = time.monotonic() + seconds


class Dashboard:
    def __init__(self, settings: Settings, console: Console | None = None) -> None:
        self.settings = settings
        self.console = console or Console()
        self.sampler = Sampler()
        self.history = History(size=int(settings.get("history_samples", 300)))
        self.state = UIState()
        self.interval = float(settings.get("sample_interval", 1.0))
        self.top_n = int(settings.get("top_n", 12))
        self.stall_threshold = float(settings.get("stall_threshold_s", 2.5))
        self._stop = threading.Event()
        self._diagnosis_lock = threading.Lock()

    # ------------------------------------------------------------- rendering
    def _header(self) -> Panel:
        sample = self.history.latest()
        if sample is None:
            return Panel(Align.center("starting…"), border_style="dim")

        grid = Table.grid(expand=True, padding=(0, 2))
        for _ in range(4):
            grid.add_column(ratio=1)

        cpu = Group(
            Text.assemble(("CPU  ", "bold"), (f"{sample.cpu:5.1f}%",
                                              "bold white")),
            bar(sample.cpu / 100),
            Text(sparkline(self.history.series("cpu", 30), 22, 100.0),
                 style="cyan"))

        memory_fraction = sample.memory_percent / 100
        memory = Group(
            Text.assemble(("RAM  ", "bold"),
                          (f"{sample.memory_percent:5.1f}%", "bold white"),
                          (f"  {sample.memory_available / 1e9:.1f}G free",
                           "dim")),
            bar(memory_fraction),
            Text(sparkline(self.history.series("memory_percent", 30), 22, 100.0),
                 style="magenta"))

        # Service time, not percent-busy — see the note in gui.py.
        disk = Group(
            Text.assemble(("DISK ", "bold"),
                          (f"{sample.disk_latency_ms:5.1f}ms", "bold white"),
                          (f"  {(sample.disk_read_bps + sample.disk_write_bps) / 1e6:.0f}MB/s",
                           "dim")),
            bar(min(1.0, sample.disk_latency_ms / 40.0)),
            Text(sparkline(self.history.series("disk_latency_ms", 30), 22),
                 style="yellow"))

        # Hard faults get equal billing with CPU deliberately: it is the
        # number that explains freezing, and no standard tool shows it.
        faults = Group(
            Text.assemble(("FAULTS ", "bold"),
                          (f"{sample.hard_faults:6.0f}/s", "bold white")),
            bar(min(1.0, sample.hard_faults / 500)),
            Text(sparkline(self.history.series("hard_faults", 30), 22),
                 style="red"))

        grid.add_row(cpu, memory, disk, faults)
        uptime = (time.time() - self.history.started) / 60
        title = (f"System Supe-Up  ·  watching {uptime:.0f} min  ·  "
                 f"{self.history.count} samples")
        return Panel(grid, title=title, title_align="left", border_style="blue")

    def _alerts(self) -> Panel | None:
        sample = self.history.latest()
        if sample is None:
            return None
        lines: list[Text] = []

        if self.history.stalls:
            recent = [s for s in self.history.stalls
                      if time.time() - s["at"] < 120]
            if recent:
                worst = max(recent, key=lambda s: s["lateness"])
                lines.append(Text.assemble(
                    ("  STALL  ", "bold white on red"),
                    (f"  the whole machine stopped for {worst['lateness']:.1f}s"
                     f"  ({len(recent)} in the last 2 min)", "bold red")))

        for window in sample.hung_windows[:3]:
            row = sample.find(window.pid)
            reason = ""
            if row is not None and row.waits.dominant:
                reason = f" — {row.waits.describe()}"
            lines.append(Text.assemble(
                (" NOT RESPONDING ", "bold white on dark_orange3"),
                (f"  {window.title[:58]}{reason}", "bold yellow")))

        if not lines:
            return None
        return Panel(Group(*lines), border_style="red", padding=(0, 1))

    def _processes(self) -> Panel:
        sample = self.history.latest()
        table = Table(expand=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("process", ratio=3, no_wrap=True)
        table.add_column("pid", justify="right", width=7)
        table.add_column("CPU", justify="right", width=7)
        table.add_column("memory", justify="right", width=9)
        table.add_column("I/O", justify="right", width=9)
        table.add_column("faults", justify="right", width=8)
        table.add_column("thr", justify="right", width=5)
        table.add_column("state", ratio=2, no_wrap=True)

        if sample is not None:
            key = self.state.sort_key
            rows = sorted(sample.processes,
                          key=lambda r: -getattr(r, key, 0))[:self.top_n]
            for row in rows:
                table.add_row(*self._process_cells(row))

        # Text() rather than a plain string: rich parses "[c]" in a markup
        # string as a style tag and silently eats it, which turns the key
        # hints into "pu emory /o aults hreads".
        return Panel(table, title=f"processes by {self.state.sort_label}",
                     title_align="left", border_style="dim",
                     subtitle=Text("[c]pu  [m]emory  [i]/o  [f]aults  "
                                   "[t]hreads", style="dim"),
                     subtitle_align="right")

    def _process_cells(self, row: ProcRow) -> list[Text]:
        fact = knowledge.lookup(row.name)
        name = Text(row.name[:38],
                    style="bold red" if row.hung else
                    "yellow" if row.waits.dominant else "")
        if row.hung:
            name.append("  NOT RESPONDING", style="bold white on red")
        elif fact and fact.essential:
            name.append("  system", style="dim")

        cpu_style = ("bold red" if row.cpu > 40 else
                     "yellow" if row.cpu > 15 else "")
        fault_style = ("bold red" if row.hard_faults > 100 else
                       "yellow" if row.hard_faults > 20 else "dim")

        if row.waits.dominant:
            bucket = row.waits.buckets[row.waits.dominant]
            state = Text(f"{bucket}× {row.waits.dominant}", style="yellow")
        elif row.waits.running:
            state = Text(f"{row.waits.running} running", style="dim")
        else:
            state = Text("idle", style="dim")

        return [
            name,
            Text(str(row.pid), style="dim"),
            Text(f"{row.cpu:5.1f}%", style=cpu_style),
            Text(humanise(row.memory)),
            Text(humanise(row.io_bps) + "/s" if row.io_bps > 1e5 else "—",
                 style="dim" if row.io_bps <= 1e5 else ""),
            Text(f"{row.hard_faults:.0f}" if row.hard_faults else "—",
                 style=fault_style),
            Text(str(row.threads), style="dim"),
            state,
        ]

    def _findings_panel(self) -> Panel:
        findings = self.state.findings
        if not findings:
            body = Align.center(
                Text("nothing wrong found yet — keep watching",
                     style="dim green"), vertical="middle")
            return Panel(body, title="findings", title_align="left",
                         border_style="green")

        lines: list[Text] = []
        for index, finding in enumerate(findings[:7]):
            marker = "▸ " if index == self.state.selected else "  "
            style = SEVERITY_STYLE.get(finding.severity, "")
            line = Text(marker, style="bold cyan")
            line.append(f"{finding.severity_name:>8}  ", style=style)
            line.append(finding.title[:70])
            lines.append(line)
            if index == self.state.selected:
                detail = Text(finding.explanation, style="dim italic")
                detail.truncate(400, overflow="ellipsis")
                # Indent the wrapped continuation too, so the detail reads as
                # belonging to the row above it rather than as a new row.
                detail.pad_left(12)
                lines.append(detail)

        return Panel(Group(*lines),
                     title=f"findings ({len(findings)})", title_align="left",
                     border_style="yellow",
                     subtitle=Text("[↑↓] select   [x] explain", style="dim"),
                     subtitle_align="right")

    def _footer(self) -> Panel:
        state = self.state
        if state.diagnosing:
            body = Text.assemble(
                ("  DIAGNOSING  ", "bold white on blue"),
                (f"  {state.progress}", "cyan"))
        elif state.message and time.monotonic() < state.message_until:
            body = Text(state.message, style="bold green")
        else:
            body = Text.assemble(
                ("[d]", "bold cyan"), (" full diagnosis + report   ", ""),
                ("[x]", "bold cyan"), (" explain selected   ", ""),
                ("[s]", "bold cyan"), (" save snapshot   ", ""),
                ("[p]", "bold cyan"), (" pause   ", ""),
                ("[q]", "bold cyan"), (" quit", ""))
            if state.paused:
                body = Text.assemble(("  PAUSED  ", "bold black on yellow"),
                                     ("  press [p] to resume", "yellow"))
        return Panel(body, border_style="dim", padding=(0, 1))

    def render(self) -> Layout:
        layout = Layout()
        alerts = self._alerts()

        sections = [Layout(self._header(), name="header", size=6)]
        if alerts is not None:
            sections.append(Layout(alerts, name="alerts",
                                   size=len(sample_lines(alerts)) + 2))
        sections.append(Layout(self._processes(), name="processes",
                               ratio=3))
        if self.state.show_findings:
            sections.append(Layout(self._findings_panel(), name="findings",
                                   ratio=2))
        sections.append(Layout(self._footer(), name="footer", size=3))
        layout.split_column(*sections)
        return layout

    # ------------------------------------------------------------- actions
    def _refresh_findings(self) -> None:
        try:
            self.state.findings = rules.analyse(self.history)
        except Exception:
            self.state.findings = []
        if self.state.selected >= len(self.state.findings):
            self.state.selected = max(0, len(self.state.findings) - 1)

    def start_diagnosis(self) -> None:
        if self.state.diagnosing:
            return
        if self.history.count < 5:
            self.state.say("need a few more seconds of data first")
            return
        self.state.diagnosing = True
        self.state.progress = "starting"

        def work() -> None:
            try:
                def progress(message: str) -> None:
                    self.state.progress = message

                with self._diagnosis_lock:
                    diagnosis = diagnose_mod.diagnose(
                        self.history, self.settings, on_progress=progress,
                        cancel=self._stop)
                    paths = report_mod.save(diagnosis)
                self.state.last_report = str(paths["html"])
                self.state.say(f"report saved → {paths['html']}", 30)
            except Exception as error:                     # never kill the UI
                self.state.say(f"diagnosis failed: {error}", 15)
            finally:
                self.state.diagnosing = False
                self.state.progress = ""

        threading.Thread(target=work, daemon=True, name="diagnose").start()

    def explain_selected(self) -> None:
        findings = self.state.findings
        if not findings:
            self.state.say("nothing selected")
            return
        finding = findings[min(self.state.selected, len(findings) - 1)]
        if self.state.diagnosing:
            self.state.say("already busy")
            return
        self.state.diagnosing = True
        self.state.progress = f"asking about “{finding.title[:40]}”"

        def work() -> None:
            try:
                answer = diagnose_mod.triage(finding, self.settings,
                                             cancel=self._stop)
                self.state.say(answer.replace("\n", " ")[:400], 40)
            except Exception as error:
                self.state.say(f"could not explain: {error}", 10)
            finally:
                self.state.diagnosing = False
                self.state.progress = ""

        threading.Thread(target=work, daemon=True, name="triage").start()

    def save_snapshot(self) -> None:
        try:
            diagnosis = diagnose_mod.diagnose(
                self.history, self.settings, use_model=False)
            paths = report_mod.save(diagnosis)
            self.state.say(f"snapshot saved → {paths['html']}", 20)
        except Exception as error:
            self.state.say(f"could not save: {error}", 10)

    # ---------------------------------------------------------------- input
    def _handle_key(self, key: str) -> bool:
        """Returns False when the user wants to quit."""
        state = self.state
        if key in ("q", "\x03", "\x1b"):
            return False
        if key == "d":
            self.start_diagnosis()
        elif key == "x":
            self.explain_selected()
        elif key == "s":
            self.save_snapshot()
        elif key == "p":
            state.paused = not state.paused
            if not state.paused:
                # Forget the pre-pause baseline, or the paused period is
                # reported as scheduler lateness — a freeze that never was.
                self.sampler.reset()
        elif key == "v":
            state.show_findings = not state.show_findings
        elif key in SORTS:
            state.sort_key, state.sort_label = SORTS[key]
        elif key == "UP":
            state.selected = max(0, state.selected - 1)
        elif key == "DOWN":
            state.selected = min(max(0, len(state.findings) - 1),
                                 state.selected + 1)
        return True

    def _poll_keys(self) -> bool:
        """Non-blocking keyboard read.  False means quit."""
        try:
            import msvcrt
        except ImportError:
            return True
        while msvcrt.kbhit():
            raw = msvcrt.getwch()
            if raw in ("\x00", "\xe0"):        # an arrow or function key
                code = msvcrt.getwch()
                mapped = {"H": "UP", "P": "DOWN"}.get(code, "")
                if mapped and not self._handle_key(mapped):
                    return False
                continue
            if not self._handle_key(raw.lower()):
                return False
        return True

    # ----------------------------------------------------------------- loop
    def run(self) -> None:
        self.sampler.sample()          # prime; the first sample has no rates
        next_tick = time.monotonic() + self.interval
        ticks = 0

        with Live(self.render(), console=self.console, refresh_per_second=4,
                  screen=True, transient=False) as live:
            while True:
                if not self._poll_keys():
                    break

                now = time.monotonic()
                if now >= next_tick:
                    if not self.state.paused:
                        sample = self.sampler.sample(self.interval)
                        self.history.add(sample, self.stall_threshold)
                        ticks += 1
                        # Re-running every rule on every tick is wasted work;
                        # findings do not change meaningfully in one second.
                        if ticks % 5 == 0:
                            self._refresh_findings()
                    # Absolute scheduling, so a slow render cannot make the
                    # next sample late and fake a stall.
                    next_tick += self.interval
                    if next_tick < now:        # genuinely fell behind
                        next_tick = now + self.interval
                    live.update(self.render())
                else:
                    live.update(self.render())
                    time.sleep(min(0.12, max(0.0, next_tick - now)))

        self._stop.set()
        if self.state.last_report:
            self.console.print(f"\nLast report: {self.state.last_report}")


def sample_lines(panel: Panel) -> list:
    """How many lines a panel's renderable will take, for layout sizing."""
    renderable = panel.renderable
    if isinstance(renderable, Group):
        return list(renderable.renderables)
    return [renderable]
