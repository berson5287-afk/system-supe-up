"""A permanent record of every change made, and whether it actually helped.

Three things this fixes, in order of how much they matter.

**Undo survives a crash.** Rollback data used to live in the dialog that made
the change, so closing the window — or the app dying, which is plausible on a
machine sick enough to need this tool — lost the ability to put things back.
It is now written to disk before the action runs.

**"Did it work" stops being a matter of opinion.** Every action declares which
measurements it expects to move and in which direction. The state is captured
before, captured again after a settling period, and compared. The result is
"available memory rose 2.1 GB, hard faults fell 94%" rather than "watch the
gauges for a bit".

**The machine accumulates evidence about itself.** Because outcomes are kept,
the next diagnosis can be told that restarting Explorer helped here three
times and that changing the power plan did nothing — which is real, local,
measured knowledge, and it is arrived at without giving a language model any
authority to experiment.

The file is append-only JSONL. A half-written line at the end of a crashed run
costs one entry, not the log.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import REPORT_DIR

JOURNAL_PATH = REPORT_DIR.parent / "action-journal.jsonl"

#: How long to let a change settle before measuring whether it worked.
#: Explorer takes a moment to come back; a service restart longer; freed
#: memory shows up almost at once. Long enough to be real, short enough that
#: nobody walks away first.
SETTLE_SECONDS = 8.0

#: Metric -> how to describe a change in it, and which direction is good.
METRICS: dict[str, tuple[str, str, str]] = {
    # key: (label, unit, "up" means better | "down" means better)
    "memory_available": ("available memory", "bytes", "up"),
    "memory_percent": ("memory in use", "%", "down"),
    "commit_percent": ("commit charge", "%", "down"),
    "hard_faults": ("hard faults", "/s", "down"),
    "disk_latency_ms": ("disk service time", "ms", "down"),
    "cpu": ("CPU", "%", "down"),
    "disk_free": ("free disk space", "bytes", "up"),
    "proc_handles": ("handles held", "", "down"),
    "proc_threads": ("threads", "", "down"),
    "proc_private": ("private memory", "bytes", "down"),
}


def _human(value: float, unit: str) -> str:
    if unit == "bytes":
        return f"{value / 1e9:.2f} GB" if abs(value) >= 1e9 \
            else f"{value / 1e6:.0f} MB"
    if unit == "%":
        return f"{value:.1f}%"
    if unit == "/s":
        return f"{value:.0f}/s"
    if unit == "ms":
        return f"{value:.2f} ms"
    return f"{value:,.0f}"


def capture_state(sample, params: dict | None = None) -> dict:
    """The measurements worth comparing, from a live sample.

    Includes the targeted process when the action names one, because most
    actions are aimed at a specific process and the machine-wide numbers move
    for a hundred unrelated reasons in the same eight seconds.
    """
    state: dict = {}
    if sample is not None:
        for key in ("memory_available", "memory_percent", "commit_percent",
                    "hard_faults", "disk_latency_ms", "cpu"):
            value = getattr(sample, key, None)
            if value is not None:
                state[key] = float(value)

    try:
        import psutil
        state["disk_free"] = float(
            psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").free)
    except Exception:
        pass

    pid = (params or {}).get("pid")
    if pid and sample is not None:
        row = sample.find(int(pid))
        if row is not None:
            state["proc_handles"] = float(row.handles)
            state["proc_threads"] = float(row.threads)
            state["proc_private"] = float(row.private)
            state["proc_exists"] = 1.0
        else:
            state["proc_exists"] = 0.0
    return state


@dataclass
class Change:
    metric: str
    before: float
    after: float

    @property
    def delta(self) -> float:
        return self.after - self.before

    @property
    def better(self) -> bool:
        _label, _unit, good = METRICS.get(self.metric, ("", "", "up"))
        return self.delta > 0 if good == "up" else self.delta < 0

    def significant(self) -> bool:
        """Is this bigger than the noise a machine makes on its own?

        Everything drifts over eight seconds. Without a floor, every action
        would be reported as having done something, which would make the
        verification worthless in exactly the way "watch the gauges" already
        was.
        """
        if self.metric in ("memory_available", "proc_private", "disk_free"):
            return abs(self.delta) > 100e6              # 100 MB
        if self.metric in ("memory_percent", "commit_percent", "cpu"):
            return abs(self.delta) > 3.0
        if self.metric == "hard_faults":
            return abs(self.delta) > 20
        if self.metric == "disk_latency_ms":
            return abs(self.delta) > 2.0
        if self.metric in ("proc_handles", "proc_threads"):
            return abs(self.delta) > max(50, self.before * 0.2)
        return abs(self.delta) > 0

    def describe(self) -> str:
        label, unit, _good = METRICS.get(self.metric,
                                         (self.metric, "", "up"))
        direction = "rose" if self.delta > 0 else "fell"
        text = (f"{label} {direction} from {_human(self.before, unit)} to "
                f"{_human(self.after, unit)}")
        if self.before:
            share = abs(self.delta) / abs(self.before) * 100
            if share >= 5:
                text += f" ({share:.0f}%)"
        return text


@dataclass
class JournalEntry:
    id: str = ""
    at: float = 0.0
    action_id: str = ""
    title: str = ""
    params: dict = field(default_factory=dict)
    reason: str = ""
    risk: str = "low"
    needs_admin: bool = False
    reversible: bool = True
    finding: str = ""
    #: "" until the action has run.
    result_ok: bool | None = None
    result_message: str = ""
    changed: bool = False
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    #: helped | no measurable change | made things worse | not verified
    verdict: str = ""
    undo: dict | None = None
    undone_at: float = 0.0

    def changes(self) -> list[Change]:
        return [Change(metric=key, before=float(value),
                       after=float(self.after[key]))
                for key, value in self.before.items()
                if key in self.after and key in METRICS]

    def summary(self) -> str:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(self.at))
        state = ("undone" if self.undone_at else
                 self.verdict or ("failed" if self.result_ok is False else "—"))
        return f"{when}  {self.title}  —  {state}"


class Journal:
    """Append-only, crash-safe record of everything this tool has changed."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else JOURNAL_PATH

    # -- writing -----------------------------------------------------------
    def _append(self, entry: JournalEntry) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(entry),
                                        ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except (OSError, TypeError, ValueError):
            # A journal that cannot be written must not stop a fix the user
            # asked for; they simply lose the record of it.
            pass

    def record(self, planned, before: dict, finding: str = "") -> JournalEntry:
        """Write the intent *before* the action runs.

        Deliberately before. If the action half-succeeds and then the process
        dies, there has to be a record that it was attempted at all — an entry
        with no outcome is a question worth asking, whereas no entry is
        indistinguishable from nothing having happened.
        """
        spec = planned.spec
        entry = JournalEntry(
            id=f"{int(time.time() * 1000):x}-{spec.id}",
            at=time.time(), action_id=spec.id, title=spec.title,
            params=dict(planned.params or {}), reason=planned.reason,
            risk=spec.risk, needs_admin=spec.needs_admin,
            reversible=spec.reversible, finding=finding, before=dict(before))
        self._append(entry)
        return entry

    def complete(self, entry: JournalEntry, result, after: dict | None = None,
                 verdict: str = "") -> JournalEntry:
        entry.result_ok = bool(result.ok)
        entry.result_message = result.message
        entry.changed = bool(result.changed)
        entry.undo = result.undo
        if after is not None:
            entry.after = dict(after)
        entry.verdict = verdict
        self._append(entry)
        return entry

    def mark_undone(self, entry: JournalEntry) -> None:
        entry.undone_at = time.time()
        self._append(entry)

    # -- reading -----------------------------------------------------------
    def entries(self, limit: int = 200) -> list[JournalEntry]:
        """Every entry, latest state per id — later lines supersede earlier."""
        if not self.path.exists():
            return []
        merged: dict[str, JournalEntry] = {}
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except ValueError:
                        continue        # a torn final line from a crash
                    try:
                        entry = JournalEntry(**data)
                    except TypeError:
                        continue        # written by a newer version
                    merged[entry.id] = entry
        except OSError:
            return []
        ordered = sorted(merged.values(), key=lambda e: -e.at)
        return ordered[:limit]

    def undoable(self) -> list[JournalEntry]:
        return [e for e in self.entries()
                if e.undo and not e.undone_at and e.result_ok]

    def outcomes_for(self, action_id: str) -> list[JournalEntry]:
        return [e for e in self.entries() if e.action_id == action_id
                and e.result_ok is not None]

    def advice(self, limit: int = 8) -> str:
        """What past attempts on *this machine* actually achieved.

        Handed to the investigator so it stops re-proposing something that
        has already been tried here and measured to do nothing.
        """
        tally: dict[str, list[str]] = {}
        for entry in self.entries(120):
            if entry.result_ok is None or not entry.verdict:
                continue
            tally.setdefault(entry.action_id, []).append(entry.verdict)
        if not tally:
            return ""
        lines = ["PREVIOUS ATTEMPTS ON THIS MACHINE (measured outcomes — do "
                 "not re-propose something that has repeatedly done nothing)"]
        for action_id, verdicts in list(tally.items())[:limit]:
            helped = sum(1 for v in verdicts if v == "helped")
            nothing = sum(1 for v in verdicts if v == "no measurable change")
            worse = sum(1 for v in verdicts if v == "made things worse")
            parts = []
            if helped:
                parts.append(f"helped {helped}×")
            if nothing:
                parts.append(f"no measurable change {nothing}×")
            if worse:
                parts.append(f"made things worse {worse}×")
            lines.append(f"- {action_id}: {', '.join(parts)}")
        return "\n".join(lines)


def verify(entry: JournalEntry, after: dict) -> tuple[str, list[Change]]:
    """Compare before and after.  Returns (verdict, significant changes).

    An action that declares no measurable effect is reported as unverified
    rather than as having failed — flushing a DNS cache genuinely does not
    move any number this program watches, and calling that "no change" would
    read as a failure when it is simply not measurable.
    """
    entry.after = dict(after)
    changes = [c for c in entry.changes() if c.significant()]

    # A process the action was supposed to end, that is gone, is a success
    # regardless of what the machine-wide numbers did.
    gone = (entry.before.get("proc_exists") == 1.0
            and after.get("proc_exists") == 0.0)

    if not changes and not gone:
        return "no measurable change", []

    good = [c for c in changes if c.better]
    bad = [c for c in changes if not c.better]
    if gone or (good and len(good) >= len(bad)):
        return "helped", changes
    if bad and not good:
        return "made things worse", changes
    return "no measurable change", changes
