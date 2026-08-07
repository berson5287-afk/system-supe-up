"""Keep the evidence from around a freeze, instead of throwing it away.

The hard part of diagnosing an intermittent stall is not detecting it — that
is a timing measurement — but that by the time anyone looks, the seconds that
mattered are gone. The live view has moved on and the ring buffer has rolled.

So when a stall is measured, the samples on either side of it are lifted out
and kept: what the machine was doing on the way in, during, and coming back
out. That window is then reduced to a verdict, by comparing the quiet period
before the stall against the stall itself. A number is only interesting if it
*changed*, and "disk latency went from 3 ms to 418 ms" is an explanation
where "disk latency is 418 ms" is only an observation.

This deliberately does not need ETW. Everything in the summary below —
per-process hard faults, disk service time, commit, who was unscheduled,
which windows were dead — is already collected every second. What was missing
was keeping it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .collect import History, Sample
from .config import REPORT_DIR

INCIDENT_DIR = REPORT_DIR.parent / "incidents"

#: How much of the run-up and recovery to keep around a stall.
BEFORE_SECONDS = 60.0
AFTER_SECONDS = 25.0
#: How many samples past the last stalling one still count as the event.
#:
#: A freeze rarely fits in one sample: the sample that trips the detector is
#: the one that arrived late, and the next one is the machine catching up
#: while the disk is still draining. Both belong to the event. A fixed *time*
#: window was tried first and is wrong — it cannot tell "still frozen" from
#: "recovered", so on a quick recovery it swallows healthy samples and dilutes
#: the very averages the verdict is built from.
DURING_CATCHUP_SAMPLES = 1


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _delta_phrase(before: float, during: float, unit: str,
                  digits: int = 1) -> str:
    """"3.1 ms → 418.0 ms (135× worse)" — the shape that explains something."""
    text = f"{before:.{digits}f}{unit} → {during:.{digits}f}{unit}"
    if before > 0 and during > before * 1.5:
        text += f" ({during / before:.0f}× worse)"
    elif before > 0 and during < before * 0.67:
        text += f" ({before / during:.0f}× lower)"
    return text


@dataclass
class Incident:
    """One measured freeze, with the evidence from either side of it."""

    at: float
    lateness: float
    before: list[Sample] = field(default_factory=list)
    during: list[Sample] = field(default_factory=list)
    after: list[Sample] = field(default_factory=list)
    #: Filled once the recovery window has been collected.
    complete: bool = False

    # -- derived ----------------------------------------------------------
    def _compare(self, attribute: str) -> tuple[float, float]:
        quiet = [getattr(s, attribute, 0.0) for s in self.before
                 if not s.discontinuity]
        stall = [getattr(s, attribute, 0.0) for s in self.during
                 if not s.discontinuity]
        return _mean(quiet), _mean(stall)

    def unscheduled(self) -> list[tuple[str, int]]:
        """Processes that had windows up but got no CPU during the stall.

        The interesting victims. A process burning CPU through a freeze is
        suspicious; a process with a window that received nothing is what the
        user was actually staring at.
        """
        if not self.during:
            return []
        sample = self.during[0]
        return [(row.name, row.pid) for row in sample.processes
                if row.title and row.cpu < 0.05][:8]

    def culprits(self) -> list[tuple[str, int, float, float]]:
        """(name, pid, hard faults/s, MB/s) for whoever was working hardest."""
        if not self.during:
            return []
        totals: dict[tuple[str, int], list[float]] = {}
        for sample in self.during:
            for row in sample.processes:
                if row.hard_faults <= 0 and row.io_bps <= 0:
                    continue
                key = (row.name, row.pid)
                current = totals.setdefault(key, [0.0, 0.0])
                current[0] += row.hard_faults
                current[1] += row.io_bps
        count = max(1, len(self.during))
        ranked = sorted(totals.items(),
                        key=lambda kv: -(kv[1][0] + kv[1][1] / 5e6))
        return [(name, pid, values[0] / count, values[1] / count / 1e6)
                for (name, pid), values in ranked[:5]]

    def hung(self) -> list[str]:
        seen: list[str] = []
        for sample in self.during:
            for window in sample.hung_windows:
                if window.title not in seen:
                    seen.append(window.title)
        return seen[:5]

    def verdict(self) -> tuple[str, list[str]]:
        """A probable cause, and the lines of evidence that support it.

        The reasoning is ordered by how specific the evidence is, not by how
        dramatic it looks: storage service time and hard faults name a
        mechanism, whereas high CPU is compatible with the machine simply
        being busy and not stalled at all.
        """
        faults_before, faults_during = self._compare("hard_faults")
        latency_before, latency_during = self._compare("disk_latency_ms")
        commit_before, commit_during = self._compare("commit_percent")
        memory_before, memory_during = self._compare("memory_percent")
        cpu_before, cpu_during = self._compare("cpu")
        ready_before, ready_during = self._compare("ready_threads")

        evidence: list[str] = []
        if faults_during > 1 or faults_before > 1:
            evidence.append("hard faults: " + _delta_phrase(
                faults_before, faults_during, "/s", 0))
        if latency_during > 0.01 or latency_before > 0.01:
            evidence.append("disk service time: " + _delta_phrase(
                latency_before, latency_during, " ms", 2))
        if commit_during:
            evidence.append("commit charge: " + _delta_phrase(
                commit_before, commit_during, "%", 0))
        evidence.append("memory in use: " + _delta_phrase(
            memory_before, memory_during, "%", 0))
        evidence.append("CPU: " + _delta_phrase(cpu_before, cpu_during, "%", 0))
        if ready_during > 1:
            evidence.append("threads queued for CPU: " + _delta_phrase(
                ready_before, ready_during, "", 0))

        paging = faults_during > 100 and faults_during > faults_before * 2
        storage = latency_during > 20 and latency_during > latency_before * 3
        starved = cpu_during > 90 and ready_during > 4
        committed = commit_during > 92

        if paging and storage:
            cause = ("memory pressure driving the disk — the machine ran out "
                     "of RAM, and the paging that followed saturated the drive")
        elif paging:
            cause = ("memory pressure — pages were being fetched back from "
                     "disk faster than the machine could serve them")
        elif storage:
            cause = ("storage — the drive stopped answering promptly, and "
                     "everything waiting on it stopped with it")
        elif committed:
            cause = ("the commit limit — Windows was close to refusing "
                     "allocations, so it was trimming applications instead")
        elif starved:
            cause = "the CPU being fully committed with work queued behind it"
        else:
            cause = ("something that blocks without showing up as load. CPU, "
                     "memory and disk were all unremarkable while the machine "
                     "was unresponsive, which rules out the usual suspects "
                     "and points at a driver or a kernel-level wait")
        return cause, evidence

    def summary(self) -> str:
        cause, evidence = self.verdict()
        when = time.strftime("%H:%M:%S", time.localtime(self.at))
        lines = [f"System stall: {self.lateness:.2f} seconds at {when}", ""]
        lines += [f"  {item}" for item in evidence]

        culprits = self.culprits()
        if culprits:
            lines.append("")
            lines.append("  busiest during the stall:")
            for name, pid, faults, megabytes in culprits:
                parts = []
                if faults > 0.5:
                    parts.append(f"{faults:.0f} hard faults/s")
                if megabytes > 0.5:
                    parts.append(f"{megabytes:.1f} MB/s")
                lines.append(f"    {name} ({pid}) — {', '.join(parts) or 'idle'}")

        unscheduled = self.unscheduled()
        if unscheduled:
            lines.append("")
            lines.append("  got no CPU at all while the machine was frozen:")
            lines.append("    " + ", ".join(
                f"{name} ({pid})" for name, pid in unscheduled))

        hung = self.hung()
        if hung:
            lines.append("")
            lines.append("  not responding: " + "; ".join(
                f"“{title[:52]}”" for title in hung))

        lines += ["", f"  Probable cause: {cause}."]
        if not self.complete:
            lines.append("  (recovery window still being collected)")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        cause, evidence = self.verdict()
        return {
            "at": self.at,
            "when": time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(self.at)),
            "lateness": round(self.lateness, 3),
            "probable_cause": cause,
            "evidence": evidence,
            "busiest": [
                {"name": n, "pid": p, "hard_faults_per_s": round(f, 1),
                 "mb_per_s": round(m, 2)}
                for n, p, f, m in self.culprits()],
            "unscheduled": [{"name": n, "pid": p}
                            for n, p in self.unscheduled()],
            "not_responding": self.hung(),
            "samples": {"before": len(self.before), "during": len(self.during),
                        "after": len(self.after)},
            # The raw window, so a later version can plot it without having to
            # have been running at the time.
            "timeline": [
                {"t": round(s.at - self.at, 2), "cpu": round(s.cpu, 1),
                 "memory_percent": round(s.memory_percent, 1),
                 "commit_percent": round(s.commit_percent, 1),
                 "hard_faults": round(s.hard_faults, 1),
                 "disk_latency_ms": round(s.disk_latency_ms, 3),
                 "disk_mb_s": round(
                     (s.disk_read_bps + s.disk_write_bps) / 1e6, 2),
                 "lateness": round(s.lateness, 3),
                 "ready_threads": s.ready_threads,
                 "hung": len(s.hung_windows)}
                for s in (self.before + self.during + self.after)],
        }


class IncidentRecorder:
    """Watches a History and preserves the window around each stall."""

    def __init__(self, history: History,
                 before_seconds: float = BEFORE_SECONDS,
                 after_seconds: float = AFTER_SECONDS,
                 catchup_samples: int = DURING_CATCHUP_SAMPLES,
                 directory: Path | None = None) -> None:
        self.history = history
        self.before_seconds = before_seconds
        self.after_seconds = after_seconds
        self.catchup_samples = catchup_samples
        self._catchup = 0
        self.directory = Path(directory) if directory else INCIDENT_DIR
        self.incidents: list[Incident] = []
        self._pending: Incident | None = None

    def on_sample(self, sample: Sample, stall: dict | None) -> Incident | None:
        """Feed every sample through.  Returns an incident when one completes.

        Called from the sampling thread, so it does no I/O beyond writing a
        finished incident — which happens at most once per stall.
        """
        if self._pending is not None:
            span = sample.at - self._pending.at
            if not sample.discontinuity:
                # Still the event while it keeps stalling, plus the catch-up
                # sample immediately behind the last stall. After that the
                # machine has recovered and everything else is aftermath.
                if stall is not None:
                    self._pending.during.append(sample)
                    self._catchup = self.catchup_samples
                elif self._catchup > 0:
                    self._pending.during.append(sample)
                    self._catchup -= 1
                else:
                    self._pending.after.append(sample)
            # A second stall inside the window is part of the same event, not
            # a new one — extend rather than start over.
            if stall is not None:
                self._pending.lateness = max(self._pending.lateness,
                                             sample.lateness)
            if span >= self.after_seconds:
                finished, self._pending = self._pending, None
                finished.complete = True
                self.incidents.append(finished)
                self._save(finished)
                return finished
            return None

        if stall is None:
            return None

        interval = max(sample.interval, 1e-3)
        wanted = int(self.before_seconds / interval) + 2
        window = self.history.recent(wanted)
        # The stalling sample is already in history; everything before it is
        # the run-up.
        before = [s for s in window[:-1] if not s.discontinuity]
        self._pending = Incident(at=sample.at, lateness=sample.lateness,
                                 before=before, during=[sample])
        self._catchup = self.catchup_samples
        return None

    def _save(self, incident: Incident) -> Path | None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S",
                                  time.localtime(incident.at))
            path = self.directory / f"incident-{stamp}.json"
            path.write_text(json.dumps(incident.as_dict(), indent=1),
                            encoding="utf-8")
            return path
        except (OSError, ValueError, TypeError):
            # Losing an incident file must never disturb sampling.
            return None

    def latest(self) -> Incident | None:
        return self.incidents[-1] if self.incidents else None


def load_recent(directory: Path | None = None,
                limit: int = 20) -> list[dict]:
    """Previously recorded incidents, newest first."""
    directory = Path(directory) if directory else INCIDENT_DIR
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("incident-*.json"), reverse=True)[:limit]
    out = []
    for path in files:
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out
