"""Sampling: turn two kernel snapshots into rates, and notice stalls.

Everything interesting is a *rate*, not a total.  `explorer.exe` having taken
1.2 million hard faults since Tuesday says nothing; taking 400 of them in the
last second says the machine is thrashing right now.  So every sample is a
difference against the one before it, and the first sample deliberately
reports nothing.

The stall detector is the other half.  It works on a principle that no
threshold on a graph can reproduce: this loop asks to be woken once a second,
so if it wakes up 4 seconds late, the machine did not run *us* for 4 seconds —
and it almost certainly did not run whatever the user was typing into either.
That is a freeze, measured rather than inferred, and it catches the whole
class of stalls (driver, paging, storage) that leave the CPU graph at 5%.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

import psutil

from . import winapi

#: 100ns kernel ticks per second.
TICKS_PER_SECOND = 10_000_000


@dataclass
class ProcRow:
    """One process over one sampling interval."""

    pid: int
    name: str
    cpu: float = 0.0             # percent of one CPU-second per wall second
    cpu_kernel: float = 0.0      # the part spent in the kernel, of `cpu`
    memory: int = 0              # working set, bytes
    private: int = 0             # private commit, bytes — the honest "leak" number
    threads: int = 0
    handles: int = 0
    hard_faults: float = 0.0     # per second — paging pressure caused by this app
    read_bps: float = 0.0
    write_bps: float = 0.0
    io_ops: float = 0.0          # read+write operations per second
    waits: winapi.ThreadWaits = field(default_factory=winapi.ThreadWaits)
    hung: bool = False           # Windows says a window of this process is dead
    title: str = ""
    #: Windows terminal-services session. 0 is where services live; anything
    #: above it is an interactive sign-in. This is the difference between "a
    #: background agent nobody asked for" and "something the user opened", and
    #: it is far more reliable than looking for a window — only one process of
    #: a multi-process application owns the window, but every one of them
    #: shares the session.
    session: int = 0
    gdi: int = 0
    user_objects: int = 0
    age_s: float = 0.0

    @property
    def io_bps(self) -> float:
        return self.read_bps + self.write_bps


@dataclass
class Sample:
    """One instant of the whole machine."""

    at: float = 0.0
    #: How late this sample was versus the interval it asked for.  The stall
    #: signal — see the module docstring.
    lateness: float = 0.0
    interval: float = 1.0
    #: True when the gap since the previous sample was too long to reason
    #: about — the monitor was paused, or the machine slept.  Such a sample
    #: carries no rates and must never be read as a stall: the time was not
    #: stolen by the system, it was time we were not watching.  Getting this
    #: wrong reports a six-second pause as a six-second freeze.
    discontinuity: bool = False

    cpu: float = 0.0
    cpu_per_core: list[float] = field(default_factory=list)
    memory_percent: float = 0.0
    memory_used: int = 0
    memory_total: int = 0
    memory_available: int = 0
    swap_percent: float = 0.0
    commit_percent: float = 0.0

    disk_read_bps: float = 0.0
    disk_write_bps: float = 0.0
    disk_busy: float = 0.0       # percent of the interval the disk had work
    #: Average service time per disk operation, in milliseconds.
    #:
    #: This, not `disk_busy`, is the number that matters on anything modern.
    #: An NVMe absorbing 123 MB/s of writes accrues about 2 ms of device time
    #: per second — 0.2% busy — so a "disk is saturated" threshold on the
    #: percentage can never be reached and the check silently never fires.
    #: Service time does not have that problem: a healthy NVMe answers in
    #: well under a millisecond, and a drive that is struggling, queued up or
    #: resetting takes tens or hundreds. It is also the quantity a stalled
    #: application is actually waiting on.
    disk_latency_ms: float = 0.0
    disk_ops: float = 0.0        # operations per second
    net_sent_bps: float = 0.0
    net_recv_bps: float = 0.0

    hard_faults: float = 0.0     # machine-wide, per second
    context_switches: float = 0.0

    processes: list[ProcRow] = field(default_factory=list)
    hung_windows: list[winapi.HungWindow] = field(default_factory=list)
    ready_threads: int = 0       # threads wanting CPU but not getting it

    @property
    def stalled(self) -> bool:
        return self.lateness >= 2.5 and not self.discontinuity

    def by_cpu(self, limit: int = 10) -> list[ProcRow]:
        return sorted(self.processes, key=lambda r: -r.cpu)[:limit]

    def by_memory(self, limit: int = 10) -> list[ProcRow]:
        return sorted(self.processes, key=lambda r: -r.memory)[:limit]

    def by_io(self, limit: int = 10) -> list[ProcRow]:
        return sorted(self.processes, key=lambda r: -r.io_bps)[:limit]

    def by_faults(self, limit: int = 10) -> list[ProcRow]:
        return sorted(self.processes, key=lambda r: -r.hard_faults)[:limit]

    def find(self, pid: int) -> ProcRow | None:
        for row in self.processes:
            if row.pid == pid:
                return row
        return None


#: A gap longer than this cannot be a stall — it is a pause, a sleep, or a
#: laptop lid. Windows does not withhold the CPU for ten seconds and then
#: carry on; that is somebody closing the machine. Expressed as both an
#: absolute floor and a multiple of the interval so it stays sensible whether
#: sampling every 250 ms or every 5 seconds.
CONTINUITY_LIMIT_S = 10.0
CONTINUITY_MULTIPLE = 6.0


class Sampler:
    """Holds the previous snapshot so each sample can be a rate."""

    def __init__(self, cpu_count: int | None = None) -> None:
        self.cpu_count = cpu_count or psutil.cpu_count(logical=True) or 1
        self._prev: dict[int, winapi.ProcSnapshot] = {}
        self._prev_at: float = 0.0
        self._prev_disk = None
        self._prev_net = None
        self._prev_switches: int | None = None
        self._boot = psutil.boot_time()
        #: GUI handle counts need a process handle each, which is far too
        #: expensive per tick for 375 processes.  Only windowed processes are
        #: worth asking about, and only every few seconds.
        self._gui_cache: dict[int, tuple[int, int]] = {}
        self._gui_checked_at: float = 0.0

    def reset(self) -> None:
        """Forget the previous sample, so the next one is a fresh baseline.

        Call this after anything that stops sampling for a while — a pause, a
        resume from sleep, a settings change. Without it the next sample
        differences against a stale baseline and reports the whole gap as
        scheduler lateness, which is indistinguishable from a genuine freeze.
        """
        self._prev = {}
        self._prev_at = 0.0
        self._prev_disk = None
        self._prev_net = None
        self._prev_switches = None

    def sample(self, expected_interval: float = 1.0) -> Sample:
        now = time.monotonic()
        elapsed = (now - self._prev_at) if self._prev_at else expected_interval
        elapsed = max(elapsed, 1e-3)

        # A gap far larger than we asked for means we were not running, not
        # that the machine was not running. Rates across it would be averages
        # over an unknown period, and its "lateness" is not a stall.
        limit = max(CONTINUITY_LIMIT_S, expected_interval * CONTINUITY_MULTIPLE)
        broken = bool(self._prev_at) and elapsed > limit

        sample = Sample(at=time.time(), interval=elapsed,
                        discontinuity=broken)
        if self._prev_at and not broken:
            sample.lateness = max(0.0, elapsed - expected_interval)

        if broken:
            # Re-prime instead of reporting nonsense: read the machine's
            # current state, but publish no rates derived from the old one.
            self.reset()
            current = winapi.snapshot_processes()
            self._read_system(sample, elapsed)
            self._read_processes(sample, current, elapsed)
            self._prev = current
            self._prev_at = now
            return sample

        self._read_system(sample, elapsed)
        current = winapi.snapshot_processes()
        self._read_processes(sample, current, elapsed)

        self._prev = current
        self._prev_at = now
        return sample

    # -- machine-wide ------------------------------------------------------
    def _read_system(self, sample: Sample, elapsed: float) -> None:
        try:
            sample.cpu_per_core = psutil.cpu_percent(percpu=True)
            sample.cpu = sum(sample.cpu_per_core) / len(sample.cpu_per_core)
        except Exception:
            pass

        try:
            memory = psutil.virtual_memory()
            sample.memory_percent = memory.percent
            sample.memory_used = memory.used
            sample.memory_total = memory.total
            sample.memory_available = memory.available
            swap = psutil.swap_memory()
            sample.swap_percent = swap.percent
            # On Windows psutil's "swap" is the page file, but the number that
            # actually predicts an out-of-memory stall is total commit against
            # the commit limit — RAM plus page file — because Windows refuses
            # allocations on that, not on free RAM.
            sample.commit_percent = memory.percent
        except Exception:
            pass

        try:
            disk = psutil.disk_io_counters()
            if disk and self._prev_disk:
                sample.disk_read_bps = max(
                    0.0, (disk.read_bytes - self._prev_disk.read_bytes) / elapsed)
                sample.disk_write_bps = max(
                    0.0, (disk.write_bytes - self._prev_disk.write_bytes) / elapsed)
                busy_ms = ((disk.read_time + disk.write_time)
                           - (self._prev_disk.read_time + self._prev_disk.write_time))
                sample.disk_busy = max(0.0, min(100.0, busy_ms / (elapsed * 10)))
                operations = ((disk.read_count + disk.write_count)
                              - (self._prev_disk.read_count
                                 + self._prev_disk.write_count))
                sample.disk_ops = max(0.0, operations / elapsed)
                if operations > 0:
                    sample.disk_latency_ms = max(0.0, busy_ms / operations)
            self._prev_disk = disk
        except Exception:
            pass

        try:
            net = psutil.net_io_counters()
            if net and self._prev_net:
                sample.net_sent_bps = max(
                    0.0, (net.bytes_sent - self._prev_net.bytes_sent) / elapsed)
                sample.net_recv_bps = max(
                    0.0, (net.bytes_recv - self._prev_net.bytes_recv) / elapsed)
            self._prev_net = net
        except Exception:
            pass

        try:
            switches = psutil.cpu_stats().ctx_switches
            if self._prev_switches is not None:
                sample.context_switches = max(
                    0.0, (switches - self._prev_switches) / elapsed)
            self._prev_switches = switches
        except Exception:
            pass

    # -- per process -------------------------------------------------------
    def _read_processes(self, sample: Sample,
                        current: dict[int, winapi.ProcSnapshot],
                        elapsed: float) -> None:
        hung = winapi.hung_windows()
        sample.hung_windows = hung
        hung_pids = {window.pid for window in hung}

        gui_pids: set[int] = set()
        rows: list[ProcRow] = []
        total_faults = 0.0
        ready = 0

        for pid, now_snap in current.items():
            if pid == 0:
                continue    # the idle process is not a suspect
            was = self._prev.get(pid)
            # A pid reused by a new process would otherwise inherit the old
            # one's counters and report an absurd rate for one tick.
            if was is not None and was.create_time != now_snap.create_time:
                was = None

            row = ProcRow(pid=pid, name=now_snap.name,
                          memory=now_snap.working_set,
                          private=now_snap.private_bytes,
                          threads=now_snap.threads,
                          handles=now_snap.handles,
                          waits=now_snap.waits,
                          session=now_snap.session,
                          hung=pid in hung_pids)
            ready += now_snap.waits.ready

            if was is not None:
                busy = ((now_snap.kernel_time - was.kernel_time)
                        + (now_snap.user_time - was.user_time))
                row.cpu = max(0.0, busy / TICKS_PER_SECOND / elapsed * 100.0
                              / self.cpu_count)
                kernel = now_snap.kernel_time - was.kernel_time
                row.cpu_kernel = max(0.0, kernel / TICKS_PER_SECOND / elapsed
                                     * 100.0 / self.cpu_count)
                row.hard_faults = max(
                    0.0, (now_snap.hard_faults - was.hard_faults) / elapsed)
                row.read_bps = max(
                    0.0, (now_snap.read_bytes - was.read_bytes) / elapsed)
                row.write_bps = max(
                    0.0, (now_snap.write_bytes - was.write_bytes) / elapsed)
                row.io_ops = max(
                    0.0, ((now_snap.read_ops - was.read_ops)
                          + (now_snap.write_ops - was.write_ops)) / elapsed)
                total_faults += row.hard_faults

            if now_snap.session:
                gui_pids.add(pid)
            rows.append(row)

        sample.hard_faults = total_faults
        sample.ready_threads = ready
        self._attach_titles(rows, gui_pids, hung_pids)
        sample.processes = rows

    def _attach_titles(self, rows: list[ProcRow], gui_pids: set[int],
                       hung_pids: set[int]) -> None:
        titles = winapi.window_titles_for(gui_pids)

        now = time.monotonic()
        refresh = (now - self._gui_checked_at) > 5.0
        if refresh:
            self._gui_checked_at = now
            # Only windowed processes can hold GDI objects worth counting, and
            # a handful of the biggest is enough to catch a leak in progress.
            watch = set(titles) | hung_pids
            self._gui_cache = {}
            for pid in list(watch)[:40]:
                gdi, user_objects = winapi.gui_resources(pid)
                if gdi or user_objects:
                    self._gui_cache[pid] = (gdi, user_objects)

        for row in rows:
            row.title = titles.get(row.pid, "")
            if row.pid in self._gui_cache:
                row.gdi, row.user_objects = self._gui_cache[row.pid]


class History:
    """A ring buffer of samples, plus the stalls seen along the way.

    Read from one thread and written from another: the sampler appends on its
    own thread while the interface and the rules read on theirs. A deque
    append is atomic, but *iterating* one while it is appended to raises
    "deque mutated during iteration" — and because `rules.analyse` catches
    exceptions per rule so that one broken rule cannot take the monitor down,
    that surfaced as findings silently going missing every so often rather
    than as a crash.

    So nothing hands out the live deque. Every reader gets a copy taken under
    the lock, and works on that.
    """

    def __init__(self, size: int = 300) -> None:
        self._samples: deque[Sample] = deque(maxlen=size)
        self._stalls: deque[dict] = deque(maxlen=50)
        self._lock = threading.Lock()
        self.started = time.time()

    # -- readers, all snapshot-based ---------------------------------------
    @property
    def samples(self) -> list[Sample]:
        """A snapshot copy. Never the live deque — see the class docstring."""
        with self._lock:
            return list(self._samples)

    @property
    def stalls(self) -> list[dict]:
        with self._lock:
            return list(self._stalls)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._samples)

    def recent(self, count: int) -> list[Sample]:
        with self._lock:
            if count >= len(self._samples):
                return list(self._samples)
            return list(self._samples)[-count:]

    def add(self, sample: Sample, threshold: float = 2.5) -> dict | None:
        with self._lock:
            self._samples.append(sample)
        # A pause or a sleep is not a freeze. `discontinuity` marks a gap we
        # were not watching across, and its lateness is meaningless.
        if sample.discontinuity or sample.lateness < threshold:
            return None
        # Name the most plausible cause at the moment of the stall, while the
        # evidence is still in hand — after the fact it is unrecoverable.
        stall = {
            "at": sample.at,
            "lateness": sample.lateness,
            "cpu": sample.cpu,
            "memory_percent": sample.memory_percent,
            "disk_busy": sample.disk_busy,
            "hard_faults": sample.hard_faults,
            "suspects": [
                {"pid": row.pid, "name": row.name, "cpu": row.cpu,
                 "hard_faults": row.hard_faults, "io_bps": row.io_bps,
                 "waits": dict(row.waits.buckets), "hung": row.hung}
                for row in sorted(sample.processes,
                                  key=lambda r: -(r.cpu + r.hard_faults / 50
                                                  + r.io_bps / 5e6))[:6]
            ],
            "hung_windows": [
                {"pid": w.pid, "title": w.title} for w in sample.hung_windows],
        }
        with self._lock:
            self._stalls.append(stall)
        return stall

    def latest(self) -> Sample | None:
        with self._lock:
            return self._samples[-1] if self._samples else None

    def series(self, attribute: str, count: int = 60) -> list[float]:
        # Discontinuity samples carry no rates, so plotting them draws a
        # false trough through every pause.
        return [getattr(s, attribute, 0.0) for s in self.recent(count)
                if not s.discontinuity]

    def average(self, attribute: str, count: int = 60) -> float:
        values = self.series(attribute, count)
        return sum(values) / len(values) if values else 0.0

    def peak(self, attribute: str, count: int = 60) -> float:
        values = self.series(attribute, count)
        return max(values) if values else 0.0

    def sustained(self, pid: int, attribute: str, count: int = 30) -> float:
        """A process's average for a field across recent samples.

        One spike is a process doing its job; ten in a row is a problem.  Every
        rule that accuses an application uses this rather than a single sample,
        which is the difference between a useful monitor and one that cries
        wolf every time something opens a file.
        """
        values = []
        for sample in self.recent(count):
            if sample.discontinuity:
                continue
            row = sample.find(pid)
            if row is not None:
                values.append(getattr(row, attribute, 0.0))
        return sum(values) / len(values) if values else 0.0

    def seen_hung(self, pid: int, count: int = 30) -> int:
        """How many of the recent samples had this process unresponsive."""
        return sum(1 for sample in self.recent(count)
                   if (row := sample.find(pid)) is not None and row.hung)
