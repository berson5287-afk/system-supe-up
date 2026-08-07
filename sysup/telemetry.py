"""The shapes telemetry comes in, and where it comes from — no Windows here.

This module is deliberately free of `ctypes`, so it imports anywhere. That
matters for one reason: the diagnostic rules are the most valuable and most
fragile part of this program, and until now they could only be tested by
producing a real fault on a real Windows machine. Some conditions cannot be
produced that way at all — you cannot ask a healthy NVMe to take 400 ms per
operation, or arrange for exactly 3.2 seconds of scheduler lateness alongside
normal memory.

With the source of telemetry behind an interface, `FakeBackend` can assert
any machine state you can describe, and the production rule engine runs
against it unchanged.

`winapi.py` provides the real implementation. Nothing else should import
`winapi` directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# --------------------------------------------------------------- wait reasons

#: KWAIT_REASON.  The names are the kernel's own; the groupings below are what
#: turn them into an explanation.
WAIT_REASONS: dict[int, str] = {
    0: "Executive", 1: "FreePage", 2: "PageIn", 3: "PoolAllocation",
    4: "DelayExecution", 5: "Suspended", 6: "UserRequest", 7: "WrExecutive",
    8: "WrFreePage", 9: "WrPageIn", 10: "WrPoolAllocation",
    11: "WrDelayExecution", 12: "WrSuspended", 13: "WrUserRequest",
    14: "WrEventPair", 15: "WrQueue", 16: "WrLpcReceive", 17: "WrLpcReply",
    18: "WrVirtualMemory", 19: "WrPageOut", 20: "WrRendezvous",
    21: "WrKeyedEvent", 22: "WrTerminated", 23: "WrProcessInSwap",
    24: "WrCpuRateControl", 25: "WrCalloutStack", 26: "WrKernel",
    27: "WrResource", 28: "WrPushLock", 29: "WrMutex", 30: "WrQuantumEnd",
    31: "WrDispatchInt", 32: "WrPreempted", 33: "WrYieldExecution",
    34: "WrFastMutex", 35: "WrGuardedMutex", 36: "WrRundown",
    37: "WrAlertByThreadId", 38: "WrDeferredPreempt", 39: "WrPhysicalFault",
    40: "WrIoRing", 41: "WrMdlCache", 42: "WrRcu",
}

THREAD_STATES: dict[int, str] = {
    0: "Initialized", 1: "Ready", 2: "Running", 3: "Standby",
    4: "Terminated", 5: "Waiting", 6: "Transition", 7: "Unknown",
}

#: A process with 400 threads parked on `WrQueue` is a healthy thread pool; a
#: process with 3 on `WrPageIn` is a machine that needs more RAM. Only the
#: second kind is worth reporting, and each bucket carries the plain-English
#: consequence because "your threads are in WrPushLock" helps nobody.
WAIT_BUCKETS: dict[str, dict] = {
    "paging": {
        "reasons": {1, 2, 8, 9, 18, 19, 23, 39},
        "label": "waiting for memory / page file",
        "meaning": (
            "threads are stopped dead waiting for RAM to be fetched back off "
            "the disk. This is the classic cause of a whole-machine freeze "
            "that ends by itself after several seconds"),
        "severity": 3,
    },
    "lock": {
        # WrEventPair is deliberately absent: it is the legacy csrss
        # client/server handshake, and it idles in exactly this state.
        "reasons": {21, 27, 28, 29, 34, 35, 36},
        "label": "blocked on a lock",
        "meaning": (
            "threads are waiting on a lock another thread is holding. If this "
            "does not clear, it is a deadlock and the app will never come "
            "back on its own"),
        "severity": 3,
    },
    "ipc": {
        # WrLpcReply only. Its sibling WrLpcReceive means "I am a server
        # sitting idle waiting for someone to call me", which is the *resting*
        # state of csrss.exe and every RPC service on the machine — counting
        # it here accuses the Windows subsystem of being blocked on every
        # healthy boot. Waiting for a reply is the blocked one; waiting for a
        # request is a job description.
        "reasons": {17},
        "label": "waiting on another process",
        "meaning": (
            "threads are blocked on an RPC/COM call into a different process, "
            "so this app is a victim rather than the cause — the process it "
            "is calling is what actually needs fixing"),
        "severity": 2,
    },
    "kernel": {
        "reasons": {0, 7, 25, 26, 40, 41},
        "label": "waiting in a driver / kernel call",
        "meaning": (
            "threads are inside a kernel or driver call that has not "
            "returned. Sustained waits here usually mean a slow or "
            "misbehaving driver, commonly storage, network or anti-virus "
            "filter drivers"),
        "severity": 2,
    },
    "pool": {
        "reasons": {3, 10},
        "label": "waiting for kernel memory",
        "meaning": (
            "threads are waiting for kernel pool memory to become available. "
            "This is serious — the system is close to a resource wall and "
            "will become unstable, not merely slow"),
        "severity": 4,
    },
    "starved": {
        "reasons": {24, 30, 31, 32, 33},
        "label": "starved of CPU time",
        "meaning": (
            "threads are ready to run but cannot get a turn on the processor, "
            "so something else is monopolising the CPU or the CPU is being "
            "throttled"),
        "severity": 2,
    },
}

#: Waits that mean "this thread has nothing to do", which is the overwhelming
#: majority of every wait on a healthy system. Counting these as evidence is
#: how naive tools conclude that a perfectly idle machine is in crisis.
#:
#: 16 (WrLpcReceive) and 14 (WrEventPair) are here rather than in a bucket
#: because they are how an idle *server* waits — see the "ipc" bucket.
BENIGN_REASONS = {4, 5, 6, 11, 12, 13, 14, 15, 16, 20, 22}

#: The ambiguous wait — see ThreadWaits.alert_waits.
WR_ALERT_BY_THREAD_ID = 37

#: Windows' own default ceiling per process for GDI and USER objects.
GUI_OBJECT_LIMIT = 10_000


def classify_wait(reason: int) -> str:
    """Which diagnostic bucket a KWAIT_REASON falls into ("" if benign)."""
    for name, bucket in WAIT_BUCKETS.items():
        if reason in bucket["reasons"]:
            return name
    return ""


# ------------------------------------------------------------------- shapes

@dataclass
class ThreadWaits:
    """Wait analysis for one process, already reduced to what matters."""

    total: int = 0
    running: int = 0
    ready: int = 0
    benign: int = 0
    #: bucket name -> how many threads are stuck there
    buckets: dict[str, int] = field(default_factory=dict)
    #: the single most significant non-benign bucket, or ""
    dominant: str = ""
    #: Threads in WrAlertByThreadId (37) — an ambiguous state that is *both*
    #: how an idle thread pool parks and how a modern critical section or
    #: SRW lock waits, because both go through WaitOnAddress. It is therefore
    #: useless as evidence on its own and is never reported as a finding.
    #:
    #: It is kept because it makes an excellent trigger: cheap to count, and
    #: exactly the population worth spending an expensive Wait Chain
    #: Traversal call on. A real lock deadlock lives here and nowhere else —
    #: which is why the first deadlock injected into this program was missed
    #: entirely until this was separated out.
    alert_waits: int = 0

    @property
    def stuck(self) -> int:
        return sum(self.buckets.values())

    def describe(self) -> str:
        if not self.dominant:
            return ""
        bucket = WAIT_BUCKETS[self.dominant]
        count = self.buckets.get(self.dominant, 0)
        return f"{count} of {self.total} threads {bucket['label']}"

    def settle(self) -> None:
        """Pick the dominant bucket: severity first, then how many threads.

        One thread deadlocked on a lock outranks nine parked in a driver call.
        """
        if self.buckets:
            self.dominant = max(
                self.buckets,
                key=lambda b: (WAIT_BUCKETS[b]["severity"], self.buckets[b]))


#: What a thread is blocked *on*, as Windows' Wait Chain Traversal reports it.
WCT_OBJECT_TYPES = {
    1: "a critical section", 2: "a SendMessage call", 3: "a mutex",
    4: "an ALPC call", 5: "a COM call", 6: "another thread",
    7: "another process", 8: "a thread", 9: "COM activation",
    10: "something unknown", 11: "a socket", 12: "a network file",
}

WCT_STATUSES = {
    0: "no access", 1: "running", 2: "blocked", 3: "pid only",
    4: "pid only (rpcss)", 5: "owned", 6: "not owned", 7: "abandoned",
    8: "unknown", 9: "error",
}


@dataclass
class WaitChainNode:
    """One link: either a thread, or the thing a thread is waiting on."""

    #: True for a thread node, False for a lock/COM/ALPC object node.
    is_thread: bool = False
    object_type: int = 0
    status: int = 0
    pid: int = 0
    tid: int = 0
    wait_time_ms: int = 0
    context_switches: int = 0
    name: str = ""

    @property
    def type_name(self) -> str:
        return WCT_OBJECT_TYPES.get(self.object_type, "something unknown")

    @property
    def status_name(self) -> str:
        return WCT_STATUSES.get(self.status, "unknown")

    @property
    def blocked(self) -> bool:
        return self.status == 2


@dataclass
class WaitChain:
    """Why a thread is stuck, followed as far as Windows will say.

    This is the difference between "Outlook is waiting on another process" and
    "Outlook's UI thread is blocked on a COM call into Teams, whose thread is
    blocked on a mutex held by another Teams thread". The first is a symptom;
    the second names the culprit.
    """

    tid: int = 0
    nodes: list[WaitChainNode] = field(default_factory=list)
    #: Windows itself telling us the chain loops — a genuine deadlock, not
    #: merely a long wait. Nothing else in this program can prove that.
    is_cycle: bool = False
    error: str = ""
    #: Windows answered, but would only say which process the thread is in —
    #: every node came back as "pid only". That is what a wait chain looks
    #: like without SeDebugPrivilege: the call succeeds and tells you nothing.
    #: Worth distinguishing from "no chain", because the remedy is running as
    #: administrator rather than concluding the process is fine.
    restricted: bool = False

    @property
    def usable(self) -> bool:
        return len(self.nodes) > 1 and not self.error

    def processes(self) -> list[int]:
        """Distinct pids along the chain, in order, excluding the first."""
        seen: list[int] = []
        for node in self.nodes:
            if node.is_thread and node.pid and node.pid not in seen:
                seen.append(node.pid)
        return seen[1:]

    def blocker(self) -> WaitChainNode | None:
        """The last thread in the chain — whoever everyone else is waiting on."""
        threads = [n for n in self.nodes if n.is_thread]
        return threads[-1] if len(threads) > 1 else None

    def describe(self, names: dict[int, str] | None = None) -> list[str]:
        """The chain as readable lines, one per hop."""
        names = names or {}
        lines: list[str] = []
        for node in self.nodes:
            if node.is_thread:
                label = names.get(node.pid) or f"pid {node.pid}"
                detail = f"thread {node.tid} in {label}"
                if node.status_name not in ("unknown", "running"):
                    detail += f" ({node.status_name})"
                if node.wait_time_ms > 1000:
                    detail += f", waiting {node.wait_time_ms / 1000:.0f}s"
                lines.append(detail)
            else:
                what = node.type_name
                if node.name:
                    what += f" “{node.name[:40]}”"
                lines.append(f"    ↓ blocked on {what}")
        return lines


@dataclass
class ProcSnapshot:
    """One process as the kernel sees it, at one instant."""

    pid: int = 0
    name: str = ""
    threads: int = 0
    hard_faults: int = 0
    page_faults: int = 0
    handles: int = 0
    session: int = 0
    cycle_time: int = 0
    #: 100ns units, as the kernel reports them. Differencing two samples is
    #: how CPU% is derived, which costs nothing extra.
    kernel_time: int = 0
    user_time: int = 0
    create_time: int = 0
    private_bytes: int = 0
    working_set: int = 0
    read_ops: int = 0
    write_ops: int = 0
    read_bytes: int = 0
    write_bytes: int = 0
    waits: ThreadWaits = field(default_factory=ThreadWaits)
    #: Thread ids of threads in a non-benign wait. Kept so a wait chain can be
    #: followed later without re-enumerating every thread on the machine —
    #: these are the only ones worth asking about.
    blocked_threads: list[int] = field(default_factory=list)


@dataclass
class HungWindow:
    pid: int
    title: str
    hwnd: int
    #: True when found as a ghost, i.e. Windows has already given up on the
    #: app and painted the stand-in. Stronger than merely missing the
    #: five-second mark.
    ghosted: bool = False


@dataclass
class MemoryInfo:
    """System-wide memory, including commit — which is not RAM usage.

    Windows refuses allocations against the *commit limit* (RAM plus page
    file), not against free RAM, so a machine can be at 95% physical with a
    perfectly healthy commit charge, or at 60% physical and about to start
    failing allocations. Reporting one as the other, which this program did
    until commit was measured properly, makes those two indistinguishable.
    """

    commit_total: int = 0
    commit_limit: int = 0
    commit_peak: int = 0
    physical_total: int = 0
    physical_available: int = 0
    system_cache: int = 0
    kernel_paged: int = 0
    kernel_nonpaged: int = 0
    page_size: int = 4096
    handle_count: int = 0
    process_count: int = 0
    thread_count: int = 0

    @property
    def commit_percent(self) -> float:
        if not self.commit_limit:
            return 0.0
        return self.commit_total / self.commit_limit * 100.0

    @property
    def commit_headroom(self) -> int:
        return max(0, self.commit_limit - self.commit_total)


# ------------------------------------------------------------------ backends

@runtime_checkable
class TelemetryBackend(Protocol):
    """Where a `Sampler` gets its readings from."""

    def snapshot_processes(self) -> dict[int, ProcSnapshot]: ...

    def hung_windows(self) -> list[HungWindow]: ...

    def window_titles_for(self, pids: set[int]) -> dict[int, str]: ...

    def gui_resources(self, pid: int) -> tuple[int, int]: ...

    def memory_info(self) -> MemoryInfo: ...

    def wait_chain(self, tid: int) -> WaitChain: ...


class FakeBackend:
    """A machine you describe, for testing rules that real hardware will not do.

    Each call pops the next scripted state, holding the last one once the
    script runs out, so a short script can drive a long sampling run.
    """

    def __init__(self, states: list[dict] | None = None) -> None:
        self.states: list[dict] = list(states or [])
        self.index = 0
        self.calls = 0

    def push(self, **state) -> "FakeBackend":
        self.states.append(state)
        return self

    def _current(self) -> dict:
        if not self.states:
            return {}
        if self.index >= len(self.states):
            return self.states[-1]
        return self.states[self.index]

    def advance(self) -> None:
        self.index += 1

    def snapshot_processes(self) -> dict[int, ProcSnapshot]:
        self.calls += 1
        processes = self._current().get("processes") or []
        result: dict[int, ProcSnapshot] = {}
        for entry in processes:
            snapshot = entry if isinstance(entry, ProcSnapshot) else \
                ProcSnapshot(**entry)
            snapshot.waits.settle()
            result[snapshot.pid] = snapshot
        # Advancing here rather than in each getter keeps one "tick" of the
        # script aligned with one call to Sampler.sample().
        self.advance()
        return result

    def hung_windows(self) -> list[HungWindow]:
        windows = self._current().get("hung_windows") or []
        return [w if isinstance(w, HungWindow) else HungWindow(**w)
                for w in windows]

    def window_titles_for(self, pids: set[int]) -> dict[int, str]:
        titles = self._current().get("titles") or {}
        return {pid: title for pid, title in titles.items() if pid in pids}

    def gui_resources(self, pid: int) -> tuple[int, int]:
        return (self._current().get("gui") or {}).get(pid, (0, 0))

    def memory_info(self) -> MemoryInfo:
        info = self._current().get("memory")
        if isinstance(info, MemoryInfo):
            return info
        return MemoryInfo(**info) if info else MemoryInfo()

    def wait_chain(self, tid: int) -> WaitChain:
        chains = self._current().get("wait_chains") or {}
        chain = chains.get(tid)
        if isinstance(chain, WaitChain):
            return chain
        return WaitChain(tid=tid, **chain) if chain else WaitChain(tid=tid)


def default_backend() -> TelemetryBackend:
    """The real Windows backend.  Imported lazily so this module stays clean."""
    from .winapi import WindowsBackend

    return WindowsBackend()
