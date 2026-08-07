"""Windows internals that psutil does not expose, via ctypes.

Three things live here, and each one answers a question a CPU graph cannot:

1. **Thread wait reasons** (`NtQuerySystemInformation`).  A frozen application
   is almost never burning CPU — it is *waiting*, and the kernel knows exactly
   what for.  A thread stuck on `WrPageIn` is waiting for the page file; one on
   `WrPushLock` is deadlocked against another thread; one on `WrLpcReply` is
   blocked on a *different process* that is itself the real culprit.  Without
   this, "chrome.exe is at 0% CPU and not responding" is the end of the story
   instead of the beginning.

2. **Hung windows** (`IsHungAppWindow`).  This is the same call Explorer uses
   to decide whether to paint "(Not Responding)" on a title bar, so it agrees
   with what the user is actually looking at rather than guessing from a
   sample.

3. **GDI/USER handle counts** (`GetGuiResources`).  Windows kills a process at
   10,000 of either by default, and the last few minutes before that are a
   slideshow.  A leak here looks like a mysterious whole-desktop slowdown and
   is invisible in every ordinary task manager column.

Everything degrades to empty rather than raising: this is diagnostic garnish,
and a monitor that crashes because an undocumented struct moved is worse than
one that quietly reports less.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
from dataclasses import dataclass, field

ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
SYSTEM_PROCESS_INFORMATION_CLASS = 5

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1

# Windows' own default ceiling per process.  Both are registry-tunable, but
# almost nobody tunes them, so treating 10,000 as the wall is right in practice.
GUI_OBJECT_LIMIT = 10_000


# --------------------------------------------------------------- wait reasons

# KWAIT_REASON.  The names are the kernel's own; the groupings below are what
# turn them into an explanation.
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

# The whole point of this module.  A process with 400 threads parked on
# `WrQueue` is a healthy thread pool; a process with 3 threads on `WrPageIn` is
# a machine that needs more RAM.  Only the second kind is worth reporting.
#
# Each bucket carries the plain-English consequence, because "your threads are
# in WrPushLock" helps nobody.
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
        # WrLpcReply only.  Its sibling WrLpcReceive means "I am a server
        # sitting idle waiting for someone to call me", which is the *resting*
        # state of csrss.exe and every RPC service on the machine — counting it
        # here accuses the Windows subsystem of being blocked on every healthy
        # boot.  Waiting for a reply is the blocked one; waiting for a request
        # is a job description.
        "reasons": {17},
        "label": "waiting on another process",
        "meaning": (
            "threads are blocked on an RPC/COM call into a different process, "
            "so this app is a victim rather than the cause — the process it is "
            "calling is what actually needs fixing"),
        "severity": 2,
    },
    "kernel": {
        "reasons": {0, 7, 25, 26, 40, 41},
        "label": "waiting in a driver / kernel call",
        "meaning": (
            "threads are inside a kernel or driver call that has not returned. "
            "Sustained waits here usually mean a slow or misbehaving driver, "
            "commonly storage, network or anti-virus filter drivers"),
        "severity": 2,
    },
    "pool": {
        "reasons": {3, 10},
        "label": "waiting for kernel memory",
        "meaning": (
            "threads are waiting for kernel pool memory to become available. "
            "This is serious — the system is close to a resource wall and will "
            "become unstable, not merely slow"),
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

# Waits that mean "this thread has nothing to do", which is the overwhelming
# majority of every wait on a healthy system.  Counting these as evidence is
# how naive tools conclude that a perfectly idle machine is in crisis.
#
# 16 (WrLpcReceive) and 14 (WrEventPair) are here rather than in a bucket
# because they are how an idle *server* waits — see the note on the "ipc"
# bucket.  Getting this wrong makes csrss.exe look permanently deadlocked.
BENIGN_REASONS = {4, 5, 6, 11, 12, 13, 14, 15, 16, 20, 22}


def classify_wait(reason: int) -> str:
    """Which diagnostic bucket a KWAIT_REASON falls into ("" if benign)."""
    for name, bucket in WAIT_BUCKETS.items():
        if reason in bucket["reasons"]:
            return name
    return ""


# ------------------------------------------------------------------- structs

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", ctypes.c_void_p)]


class CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", ctypes.c_void_p),
                ("UniqueThread", ctypes.c_void_p)]


class SYSTEM_THREAD_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("KernelTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("CreateTime", ctypes.c_longlong),
        ("WaitTime", wintypes.ULONG),
        ("StartAddress", ctypes.c_void_p),
        ("ClientId", CLIENT_ID),
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
        ("ContextSwitches", wintypes.ULONG),
        ("ThreadState", wintypes.ULONG),
        ("WaitReason", wintypes.ULONG),
    ]


class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    """Undocumented but stable since Windows 7.

    `HardFaultCount` is the field that makes this worth the trouble: it is a
    *per-process* count of reads that had to go to the disk because the page
    was not in RAM.  Windows' own Task Manager shows nothing like it, and it is
    the single number that names which application is causing a paging storm.
    """

    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_longlong),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("KernelTime", ctypes.c_longlong),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.ULONG),
        ("UniqueProcessKey", ctypes.c_void_p),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", wintypes.ULONG),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivatePageCount", ctypes.c_size_t),
        ("ReadOperationCount", ctypes.c_longlong),
        ("WriteOperationCount", ctypes.c_longlong),
        ("OtherOperationCount", ctypes.c_longlong),
        ("ReadTransferCount", ctypes.c_longlong),
        ("WriteTransferCount", ctypes.c_longlong),
        ("OtherTransferCount", ctypes.c_longlong),
    ]


ntdll.NtQuerySystemInformation.argtypes = [
    ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong


# -------------------------------------------------------------------- results

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

    @property
    def stuck(self) -> int:
        return sum(self.buckets.values())

    def describe(self) -> str:
        if not self.dominant:
            return ""
        bucket = WAIT_BUCKETS[self.dominant]
        count = self.buckets.get(self.dominant, 0)
        return (f"{count} of {self.total} threads {bucket['label']}")


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
    #: 100ns units, as the kernel reports them.  Differencing two samples is
    #: how CPU% is derived, which costs nothing extra — psutil's per-process
    #: cpu_percent would mean re-opening every process on every tick.
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


def snapshot_processes() -> dict[int, ProcSnapshot]:
    """Every process, with its threads already classified.  {} on failure.

    One call for the whole machine — this is a single kernel transition that
    returns everything, which is why it is cheap enough to run every second
    while iterating psutil's per-process thread lists is not.
    """
    size = ctypes.c_ulong(512 * 1024)
    for _attempt in range(8):
        buffer = ctypes.create_string_buffer(size.value)
        needed = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(
            SYSTEM_PROCESS_INFORMATION_CLASS, buffer, size.value,
            ctypes.byref(needed))
        if status == 0:
            break
        if status == STATUS_INFO_LENGTH_MISMATCH:
            # Processes start between the sizing call and the real one, so ask
            # for noticeably more than the kernel just said it wanted.
            size = ctypes.c_ulong(max(needed.value * 2, size.value * 2))
            continue
        return {}
    else:
        return {}

    processes: dict[int, ProcSnapshot] = {}
    address = ctypes.addressof(buffer)
    thread_size = ctypes.sizeof(SYSTEM_THREAD_INFORMATION)
    header_size = ctypes.sizeof(SYSTEM_PROCESS_INFORMATION)

    while True:
        entry = SYSTEM_PROCESS_INFORMATION.from_address(address)
        pid = entry.UniqueProcessId or 0

        name = ""
        if entry.ImageName.Buffer and entry.ImageName.Length:
            try:
                name = ctypes.wstring_at(entry.ImageName.Buffer,
                                         entry.ImageName.Length // 2)
            except (ValueError, OSError):
                name = ""
        if not name:
            name = "System Idle Process" if pid == 0 else f"pid {pid}"

        snap = ProcSnapshot(
            pid=int(pid), name=name,
            threads=entry.NumberOfThreads,
            hard_faults=entry.HardFaultCount,
            page_faults=entry.PageFaultCount,
            handles=entry.HandleCount,
            session=entry.SessionId,
            cycle_time=entry.CycleTime,
            kernel_time=entry.KernelTime,
            user_time=entry.UserTime,
            create_time=entry.CreateTime,
            private_bytes=entry.PrivatePageCount,
            working_set=entry.WorkingSetSize,
            read_ops=entry.ReadOperationCount,
            write_ops=entry.WriteOperationCount,
            read_bytes=entry.ReadTransferCount,
            write_bytes=entry.WriteTransferCount,
        )

        waits = ThreadWaits(total=entry.NumberOfThreads)
        threads_at = address + header_size
        for index in range(entry.NumberOfThreads):
            try:
                thread = SYSTEM_THREAD_INFORMATION.from_address(
                    threads_at + index * thread_size)
            except (ValueError, OSError):
                break
            state = thread.ThreadState
            if state == 2:
                waits.running += 1
                continue
            if state in (1, 3):
                waits.ready += 1
                continue
            if state != 5:
                continue
            reason = thread.WaitReason
            if reason in BENIGN_REASONS:
                waits.benign += 1
                continue
            bucket = classify_wait(reason)
            if bucket:
                waits.buckets[bucket] = waits.buckets.get(bucket, 0) + 1
            else:
                waits.benign += 1

        if waits.buckets:
            # Severity first, then how many threads are affected — one thread
            # deadlocked on a lock outranks nine parked in a driver call.
            waits.dominant = max(
                waits.buckets,
                key=lambda b: (WAIT_BUCKETS[b]["severity"], waits.buckets[b]))
        snap.waits = waits
        processes[snap.pid] = snap

        if not entry.NextEntryOffset:
            break
        address += entry.NextEntryOffset

    return processes


# ------------------------------------------------------------- hung windows

user32.IsHungAppWindow.argtypes = [wintypes.HWND]
user32.IsHungAppWindow.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int

ENUM_WINDOWS_PROC = ctypes.WINFUNCTYPE(
    wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

# When an application stops pumping messages, Windows hides the real window and
# puts up a stand-in — the "(Not Responding)" one you can still drag around.
# That stand-in is owned by the Desktop Window Manager, not by the application,
# so asking it who it belongs to names dwm.exe every single time.  Blaming the
# compositor for every hang in the system would be worse than useless, and
# these two undocumented exports are the only way to map a ghost back to the
# window it is standing in for.  They have been in user32 since Vista; if a
# future Windows drops them we fall back to ignoring dwm-owned windows.
try:
    user32.HungWindowFromGhostWindow.argtypes = [wintypes.HWND]
    user32.HungWindowFromGhostWindow.restype = wintypes.HWND
    _CAN_UNGHOST = True
except AttributeError:      # pragma: no cover - depends on the OS build
    _CAN_UNGHOST = False


def _pid_of(hwnd) -> int:
    pid = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value)


def _title_of(hwnd) -> str:
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buffer = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buffer, length + 1)
    return buffer.value


def _resolve_ghost(hwnd, pid: int) -> tuple[int, int]:
    """Map a ghost window back to the application that is actually hung."""
    if not _CAN_UNGHOST:
        return hwnd, pid
    try:
        real = user32.HungWindowFromGhostWindow(hwnd)
    except OSError:
        return hwnd, pid
    if not real:
        return hwnd, pid
    real_pid = _pid_of(real)
    return (real, real_pid) if real_pid else (hwnd, pid)


@dataclass
class HungWindow:
    pid: int
    title: str
    hwnd: int
    #: True when this was found as a ghost, i.e. Windows has already given up
    #: on the app and painted the stand-in.  A stronger signal than a window
    #: that has merely missed the 5-second mark.
    ghosted: bool = False


def hung_windows() -> list[HungWindow]:
    """Visible top-level windows Windows itself considers unresponsive.

    `IsHungAppWindow` is true when a window has not pumped its message queue
    for five seconds — the same threshold that makes Explorer grey the window
    out and append "(Not Responding)".  Agreeing with the shell matters: a
    freeze the user can see and the tool cannot is worse than no tool.
    """
    found: list[HungWindow] = []
    seen: set[int] = set()

    def callback(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            title = _title_of(hwnd)
            if not title:
                return True  # tool windows and invisible helpers, not apps
            pid = _pid_of(hwnd)
            real_hwnd, real_pid = _resolve_ghost(hwnd, pid)
            ghosted = real_hwnd != hwnd
            # A ghost is proof on its own; a normal window has to be asked.
            if not ghosted and not user32.IsHungAppWindow(hwnd):
                return True
            if real_hwnd in seen:
                return True
            seen.add(real_hwnd)
            found.append(HungWindow(
                pid=real_pid, title=title, hwnd=int(real_hwnd),
                ghosted=ghosted))
        except Exception:
            pass
        return True

    try:
        user32.EnumWindows(ENUM_WINDOWS_PROC(callback), 0)
    except Exception:
        return []
    return found


def window_titles_for(pids: set[int]) -> dict[int, str]:
    """The main visible window title for each pid, for naming things humanly.

    "the window called 'Budget 2026.xlsx - Excel'" lands where "pid 8123" does
    not, and the report is for a person.
    """
    titles: dict[int, str] = {}

    def callback(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            title = _title_of(hwnd)
            if not title:
                return True
            # Attribute a ghost to the app it stands in for, never to dwm.exe,
            # for the same reason `hung_windows` does.
            _real_hwnd, key = _resolve_ghost(hwnd, _pid_of(hwnd))
            if key in pids and key not in titles:
                titles[key] = title
        except Exception:
            pass
        return True

    try:
        user32.EnumWindows(ENUM_WINDOWS_PROC(callback), 0)
    except Exception:
        return {}
    return titles


# --------------------------------------------------------------- GUI handles

user32.GetGuiResources.argtypes = [wintypes.HANDLE, wintypes.DWORD]
user32.GetGuiResources.restype = wintypes.DWORD
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def gui_resources(pid: int) -> tuple[int, int]:
    """(GDI objects, USER objects) for a pid — (0, 0) if it cannot be read.

    Both are capped at 10,000 per process. A process climbing steadily towards
    that ceiling is leaking, and the symptom the user reports is never "handle
    leak" — it is "everything goes weird after the app has been open a while".
    """
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return (0, 0)
    try:
        return (int(user32.GetGuiResources(handle, GR_GDIOBJECTS)),
                int(user32.GetGuiResources(handle, GR_USEROBJECTS)))
    finally:
        kernel32.CloseHandle(handle)
