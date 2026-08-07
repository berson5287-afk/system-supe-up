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

ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
SYSTEM_PROCESS_INFORMATION_CLASS = 5

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1

psapi = ctypes.WinDLL("psapi", use_last_error=True)


# The wait-reason tables, the shapes and the bucket definitions live in
# `telemetry`, which has no ctypes in it so that the rules can be tested
# without Windows.  They are re-exported here because this module used to own
# them and callers still reach for `winapi.ProcSnapshot`.
from .telemetry import (                                       # noqa: E402
    BENIGN_REASONS, GUI_OBJECT_LIMIT, HungWindow, MemoryInfo, ProcSnapshot,
    THREAD_STATES, ThreadWaits, WAIT_BUCKETS, WAIT_REASONS, WR_ALERT_BY_THREAD_ID,
    WaitChain, WaitChainNode, classify_wait,
)


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


# ------------------------------------------------------------------- reading

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
            if reason == WR_ALERT_BY_THREAD_ID:
                # Ambiguous: both an idle thread pool and a blocked critical
                # section land here. Counted, not accused — but its threads
                # are worth handing to Wait Chain Traversal, which can tell
                # the two apart authoritatively.
                waits.alert_waits += 1
                waits.benign += 1
                if len(snap.blocked_threads) < 4:
                    try:
                        snap.blocked_threads.append(
                            int(thread.ClientId.UniqueThread or 0))
                    except (TypeError, ValueError):
                        pass
                continue
            if reason in BENIGN_REASONS:
                waits.benign += 1
                continue
            bucket = classify_wait(reason)
            if bucket:
                waits.buckets[bucket] = waits.buckets.get(bucket, 0) + 1
                # Keep a few thread ids so a wait chain can be followed later.
                # Only blocked threads are worth asking WCT about, and a
                # handful is plenty — the chain from any one of them leads to
                # the same place.
                if len(snap.blocked_threads) < 4:
                    try:
                        snap.blocked_threads.append(
                            int(thread.ClientId.UniqueThread or 0))
                    except (TypeError, ValueError):
                        pass
            else:
                waits.benign += 1

        waits.settle()
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


# ------------------------------------------------------------------- commit

class PERFORMANCE_INFORMATION(ctypes.Structure):
    """What `GetPerformanceInfo` returns.  Every size is in *pages*.

    This is here for one field in particular: `CommitLimit`. Windows refuses
    an allocation when the commit charge reaches that limit — RAM plus page
    file — not when physical memory runs out. Reporting physical usage as
    "commit", which this program did until now, makes two completely
    different conditions indistinguishable: a machine at 95% physical with
    plenty of commit headroom is fine, and a machine at 60% physical that is
    near its commit limit is about to start failing allocations.
    """

    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]


psapi.GetPerformanceInfo.argtypes = [
    ctypes.POINTER(PERFORMANCE_INFORMATION), wintypes.DWORD]
psapi.GetPerformanceInfo.restype = wintypes.BOOL


def memory_info() -> MemoryInfo:
    """Commit charge, commit limit and kernel pools.  Zeroed on failure."""
    info = PERFORMANCE_INFORMATION()
    info.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
    try:
        if not psapi.GetPerformanceInfo(ctypes.byref(info), info.cb):
            return MemoryInfo()
    except OSError:
        return MemoryInfo()

    page = int(info.PageSize) or 4096
    return MemoryInfo(
        commit_total=int(info.CommitTotal) * page,
        commit_limit=int(info.CommitLimit) * page,
        commit_peak=int(info.CommitPeak) * page,
        physical_total=int(info.PhysicalTotal) * page,
        physical_available=int(info.PhysicalAvailable) * page,
        system_cache=int(info.SystemCache) * page,
        kernel_paged=int(info.KernelPaged) * page,
        kernel_nonpaged=int(info.KernelNonpaged) * page,
        page_size=page,
        handle_count=int(info.HandleCount),
        process_count=int(info.ProcessCount),
        thread_count=int(info.ThreadCount),
    )


# ------------------------------------------------------------------ backend

class WindowsBackend:
    """The real telemetry source, satisfying `telemetry.TelemetryBackend`.

    A thin object rather than bare module functions purely so that a `Sampler`
    can be handed a different one — see `telemetry.FakeBackend`, which is how
    the rules get tested against machine states real hardware will not produce
    on demand.
    """

    def snapshot_processes(self) -> dict[int, ProcSnapshot]:
        return snapshot_processes()

    def hung_windows(self) -> list[HungWindow]:
        return hung_windows()

    def window_titles_for(self, pids: set[int]) -> dict[int, str]:
        return window_titles_for(pids)

    def gui_resources(self, pid: int) -> tuple[int, int]:
        return gui_resources(pid)

    def memory_info(self) -> MemoryInfo:
        return memory_info()

    def wait_chain(self, tid: int) -> WaitChain:
        return wait_chain(tid)


# -------------------------------------------------------- wait chain traversal

# Windows will follow a blocked thread through critical sections, mutexes,
# SendMessage, ALPC, COM and socket waits, across process boundaries, and tell
# you whether the chain forms a cycle. That last part is the only proof of a
# genuine deadlock available from outside a process — everything else this
# program can measure shows a long wait, which is not the same thing.
#
# It is also how "Outlook is waiting on another process" becomes "Outlook's UI
# thread is blocked on a COM call into Teams, whose thread holds a mutex".

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

WCT_MAX_NODE_COUNT = 16
WCT_OBJNAME_LENGTH = 128

WCT_OUT_OF_PROC_FLAG = 0x1
WCT_OUT_OF_PROC_COM_FLAG = 0x2
WCT_OUT_OF_PROC_CS_FLAG = 0x4
WCT_ALL_FLAGS = (WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_COM_FLAG
                 | WCT_OUT_OF_PROC_CS_FLAG)

#: WCT's own thread-node type (WctThreadType).  Everything else is an object
#: a thread is waiting on.
WCT_THREAD_TYPE = 8


class _WCT_LOCK_OBJECT(ctypes.Structure):
    _fields_ = [("ObjectName", ctypes.c_wchar * WCT_OBJNAME_LENGTH),
                ("Timeout", ctypes.c_longlong),
                ("Alertable", wintypes.BOOL)]


class _WCT_THREAD_OBJECT(ctypes.Structure):
    _fields_ = [("ProcessId", wintypes.DWORD),
                ("ThreadId", wintypes.DWORD),
                ("WaitTime", wintypes.DWORD),
                ("ContextSwitches", wintypes.DWORD)]


class _WCT_UNION(ctypes.Union):
    _fields_ = [("LockObject", _WCT_LOCK_OBJECT),
                ("ThreadObject", _WCT_THREAD_OBJECT)]


class WAITCHAIN_NODE_INFO(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("ObjectType", ctypes.c_int),
                ("ObjectStatus", ctypes.c_int),
                ("u", _WCT_UNION)]


advapi32.OpenThreadWaitChainSession.argtypes = [wintypes.DWORD,
                                                ctypes.c_void_p]
advapi32.OpenThreadWaitChainSession.restype = ctypes.c_void_p
advapi32.CloseThreadWaitChainSession.argtypes = [ctypes.c_void_p]
advapi32.CloseThreadWaitChainSession.restype = None
advapi32.GetThreadWaitChain.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), wintypes.DWORD,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(WAITCHAIN_NODE_INFO), ctypes.POINTER(wintypes.BOOL)]
advapi32.GetThreadWaitChain.restype = wintypes.BOOL

#: Following a wait chain out of our own process needs SeDebugPrivilege.
#:
#: Without it `GetThreadWaitChain` still succeeds — which is the trap — but
#: every node comes back as WctStatusPidOnly: Windows will say which process
#: a thread lives in and nothing else, so the chain is one node long and
#: reveals nothing. Measured on a real deadlock while unelevated, that is
#: exactly what happens. The privilege is held by administrators; asking for
#: it costs nothing when it is not available.
SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
ERROR_NOT_ALL_ASSIGNED = 1300

WCT_STATUS_PID_ONLY = 3

_DEBUG_PRIVILEGE: bool | None = None


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


def enable_debug_privilege() -> bool:
    """Try to acquire SeDebugPrivilege.  False when it is not available.

    Cached: the answer cannot change while the process is running, and the
    result decides whether wait chains are worth attempting at all.
    """
    global _DEBUG_PRIVILEGE
    if _DEBUG_PRIVILEGE is not None:
        return _DEBUG_PRIVILEGE
    _DEBUG_PRIVILEGE = False
    try:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
            return False
        try:
            luid = _LUID()
            if not advapi32.LookupPrivilegeValueW(
                    None, "SeDebugPrivilege", ctypes.byref(luid)):
                return False
            privileges = _TOKEN_PRIVILEGES()
            privileges.PrivilegeCount = 1
            privileges.Privileges[0].Luid = luid
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            ctypes.set_last_error(0)
            advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(privileges), 0, None, None)
            # AdjustTokenPrivileges reports success even when it granted
            # nothing, so the error code is the only honest answer.
            _DEBUG_PRIVILEGE = ctypes.get_last_error() != ERROR_NOT_ALL_ASSIGNED
        finally:
            kernel32.CloseHandle(token)
    except (AttributeError, OSError):
        _DEBUG_PRIVILEGE = False
    return _DEBUG_PRIVILEGE


#: WCT resolves COM chains only if these two ole32 entry points are handed to
#: it first. Without the registration a COM wait is reported as an opaque
#: "unknown" node — and Office and Teams talk to each other over COM
#: constantly, so the most interesting chains would stop exactly where they
#: start being interesting.
_COM_REGISTERED = False


def _register_com() -> None:
    global _COM_REGISTERED
    if _COM_REGISTERED:
        return
    _COM_REGISTERED = True          # only ever attempt this once
    try:
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        advapi32.RegisterWaitChainCOMCallback.argtypes = [ctypes.c_void_p,
                                                          ctypes.c_void_p]
        advapi32.RegisterWaitChainCOMCallback.restype = None
        advapi32.RegisterWaitChainCOMCallback(
            ctypes.cast(ole32.CoGetCallState, ctypes.c_void_p),
            ctypes.cast(ole32.CoGetActivationState, ctypes.c_void_p))
    except (AttributeError, OSError):
        pass                        # COM hops will read as "unknown"; fine


def wait_chain(tid: int) -> WaitChain:
    """Follow what a thread is blocked on, as far as Windows will say.

    Returns an empty chain rather than raising. Several outcomes are normal
    and not errors: a thread that has exited, one in another session, or one
    in a process this user cannot open — WCT needs debugger-like rights for
    some hops, so a partial chain is expected rather than a malfunction, and
    is still useful.
    """
    chain = WaitChain(tid=int(tid))
    if not tid:
        chain.error = "no thread id"
        return chain
    enable_debug_privilege()
    _register_com()

    session = advapi32.OpenThreadWaitChainSession(0, None)
    if not session:
        chain.error = "could not open a wait chain session"
        return chain

    try:
        nodes = (WAITCHAIN_NODE_INFO * WCT_MAX_NODE_COUNT)()
        count = wintypes.DWORD(WCT_MAX_NODE_COUNT)
        is_cycle = wintypes.BOOL(0)
        ok = advapi32.GetThreadWaitChain(
            session, None, WCT_ALL_FLAGS, wintypes.DWORD(int(tid)),
            ctypes.byref(count), nodes, ctypes.byref(is_cycle))
        if not ok:
            chain.error = f"WCT refused (error {ctypes.get_last_error()})"
            return chain

        chain.is_cycle = bool(is_cycle.value)
        for index in range(min(count.value, WCT_MAX_NODE_COUNT)):
            node = nodes[index]
            if node.ObjectType == WCT_THREAD_TYPE:
                chain.nodes.append(WaitChainNode(
                    is_thread=True, object_type=int(node.ObjectType),
                    status=int(node.ObjectStatus),
                    pid=int(node.ThreadObject.ProcessId),
                    tid=int(node.ThreadObject.ThreadId),
                    wait_time_ms=int(node.ThreadObject.WaitTime),
                    context_switches=int(node.ThreadObject.ContextSwitches)))
            else:
                try:
                    name = node.LockObject.ObjectName or ""
                except (ValueError, UnicodeDecodeError):
                    name = ""
                chain.nodes.append(WaitChainNode(
                    is_thread=False, object_type=int(node.ObjectType),
                    status=int(node.ObjectStatus), name=name))

        # A chain that is entirely "pid only" is Windows declining to look,
        # not a thread that is fine. Say which it is.
        threads = [n for n in chain.nodes if n.is_thread]
        if threads and all(n.status == WCT_STATUS_PID_ONLY for n in threads):
            chain.restricted = True
    except OSError as error:
        chain.error = str(error)
    finally:
        try:
            advapi32.CloseThreadWaitChainSession(session)
        except OSError:
            pass
    return chain
