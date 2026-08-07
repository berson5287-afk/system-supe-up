"""One-shot facts about the machine, gathered only when a diagnosis is asked for.

None of this belongs in the sampling loop — startup entries and the event log
do not change from second to second, and reading them costs far more than a
sample.  But they answer questions the live numbers cannot: a machine that is
slow *from the moment it boots* is explained by forty startup entries, not by
whatever happens to be busy now, and a machine that freezes hard every few
days is usually explained by an error in the system event log that nobody has
ever looked at.

Everything is best-effort.  A missing registry key or an event log the user
cannot read must not stop the diagnosis.
"""

from __future__ import annotations

import os
import platform
import subprocess
import time
import winreg
from dataclasses import dataclass, field

import psutil

#: Where Windows keeps the things it launches at sign-in.
RUN_KEYS = (
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
)

#: Events that actually explain a freeze, keyed by **provider and id together**.
#:
#: An event id means nothing on its own. Id 1 is emitted by hundreds of
#: providers; so are 7, 17 and 18. Keying meanings by id alone — which this
#: did originally — labels an unrelated Event 1 from any random service as
#: "A WHEA hardware error was recorded", which is exactly the kind of
#: confident, wrong, hardware-shaped claim that sends someone off to buy
#: memory they do not need.
#:
#: Each entry is (id, provider substrings that must match, meaning). Provider
#: matching is case-insensitive and substring-based against the source name,
#: which is how Windows abbreviates these in the classic event log.
EVENT_MEANINGS: tuple[tuple[int, tuple[str, ...], str], ...] = (
    (41, ("kernel-power",),
     "The machine lost power or locked up hard — Windows did not shut down "
     "cleanly. This is logged on the *next* boot, so it describes the "
     "previous crash."),
    (6008, ("eventlog",), "Unexpected shutdown."),
    (1001, ("windows error reporting", "bugcheck", "savedump"),
     "Windows Error Reporting recorded a crash (often a bugcheck)."),
    (7, ("disk", "storahci", "stornvme", "iastor"),
     "The disk reported a bad block."),
    (51, ("disk", "ntfs", "volmgr", "storahci", "stornvme", "iastor"),
     "An error was detected during a paging operation — the drive failed a "
     "read or write of the page file. Strongly associated with freezes."),
    (153, ("disk", "storahci", "stornvme", "iastor", "vhdmp"),
     "The storage driver retried or abandoned an I/O request."),
    (129, ("storahci", "stornvme", "iastor", "disk", "vhdmp", "megasas",
           "arcsas", "lsi"),
     "The storage controller reset a device that stopped responding — a "
     "classic cause of multi-second whole-system freezes."),
    (157, ("disk",), "A disk was surprise-removed or dropped off the bus."),
    (55, ("ntfs", "refs"),
     "The file system detected corruption on a volume."),
    (1, ("whea",), "A WHEA hardware error was recorded."),
    (17, ("whea",), "A correctable hardware error was recorded."),
    (18, ("whea",), "An uncorrectable hardware error was recorded."),
    (219, ("kernel-pnp",), "A driver failed to load."),
    (2004, ("resource-exhaustion",),
     "Windows detected that the machine was running out of memory and "
     "started trimming applications."),
)


def event_meaning(event_id: int, source: str) -> str:
    """The meaning of an event, but only when the provider agrees."""
    lowered = (source or "").lower()
    for known_id, providers, meaning in EVENT_MEANINGS:
        if known_id != event_id:
            continue
        if any(marker in lowered for marker in providers):
            return meaning
    return ""


def event_matches(event_id: int, source: str, wanted_id: int,
                  ) -> bool:
    """Is this genuinely `wanted_id` from a provider that means it?"""
    return event_id == wanted_id and bool(event_meaning(event_id, source))

CRITICAL_SOURCES = ("disk", "Disk", "Ntfs", "volmgr", "storahci", "stornvme",
                    "WHEA-Logger", "Microsoft-Windows-WHEA-Logger",
                    "Microsoft-Windows-Kernel-Power",
                    "Microsoft-Windows-Resource-Exhaustion-Detector",
                    "EventLog", "Application Popup", "nvlddmkm", "amdkmdag",
                    "igfx", "iaStorA", "Microsoft-Windows-DriverFrameworks-UserMode")


@dataclass
class StartupItem:
    name: str
    command: str
    scope: str          # "user" or "machine"


@dataclass
class DiskInfo:
    device: str
    mountpoint: str
    total: int
    used: int
    free: int
    percent: float

    @property
    def free_fraction(self) -> float:
        return self.free / self.total if self.total else 1.0


@dataclass
class EventRecord:
    when: float
    source: str
    event_id: int
    level: str
    meaning: str = ""
    message: str = ""


@dataclass
class MemorySlots:
    """What is physically installed, and whether there is room for more.

    This is what turns "you need more RAM" from a shrug into a decision. Two
    empty slots and a 128 GB ceiling means adding memory is cheap and takes ten
    minutes; four full slots on a laptop means the only route is replacing
    what is there, which is a different conversation entirely.
    """

    installed: list[tuple[str, int, int]] = field(default_factory=list)
    total_slots: int = 0
    max_capacity: int = 0

    @property
    def used_slots(self) -> int:
        return len(self.installed)

    @property
    def free_slots(self) -> int:
        return max(0, self.total_slots - self.used_slots)

    @property
    def installed_bytes(self) -> int:
        return sum(size for _label, size, _speed in self.installed)

    def describe(self) -> str:
        if not self.installed:
            return ""
        # Memory modules are sold and labelled in binary gigabytes, so an
        # 8 GiB stick must read as "8 GB" and not as the 8.59 that dividing by
        # a decimal billion produces. Everywhere else in this program uses
        # decimal, which is right for capacities Windows reports — but not for
        # a part number someone is about to go and buy.
        parts = [f"{size / (1 << 30):.0f} GB" for _l, size, _s in self.installed]
        text = f"{' + '.join(parts)} in {self.used_slots} of {self.total_slots} slots"
        speeds = {speed for _l, _sz, speed in self.installed if speed}
        if len(speeds) == 1:
            text += f" at {speeds.pop()} MHz"
        return text

    def upgrade_advice(self, wanted_bytes: int) -> str:
        """How to get to `wanted_bytes`, given the slots actually available."""
        if not self.installed:
            return ""
        current = self.installed_bytes
        if current >= wanted_bytes:
            return ""
        extra = wanted_bytes - current
        if self.free_slots:
            per_stick = max(8, int(extra / self.free_slots / (1 << 30)))
            # Memory is sold in powers of two; round up to one.
            for size in (8, 16, 32, 64):
                if size >= per_stick:
                    per_stick = size
                    break
            total_after = (current + self.free_slots * per_stick * (1 << 30))
            return (f"There {'is' if self.free_slots == 1 else 'are'} "
                    f"{self.free_slots} empty slot"
                    f"{'' if self.free_slots == 1 else 's'}, so "
                    f"{self.free_slots} × {per_stick} GB can be added without "
                    f"removing anything already fitted — taking the machine to "
                    f"{total_after / (1 << 30):.0f} GB. That is the cheapest "
                    f"and least disruptive way out of this, and the only one "
                    f"that fixes it permanently.")
        largest = max(size for _l, size, _s in self.installed) / (1 << 30)
        return (f"All {self.total_slots} slots are full with "
                f"{largest:.0f} GB modules, so more memory means replacing "
                f"what is there rather than adding to it. The board accepts "
                f"up to {self.max_capacity / (1 << 30):.0f} GB.")


#: Read once. It needs a WMI round trip of about a second and physical memory
#: does not change while the machine is running.
_SLOTS_CACHE: MemorySlots | None = None


def memory_slots(refresh: bool = False) -> MemorySlots:
    global _SLOTS_CACHE
    if _SLOTS_CACHE is not None and not refresh:
        return _SLOTS_CACHE

    slots = MemorySlots()
    script = (
        "$m = Get-CimInstance Win32_PhysicalMemory | ForEach-Object { "
        "'{0}|{1}|{2}' -f $_.DeviceLocator, $_.Capacity, $_.Speed }; "
        "$a = Get-CimInstance Win32_PhysicalMemoryArray | "
        "Select-Object -First 1; "
        "Write-Output ('SLOTS|' + $a.MemoryDevices + '|' + $a.MaxCapacityEx); "
        "$m")
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=25,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            encoding="utf-8", errors="replace")
        output = completed.stdout or ""
    except (OSError, subprocess.SubprocessError):
        output = ""

    for line in output.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if parts[0] == "SLOTS":
            try:
                slots.total_slots = int(parts[1] or 0)
                # MaxCapacityEx is in kilobytes; the older MaxCapacity field
                # overflows above 4 TB and reports nonsense, so prefer Ex.
                slots.max_capacity = int(parts[2] or 0) * 1024
            except (ValueError, IndexError):
                pass
            continue
        try:
            slots.installed.append(
                (parts[0] or "?", int(parts[1] or 0), int(parts[2] or 0)))
        except (ValueError, IndexError):
            continue

    if slots.total_slots < len(slots.installed):
        slots.total_slots = len(slots.installed)
    _SLOTS_CACHE = slots
    return slots


@dataclass
class MachineFacts:
    os_name: str = ""
    os_build: str = ""
    computer: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    cpu_threads: int = 0
    cpu_freq_current: float = 0.0
    cpu_freq_max: float = 0.0
    ram_total: int = 0
    uptime_s: float = 0.0
    boot_time: float = 0.0
    power_plan: str = ""
    on_battery: bool = False
    battery_percent: float = 0.0
    disks: list[DiskInfo] = field(default_factory=list)
    startup: list[StartupItem] = field(default_factory=list)
    events: list[EventRecord] = field(default_factory=list)
    #: Percent of nominal clock the CPU is currently allowed.  Well under 100
    #: for a sustained period means throttling, which is the explanation for
    #: "it got slow and nothing is using the CPU".
    throttle_percent: float = 0.0

    @property
    def uptime_days(self) -> float:
        return self.uptime_s / 86400.0

    @property
    def system_disk(self) -> DiskInfo | None:
        drive = os.environ.get("SystemDrive", "C:").rstrip("\\") + "\\"
        for disk in self.disks:
            if disk.mountpoint.upper().startswith(drive.upper()):
                return disk
        return self.disks[0] if self.disks else None


def _startup_items() -> list[StartupItem]:
    items: list[StartupItem] = []
    for root, path in RUN_KEYS:
        scope = "user" if root == winreg.HKEY_CURRENT_USER else "machine"
        try:
            with winreg.OpenKey(root, path) as key:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    items.append(StartupItem(name=str(name),
                                             command=str(value)[:300],
                                             scope=scope))
                    index += 1
        except OSError:
            continue

    for folder, scope in ((os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "user"),
            (os.path.expandvars(
                r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
             "machine")):
        try:
            for entry in os.scandir(folder):
                if entry.is_file() and not entry.name.lower().endswith(".ini"):
                    items.append(StartupItem(name=entry.name,
                                             command=entry.path, scope=scope))
        except OSError:
            continue
    return items


#: Windows stores a scheme's FriendlyName as an indirect string — literally
#: "@%SystemRoot%\system32\powrprof.dll,-331" — which has to be resolved
#: through SHLoadIndirectString to become "Balanced".  For the four schemes
#: that ship with Windows the GUID is the more reliable answer anyway, since
#: it does not depend on the display language.
POWER_SCHEMES = {
    "381b4222-f694-41f0-9685-ff5bb260df2e": "Balanced",
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "High performance",
    "a1841308-3541-4fab-bc81-f71556f20b4a": "Power saver",
    "e9a42b02-d5df-448d-aa00-03f14749eb61": "Ultimate Performance",
    "ded574b5-45a0-4f42-8737-46345c09c238": "Ultimate Performance",
}


def _resolve_indirect(value: str) -> str:
    """Turn "@file.dll,-331" into the string it points at, or "" on failure."""
    if not value.startswith("@"):
        return value
    try:
        import ctypes
        buffer = ctypes.create_unicode_buffer(512)
        result = ctypes.windll.shlwapi.SHLoadIndirectString(
            ctypes.c_wchar_p(value), buffer, 512, None)
        return buffer.value if result == 0 and buffer.value else ""
    except Exception:
        return ""


def _power_plan() -> str:
    """The active power scheme's friendly name.

    Read from the registry rather than by running powercfg: spawning a process
    to answer one question is slow, and this tool is often run on a machine
    that is already struggling to start processes.
    """
    try:
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes") as key:
            active, _ = winreg.QueryValueEx(key, "ActivePowerScheme")
        guid = str(active).strip("{}").lower()
        if guid in POWER_SCHEMES:
            return POWER_SCHEMES[guid]
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
                f"\\{active}") as scheme:
            name = str(winreg.QueryValueEx(scheme, "FriendlyName")[0])
        return _resolve_indirect(name) or f"custom ({guid[:8]})"
    except OSError:
        return ""


def _cpu_model() -> str:
    try:
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            return str(name).strip()
    except OSError:
        return platform.processor()


def _os_build() -> str:
    try:
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product = winreg.QueryValueEx(key, "ProductName")[0]
            build = winreg.QueryValueEx(key, "CurrentBuild")[0]
            try:
                ubr = winreg.QueryValueEx(key, "UBR")[0]
                build = f"{build}.{ubr}"
            except OSError:
                pass
            try:
                display = winreg.QueryValueEx(key, "DisplayVersion")[0]
            except OSError:
                display = ""
            return f"{product} {display} (build {build})".replace("  ", " ")
    except OSError:
        return platform.platform()


def _recent_events(hours: int = 48, limit: int = 40) -> list[EventRecord]:
    """Errors and criticals from the System log that bear on freezing.

    Reads backwards from the newest record and stops at the time cutoff, so
    the cost is proportional to how much happened recently rather than to the
    size of the log.
    """
    try:
        import win32evtlog
    except ImportError:
        return []

    cutoff = time.time() - hours * 3600
    records: list[EventRecord] = []
    handle = None
    try:
        handle = win32evtlog.OpenEventLog(None, "System")
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ
                 | win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        scanned = 0
        while len(records) < limit and scanned < 4000:
            try:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception:
                break
            if not batch:
                break
            for event in batch:
                scanned += 1
                try:
                    when = int(event.TimeGenerated.timestamp())
                except Exception:
                    continue
                if when < cutoff:
                    batch = None
                    break
                # 1 = error, 2 = warning, 4 = information (EVENTLOG_* flags)
                event_type = getattr(event, "EventType", 4)
                if event_type not in (1, 2):
                    continue
                event_id = int(getattr(event, "EventID", 0)) & 0xFFFF
                source = str(getattr(event, "SourceName", ""))
                # Only claim to know what an event means when the provider
                # backs it up; otherwise keep it (it came from a provider we
                # care about) but describe it with its own message text.
                meaning = event_meaning(event_id, source)
                relevant = bool(meaning) or any(
                    marker.lower() in source.lower()
                    for marker in CRITICAL_SOURCES)
                if not relevant:
                    continue
                message = ""
                try:
                    strings = getattr(event, "StringInserts", None) or []
                    message = " | ".join(str(s) for s in strings)[:300]
                except Exception:
                    pass
                records.append(EventRecord(
                    when=when, source=source, event_id=event_id,
                    level="error" if event_type == 1 else "warning",
                    meaning=meaning, message=message))
                if len(records) >= limit:
                    break
            if batch is None:
                break
    except Exception:
        return records
    finally:
        if handle is not None:
            try:
                import win32evtlog
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
    return records


def gather(include_events: bool = True) -> MachineFacts:
    facts = MachineFacts()
    facts.os_name = platform.system() + " " + platform.release()
    facts.os_build = _os_build()
    facts.computer = platform.node()
    facts.cpu_model = _cpu_model()

    try:
        facts.cpu_cores = psutil.cpu_count(logical=False) or 0
        facts.cpu_threads = psutil.cpu_count(logical=True) or 0
        freq = psutil.cpu_freq()
        if freq:
            facts.cpu_freq_current = freq.current or 0.0
            facts.cpu_freq_max = freq.max or 0.0
            if facts.cpu_freq_max:
                facts.throttle_percent = (facts.cpu_freq_current
                                          / facts.cpu_freq_max * 100.0)
    except Exception:
        pass

    try:
        facts.ram_total = psutil.virtual_memory().total
        facts.boot_time = psutil.boot_time()
        facts.uptime_s = max(0.0, time.time() - facts.boot_time)
    except Exception:
        pass

    try:
        battery = psutil.sensors_battery()
        if battery is not None:
            facts.on_battery = not battery.power_plugged
            facts.battery_percent = battery.percent
    except Exception:
        pass

    facts.power_plan = _power_plan()

    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (OSError, PermissionError):
            continue
        facts.disks.append(DiskInfo(
            device=partition.device, mountpoint=partition.mountpoint,
            total=usage.total, used=usage.used, free=usage.free,
            percent=usage.percent))

    facts.startup = _startup_items()
    if include_events:
        facts.events = _recent_events()
    return facts


# ---------------------------------------------------------------- findings

def static_findings(facts: MachineFacts) -> list[dict]:
    """Problems visible from the machine's configuration alone.

    Returned as plain dicts and converted by `rules` rather than importing
    Finding here, which keeps this module free of the live-sampling types and
    usable on its own.
    """
    out: list[dict] = []

    disk = facts.system_disk
    if disk and disk.free_fraction < 0.10:
        critical = disk.free_fraction < 0.05
        out.append({
            "id": "disk-space",
            "title": f"The system drive is {disk.percent:.0f}% full",
            "severity": 5 if critical else 4,
            "confidence": 0.95,
            "category": "disk",
            "explanation": (
                f"{disk.mountpoint} has {disk.free / 1e9:.1f} GB free of "
                f"{disk.total / 1e9:.1f} GB. Windows needs free space to work, "
                f"not merely to store things: the page file grows into it, "
                f"Windows Update stages into it, and NTFS slows markedly once "
                f"a volume is this full because free space becomes fragmented "
                f"and every write has to hunt for somewhere to go. Below about "
                f"10% free, a machine develops exactly the symptoms of failing "
                f"hardware — long pauses, slow saves, stalls — with nothing "
                f"wrong with the drive at all."),
            "evidence": [f"{disk.mountpoint} {disk.free / 1e9:.1f} GB free of "
                         f"{disk.total / 1e9:.1f} GB "
                         f"({disk.free_fraction * 100:.1f}%)"],
            "fixes": [
                ("Run Disk Cleanup including system files",
                 "Windows Update leftovers and previous installations are "
                 "usually the largest single reclaim.", "cleanmgr /d C:"),
                ("Check what is actually using the space",
                 "Settings > System > Storage breaks it down; WizTree or "
                 "WinDirStat are faster for finding one huge folder.", ""),
            ],
        })

    if len(facts.startup) > 20:
        out.append({
            "id": "startup-bloat",
            "title": f"{len(facts.startup)} programs launch at sign-in",
            "severity": 3 if len(facts.startup) > 30 else 2,
            "confidence": 0.8,
            "category": "startup",
            "explanation": (
                f"{len(facts.startup)} entries start automatically. They all "
                f"compete for the disk and the CPU in the same few seconds, "
                f"which is why the desktop appears long before the machine is "
                f"usable, and most of them then stay resident for the rest of "
                f"the day holding memory. This is the usual explanation for a "
                f"machine that is slow from the moment it boots rather than "
                f"slow under load."),
            "evidence": [f"{item.name} ({item.scope}): {item.command[:90]}"
                         for item in facts.startup[:12]],
            "fixes": [
                ("Disable what you do not need at sign-in",
                 "Task Manager > Startup apps. Updaters, launchers and "
                 "vendor helpers can nearly all be started on demand.",
                 "taskmgr /0 /startup"),
            ],
        })

    if facts.uptime_days > 14:
        out.append({
            "id": "long-uptime",
            "title": f"The machine has been up for {facts.uptime_days:.0f} days",
            "severity": 2, "confidence": 0.7, "category": "system",
            "explanation": (
                f"Uptime of {facts.uptime_days:.0f} days is long enough for "
                f"slow leaks to matter. Handle and pool leaks accumulate with "
                f"uptime rather than with load, which is why a machine can be "
                f"fine for a week and unbearable in the second week, and why "
                f"the problem appears to fix itself after a restart and then "
                f"comes back."),
            "evidence": [f"uptime {facts.uptime_days:.1f} days",
                         f"booted {time.strftime('%Y-%m-%d %H:%M', time.localtime(facts.boot_time))}"],
            "fixes": [("Restart, then note how long until it returns",
                       "If the trouble comes back after a predictable number "
                       "of days, it is a leak and the timing identifies it.",
                       "")],
        })

    if facts.throttle_percent and facts.throttle_percent < 70:
        out.append({
            "id": "cpu-throttle",
            "title": f"The CPU is running at {facts.throttle_percent:.0f}% of "
                     f"its rated clock",
            "severity": 3, "confidence": 0.55, "category": "cpu",
            "explanation": (
                f"The processor is currently clocked at "
                f"{facts.cpu_freq_current:.0f} MHz against a rated "
                f"{facts.cpu_freq_max:.0f} MHz. Sustained, that means it is "
                f"being held back — by the power plan, by running on battery, "
                f"or by heat. A throttled CPU produces the most confusing kind "
                f"of slowness, because Task Manager reports a low CPU "
                f"percentage while everything takes longer: the percentage is "
                f"of a much smaller machine than you paid for."),
            "evidence": [f"current {facts.cpu_freq_current:.0f} MHz of "
                         f"{facts.cpu_freq_max:.0f} MHz rated",
                         f"power plan: {facts.power_plan or 'unknown'}",
                         f"on battery: {facts.on_battery}"],
            "fixes": [
                ("Check the power plan",
                 "Balanced is fine; Power saver holds the clock down "
                 "permanently.", "powercfg /list"),
                ("If it is a laptop, check for heat",
                 "A blocked fan or dried thermal paste throttles the CPU "
                 "under any load and is the most common cause on a machine "
                 "more than two years old.", ""),
            ],
        })

    # Storage and power events are the two that explain hard freezes.
    # `e.meaning` is only populated when the provider matched the id, so
    # filtering on it keeps an unrelated Event 51 from a random service out
    # of a finding that tells the user their drive is failing.
    storage_events = [e for e in facts.events
                      if e.event_id in (7, 51, 153, 129, 157, 55)
                      and e.meaning]
    if storage_events:
        out.append({
            "id": "storage-errors",
            "title": f"{len(storage_events)} storage error(s) in the system log",
            "severity": 5, "confidence": 0.85, "category": "hardware",
            "explanation": (
                "The system event log contains storage errors. These are the "
                "single most reliable explanation for a machine that freezes "
                "completely for several seconds and then carries on: the drive "
                "or its controller stopped answering, every thread waiting on "
                "it stopped with it, and the system resumed when the request "
                "was retried or abandoned. No amount of closing applications "
                "will help — this is the hardware or its driver."),
            "evidence": [
                f"{time.strftime('%m-%d %H:%M', time.localtime(e.when))} "
                f"{e.source} (id {e.event_id}): {e.meaning or e.message[:120]}"
                for e in storage_events[:8]],
            "fixes": [
                ("Check the drive's SMART health",
                 "CrystalDiskInfo reads the drive's own reliability counters. "
                 "Reallocated or pending sectors mean replace it now.", ""),
                ("Update the storage driver and firmware",
                 "Controller resets are as often a driver bug as a dying "
                 "drive, particularly on NVMe.", ""),
                ("Back up before investigating further",
                 "If the drive is failing, the investigation matters less "
                 "than the copy.", ""),
            ],
        })

    # Windows' own Resource Exhaustion Detector.  This is worth its own
    # finding rather than being folded into the live memory rule, because it
    # is retrospective evidence: it proves the machine ran out of memory at
    # specific times in the past, including times the user was complaining
    # about and this tool was not running.
    exhaustion = [e for e in facts.events
                  if e.event_id == 2004 and e.meaning]
    if exhaustion:
        span = ""
        if len(exhaustion) > 1:
            first = min(e.when for e in exhaustion)
            last = max(e.when for e in exhaustion)
            hours = max(1.0, (last - first) / 3600)
            span = (f" — {len(exhaustion)} of them across "
                    f"{hours:.0f} hours, roughly one every "
                    f"{hours * 60 / len(exhaustion):.0f} minutes")
        out.append({
            "id": "memory-exhaustion-events",
            "title": f"Windows logged running out of memory "
                     f"{len(exhaustion)} time(s)",
            "severity": 5 if len(exhaustion) > 3 else 4,
            "confidence": 0.95,
            "category": "memory",
            "explanation": (
                f"Windows' Resource Exhaustion Detector fires when the commit "
                f"charge gets close enough to the limit that Windows has to "
                f"start forcibly trimming running applications{span}. This is "
                f"not an inference from a graph — it is Windows recording, at "
                f"the time, that it could not meet the demand for memory. "
                f"Each of these entries corresponds to a period where "
                f"applications were being paged out from under the user, "
                f"which is felt as the whole machine locking up for several "
                f"seconds at a time. It also names the processes that were "
                f"largest when it happened, which is the closest thing to a "
                f"confession available."),
            "evidence": [
                f"{time.strftime('%m-%d %H:%M', time.localtime(e.when))} "
                f"{e.source} (id {e.event_id})"
                + (f": {e.message[:160]}" if e.message else "")
                for e in exhaustion[:8]],
            "fixes": [
                ("Read the full entry for the process list",
                 "Event 2004 records the top memory consumers at the moment "
                 "it fired, which names the culprit at the time of the "
                 "freeze rather than now.",
                 "wevtutil qe System /q:\"*[System[(EventID=2004)]]\" /c:3 /rd:true /f:text"),
                ("Treat this as the primary problem",
                 "While these keep appearing, every other slowdown on the "
                 "machine is downstream of them.", ""),
            ],
        })

    power_events = [e for e in facts.events
                    if e.event_id in (41, 6008) and e.meaning]
    if power_events:
        out.append({
            "id": "hard-lockups",
            "title": f"{len(power_events)} unclean shutdown(s) recorded",
            "severity": 4, "confidence": 0.8, "category": "hardware",
            "explanation": (
                "Windows recorded that it was not shut down cleanly. That "
                "means the machine either lost power or locked up so hard it "
                "had to be held down — a different and more serious class of "
                "problem than an application freezing. The usual causes are "
                "a failing power supply, memory errors, overheating, or a "
                "driver bugcheck."),
            "evidence": [
                f"{time.strftime('%m-%d %H:%M', time.localtime(e.when))} "
                f"{e.source} (id {e.event_id}): {e.meaning}"
                for e in power_events[:6]],
            "fixes": [
                ("Test the memory",
                 "Windows Memory Diagnostic, or MemTest86 for a thorough "
                 "run.", "mdsched.exe"),
                ("Look for a bugcheck dump",
                 "A minidump names the driver that crashed.",
                 "dir %SystemRoot%\\Minidump"),
            ],
        })

    whea = [e for e in facts.events
            if e.event_id in (1, 17, 18) and e.meaning]
    if whea:
        out.append({
            "id": "hardware-errors",
            "title": f"{len(whea)} hardware error(s) reported by WHEA",
            "severity": 5, "confidence": 0.9, "category": "hardware",
            "explanation": (
                "The Windows Hardware Error Architecture recorded machine "
                "check errors. These come from the processor itself reporting "
                "that something went wrong at the hardware level — memory, "
                "cache, PCIe or the CPU. Correctable ones are a warning; "
                "uncorrectable ones are why the machine crashed. Software "
                "cannot fix this."),
            "evidence": [
                f"{time.strftime('%m-%d %H:%M', time.localtime(e.when))} "
                f"{e.source} (id {e.event_id}): {e.meaning}"
                for e in whea[:6]],
            "fixes": [
                ("Test memory and check temperatures", "", "mdsched.exe"),
                ("Reseat memory and check for BIOS updates",
                 "Correctable WHEA errors are very often one loose or failing "
                 "DIMM.", ""),
            ],
        })

    return out
