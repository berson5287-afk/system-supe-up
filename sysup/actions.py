"""Things the tool can actually do to the machine, and nothing else.

**The model never writes a command that gets run.** It picks an action from
this catalogue by id and supplies parameters that are validated here. That is
the entire safety model, and it is deliberate: a language model asked to fix a
Windows problem will cheerfully produce `del /s /q C:\\Windows\\*` with an
explanation of why that is reasonable, and no amount of prompting reliably
prevents it. Free-form suggestions from the model are shown to the user as
text to read, never as something to execute.

Every action declares:

* whether it needs administrator rights (and elevation is requested per action
  rather than the whole app running elevated, so a monitor is not a permanent
  administrator process),
* whether it is reversible, and how,
* what it expects to change, so the result can be checked afterwards rather
  than assumed.

`dry_run` is honoured by every handler. The interface always previews before
it applies.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import time
import winreg
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import requests

from . import knowledge

#: Keeps a console window from flashing up for every command.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(command: list[str], timeout: int = 120) -> tuple[int, str]:
    """Run a command with no shell, so nothing can be injected into it."""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return 1, f"timed out after {timeout}s"
    except (OSError, ValueError) as error:
        return 1, str(error)
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output.strip()


def _run_elevated(command: str, arguments: str, wait: bool = True) -> tuple[int, str]:
    """Ask for elevation for one command, via PowerShell's Start-Process.

    Deliberately per-action. A performance monitor that runs as administrator
    all day so that it can occasionally restart a service is a much larger
    thing to trust than one that asks each time.
    """
    script = (f"$p = Start-Process -FilePath '{command}' -ArgumentList "
              f"'{arguments}' -Verb RunAs -PassThru"
              + ("; $p.WaitForExit(); exit $p.ExitCode" if wait else ""))
    code, output = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=600)
    if "canceled by the user" in output or "cancelled" in output.lower():
        return 1, "The administrator prompt was declined."
    return code, output


@dataclass
class ActionSpec:
    """One thing that can be done, described well enough to be chosen."""

    id: str
    title: str
    detail: str
    category: str
    risk: str = "low"
    needs_admin: bool = False
    reversible: bool = True
    undo_hint: str = ""
    #: parameter name -> what it means. Kept tiny; the model has to fill these
    #: in correctly and every extra field is another thing to get wrong.
    params: dict[str, str] = field(default_factory=dict)
    #: What the user should expect to see change, so the result is checkable.
    expect: str = ""
    handler: Callable | None = None

    def describe(self) -> dict:
        """The form the model sees.  No handler, no Python objects."""
        return {"id": self.id, "title": self.title, "what_it_does": self.detail,
                "risk": self.risk, "needs_admin": self.needs_admin,
                "reversible": self.reversible,
                "parameters": self.params or {}}


@dataclass
class ActionResult:
    ok: bool
    message: str
    changed: bool = False
    output: str = ""
    #: Enough to reverse it, when it is reversible.
    undo: dict | None = None


@dataclass
class PlannedAction:
    """A catalogue action with arguments, chosen for a specific finding."""

    spec: ActionSpec
    params: dict
    reason: str = ""
    selected: bool = True
    result: ActionResult | None = None

    @property
    def label(self) -> str:
        target = self.params.get("name") or self.params.get("pid") or ""
        return f"{self.spec.title}{f' — {target}' if target else ''}"


REGISTRY: dict[str, ActionSpec] = {}


def action(spec: ActionSpec):
    def wrap(function):
        spec.handler = function
        REGISTRY[spec.id] = spec
        return function
    return wrap


# --------------------------------------------------------------- diagnostics
# Read-only. These change nothing and are always safe to offer.

@action(ActionSpec(
    id="check_smart",
    title="Check the drive's own health report",
    detail="Reads the SMART predict-failure flag and status for every physical "
           "disk. Changes nothing. This is the check that settles whether "
           "storage errors are a dying drive or a driver problem.",
    category="diagnostic", risk="low", reversible=True,
    expect="A status line per drive."))
def _check_smart(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would read SMART status for each disk.")
    # Emit one parseable line per drive. The original version searched the
    # whole blob for "PredictFailure : False", which reported a healthy
    # machine as long as *any* drive was fine — exactly backwards on the
    # multi-drive systems where it matters most.
    code, output = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-CimInstance -Namespace root\\wmi "
        "-ClassName MSStorageDriver_FailurePredictStatus "
        "-ErrorAction SilentlyContinue | ForEach-Object { "
        "'SMART|{0}|{1}|{2}' -f $_.InstanceName, $_.PredictFailure, $_.Reason };"
        "Get-CimInstance Win32_DiskDrive | ForEach-Object { "
        "'DISK|{0}|{1}|{2}' -f $_.Model, $_.Status, $_.Size }"], timeout=90)

    drives: list[tuple[str, bool, str]] = []
    disks: list[tuple[str, str]] = []
    for line in (output or "").splitlines():
        parts = line.strip().split("|")
        if parts[0] == "SMART" and len(parts) >= 3:
            predicts = parts[2].strip().lower() in ("true", "1")
            drives.append((parts[1].strip(), predicts,
                           parts[3].strip() if len(parts) > 3 else ""))
        elif parts[0] == "DISK" and len(parts) >= 3:
            disks.append((parts[1].strip(), parts[2].strip()))

    if not drives and not disks:
        return ActionResult(False, "The drives did not report SMART data. "
                                   "Many NVMe drives need vendor tooling such "
                                   "as CrystalDiskInfo to read it.")

    failing = [name for name, predicts, _reason in drives if predicts]
    unhealthy = [model for model, status in disks
                 if status and status.upper() != "OK"]

    lines = [f"{name}: {'FAILURE PREDICTED' if predicts else 'no failure predicted'}"
             + (f" ({reason})" if reason else "")
             for name, predicts, reason in drives]
    lines += [f"{model}: status {status}" for model, status in disks]
    detail = "\n".join(lines)

    if failing or unhealthy:
        named = ", ".join(failing + unhealthy)
        return ActionResult(
            True, f"At least one drive is reporting a problem: {named}. Back "
                  f"up now and replace it — this is not a driver issue.",
            output=detail)
    return ActionResult(
        True, f"All {len(drives) or len(disks)} drive(s) report healthy, so "
              f"storage errors point at the driver or controller rather than "
              f"at failing media.", output=detail)


@action(ActionSpec(
    id="storage_driver_info",
    title="Show the storage controller driver and its date",
    detail="Lists the storage controller driver, version and date. Changes "
           "nothing. A driver that predates the trouble, or a very old one, "
           "is the first suspect for controller resets.",
    category="diagnostic", risk="low",
    expect="Driver name, version and date."))
def _storage_driver_info(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would list storage controller drivers.")
    code, output = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-CimInstance Win32_PnPSignedDriver | Where-Object { "
        "$_.DeviceClass -eq 'SCSIADAPTER' -or $_.DeviceName -match "
        "'SATA|NVMe|RAID|Storage' } | Select-Object DeviceName,DriverVersion,"
        "DriverDate,Manufacturer | Format-List"], timeout=90)
    return ActionResult(bool(output.strip()),
                        "Storage drivers listed." if output.strip()
                        else "Nothing returned.", output=output)


@action(ActionSpec(
    id="chkdsk_scan",
    title="Scan the system drive for errors (read-only)",
    detail="Runs a read-only scan of the file system. It does not repair "
           "anything, does not need a reboot, and can run while you work.",
    category="diagnostic", risk="low", needs_admin=True,
    expect="A summary of any problems found."))
def _chkdsk_scan(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would run 'chkdsk C: /scan' (read-only).")
    drive = str(params.get("drive") or os.environ.get("SystemDrive", "C:"))
    if not drive.rstrip(":\\").isalpha() or len(drive.rstrip(":\\")) != 1:
        return ActionResult(False, f"Refusing an odd drive letter: {drive!r}")
    code, output = _run_elevated("chkdsk.exe", f"{drive} /scan")
    return ActionResult(code == 0, "Scan finished." if code == 0
                        else "Scan did not complete.", output=output)


@action(ActionSpec(
    id="show_event_detail",
    title="Show the full text of the recent memory-exhaustion events",
    detail="Prints the complete event 2004 entries, which name the processes "
           "that were largest at the moment Windows ran out of memory. "
           "Changes nothing.",
    category="diagnostic", risk="low",
    expect="Full event text including the offending processes."))
def _show_event_detail(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would read the last few event 2004 entries.")
    event_id = int(params.get("event_id") or 2004)
    if event_id not in (41, 51, 129, 153, 1001, 2004, 6008):
        return ActionResult(False, f"Not an event this tool reads: {event_id}")
    code, output = _run([
        "wevtutil", "qe", "System",
        f"/q:*[System[(EventID={event_id})]]", "/c:4", "/rd:true", "/f:text"],
        timeout=90)
    return ActionResult(bool(output.strip()), "Event detail read.",
                        output=output)


# ------------------------------------------------------------------- memory

def _ollama_candidates(given: str = "") -> list[str]:
    """Which servers to try.  The configured ones, not just loopback.

    The model routinely leaves this parameter out, and defaulting to
    127.0.0.1 then reports "nothing loaded" on a machine whose models are
    held by the host box — which is exactly the memory this action exists to
    reclaim.
    """
    if given:
        return [given.rstrip("/")]
    urls = ["http://127.0.0.1:11434"]
    try:
        from .config import Settings
        urls = list(dict.fromkeys(Settings.load().servers() + urls))
    except Exception:
        pass
    return urls


@action(ActionSpec(
    id="unload_ollama_models",
    title="Unload the models held in memory by Ollama",
    detail="Tells the Ollama server to drop every model it currently has "
           "loaded, returning that memory immediately. Nothing is deleted — "
           "the model reloads from disk the next time it is used, which takes "
           "a few seconds. On a machine short of RAM this is usually the "
           "single largest amount of memory recoverable in one step.",
    category="memory", risk="low", reversible=True,
    undo_hint="The model reloads automatically on next use.",
    params={"url": "Ollama server URL — leave out to try the configured ones"},
    expect="Available memory rises by the size of the loaded models."))
def _unload_ollama(params: dict, dry_run: bool = False) -> ActionResult:
    given = str(params.get("url") or "").strip()
    if given and not given.startswith(("http://", "https://")):
        return ActionResult(False, f"Not a URL: {given!r}")

    url, loaded, errors = "", [], []
    for candidate in _ollama_candidates(given):
        try:
            response = requests.get(f"{candidate}/api/ps", timeout=6)
            found = response.json().get("models", []) if response.ok else []
        except (requests.RequestException, ValueError) as error:
            errors.append(f"{candidate}: {error}")
            continue
        if found:
            url, loaded = candidate, found
            break
        url = url or candidate
    if not loaded:
        if errors and not url:
            return ActionResult(False, "No Ollama server answered.\n"
                                       + "\n".join(errors))
        return ActionResult(True, "No Ollama server is holding a model in "
                                  "memory right now.")

    names = [m.get("name") or m.get("model") for m in loaded if m.get("name")
             or m.get("model")]
    freed = sum(int(m.get("size") or 0) for m in loaded)
    if dry_run:
        return ActionResult(
            True, f"Would unload {len(names)} model(s) from {url} — about "
                  f"{freed / 1e9:.1f} GB: {', '.join(names)}")

    unloaded = []
    for name in names:
        try:
            # keep_alive 0 is Ollama's own "drop it now" instruction.
            requests.post(f"{url}/api/generate",
                          json={"model": name, "keep_alive": 0}, timeout=30)
            unloaded.append(name)
        except requests.RequestException:
            continue
    return ActionResult(
        bool(unloaded),
        f"Unloaded {len(unloaded)} model(s), freeing about {freed / 1e9:.1f} GB."
        if unloaded else "Could not unload the models.",
        changed=bool(unloaded), output="\n".join(unloaded))


@action(ActionSpec(
    id="restart_process",
    title="Close a process",
    detail="Ends one process. Unsaved work in it is lost. Only processes the "
           "built-in table marks as safe to end can be chosen — anything "
           "essential to Windows is refused.",
    category="memory", risk="medium", reversible=False,
    undo_hint="Start the application again yourself.",
    params={"pid": "The numeric process id", "name": "The executable name"},
    expect="The process disappears and its memory is returned."))
def _restart_process(params: dict, dry_run: bool = False) -> ActionResult:
    name = str(params.get("name") or "")
    try:
        pid = int(params.get("pid") or 0)
    except (TypeError, ValueError):
        return ActionResult(False, "No usable process id.")
    if pid <= 4:
        return ActionResult(False, "Refusing: that is a system process.")
    if not knowledge.is_killable(name):
        return ActionResult(
            False, f"Refusing to end {name}: it is not on the list of "
                   f"processes that are safe to close.")

    # Windows reuses process ids, and freely. Between the moment the planner
    # chose this pid and the moment somebody clicks Apply — which may be
    # minutes, across a research round trip and a confirmation dialog — the
    # original process can exit and an entirely unrelated one inherit the
    # number. Killing by a stale pid is how a tool that promised to close a
    # browser tab ends a database instead, so the identity is re-checked
    # against the name here, immediately before the kill.
    import psutil

    try:
        target = psutil.Process(pid)
        actual = target.name()
        created = target.create_time()
    except psutil.NoSuchProcess:
        return ActionResult(True, f"{name} (pid {pid}) has already exited — "
                                  f"nothing to do.")
    except (psutil.AccessDenied, OSError) as error:
        return ActionResult(False, f"Could not verify pid {pid}: {error}")

    if actual.lower() != name.lower():
        return ActionResult(
            False, f"Refusing: pid {pid} is now {actual}, not {name}. Windows "
                   f"reuses process ids and this one has been recycled since "
                   f"the plan was made. Re-run the diagnosis.")
    # If the planner recorded when it saw the process, insist it is the same
    # one. Names collide too — two chrome.exe are not interchangeable.
    expected_created = params.get("create_time")
    if expected_created is not None:
        try:
            if abs(float(expected_created) - created) > 1.0:
                return ActionResult(
                    False, f"Refusing: pid {pid} is a different {name} from "
                           f"the one that was inspected.")
        except (TypeError, ValueError):
            pass

    # Browsers and Electron apps run one process per tab or window. Ending one
    # of twenty-one closes a tab and frees a fraction of what the name
    # suggests, so say so before it is approved rather than after.
    siblings, family_bytes = 0, 0
    try:
        for other in psutil.process_iter(["name", "memory_info"]):
            if (other.info.get("name") or "").lower() == name.lower():
                siblings += 1
                info = other.info.get("memory_info")
                family_bytes += getattr(info, "private", 0) or getattr(
                    info, "rss", 0) or 0
    except Exception:
        siblings = 0

    if dry_run:
        note = f"Would end {name} (pid {pid})."
        if siblings > 1:
            note += (f"\n  Note: {siblings} processes are running under this "
                     f"name, holding about {family_bytes / 1e9:.1f} GB "
                     f"between them. Ending this one closes a single tab or "
                     f"window, not the whole application — expect to recover "
                     f"roughly {family_bytes / siblings / 1e6:.0f} MB, not "
                     f"{family_bytes / 1e9:.1f} GB.")
        return ActionResult(True, note)
    code, output = _run(["taskkill", "/f", "/pid", str(pid)], timeout=30)
    return ActionResult(code == 0, f"Ended {name}." if code == 0
                        else f"Could not end {name}.", changed=code == 0,
                        output=output)


@action(ActionSpec(
    id="restart_explorer",
    title="Restart Windows Explorer",
    detail="Restarts the desktop, taskbar and file windows. Costs you any "
           "open folder windows and nothing else, and immediately returns "
           "leaked handles and threads.",
    category="memory", risk="low", reversible=True,
    undo_hint="Explorer restarts itself; nothing to undo.",
    expect="Explorer's thread and handle counts drop to a few hundred."))
def _restart_explorer(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would restart explorer.exe.")
    _run(["taskkill", "/f", "/im", "explorer.exe"], timeout=30)
    time.sleep(1.5)
    try:
        subprocess.Popen(["explorer.exe"], creationflags=NO_WINDOW)
    except OSError as error:
        return ActionResult(False, f"Explorer did not restart: {error}. "
                                   f"Press Ctrl+Shift+Esc > File > Run new "
                                   f"task > explorer.exe")
    return ActionResult(True, "Explorer restarted.", changed=True)


@action(ActionSpec(
    id="restart_audio_service",
    title="Restart the Windows Audio service",
    detail="Restarts Windows Audio, which recycles the audio engine process "
           "(audiodg.exe) and releases the handles it has accumulated. Audio "
           "cuts out for a second or two. Anything currently playing may need "
           "restarting.",
    category="handles", risk="medium", needs_admin=True, reversible=True,
    undo_hint="The service restarts itself; nothing to undo.",
    expect="audiodg.exe reappears with a few hundred handles instead of "
           "tens of thousands."))
def _restart_audio(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would restart the Audiosrv service.")
    code, output = _run_elevated(
        "powershell.exe",
        "-NoProfile -Command \"Restart-Service -Name Audiosrv -Force\"")
    return ActionResult(code == 0, "Windows Audio restarted." if code == 0
                        else "Could not restart Windows Audio.",
                        changed=code == 0, output=output)


@action(ActionSpec(
    id="set_wsl_memory_cap",
    title="Cap how much memory WSL may take",
    detail="Writes a memory limit into %UserProfile%\\.wslconfig. WSL2 "
           "otherwise helps itself to up to half the machine's RAM and does "
           "not give it back.",
    category="memory", risk="low", reversible=True,
    undo_hint="The previous .wslconfig is kept and can be restored.",
    params={"gigabytes": "The cap in GB, e.g. 4"},
    expect="After 'wsl --shutdown', WSL never exceeds the cap."))
def _wsl_cap(params: dict, dry_run: bool = False) -> ActionResult:
    try:
        gigabytes = int(params.get("gigabytes") or 4)
    except (TypeError, ValueError):
        return ActionResult(False, "The cap has to be a whole number of GB.")
    if not 1 <= gigabytes <= 64:
        return ActionResult(False, "Refusing a cap outside 1–64 GB.")
    path = Path.home() / ".wslconfig"
    existing = ""
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as error:
            return ActionResult(False, f"Could not read {path}: {error}")

    merged, replaced = _merge_wslconfig(existing, gigabytes)
    if dry_run:
        note = (f"Would set WSL's memory cap to {gigabytes} GB in {path}.")
        if existing:
            other = [line.split("=")[0].strip()
                     for line in existing.splitlines()
                     if "=" in line and not line.strip().startswith("#")
                     and not line.strip().lower().startswith("memory")]
            note += (f"\n  {'Replacing' if replaced else 'Adding'} the memory "
                     f"setting and keeping everything else"
                     + (f" ({', '.join(other[:6])})" if other else ""))
        return ActionResult(True, note)

    try:
        path.write_text(merged, encoding="utf-8")
    except OSError as error:
        return ActionResult(False, f"Could not write {path}: {error}")
    return ActionResult(
        True, f"WSL capped at {gigabytes} GB. Run 'wsl --shutdown' to apply.",
        changed=True,
        undo={"path": str(path), "content": existing if existing else None})


def _merge_wslconfig(existing: str, gigabytes: int) -> tuple[str, bool]:
    """Set memory= under [wsl2], leaving every other line exactly as it was.

    `.wslconfig` carries processors, swap, kernel, networking and a dozen
    other independent settings. Rewriting the file with a single memory line —
    which is what this did originally — silently destroys all of them, and the
    user does not find out until WSL next behaves strangely. Editing line by
    line rather than through a config parser also preserves comments and
    ordering, which a parser would quietly discard.
    """
    if not existing.strip():
        return f"[wsl2]\nmemory={gigabytes}GB\n", False

    lines = existing.splitlines()
    out: list[str] = []
    in_wsl2 = False
    replaced = False
    wsl2_end = -1

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_wsl2 and not replaced:
                wsl2_end = len(out)     # remember where the section finished
            in_wsl2 = stripped.lower() == "[wsl2]"
        elif (in_wsl2 and not stripped.startswith("#")
              and stripped.lower().replace(" ", "").startswith("memory=")):
            out.append(f"memory={gigabytes}GB")
            replaced = True
            continue
        out.append(line)

    if not replaced:
        if in_wsl2:                      # [wsl2] ran to the end of the file
            out.append(f"memory={gigabytes}GB")
        elif wsl2_end >= 0:              # insert at the end of the section
            out.insert(wsl2_end, f"memory={gigabytes}GB")
        else:                            # no [wsl2] section at all
            out += ["", "[wsl2]", f"memory={gigabytes}GB"]

    return "\n".join(out).rstrip("\n") + "\n", replaced


# ------------------------------------------------------------------ startup

@action(ActionSpec(
    id="disable_startup_item",
    title="Stop a program starting at sign-in",
    detail="Moves a Run-key entry aside so it no longer launches at sign-in. "
           "The program itself is untouched and can still be started by hand. "
           "The original value is kept so this can be undone exactly.",
    category="startup", risk="medium", reversible=True,
    undo_hint="The original registry value is stored and can be restored.",
    params={"name": "The exact name of the startup entry",
            "scope": "'user' or 'machine'"},
    expect="The entry no longer appears in Task Manager's Startup tab."))
def _disable_startup(params: dict, dry_run: bool = False) -> ActionResult:
    name = str(params.get("name") or "").strip()
    scope = str(params.get("scope") or "user").lower()
    if not name:
        return ActionResult(False, "No startup entry named.")
    root = winreg.HKEY_CURRENT_USER if scope == "user" else winreg.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    if scope != "user" and not is_admin():
        return ActionResult(False, "Changing a machine-wide startup entry "
                                   "needs administrator rights.")
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, name)
    except OSError:
        return ActionResult(False, f"No startup entry called {name!r} in the "
                                   f"{scope} list.")
    if dry_run:
        return ActionResult(True, f"Would stop {name!r} launching at sign-in "
                                  f"(currently: {str(value)[:80]}).")
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except OSError as error:
        return ActionResult(False, f"Could not change it: {error}")
    return ActionResult(
        True, f"{name} will no longer start at sign-in.", changed=True,
        undo={"kind": "run_key", "root": scope, "name": name,
              "value": str(value), "type": int(kind)})


@action(ActionSpec(
    id="disable_sysmain",
    title="Turn off SysMain (Superfetch)",
    detail="SysMain pre-loads applications into RAM hoping you will want "
           "them. On an SSD it buys very little, and on a machine short of "
           "memory it competes with the applications you are actually using.",
    category="memory", risk="medium", needs_admin=True, reversible=True,
    undo_hint="Re-enable with: sc config SysMain start=auto",
    expect="One less service competing for memory and disk."))
def _disable_sysmain(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would stop SysMain and set it to disabled.")
    code, output = _run_elevated(
        "powershell.exe",
        "-NoProfile -Command \"Set-Service -Name SysMain -StartupType "
        "Disabled; Stop-Service -Name SysMain -Force\"")
    return ActionResult(code == 0, "SysMain disabled." if code == 0
                        else "Could not disable SysMain.", changed=code == 0,
                        output=output,
                        undo={"kind": "service", "name": "SysMain",
                              "start": "auto"})


# ---------------------------------------------------------------- disk space

@action(ActionSpec(
    id="clear_temp_files",
    title="Delete temporary files",
    detail="Empties your user temp folder. Files in use are skipped. This is "
           "the safest space to reclaim — everything here is by definition "
           "disposable.",
    category="disk", risk="low", reversible=False,
    undo_hint="Temporary files are not meant to be kept.",
    expect="Free space on the system drive increases."))
def _clear_temp(params: dict, dry_run: bool = False) -> ActionResult:
    temp = Path(os.environ.get("TEMP", ""))
    if not temp.is_dir():
        return ActionResult(False, "Could not find the temp folder.")
    entries = list(temp.iterdir())
    total = 0
    for entry in entries:
        try:
            total += entry.stat().st_size if entry.is_file() else 0
        except OSError:
            continue
    if dry_run:
        return ActionResult(
            True, f"Would try to delete {len(entries)} items in {temp} "
                  f"(about {total / 1e6:.0f} MB of loose files; folders add "
                  f"more). Anything in use is skipped.")
    removed = 0
    for entry in entries:
        try:
            if entry.is_file() or entry.is_symlink():
                entry.unlink()
            else:
                shutil.rmtree(entry, ignore_errors=True)
            removed += 1
        except OSError:
            continue
    return ActionResult(True, f"Removed {removed} of {len(entries)} items "
                              f"from the temp folder.", changed=removed > 0)


@action(ActionSpec(
    id="clear_thumbnail_cache",
    title="Clear the thumbnail cache",
    detail="Deletes Explorer's thumbnail database. A corrupt entry in it "
           "makes Explorer hang on any folder containing the offending file. "
           "Thumbnails are rebuilt as you browse.",
    category="disk", risk="low", reversible=False,
    undo_hint="Thumbnails regenerate automatically.",
    expect="Explorer stops hanging on the folder that was misbehaving."))
def _clear_thumbnails(params: dict, dry_run: bool = False) -> ActionResult:
    folder = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Windows/Explorer"
    if not folder.is_dir():
        return ActionResult(False, "Could not find the Explorer cache folder.")
    files = list(folder.glob("thumbcache_*.db")) + list(
        folder.glob("iconcache_*.db"))
    if dry_run:
        return ActionResult(True, f"Would delete {len(files)} cache file(s). "
                                  f"Explorer restarts as part of this.")
    _run(["taskkill", "/f", "/im", "explorer.exe"], timeout=30)
    time.sleep(1.0)
    removed = 0
    for file in files:
        try:
            file.unlink()
            removed += 1
        except OSError:
            continue
    try:
        subprocess.Popen(["explorer.exe"], creationflags=NO_WINDOW)
    except OSError:
        pass
    return ActionResult(True, f"Deleted {removed} cache file(s) and restarted "
                              f"Explorer.", changed=removed > 0)


@action(ActionSpec(
    id="run_disk_cleanup",
    title="Open Disk Cleanup for the system drive",
    detail="Opens Windows' own Disk Cleanup with system files included. It is "
           "opened rather than run silently so you can see and choose what it "
           "removes — some categories, like previous Windows installations, "
           "cannot be undone.",
    category="disk", risk="low", reversible=False,
    expect="A dialog you drive yourself."))
def _disk_cleanup(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would open Disk Cleanup for the system "
                                  "drive.")
    drive = os.environ.get("SystemDrive", "C:")
    try:
        subprocess.Popen(["cleanmgr.exe", f"/d{drive}"], creationflags=0)
    except OSError as error:
        return ActionResult(False, f"Could not open Disk Cleanup: {error}")
    return ActionResult(True, "Disk Cleanup opened — choose what to remove.")


# ------------------------------------------------------------------ network

@action(ActionSpec(
    id="flush_dns",
    title="Flush the DNS cache",
    detail="Clears cached name lookups. Helps when applications stall waiting "
           "on a name that has since changed or gone away.",
    category="network", risk="low", reversible=True,
    undo_hint="The cache refills by itself.",
    expect="Name lookups are resolved fresh."))
def _flush_dns(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would run 'ipconfig /flushdns'.")
    code, output = _run(["ipconfig", "/flushdns"], timeout=30)
    return ActionResult(code == 0, "DNS cache flushed." if code == 0
                        else "Could not flush the DNS cache.",
                        changed=code == 0, output=output)


# ------------------------------------------------------------------- system

@action(ActionSpec(
    id="create_restore_point",
    title="Create a system restore point first",
    detail="Takes a restore point so anything done afterwards can be rolled "
           "back. Worth doing before any change that is not trivially "
           "reversible. Requires System Protection to be turned on.",
    category="safety", risk="low", needs_admin=True, reversible=True,
    params={"description": "A short label"},
    expect="A restore point dated now."))
def _restore_point(params: dict, dry_run: bool = False) -> ActionResult:
    label = str(params.get("description") or "Before System Supe-Up")[:60]
    label = "".join(c for c in label if c.isalnum() or c in " -_.")
    if dry_run:
        return ActionResult(True, f"Would create a restore point “{label}”.")
    code, output = _run_elevated(
        "powershell.exe",
        f"-NoProfile -Command \"Checkpoint-Computer -Description '{label}' "
        f"-RestorePointType MODIFY_SETTINGS\"")
    if code != 0 and "disabled" in output.lower():
        return ActionResult(False, "System Protection is turned off, so no "
                                   "restore point could be made. Turn it on "
                                   "in System Properties > System Protection.")
    return ActionResult(code == 0, "Restore point created." if code == 0
                        else "Could not create a restore point.",
                        changed=code == 0, output=output)


@action(ActionSpec(
    id="set_power_plan",
    title="Switch the power plan",
    detail="Changes the active power scheme. A machine on Power saver holds "
           "its processor clock down permanently, which reads as general "
           "slowness with a low CPU percentage.",
    category="cpu", risk="low", reversible=True,
    undo_hint="Switch back to the previous plan the same way.",
    params={"plan": "'balanced' or 'high'"},
    expect="The processor is allowed its full clock again."))
def _set_power_plan(params: dict, dry_run: bool = False) -> ActionResult:
    plans = {"balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
             "high": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"}
    wanted = str(params.get("plan") or "balanced").lower()
    if wanted not in plans:
        return ActionResult(False, "Choose 'balanced' or 'high'.")
    if dry_run:
        return ActionResult(True, f"Would switch the power plan to {wanted}.")
    code, output = _run(["powercfg", "/setactive", plans[wanted]], timeout=30)
    return ActionResult(code == 0, f"Power plan set to {wanted}." if code == 0
                        else "Could not change the power plan.",
                        changed=code == 0, output=output)


@action(ActionSpec(
    id="sfc_verify",
    title="Check Windows' own files for damage (report only)",
    detail="Runs System File Checker in verify-only mode. It reports whether "
           "protected Windows files have been altered and changes absolutely "
           "nothing. Takes several minutes and keeps a processor core busy.",
    category="diagnostic", risk="low", needs_admin=True, reversible=True,
    expect="A report of whether anything is damaged. No repairs are made."))
def _sfc_verify(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would run 'sfc /verifyonly' — reports "
                                  "damage, repairs nothing. Several minutes.")
    code, output = _run_elevated("cmd.exe", "/c sfc /verifyonly & pause")
    return ActionResult(code == 0, "Verification finished." if code == 0
                        else "The check did not complete.", output=output)


@action(ActionSpec(
    id="sfc_repair",
    title="Repair damaged Windows files",
    # Kept separate from the verify action, and marked irreversible, because
    # /scannow does not merely inspect — it replaces protected system files
    # from the component store. Describing that as a reversible diagnostic,
    # which the original single action did, understates it considerably.
    detail="Runs 'sfc /scannow', which REPLACES any protected Windows file it "
           "considers damaged, using the component store as its source. There "
           "is no undo. Run the verify-only check first and only do this if it "
           "actually found something.",
    category="system", risk="high", needs_admin=True, reversible=False,
    undo_hint="None. Replaced system files cannot be put back.",
    expect="Damaged files replaced; a log at %windir%\\Logs\\CBS\\CBS.log."))
def _sfc_repair(params: dict, dry_run: bool = False) -> ActionResult:
    if dry_run:
        return ActionResult(True, "Would run 'sfc /scannow', which REPLACES "
                                  "damaged system files. Not reversible.")
    code, output = _run_elevated("cmd.exe", "/c sfc /scannow & pause")
    return ActionResult(code == 0, "System file repair finished." if code == 0
                        else "The repair did not complete.", changed=code == 0,
                        output=output)


# -------------------------------------------------------------------- undo

def undo(record: dict) -> ActionResult:
    """Reverse an action from the token it returned."""
    kind = (record or {}).get("kind")
    if kind == "run_key":
        root = (winreg.HKEY_CURRENT_USER if record.get("root") == "user"
                else winreg.HKEY_LOCAL_MACHINE)
        try:
            with winreg.OpenKey(
                    root, r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                    winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, record["name"], 0,
                                  record.get("type") or winreg.REG_SZ,
                                  record["value"])
        except OSError as error:
            return ActionResult(False, f"Could not restore it: {error}")
        return ActionResult(True, f"{record['name']} will start at sign-in "
                                  f"again.", changed=True)
    if kind == "service":
        code, output = _run_elevated(
            "powershell.exe",
            f"-NoProfile -Command \"Set-Service -Name {record['name']} "
            f"-StartupType Automatic; Start-Service -Name {record['name']}\"")
        return ActionResult(code == 0, f"{record['name']} restored.",
                            changed=code == 0, output=output)
    if record and "path" in record:
        path = Path(record["path"])
        try:
            if record.get("content") is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(record["content"], encoding="utf-8")
        except OSError as error:
            return ActionResult(False, f"Could not restore {path}: {error}")
        return ActionResult(True, f"{path.name} restored.", changed=True)
    return ActionResult(False, "There is nothing recorded to undo.")


# ------------------------------------------------------------------ running

def catalogue() -> list[dict]:
    """Everything available, in the form the model is shown."""
    return [spec.describe() for spec in REGISTRY.values()]


#: Which actions may even be offered for a given finding category.
#:
#: The catalogue already stops the model inventing a command. This stops it
#: choosing a real but irrelevant one — which matters because the planner's
#: context includes scraped web pages, and a page is attacker-influenceable
#: text. Without this, a hostile page found while researching a disk error
#: could try to talk the model into "disable_sysmain" or ending a process.
#: With it, a disk finding can only ever reach for disk diagnostics, so the
#: worst a successful injection achieves is a useless suggestion.
ALLOWED_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "disk": ("check_smart", "storage_driver_info", "chkdsk_scan",
             "clear_temp_files", "run_disk_cleanup", "clear_thumbnail_cache"),
    "hardware": ("check_smart", "storage_driver_info", "chkdsk_scan",
                 "show_event_detail", "sfc_verify"),
    "memory": ("unload_ollama_models", "restart_process", "set_wsl_memory_cap",
               "disable_sysmain", "clear_temp_files", "show_event_detail",
               "create_restore_point"),
    "cpu": ("restart_process", "set_power_plan", "show_event_detail"),
    "freeze": ("restart_process", "restart_explorer", "show_event_detail",
               "check_smart", "storage_driver_info"),
    "handles": ("restart_process", "restart_explorer",
                "restart_audio_service"),
    "threads": ("restart_process", "restart_explorer"),
    "startup": ("disable_startup_item", "create_restore_point"),
    "driver": ("storage_driver_info", "check_smart", "show_event_detail",
               "sfc_verify"),
    "security": (),          # never automate changes to security software
    "system": ("create_restore_point", "sfc_verify", "clear_temp_files",
               "run_disk_cleanup", "flush_dns"),
    "network": ("flush_dns",),
}

#: Offered for anything, because they change nothing or are pure safety.
ALWAYS_ALLOWED = ("show_event_detail", "create_restore_point")


def allowed_ids(category: str) -> tuple[str, ...]:
    """Action ids permitted for a finding of this category."""
    allowed = ALLOWED_BY_CATEGORY.get((category or "").strip().lower())
    if allowed is None:
        # An unrecognised category gets diagnostics only. Failing closed here
        # is the whole point of the mechanism.
        return ALWAYS_ALLOWED
    return tuple(dict.fromkeys(allowed + ALWAYS_ALLOWED))


def plan_from_model(chosen: list[dict],
                    allowed: tuple[str, ...] | None = None
                    ) -> list[PlannedAction]:
    """Turn the model's choices into planned actions, dropping anything unknown.

    Silently ignoring an invented action id is the correct behaviour: the model
    occasionally proposes a plausible-sounding one that does not exist, and the
    alternative to dropping it is executing something nobody wrote.

    `allowed` narrows this further to the actions relevant to one finding —
    see `ALLOWED_BY_CATEGORY`.
    """
    planned: list[PlannedAction] = []
    for item in chosen or []:
        if not isinstance(item, dict):
            continue
        identifier = str(item.get("id") or "").strip()
        if allowed is not None and identifier not in allowed:
            continue
        spec = REGISTRY.get(identifier)
        if spec is None:
            continue
        params = item.get("parameters")
        planned.append(PlannedAction(
            spec=spec, params=params if isinstance(params, dict) else {},
            reason=str(item.get("why") or "")[:400]))
    return planned


def apply(planned: PlannedAction, dry_run: bool = True) -> ActionResult:
    spec = planned.spec
    if spec.handler is None:
        return ActionResult(False, "That action has no implementation.")
    if spec.needs_admin and not is_admin() and not dry_run:
        # Not an error: the handler asks for elevation itself. This only warns
        # when a handler cannot.
        pass
    try:
        return spec.handler(planned.params, dry_run)
    except Exception as error:
        return ActionResult(False, f"It failed: {error}")


def _check_registry() -> list[str]:
    """Every handler must accept (params, dry_run).

    Worth asserting at import rather than trusting the layout of the file: an
    `@action(...)` decorator separated from its function by a helper silently
    registers the *helper* as the handler, and the failure surfaces only when
    a user clicks the button. That happened once already.
    """
    import inspect

    problems = []
    for identifier, spec in REGISTRY.items():
        if spec.handler is None:
            problems.append(f"{identifier}: no handler")
            continue
        parameters = list(inspect.signature(spec.handler).parameters)
        if parameters[:2] != ["params", "dry_run"]:
            problems.append(
                f"{identifier}: handler {spec.handler.__name__} takes "
                f"{parameters} — expected (params, dry_run). A decorator is "
                f"probably attached to the wrong function.")
    return problems


_REGISTRY_PROBLEMS = _check_registry()
if _REGISTRY_PROBLEMS:      # pragma: no cover - a programming error, not input
    raise RuntimeError("Action catalogue is wired up wrongly:\n  "
                       + "\n  ".join(_REGISTRY_PROBLEMS))


def summary_for_prompt(only: tuple[str, ...] | None = None) -> str:
    """A compact catalogue for the model, grouped so it reads quickly.

    `only` restricts it to the actions valid for one finding. Showing the
    model just the relevant handful, rather than all eighteen, both improves
    its choices and means an injected instruction naming something outside
    the list has nothing to point at.
    """
    lines = []
    by_category: dict[str, list[ActionSpec]] = {}
    for spec in REGISTRY.values():
        if only is not None and spec.id not in only:
            continue
        by_category.setdefault(spec.category, []).append(spec)
    if not by_category:
        return "  (no automated action is appropriate for this finding)"
    for category, specs in sorted(by_category.items()):
        lines.append(f"\n{category.upper()}")
        for spec in specs:
            flags = []
            if spec.needs_admin:
                flags.append("admin")
            if spec.risk != "low":
                flags.append(f"{spec.risk} risk")
            if not spec.reversible:
                flags.append("not reversible")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(f"  {spec.id}{suffix}")
            lines.append(f"      {spec.detail}")
            if spec.params:
                for key, meaning in spec.params.items():
                    lines.append(f"      param {key}: {meaning}")
    return "\n".join(lines)
