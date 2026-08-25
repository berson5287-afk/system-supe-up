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
from .bridge import bridge
from .elevate import is_admin

#: Keeps a console window from flashing up for every command.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


# `is_admin` is imported from elevate.py, which owns everything to do with
# elevation now that the whole app can optionally be relaunched as
# administrator. Re-exported here because half the codebase reads it from
# `actions`, and one definition beats two that could disagree.


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
        return 1, ("The administrator prompt was declined."
                   + ("" if is_admin() else
                      " (Running System Supe-Up as administrator would ask "
                      "once, at startup, instead of once per action.)"))
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


# ------------------------------------------------------------------ tune-up
# Changes that make a working machine faster, as opposed to repairs for one
# that is broken. Every one of them is reversible and records the value it
# found before changing it, because "make it faster" is exactly the category
# where an irreversible change is not worth having.

#: The power-scheme disk subgroup, and the AHCI Link Power Management setting
#: inside it. Both are hidden from the Power Options window by default, which
#: is precisely why the remedy for one of the commonest causes of multi-second
#: storage stalls is not something a user can reach.
_SUB_DISK = "0012ee47-9041-4b5d-9b77-535fba8b1442"
_HIPM_DIPM = "0b2d69d7-a2a1-449c-9680-f91c70521c60"

#: 0 Active (the link is never powered down) .. 3 Lowest. Anything above 0
#: saves a little power, and is what leaves a controller having to wake a
#: drive that went to sleep underneath an outstanding request.
_LPM_MODES = {"off": 0, "hipm": 1, "hipm+dipm": 2, "lowest": 3}
_LPM_NAMES = {0: "Active (link power management off)", 1: "HIPM",
              2: "HIPM + DIPM", 3: "Lowest (HIPM + DIPM + DevSleep)"}


def _setting_index(line: str) -> int:
    try:
        return int(line.split(":")[-1].strip(), 16)
    except ValueError:
        return -1


def link_power_management() -> tuple[int, int]:
    """Current AC and DC Link Power Management indexes; (-1, -1) if unknown.

    Read-only and needs no elevation, so the tune-up scan can ask about it on
    every machine without producing a prompt.
    """
    code, output = _run(["powercfg", "/q", "SCHEME_CURRENT", _SUB_DISK,
                         _HIPM_DIPM], timeout=30)
    if code != 0:
        return -1, -1
    alternating = direct = -1
    for line in output.splitlines():
        lowered = line.lower()
        if "current ac power setting index" in lowered:
            alternating = _setting_index(line)
        elif "current dc power setting index" in lowered:
            direct = _setting_index(line)
    return alternating, direct


@action(ActionSpec(
    id="set_link_power_management",
    title="Stop the drive link powering down between requests",
    detail="Sets AHCI Link Power Management to Active in the current power "
           "plan. While it is on, the controller lets the link to the drive "
           "drop into a low-power state between requests and has to wake it "
           "for the next one. On the Intel RST controllers where this goes "
           "wrong the wake occasionally does not complete, and Windows resets "
           "the device instead -- logged as iaStorAC event 129, and felt as "
           "the whole machine freezing for several seconds. Turning it off "
           "costs a small amount of idle power and nothing else.",
    category="disk", risk="medium", needs_admin=True, reversible=True,
    undo_hint="The previous AC and DC values are recorded and restored "
              "exactly.",
    params={"mode": "'off' to stop the link idling (the point of this), or "
                    "'hipm', 'hipm+dipm', 'lowest' to put it back"},
    expect="No further iaStorAC event 129 resets in the system log. Watch for "
           "a few days -- they were intermittent to begin with."))
def _set_link_power(params: dict, dry_run: bool = False) -> ActionResult:
    wanted = str(params.get("mode") or "off").strip().lower()
    if wanted not in _LPM_MODES:
        return ActionResult(False, f"Mode must be one of "
                                   f"{', '.join(_LPM_MODES)}.")
    value = _LPM_MODES[wanted]
    was_ac, was_dc = link_power_management()
    if was_ac < 0:
        return ActionResult(False, "This power plan does not expose the AHCI "
                                   "link power setting, so there is nothing "
                                   "to change here.")
    if was_ac == value and was_dc in (value, -1):
        return ActionResult(True, f"Already set to {_LPM_NAMES[value]} -- "
                                  f"nothing to do.")
    if dry_run:
        return ActionResult(
            True, f"Would set AHCI Link Power Management to "
                  f"{_LPM_NAMES[value]}; it is currently "
                  f"{_LPM_NAMES.get(was_ac, was_ac)} on mains"
                  + (f" and {_LPM_NAMES.get(was_dc, was_dc)} on battery."
                     if was_dc >= 0 else "."))
    code, output = _run_elevated(
        "cmd.exe",
        f"/c powercfg /setacvalueindex SCHEME_CURRENT {_SUB_DISK} "
        f"{_HIPM_DIPM} {value} && powercfg /setdcvalueindex SCHEME_CURRENT "
        f"{_SUB_DISK} {_HIPM_DIPM} {value} && powercfg /setactive "
        f"SCHEME_CURRENT")
    if code != 0:
        return ActionResult(False, "Could not change the setting.",
                            output=output)
    return ActionResult(
        True, f"AHCI Link Power Management is now {_LPM_NAMES[value]}.",
        changed=True, output=output,
        undo={"kind": "lpm", "ac": was_ac, "dc": was_dc})


def memory_compression() -> bool | None:
    """Is Windows compressing memory rather than paging it out?  None = unknown.

    Asked of the process list first, because `Get-MMAgent` refuses to answer
    without administrator rights -- and a probe that needs a UAC prompt to
    read a setting is not one a background scan can use. When compression is
    on, Windows runs a hidden system process to hold the compressed store, so
    its presence answers the question for free and without elevation. The
    PowerShell call stays as the fallback for the case where the process list
    cannot be read either.
    """
    try:
        import psutil

        for process in psutil.process_iter(["name"]):
            name = (process.info.get("name") or "").lower()
            if name in ("memcompression", "memory compression"):
                return True
        found_any = True
    except Exception:
        found_any = False
    if found_any:
        # The list was readable and the process was not in it.
        return False

    code, output = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-MMAgent).MemoryCompression"], timeout=45)
    if code != 0:
        return None
    text = output.strip().lower()
    if text.startswith("true"):
        return True
    if text.startswith("false"):
        return False
    return None


@action(ActionSpec(
    id="set_memory_compression",
    title="Turn on memory compression",
    detail="Windows can compress a page of memory instead of writing it out "
           "to the page file. Compressing costs microseconds and paging costs "
           "milliseconds, so on a machine short of RAM this converts a large "
           "part of the hard-fault traffic -- the thing that actually causes "
           "the freezing -- into a little extra CPU. That is the right trade "
           "on a machine with spare cores and no spare memory.",
    category="memory", risk="low", needs_admin=True, reversible=True,
    undo_hint="Turned off again with Disable-MMAgent -mc.",
    params={"enabled": "true to turn it on, false to turn it off"},
    expect="Hard page faults per second fall; Task Manager shows a "
           "'Compressed' figure against memory in use."))
def _set_memory_compression(params: dict, dry_run: bool = False) -> ActionResult:
    wanted = params.get("enabled", True)
    if isinstance(wanted, str):
        wanted = wanted.strip().lower() in ("1", "true", "yes", "on")
    wanted = bool(wanted)
    current = memory_compression()
    if current is wanted:
        return ActionResult(True, f"Memory compression is already "
                                  f"{'on' if wanted else 'off'}.")
    if dry_run:
        state = "on" if current else "off" if current is False else "unknown"
        return ActionResult(True, f"Would turn memory compression "
                                  f"{'on' if wanted else 'off'}; it is "
                                  f"currently {state}.")
    verb = "Enable-MMAgent -mc" if wanted else "Disable-MMAgent -mc"
    code, output = _run_elevated(
        "powershell.exe", f"-NoProfile -NonInteractive -Command \"{verb}\"")
    if code != 0:
        return ActionResult(False, "Could not change memory compression.",
                            output=output)
    return ActionResult(
        True, f"Memory compression turned {'on' if wanted else 'off'}.",
        changed=True, output=output,
        undo=({"kind": "mmagent", "enabled": bool(current)}
              if current is not None else None))


#: Services this tool is willing to touch, and what each one costs to leave
#: running.  An allowlist rather than a check, because "set a service to
#: disabled" is a general-purpose weapon and the model is choosing the target:
#: anything not named here -- every security agent, every core Windows service
#: -- cannot be reached through this action at all.
TUNABLE_SERVICES: dict[str, str] = {
    "SysMain": "Superfetch. Pre-loads applications into RAM speculatively; on "
               "an SSD it buys almost nothing, and on a machine short of "
               "memory it competes with the applications you are using.",
    "DoSvc": "Delivery Optimization. Uploads Windows updates to other "
             "machines, and can hold the disk and the network for hours.",
    "DiagTrack": "Connected User Experiences and Telemetry. Sends diagnostic "
                 "data to Microsoft and writes continuously.",
    "MapsBroker": "Downloaded Maps Manager. Does nothing unless the Maps app "
                  "is used offline.",
    "RetailDemo": "Retail Demo mode. Only shop display machines use it.",
    "WMPNetworkSvc": "Windows Media Player network sharing.",
    "Fax": "The fax service.",
    "RemoteRegistry": "Lets other machines edit this one's registry. Normally "
                      "disabled already.",
    "WSearch": "Windows Search indexing. CAUTION: turning this off removes "
               "search inside Outlook and in File Explorer. Only worth doing "
               "if the indexer is measurably the thing hurting the machine.",
    "SupportAssistAgent": "Dell SupportAssist. Documented to leak memory "
                          "steadily with uptime.",
    "DellSupportAssistRemedationService": "Dell SupportAssist's remediation "
                                          "half.",
    "DDVCollectorSvcApi": "Dell Data Vault collector.",
    "DDVDataCollector": "Dell Data Vault collector.",
    "DDVRulesProcessor": "Dell Data Vault rules processor.",
}

_START_TYPES = {0: "boot", 1: "system", 2: "automatic", 3: "manual",
                4: "disabled"}
_START_VALUES = {"automatic": 2, "auto": 2, "manual": 3, "demand": 3,
                 "disabled": 4}


def service_start_type(name: str) -> str:
    """How a service is set to start, read straight from the registry.

    Cheap enough to call for a list of services during a scan, unlike
    `Get-Service`, which costs a PowerShell start-up each time.
    """
    try:
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{name}", 0,
                winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, "Start")
    except OSError:
        return ""
    return _START_TYPES.get(int(value), str(value))


@action(ActionSpec(
    id="set_service_startup",
    title="Change how a background service starts",
    detail="Sets a Windows service to disabled, manual or automatic, and "
           "stops it if it is being disabled. Only services on this tool's "
           "vetted list can be reached -- no security agent and no core "
           "Windows service is on that list, whatever is asked for.",
    category="tuneup", risk="medium", needs_admin=True, reversible=True,
    undo_hint="The previous start type is recorded and restored.",
    params={"service": "The service name, from the vetted list",
            "startup": "'disabled', 'manual' or 'automatic'"},
    expect="The service stops competing for memory, disk and CPU. Visible in "
           "services.msc."))
def _set_service_startup(params: dict, dry_run: bool = False) -> ActionResult:
    name = str(params.get("service") or "").strip()
    wanted = str(params.get("startup") or "manual").strip().lower()
    match = next((s for s in TUNABLE_SERVICES if s.lower() == name.lower()), "")
    if not match:
        return ActionResult(
            False, f"{name!r} is not on the list of services this tool will "
                   f"change. That list deliberately excludes security and "
                   f"core Windows services.")
    if wanted not in _START_VALUES:
        return ActionResult(False, "Startup must be 'disabled', 'manual' or "
                                   "'automatic'.")
    was = service_start_type(match)
    if not was:
        return ActionResult(False, f"{match} is not installed on this machine.")
    if was == wanted or (wanted == "auto" and was == "automatic"):
        return ActionResult(True, f"{match} is already {was}.")
    if dry_run:
        return ActionResult(
            True, f"Would set {match} from {was} to {wanted}"
                  + (" and stop it now. " if wanted == "disabled" else ". ")
                  + TUNABLE_SERVICES[match])
    flag = {"disabled": "disabled", "manual": "demand", "demand": "demand",
            "automatic": "auto", "auto": "auto"}[wanted]
    command = f"/c sc config {match} start= {flag}"
    if wanted == "disabled":
        command += f" && sc stop {match}"
    code, output = _run_elevated("cmd.exe", command)
    # `sc stop` returns non-zero when the service was not running, which is
    # not a failure of what was asked for.
    ok = code == 0 or "1062" in output or "not been started" in output.lower()
    if not ok:
        return ActionResult(False, f"Could not change {match}.", output=output)
    return ActionResult(
        True, f"{match} set to {wanted} (was {was}).", changed=True,
        output=output,
        undo={"kind": "service_start", "name": match, "start": was})


@action(ActionSpec(
    id="disable_game_recording",
    title="Turn off background game recording",
    detail="Xbox Game Bar keeps a rolling recording buffer so that the last "
           "thirty seconds can be saved. It hooks graphics and keeps a "
           "capture path warm whether or not anything is being played, which "
           "costs CPU, GPU and disk on a machine that never games. Needs no "
           "administrator rights -- it is a per-user setting.",
    category="tuneup", risk="low", reversible=True,
    undo_hint="The previous registry values are recorded and restored.",
    expect="Less background CPU and GPU use, particularly in full-screen "
           "applications."))
def _disable_game_recording(params: dict, dry_run: bool = False) -> ActionResult:
    targets = [
        (r"System\GameConfigStore", "GameDVR_Enabled"),
        (r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
         "AppCaptureEnabled"),
    ]
    previous: list[dict] = []
    already = True
    for path, name in targets:
        current = None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                                winreg.KEY_READ) as key:
                current, _kind = winreg.QueryValueEx(key, name)
        except OSError:
            pass
        if current != 0:
            already = False
        previous.append({"path": path, "name": name, "value": current})
    if already:
        return ActionResult(True, "Background game recording is already off.")
    if dry_run:
        return ActionResult(True, "Would turn off Xbox Game Bar background "
                                  "recording for this user account.")
    for path, name in targets:
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 0)
        except OSError as error:
            return ActionResult(False, f"Could not change it: {error}")
    return ActionResult(True, "Background game recording turned off.",
                        changed=True,
                        undo={"kind": "hkcu_dwords", "values": previous})


@action(ActionSpec(
    id="retrim_volume",
    title="Tell the SSD which blocks are free",
    detail="Runs a TRIM pass over the volume: it sends the drive the list of "
           "blocks Windows no longer needs, which is what lets the drive's "
           "controller keep enough pre-erased space to write quickly. A drive "
           "that has not been trimmed for a long time develops exactly the "
           "symptoms of one that is wearing out. No file data is read or "
           "written.",
    category="disk", risk="low", needs_admin=True, reversible=True,
    undo_hint="Nothing to undo -- this changes no data, only the drive's own "
              "free-block map.",
    params={"drive": "Drive letter, e.g. 'C'"},
    expect="Write latency settles. Takes seconds to a few minutes."))
def _retrim_volume(params: dict, dry_run: bool = False) -> ActionResult:
    letter = str(params.get("drive") or "C").strip().rstrip(":").upper()[:1]
    if not letter.isalpha():
        return ActionResult(False, "Give a drive letter.")
    if dry_run:
        return ActionResult(True, f"Would run a TRIM pass over {letter}:. No "
                                  f"file data is read or written.")
    code, output = _run_elevated(
        "powershell.exe",
        f"-NoProfile -NonInteractive -Command \"Optimize-Volume "
        f"-DriveLetter {letter} -ReTrim -Verbose\"")
    return ActionResult(code == 0,
                        f"TRIM pass over {letter}: finished." if code == 0
                        else f"The TRIM pass over {letter}: did not complete.",
                        changed=code == 0, output=output)


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
    if kind == "service_start":
        flag = {"automatic": "auto", "manual": "demand",
                "disabled": "disabled"}.get(record.get("start", ""), "demand")
        code, output = _run_elevated(
            "cmd.exe", f"/c sc config {record['name']} start= {flag}"
                       + (f" && sc start {record['name']}"
                          if flag == "auto" else ""))
        return ActionResult(code == 0,
                            f"{record['name']} set back to "
                            f"{record.get('start')}.",
                            changed=code == 0, output=output)
    if kind == "lpm":
        parts = []
        if record.get("ac", -1) >= 0:
            parts.append(f"powercfg /setacvalueindex SCHEME_CURRENT "
                         f"{_SUB_DISK} {_HIPM_DIPM} {record['ac']}")
        if record.get("dc", -1) >= 0:
            parts.append(f"powercfg /setdcvalueindex SCHEME_CURRENT "
                         f"{_SUB_DISK} {_HIPM_DIPM} {record['dc']}")
        if not parts:
            return ActionResult(False, "No previous value was recorded.")
        parts.append("powercfg /setactive SCHEME_CURRENT")
        code, output = _run_elevated("cmd.exe", "/c " + " && ".join(parts))
        return ActionResult(code == 0, "Link power management put back.",
                            changed=code == 0, output=output)
    if kind == "mmagent":
        verb = ("Enable-MMAgent -mc" if record.get("enabled")
                else "Disable-MMAgent -mc")
        code, output = _run_elevated(
            "powershell.exe",
            "-NoProfile -NonInteractive -Command " + chr(34) + verb + chr(34))
        return ActionResult(code == 0, "Memory compression put back.",
                            changed=code == 0, output=output)
    if kind == "hkcu_dwords":
        for item in record.get("values", []):
            try:
                if item.get("value") is None:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        item["path"], 0,
                                        winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, item["name"])
                else:
                    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                                            item["path"], 0,
                                            winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, item["name"], 0,
                                          winreg.REG_DWORD, int(item["value"]))
            except OSError as error:
                return ActionResult(False, f"Could not restore it: {error}")
        return ActionResult(True, "Previous settings restored.", changed=True)
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
             "clear_temp_files", "run_disk_cleanup", "clear_thumbnail_cache",
             "retrim_volume", "set_link_power_management"),
    "hardware": ("check_smart", "storage_driver_info", "chkdsk_scan",
                 "show_event_detail", "sfc_verify",
                 # The one automated thing that has ever fixed a storage
                 # controller reset. Everything else in a hardware finding is
                 # a diagnostic, and this stays reversible.
                 "set_link_power_management"),
    "memory": ("unload_ollama_models", "restart_process", "set_wsl_memory_cap",
               "disable_sysmain", "clear_temp_files", "show_event_detail",
               "create_restore_point", "set_memory_compression",
               "set_service_startup"),
    "cpu": ("restart_process", "set_power_plan", "show_event_detail",
            "disable_game_recording"),
    "freeze": ("restart_process", "restart_explorer", "show_event_detail",
               "check_smart", "storage_driver_info",
               "set_link_power_management"),
    "handles": ("restart_process", "restart_explorer",
                "restart_audio_service"),
    "threads": ("restart_process", "restart_explorer"),
    "startup": ("disable_startup_item", "create_restore_point",
                "set_service_startup"),
    # Headroom rather than faults: what the tune-up scan proposes. Everything
    # here is reversible and records what it found first, because a change
    # made to a working machine has to be walkable back.
    "tuneup": ("set_service_startup", "disable_startup_item",
               "disable_game_recording", "set_memory_compression",
               "set_link_power_management", "set_power_plan", "retrim_volume",
               "clear_temp_files", "run_disk_cleanup", "unload_ollama_models",
               "create_restore_point"),
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
    feed = bridge()
    if spec.handler is None:
        return ActionResult(False, "That action has no implementation.")
    if spec.needs_admin and not is_admin() and not dry_run:
        # Not an error: the handler asks for elevation itself. This only warns
        # when a handler cannot.
        pass
    feed.emit("action.start", id=spec.id, dry_run=dry_run,
              params=planned.params, risk=spec.risk,
              needs_admin=spec.needs_admin, reason=planned.reason[:200])
    started = time.perf_counter()
    try:
        result = spec.handler(planned.params, dry_run)
    except Exception as error:
        feed.emit("action.error", id=spec.id, dry_run=dry_run,
                  error=f"{type(error).__name__}: {error}"[:200])
        return ActionResult(False, f"It failed: {error}")
    feed.emit("action.done", id=spec.id, dry_run=dry_run, ok=result.ok,
              changed=result.changed, message=result.message,
              undoable=bool(result.undo),
              duration_s=round(time.perf_counter() - started, 2))
    return result


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
