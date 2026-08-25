"""Running the whole tool as administrator — only when the user says so.

`actions.py` asks for elevation one action at a time, and that remains the
default because it is the smaller thing to trust: a monitor that samples every
process every second, all day, does not need administrator rights to do it,
and a tool that holds them permanently is a much bigger promise than one that
asks at the moment it needs them.

But per-action elevation has two real costs, and this module exists for them:

1. **Readings, not just fixes, are refused.** Windows will not say what a
   frozen program is waiting on unless the asker is an administrator, and a
   UAC prompt cannot be raised mid-sample. Those findings are not "clean",
   they are unknown, and no amount of per-action elevation recovers them.
2. **A tune-up is a plan, not one action.** Approving eight changes and then
   answering eight consecutive UAC prompts is the kind of thing people click
   through without reading, which is exactly the habit this tool should not
   be teaching.

So the choice is offered, never taken: `admin_mode` is `ask` by default, which
means the interface says what is limited and puts a button next to it. Nothing
here elevates on its own unless the setting is `always`, and that setting has
to be turned on by hand.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path

#: Passed to the relaunched copy so it can tell it is the child of an
#: elevation attempt. Without it, a machine where elevation silently fails --
#: UAC turned off for a standard account, say -- would relaunch for ever under
#: `admin_mode="always"`.
RELAUNCH_FLAG = "--elevated"

#: The three settings values. "ask" shows what is limited and offers a button;
#: "always" relaunches at startup; "never" says nothing at all.
MODES = ("ask", "always", "never")

SW_SHOWNORMAL = 1
ERROR_CANCELLED = 1223


def is_admin() -> bool:
    """Whether this process is running with administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def was_relaunched() -> bool:
    """True in a copy started by `relaunch()`, elevated or not."""
    return RELAUNCH_FLAG in sys.argv


def mode(settings) -> str:
    """The configured admin mode, defaulting safely if it is nonsense."""
    value = str(getattr(settings, "get", lambda *_a: "ask")("admin_mode",
                                                            "ask")).lower()
    return value if value in MODES else "ask"


#: What is actually unavailable without elevation, in the terms a person would
#: describe it. Kept short and true — a list that overstates the cost is how a
#: tool talks somebody into granting rights it does not need.
RESTRICTED = [
    "what a frozen program is blocked on (Windows reveals a wait chain only "
    "to an administrator, and it cannot be asked for later — the moment has "
    "passed)",
    "the command line and open files of processes owned by other accounts, "
    "including most services",
    "fixes that change a service, a page file or a scheduled task: each one "
    "raises its own UAC prompt instead of running",
]


def summary(elevated: bool | None = None) -> str:
    """One line for a status bar."""
    if is_admin() if elevated is None else elevated:
        return "Running as administrator — every reading and fix is available."
    return (f"Running without administrator rights — {len(RESTRICTED)} kinds "
            f"of reading and fix are limited.")


def _relaunch_target() -> tuple[str, list[str]]:
    """The executable and arguments that would start this program again.

    Built entirely from `sys.executable` and `sys.argv`, never from anything a
    model produced — the same rule the action catalogue lives by.
    """
    if getattr(sys, "frozen", False):        # a packaged .exe, if there ever is one
        return sys.executable, list(sys.argv[1:])
    script = Path(sys.argv[0]).resolve()
    return sys.executable, [str(script), *sys.argv[1:]]


def command_preview() -> str:
    """What `relaunch()` would run, for showing before it is agreed to."""
    executable, arguments = _relaunch_target()
    return subprocess.list2cmdline([executable, *arguments, RELAUNCH_FLAG])


def relaunch() -> tuple[bool, str]:
    """Start this program again, elevated. Returns (started, why not).

    On success the caller must exit: two copies sampling the same machine is
    worse than one, and the elevated copy is the one that was asked for.
    """
    if is_admin():
        return False, "This is already running as administrator."

    executable, arguments = _relaunch_target()
    if RELAUNCH_FLAG not in arguments:
        arguments.append(RELAUNCH_FLAG)
    parameters = subprocess.list2cmdline(arguments)

    try:
        shell_execute = ctypes.windll.shell32.ShellExecuteW
        shell_execute.restype = ctypes.c_void_p
        result = shell_execute(None, "runas", executable, parameters,
                               os.getcwd(), SW_SHOWNORMAL)
        code = int(result) if result is not None else 0
    except Exception as error:                  # not Windows, or no shell32
        return False, f"Windows refused the request: {error}"

    if code == ERROR_CANCELLED:
        return False, "The administrator prompt was declined."
    if code <= 32:
        return False, (f"Windows would not start an elevated copy "
                       f"(error {code}). This usually means the account "
                       f"cannot elevate at all.")
    return True, ""


def relaunch_and_exit(on_message=None) -> bool:
    """`relaunch()`, then quit this copy. Returns False if it did not start."""
    started, why = relaunch()
    if started:
        return True
    if on_message is not None and why:
        on_message(why)
    return False


def should_elevate_at_startup(settings) -> bool:
    """Whether to relaunch before showing anything, per the setting.

    Only ever true for `always`, and never in a copy that was already
    relaunched — a failed elevation must land on a working unelevated window,
    not in a loop.
    """
    return (mode(settings) == "always" and not is_admin()
            and not was_relaunched())
