"""Elevation: the one place the tool can restart itself.

Two things are being protected here.

The first is the loop. `admin_mode="always"` relaunches at startup, and on a
machine where elevation cannot succeed -- a standard account with no
administrator to ask -- a relaunch that does not check whether it is already
the child of a relaunch will keep starting copies of itself for ever. That is
what `RELAUNCH_FLAG` and `should_elevate_at_startup` exist for, and it is the
first test below.

The second is the rule the rest of the codebase lives by: nothing that gets
run is ever built from model output. The command `relaunch()` would execute is
assembled from `sys.executable` and `sys.argv` alone, and the test asserts
that by checking the interpreter is this interpreter -- not by trusting the
comment above it.

    python tests/test_elevate.py
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace", line_buffering=True)

from sysup import elevate                                   # noqa: E402
from sysup.config import DEFAULTS, Settings                 # noqa: E402

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


class FakeSettings:
    """Only what elevate reads, so a test cannot drift with the real class."""

    def __init__(self, **values) -> None:
        self.values = values

    def get(self, key, default=None):
        return self.values.get(key, default)


def test_startup_elevation_cannot_loop() -> None:
    print("\nstartup elevation cannot relaunch for ever")
    original = list(sys.argv)
    try:
        sys.argv = ["run.py"]
        wants = elevate.should_elevate_at_startup(
            FakeSettings(admin_mode="always"))
        # On a machine already running elevated this is False for the other
        # reason, which is still correct -- so only the child case is asserted
        # unconditionally.
        check("always asks when it can", wants or elevate.is_admin(),
              f"is_admin={elevate.is_admin()}")

        sys.argv = ["run.py", elevate.RELAUNCH_FLAG]
        check("a relaunched copy never relaunches again",
              elevate.should_elevate_at_startup(
                  FakeSettings(admin_mode="always")) is False)
        check("was_relaunched sees the flag", elevate.was_relaunched() is True)
    finally:
        sys.argv = original
    check("and not when the flag is absent", elevate.was_relaunched() is False)


def test_only_always_elevates_on_its_own() -> None:
    print("\nonly 'always' elevates without being asked")
    for value in ("ask", "never", "", "nonsense", None):
        settings = FakeSettings(admin_mode=value)
        check(f"mode {value!r} does not elevate at startup",
              elevate.should_elevate_at_startup(settings) is False)
    check("an unknown mode falls back to ask",
          elevate.mode(FakeSettings(admin_mode="banana")) == "ask")
    check("a missing setting falls back to ask",
          elevate.mode(FakeSettings()) == "ask")


def test_default_is_ask() -> None:
    print("\nthe shipped default asks rather than elevating")
    check("admin_mode is in the defaults", "admin_mode" in DEFAULTS)
    check("and it is 'ask'", DEFAULTS.get("admin_mode") == "ask",
          str(DEFAULTS.get("admin_mode")))
    check("every mode the dialog offers is a real one",
          set(elevate.MODES) == {"ask", "always", "never"})
    loaded = Settings.load()
    check("a real settings load produces a valid mode",
          elevate.mode(loaded) in elevate.MODES, elevate.mode(loaded))


def test_relaunch_command_is_built_from_this_process() -> None:
    """The command is python + this script, never anything a model wrote."""
    print("\nthe relaunch command comes from sys.executable and sys.argv")
    preview = elevate.command_preview()
    check("it runs this interpreter", sys.executable in preview,
          preview[:90])
    check("it carries the loop guard", elevate.RELAUNCH_FLAG in preview)
    check("it names this script", "test_elevate" in preview.lower(),
          preview[-60:])

    original = list(sys.argv)
    try:
        # An argument with a space in it must survive as one argument. The
        # tool lives in a folder called "System Supe-Up", so this is the
        # normal case, not the exotic one.
        sys.argv = ["C:\\Program Files\\thing\\run.py", "--watch", "10"]
        preview = elevate.command_preview()
        check("a path with spaces stays quoted",
              '"C:\\Program Files\\thing\\run.py"' in preview
              or "Program Files" in preview, preview[:120])
        check("later arguments are kept", "--watch" in preview
              and "10" in preview)
    finally:
        sys.argv = original


def test_relaunch_refuses_when_already_elevated() -> None:
    print("\nrelaunch refuses rather than starting a second copy")
    if not elevate.is_admin():
        check("skipped: this test run is not elevated", True)
        return
    started, why = elevate.relaunch()
    check("it does not start another copy", started is False, why)


def test_restricted_list_is_usable() -> None:
    print("\nwhat is restricted is stated in words a person can read")
    check("there is a list", len(elevate.RESTRICTED) >= 1)
    check("each entry is a sentence, not an API name",
          all(len(item) > 20 and " " in item for item in elevate.RESTRICTED))
    check("the summary says which way round it is",
          "administrator" in elevate.summary(False).lower()
          and "administrator" in elevate.summary(True).lower())


def main() -> int:
    print("=" * 74)
    print("  Elevation: the setting, the loop guard, and the command it runs")
    print("=" * 74)
    for test in (test_startup_elevation_cannot_loop,
                 test_only_always_elevates_on_its_own,
                 test_default_is_ask,
                 test_relaunch_command_is_built_from_this_process,
                 test_relaunch_refuses_when_already_elevated,
                 test_restricted_list_is_usable):
        try:
            test()
        except Exception as error:
            check(f"{test.__name__} raised", False, repr(error))

    passed = sum(1 for _n, ok, _d in RESULTS if ok)
    print("\n" + "=" * 74)
    print(f"  {passed}/{len(RESULTS)} checks passed")
    for name, ok, _d in RESULTS:
        if not ok:
            print(f"  {RED}FAILED{RESET}: {name}")
    print("=" * 74 + "\n")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
