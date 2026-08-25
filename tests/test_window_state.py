"""Remembered window positions, and the ones that must not be remembered.

The whole point of this file is the second half of that sentence. Saving a
geometry is trivial; restoring one is where it goes wrong, and it goes wrong
in a way the user cannot fix from inside the app -- a window placed on a
monitor that has since been unplugged opens off-screen, with its title bar out
of reach, and the only way back is to delete a JSON file they do not know
exists.

So `usable()` is the thing under test here: what it accepts, what it trims to
a size with no position, and what it throws away entirely. The screen it
checks against is the *virtual* one covering every monitor, which is why the
tests below compute their coordinates from `virtual_screen()` rather than
hard-coding a resolution that would only be true on the machine it was
written on.

    python tests/test_window_state.py
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace", line_buffering=True)

from sysup import window_state as ws                        # noqa: E402

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def test_a_sensible_geometry_survives() -> None:
    print("\na window where it was left is put back there")
    x, y, width, height = ws.virtual_screen()
    check("the virtual screen is readable", width > 0 and height > 0,
          f"{width}x{height} at {x},{y}")
    geometry = f"900x600+{x + 120}+{y + 80}"
    check("it comes back unchanged", ws.usable(geometry) == geometry,
          ws.usable(geometry))


def test_an_offscreen_position_is_dropped_but_the_size_is_kept() -> None:
    """The failure this file exists for: a monitor that is no longer there."""
    print("\na position on a monitor that has gone keeps only the size")
    x, y, width, height = ws.virtual_screen()
    for geometry in (f"900x600+{x + width + 400}+{y + 100}",   # off the right
                     f"900x600+{x - 4000}+{y + 100}",          # off the left
                     f"900x600+{x + 100}+{y + height + 900}"): # below
        result = ws.usable(geometry)
        check(f"{geometry} -> size only", result == "900x600", result)
    check("a window just inside the edge is still kept",
          ws.usable(f"900x600+{x + width - 300}+{y + 50}").endswith(
              f"+{x + width - 300}+{y + 50}"))


def test_tk_negative_coordinates_do_not_raise() -> None:
    """Tk writes "+-1900" for a monitor left of the primary. int() will not
    take that, and the crash would happen while opening a window."""
    print("\nthe doubled sign Tk writes for a left-hand monitor is handled")
    for geometry in ("800x600+-1900+100", "800x600+100+-40",
                     "800x600-20+0", "800x600+-1+-1"):
        try:
            result = ws.usable(geometry)
            check(f"{geometry} parsed", isinstance(result, str), repr(result))
        except Exception as error:
            check(f"{geometry} parsed", False, repr(error))


def test_nonsense_is_refused_rather_than_applied() -> None:
    print("\nnothing that is not a geometry is ever handed to Tk")
    for geometry in ("", "nonsense", "1300x860", "x860+0+0", "0x0+0+0",
                     "10x10+0+0", "abcxdef+1+1", None):
        check(f"{geometry!r} refused", ws.usable(geometry) == "",
              repr(ws.usable(geometry)))


def test_minimum_size_wins() -> None:
    print("\na window is never restored smaller than it can work at")
    x, y, _w, _h = ws.virtual_screen()
    result = ws.usable(f"400x300+{x + 60}+{y + 60}", minimum=(1060, 680))
    check("the minimum is applied", result.startswith("1060x680"), result)
    result = ws.usable(f"1400x900+{x + 60}+{y + 60}", minimum=(1060, 680))
    check("a larger window is left alone", result.startswith("1400x900"),
          result)


def test_it_round_trips_through_the_file() -> None:
    print("\nwhat is recorded is what comes back")
    original_path, original_cache = ws.STATE_PATH, ws._cache
    try:
        with tempfile.TemporaryDirectory() as directory:
            ws.STATE_PATH = Path(directory) / "windows.json"
            ws._cache = None
            ws.record("main", "1200x700+220+120")
            ws.record("settings", "820x760+300+80", zoomed=True)
            check("nothing is written until it is flushed",
                  not ws.STATE_PATH.exists())
            check("flush writes", ws.flush() is True)

            ws._cache = None                    # force a real read back
            check("geometry survives",
                  ws.saved("main").get("geometry") == "1200x700+220+120",
                  str(ws.saved("main")))
            check("the maximised flag survives",
                  ws.saved("settings").get("zoomed") is True)
            check("an unknown window has no opinion", ws.saved("nope") == {})

            written = json.loads(ws.STATE_PATH.read_text(encoding="utf-8"))
            check("the file is readable by a person", set(written) ==
                  {"main", "settings"}, str(list(written)))

            ws.forget_all()
            ws._cache = None
            check("forget_all clears every window", ws.saved("main") == {})
    finally:
        ws.STATE_PATH, ws._cache = original_path, original_cache


def test_a_read_only_home_does_not_break_a_window() -> None:
    """Persisting geometry is a convenience. It may never stop a window."""
    print("\nan unwritable state file is survivable")
    original_path, original_cache = ws.STATE_PATH, ws._cache
    try:
        ws.STATE_PATH = Path("Z:/nowhere/at/all/windows.json")
        ws._cache = {"main": {"geometry": "800x600+0+0", "zoomed": False}}
        check("flush reports failure rather than raising", ws.flush() is False)
    except Exception as error:
        check("flush reports failure rather than raising", False, repr(error))
    finally:
        ws.STATE_PATH, ws._cache = original_path, original_cache


def test_every_window_has_its_own_key() -> None:
    """Two windows sharing a key would drag each other around the screen."""
    print("\nevery window is remembered separately")
    import re

    keys: list[str] = []
    for name in ("gui.py", "settings_dialog.py", "fix_dialog.py"):
        source = (Path(__file__).resolve().parent.parent / "sysup"
                  / name).read_text(encoding="utf-8")
        keys += re.findall(r'window_state\.remember\([^,]+,\s*"([^"]+)"',
                           source)
    check("every window is wired up", len(keys) >= 6, str(keys))
    check("no two share a key", len(keys) == len(set(keys)), str(keys))


def main() -> int:
    print("=" * 74)
    print("  Remembered window geometry, and the monitor that is not there")
    print("=" * 74)
    for test in (test_a_sensible_geometry_survives,
                 test_an_offscreen_position_is_dropped_but_the_size_is_kept,
                 test_tk_negative_coordinates_do_not_raise,
                 test_nonsense_is_refused_rather_than_applied,
                 test_minimum_size_wins,
                 test_it_round_trips_through_the_file,
                 test_a_read_only_home_does_not_break_a_window,
                 test_every_window_has_its_own_key):
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
