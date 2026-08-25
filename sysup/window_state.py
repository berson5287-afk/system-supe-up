"""Where each window was last time, remembered per window.

Kept out of `~/.system_supeup_settings.json` deliberately. That file is
configuration -- servers, models, thresholds, things a person chose -- and it
is edited by hand often enough that filling it with pixel coordinates that
change every time a window is dragged would make it unreadable. This is UI
state, it lives in its own file, and losing it costs nothing.

Two things here are not obvious, and both are bugs waiting to happen:

* A `<Configure>` binding on a Toplevel also fires for its children, because
  the toplevel is in every child widget's bind tags. Without the identity
  check in `on_configure`, a window would save the geometry of whichever
  frame last resized itself, which is not a window geometry at all.
* A monitor that is no longer there leaves a saved position pointing into
  nothing, and Windows will place a window entirely off-screen where it
  cannot be dragged back. Every restored position is checked against the
  *virtual* screen -- all monitors, not just the primary -- and dropped if it
  no longer lands on one. The size is still kept.
"""

from __future__ import annotations

import ctypes
import json
import re
from pathlib import Path

STATE_PATH = Path.home() / ".system_supeup_windows.json"

#: "1300x860+120+40", and the negative forms Windows produces for a monitor
#: sitting to the left of, or above, the primary one.
GEOMETRY = re.compile(r"^(\d+)x(\d+)([+-]-?\d+)([+-]-?\d+)$")

#: Written this long after the last move or resize, so dragging a window
#: across the screen costs one write rather than one per frame.
FLUSH_DELAY_MS = 1500

#: How much of a window has to land on a monitor for its position to be
#: reused. A title bar that cannot be reached is the same as a lost window.
VISIBLE_MARGIN = 80

#: SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN
_SM = {"x": 76, "y": 77, "width": 78, "height": 79}

_cache: dict | None = None


def _load() -> dict:
    global _cache
    if _cache is None:
        try:
            raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            _cache = raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            _cache = {}
    return _cache


def flush() -> bool:
    """Write what has been recorded. A read-only home is not an error here."""
    try:
        STATE_PATH.write_text(json.dumps(_load(), indent=2), encoding="utf-8")
        return True
    except OSError:
        return False


def virtual_screen() -> tuple[int, int, int, int]:
    """The rectangle covering every monitor, as (x, y, width, height)."""
    try:
        metric = ctypes.windll.user32.GetSystemMetrics
        rect = (metric(_SM["x"]), metric(_SM["y"]),
                metric(_SM["width"]), metric(_SM["height"]))
        if rect[2] > 0 and rect[3] > 0:
            return rect
    except Exception:
        pass
    return (0, 0, 0, 0)     # unknown, so `usable` accepts whatever was saved


def _coordinate(text: str) -> int:
    """"+120" -> 120, "-40" -> -40, "+-1900" -> -1900."""
    return int(text.lstrip("+"))


def usable(geometry: str, minimum: tuple[int, int] | None = None) -> str:
    """A saved geometry, trimmed to something that will actually be visible.

    Returns "" when there is nothing worth restoring, the full "WxH+X+Y" when
    the position still lands on a monitor, and a bare "WxH" when it does not:
    the size is worth keeping even when the screen it was on has gone.
    """
    match = GEOMETRY.match((geometry or "").strip())
    if not match:
        return ""
    width, height = int(match.group(1)), int(match.group(2))
    # Tk writes a window on a monitor left of the primary one as "+-1900",
    # which `int` will not take. The doubled sign is Tk's, not a typo, and it
    # has to be handed back unchanged -- Tk is the thing that reads it again.
    left, top = _coordinate(match.group(3)), _coordinate(match.group(4))
    if width < 200 or height < 150:
        return ""
    if minimum:
        width, height = max(width, minimum[0]), max(height, minimum[1])

    screen_x, screen_y, screen_w, screen_h = virtual_screen()
    if screen_w and screen_h:
        width, height = min(width, screen_w), min(height, screen_h)
        on_screen = (left + width > screen_x + VISIBLE_MARGIN
                     and left < screen_x + screen_w - VISIBLE_MARGIN
                     and top + height > screen_y
                     and top < screen_y + screen_h - VISIBLE_MARGIN)
        if not on_screen:
            return f"{width}x{height}"
    return f"{width}x{height}{match.group(3)}{match.group(4)}"


def saved(key: str) -> dict:
    entry = _load().get(key)
    return entry if isinstance(entry, dict) else {}


def record(key: str, geometry: str, zoomed: bool = False) -> None:
    """Remember one window's geometry in memory; `flush` puts it on disk."""
    if not GEOMETRY.match((geometry or "").strip()):
        return
    _load()[key] = {"geometry": geometry, "zoomed": bool(zoomed)}


def forget_all() -> bool:
    """Back to the built-in sizes, for every window, next time it opens."""
    _load().clear()
    return flush()


def save_now(window, key: str) -> None:
    """Record and write this window's geometry immediately.

    A maximised window reports the maximised rectangle, which is not what
    should come back when it is un-maximised -- so in that state only the flag
    is updated and the last normal geometry is left alone.
    """
    try:
        zoomed = window.state() == "zoomed"
        if zoomed:
            geometry = str(saved(key).get("geometry", "")) or window.geometry()
        else:
            geometry = window.geometry()
        record(key, geometry, zoomed=zoomed)
    except Exception:
        return
    flush()


def _zoom(window) -> None:
    try:
        window.state("zoomed")
    except Exception:
        pass


def remember(window, key: str, default: str = "",
             minimum: tuple[int, int] | None = None) -> None:
    """Restore this window where it was, then keep the record up to date.

    `default` is used the first time, so every window still opens at the size
    it was designed at until somebody moves it.
    """
    entry = saved(key)
    geometry = usable(str(entry.get("geometry", "")), minimum)
    try:
        if geometry:
            window.geometry(geometry)
        elif default:
            window.geometry(default)
    except Exception:
        return              # a window that cannot be placed still has to open

    if entry.get("zoomed"):
        # Deferred: maximising before the window is mapped discards the
        # restored size, so un-maximising would drop it to the default.
        try:
            window.after(60, lambda: _zoom(window))
        except Exception:
            pass

    pending: dict[str, object] = {"id": None}

    def on_configure(event) -> None:
        if event.widget is not window:
            return          # a child resized, not the window
        try:
            if window.state() != "normal":
                return      # iconified or maximised: not a position to keep
            record(key, window.geometry(), zoomed=False)
        except Exception:
            return
        if pending["id"] is not None:
            try:
                window.after_cancel(pending["id"])
            except Exception:
                pass
        try:
            pending["id"] = window.after(FLUSH_DELAY_MS, flush)
        except Exception:
            pending["id"] = None

    def on_destroy(event) -> None:
        if event.widget is not window:
            return
        # The debounced write is scheduled on this window, so it has to be
        # cancelled here: a timer that comes due after the window is gone
        # makes Tk print "invalid command name" to stderr on every close.
        if pending["id"] is not None:
            try:
                window.after_cancel(pending["id"])
            except Exception:
                pass
            pending["id"] = None
        save_now(window, key)

    window.bind("<Configure>", on_configure, add="+")
    window.bind("<Destroy>", on_destroy, add="+")
