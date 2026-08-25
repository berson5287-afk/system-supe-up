"""A live event bridge: everything this tool is doing, as it does it.

The problem this solves is that the interesting parts of a diagnosis are
invisible.  A rule that *nearly* fired leaves no trace, a model that was asked
the wrong question produces a plausible answer, and a fix that was discarded
for being outside its category disappears silently by design.  All of that is
correct behaviour for a user-facing tool and useless when the thing being
debugged is the tool itself.

So every stage announces what it is doing to a newline-delimited JSON log that
anything can tail -- a terminal, another process, an agent working on the
code.  Nothing in the pipeline changes behaviour when the bridge is off, and
nothing waits for it when it is on.

Two rules govern the implementation, and both come from what this tool
measures:

**It must never block the caller.**  Stall detection works by measuring how
late the sampler's own tick is, so an instrumentation call that waits on a
disk write would make the monitor report itself as a system freeze.  Events go
onto a queue and a daemon thread writes them; if the writer falls behind, the
events are dropped and the drop is counted.  Losing telemetry about the
diagnosis is always better than corrupting the diagnosis.

**It must be free when off.**  A disabled bridge is one module-level object
and an early return, so `emit()` can sit in the per-process loop.

Two files are written, because they have different readers:

* ``bridge.jsonl`` -- one compact line per event, meant to be tailed.
* ``llm.jsonl``    -- the full prompts and completions, which are far too big
  to interleave with a live feed but are the whole story when the model gives
  a bad answer.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .config import REPORT_DIR

LIVE_DIR = REPORT_DIR.parent / "live"

#: Turn the bridge on without touching settings or code -- this is how the
#: launcher, the test harness and anything watching from outside enable it.
ENV_FLAG = "SYSUP_BRIDGE"
ENV_DIR = "SYSUP_BRIDGE_DIR"

#: Beyond this many queued events the writer is losing, and dropping is the
#: correct response: the alternative is unbounded memory growth on a machine
#: that is already short of it.
MAX_QUEUE = 4000

#: How much of a text field survives into the tailable log.  The full text is
#: in llm.jsonl; this is just enough to recognise it going past.
SNIPPET = 400


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > SNIPPET:
        return value[:SNIPPET] + f"... (+{len(value) - SNIPPET} chars)"
    if isinstance(value, dict):
        return {k: _truncate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v) for v in value[:40]]
    return value


class Bridge:
    """A writer for one process's live event stream."""

    def __init__(self, directory: Path | None = None,
                 enabled: bool = True) -> None:
        self.enabled = enabled
        self.directory = Path(directory) if directory else LIVE_DIR
        self.dropped = 0
        self.written = 0
        self.started = time.time()
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._queue: queue.SimpleQueue = queue.SimpleQueue()
        self._pending = 0
        self._thread: threading.Thread | None = None
        self.event_path = self.directory / "bridge.jsonl"
        self.llm_path = self.directory / "llm.jsonl"
        self.state_path = self.directory / "state.json"
        if self.enabled:
            self._open()

    # -- lifecycle ---------------------------------------------------------
    def _open(self) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            # Truncate on start: a live feed from the previous run is history,
            # and appending makes "tail the file" show the wrong session.
            self.event_path.write_text("", encoding="utf-8")
            self.llm_path.write_text("", encoding="utf-8")
        except OSError:
            self.enabled = False
            return
        self._thread = threading.Thread(target=self._pump, name="sysup-bridge",
                                        daemon=True)
        self._thread.start()
        self.emit("bridge.open", pid=os.getpid(),
                  directory=str(self.directory))

    def close(self, timeout: float = 2.0) -> None:
        if not self.enabled:
            return
        self.emit("bridge.close", written=self.written, dropped=self.dropped)
        self._queue.put(None)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self.enabled = False

    # -- writing -----------------------------------------------------------
    def _pump(self) -> None:
        handle = llm_handle = None
        try:
            handle = self.event_path.open("a", encoding="utf-8",
                                          errors="replace")
            llm_handle = self.llm_path.open("a", encoding="utf-8",
                                            errors="replace")
        except OSError:
            return
        try:
            while True:
                item = self._queue.get()
                self._pending = max(0, self._pending - 1)
                if item is None:
                    break
                target, line = item
                stream = llm_handle if target == "llm" else handle
                try:
                    stream.write(line + "\n")
                    stream.flush()
                    self.written += 1
                except (OSError, ValueError):
                    pass
        finally:
            for stream in (handle, llm_handle):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass

    def _put(self, target: str, payload: dict) -> None:
        if self._pending >= MAX_QUEUE:
            self.dropped += 1
            return
        try:
            line = json.dumps(payload, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            return
        self._pending += 1
        self._queue.put((target, line))

    # -- the interface every other module uses -----------------------------
    def emit(self, kind: str, **fields: Any) -> None:
        """Record one event.  Never raises, never blocks, never waits."""
        if not self.enabled:
            return
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._put("event", {"seq": seq, "t": round(time.time(), 3),
                            "kind": kind, **_truncate(fields)})

    def llm(self, kind: str, **fields: Any) -> None:
        """Record a full prompt or completion, untruncated, in llm.jsonl.

        A summary line still goes to the event stream, so a tail shows that
        the model was asked something without carrying 30 KB of brief.
        """
        if not self.enabled:
            return
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._put("llm", {"seq": seq, "t": round(time.time(), 3),
                          "kind": kind, **fields})
        summary = {k: v for k, v in fields.items()
                   if k in ("model", "server", "role", "purpose", "duration_s",
                            "chars", "ok", "finding")}
        self._put("event", {"seq": seq, "t": round(time.time(), 3),
                            "kind": kind, "detail": "-> llm.jsonl", **summary})

    @contextmanager
    def span(self, kind: str, **fields: Any):
        """Time a stage, and report it even when it raises."""
        if not self.enabled:
            yield lambda **_f: None
            return
        extra: dict[str, Any] = {}
        self.emit(f"{kind}.start", **fields)
        started = time.perf_counter()
        try:
            yield lambda **f: extra.update(f)
        except BaseException as error:      # noqa: BLE001 - reported, re-raised
            self.emit(f"{kind}.error", error=f"{type(error).__name__}: {error}",
                      duration_s=round(time.perf_counter() - started, 3),
                      **fields)
            raise
        else:
            self.emit(f"{kind}.done",
                      duration_s=round(time.perf_counter() - started, 3),
                      **fields, **extra)

    def state(self, payload: dict) -> None:
        """Overwrite the at-a-glance snapshot.

        Written whole and renamed into place, so a reader never catches it
        half-written.  This is the file to poll when you want the current
        picture rather than the history of how it got there.
        """
        if not self.enabled:
            return
        temporary = self.state_path.with_suffix(".json.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, default=str, indent=1, ensure_ascii=False),
                encoding="utf-8")
            os.replace(temporary, self.state_path)
        except (OSError, TypeError, ValueError):
            pass


class _Null:
    """What every module gets when the bridge is off: nothing, cheaply."""

    enabled = False

    def emit(self, kind: str, **fields: Any) -> None:
        pass

    def llm(self, kind: str, **fields: Any) -> None:
        pass

    def state(self, payload: dict) -> None:
        pass

    def close(self, timeout: float = 2.0) -> None:
        pass

    @contextmanager
    def span(self, kind: str, **fields: Any):
        yield lambda **_f: None


_NULL = _Null()
_BRIDGE: Bridge | _Null = _NULL


def _directory_from_env() -> Path:
    raw = os.environ.get(ENV_DIR, "").strip()
    return Path(raw) if raw else LIVE_DIR


def start(directory: Path | None = None) -> Bridge | _Null:
    """Turn the bridge on for this process."""
    global _BRIDGE
    if isinstance(_BRIDGE, Bridge) and _BRIDGE.enabled:
        return _BRIDGE
    candidate = Bridge(directory or _directory_from_env())
    _BRIDGE = candidate if candidate.enabled else _NULL
    return _BRIDGE


def stop() -> None:
    global _BRIDGE
    _BRIDGE.close()
    _BRIDGE = _NULL


def bridge() -> Bridge | _Null:
    return _BRIDGE


def active() -> bool:
    return _BRIDGE.enabled


def start_if_requested() -> Bridge | _Null:
    """Honour SYSUP_BRIDGE=1 in the environment.

    Called from every entry point, so switching the bridge on is one variable
    and does not require the app to be launched differently.
    """
    if os.environ.get(ENV_FLAG, "").strip().lower() in ("1", "true", "yes", "on"):
        return start()
    return _BRIDGE
