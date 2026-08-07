"""Deliberately misbehave, in one specific way, for a fixed number of seconds.

Run as a separate process so it has its own pid, its own thread table and its
own window — the monitor has to find it the same way it would find a real
problem, with no cooperation from inside.

Every mode is self-limiting: it stops on its own after `seconds` even if the
harness that started it dies, so a crashed test cannot leave a CPU spinning or
a gigabyte held. Nothing here touches a file outside the temp folder, changes
a setting, or writes to the registry.

    python fault.py cpu 40 --workers 4
    python fault.py hang 30
    python fault.py memory 25 --mb 700
    python fault.py handles 30 --count 25000
    python fault.py threads 30 --count 600
    python fault.py io 30
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import sys
import tempfile
import threading
import time

STOP = threading.Event()


def _deadline(seconds: float) -> float:
    return time.monotonic() + seconds


def cpu(seconds: float, workers: int) -> None:
    """Burn several cores inside ONE process.

    hashlib releases the GIL for buffers over a couple of kilobytes, so real
    OS threads genuinely run in parallel here. Pure-Python spinning would peg
    exactly one core no matter how many threads were started, and the rule
    under test measures a single process against the whole machine — so it
    would never trip.
    """
    end = _deadline(seconds)
    block = os.urandom(1 << 22)          # 4 MB

    def work() -> None:
        while time.monotonic() < end and not STOP.is_set():
            hashlib.sha256(block).digest()

    threads = [threading.Thread(target=work, daemon=True)
               for _ in range(workers)]
    for thread in threads:
        thread.start()
    print(f"cpu: {workers} workers, pid {os.getpid()}", flush=True)
    for thread in threads:
        thread.join()


def hang(seconds: float) -> None:
    """Show a real window, then stop pumping its message queue.

    This is what "Not Responding" actually is: the window exists and is
    visible, but nobody is reading its messages. Windows notices after five
    seconds and this is the same condition `IsHungAppWindow` reports.
    """
    import tkinter as tk

    root = tk.Tk()
    root.title("SUPEUP-FAULT-TEST — deliberately frozen window")
    root.geometry("460x130+80+80")
    tk.Label(root, text="This window is a test fixture.\n"
                        "It stops responding on purpose, then closes itself.",
             font=("Segoe UI", 10), justify="left").pack(padx=18, pady=18)

    # Let it paint and register properly before going silent.
    end = time.monotonic() + 1.5
    while time.monotonic() < end:
        root.update()
        time.sleep(0.02)

    print(f"hang: window up, pid {os.getpid()}, blocking for {seconds}s",
          flush=True)
    time.sleep(seconds)          # the message loop is now dead
    try:
        root.destroy()
    except Exception:
        pass


def memory(seconds: float, megabytes: int) -> None:
    """Hold a block of memory and touch it so it cannot be trimmed away."""
    print(f"memory: allocating {megabytes} MB, pid {os.getpid()}", flush=True)
    chunks = []
    page = 4096
    for _ in range(megabytes):
        chunk = bytearray(1 << 20)
        # Touch every page, or Windows never actually commits it and the
        # process looks large while costing nothing.
        for offset in range(0, len(chunk), page):
            chunk[offset] = 1
        chunks.append(chunk)
    print("memory: resident", flush=True)
    time.sleep(seconds)
    del chunks


def handles(seconds: float, count: int) -> None:
    """Open a great many kernel handles and hold them.

    Unnamed events are the cheapest handle there is and every one is released
    when the process exits, so this cannot leak past the test.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateEventW.restype = ctypes.c_void_p
    opened = []
    for _ in range(count):
        handle = kernel32.CreateEventW(None, True, False, None)
        if not handle:
            break
        opened.append(handle)
    print(f"handles: {len(opened)} open, pid {os.getpid()}", flush=True)
    time.sleep(seconds)
    for handle in opened:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def threads(seconds: float, count: int) -> None:
    """Start a lot of threads that do nothing, and keep them alive."""
    end = _deadline(seconds)

    def idle() -> None:
        while time.monotonic() < end and not STOP.is_set():
            time.sleep(0.5)

    started = []
    for _ in range(count):
        try:
            thread = threading.Thread(target=idle, daemon=True)
            thread.start()
            started.append(thread)
        except RuntimeError:
            break        # the OS said no; that is a fine place to stop
    print(f"threads: {len(started)} running, pid {os.getpid()}", flush=True)
    time.sleep(seconds)


def io(seconds: float) -> None:
    """Write and re-read a file continuously, bypassing the cache on read."""
    end = _deadline(seconds)
    path = os.path.join(tempfile.gettempdir(), f"supeup-io-{os.getpid()}.tmp")
    block = os.urandom(1 << 20)
    print(f"io: churning {path}, pid {os.getpid()}", flush=True)
    try:
        while time.monotonic() < end and not STOP.is_set():
            with open(path, "wb") as handle:
                for _ in range(64):          # 64 MB
                    handle.write(block)
                handle.flush()
                os.fsync(handle.fileno())    # force it to the device
            with open(path, "rb") as handle:
                while handle.read(1 << 20):
                    pass
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Misbehave on purpose.")
    parser.add_argument("mode", choices=("cpu", "hang", "memory", "handles",
                                         "threads", "io"))
    parser.add_argument("seconds", type=float, nargs="?", default=30.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--mb", type=int, default=700)
    parser.add_argument("--count", type=int, default=20000)
    args = parser.parse_args()

    seconds = max(1.0, min(args.seconds, 300.0))
    if args.mode == "cpu":
        cpu(seconds, max(1, min(args.workers, 16)))
    elif args.mode == "hang":
        hang(seconds)
    elif args.mode == "memory":
        memory(seconds, max(1, min(args.mb, 4096)))
    elif args.mode == "handles":
        handles(seconds, max(1, min(args.count, 200_000)))
    elif args.mode == "threads":
        threads(seconds, max(1, min(args.count, 2000)))
    elif args.mode == "io":
        io(seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
