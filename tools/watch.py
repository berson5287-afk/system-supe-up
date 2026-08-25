"""Watch the live bridge: everything System Supe-Up is doing, as it does it.

    python tools/watch.py                 follow the feed
    python tools/watch.py --all           include every sample line
    python tools/watch.py --only rule,llm keep only these event kinds
    python tools/watch.py --state         print the current snapshot and exit
    python tools/watch.py --llm 3         print the last 3 model exchanges
    python tools/watch.py --since 0       replay from the beginning

The feed is newline-delimited JSON, so this is a convenience rather than the
interface -- `Get-Content -Wait ~/SystemSupeUp/live/bridge.jsonl` works too.
What this adds is knowing which fields matter for each kind of event, and
collapsing the once-a-second sample line into something a person can watch
without it scrolling the interesting parts away.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sysup.bridge import LIVE_DIR      # noqa: E402

# ANSI, because this is meant to be watched rather than read later.
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
OFF = "\033[0m"

COLOURS = {
    "stall": RED, "rule.error": RED, "llm.failed": RED, "action.error": RED,
    "search.failed": RED, "fetch.failed": YELLOW, "llm.unreachable": RED,
    "rule": GREEN, "rules.end": BOLD + GREEN, "investigate.plan": BOLD + CYAN,
    "llm.request": MAGENTA, "llm.response": MAGENTA,
    "action.start": YELLOW, "action.done": YELLOW,
    "opportunity": CYAN, "optimise.end": BOLD + CYAN,
}


def _stamp(event: dict) -> str:
    return time.strftime("%H:%M:%S", time.localtime(event.get("t", 0)))


def render(event: dict) -> str | None:
    """One line per event, or None to hide it."""
    kind = event.get("kind", "")
    colour = COLOURS.get(kind, "")

    if kind == "sample":
        parts = [f"cpu {event.get('cpu', 0):>5}%",
                 f"ram {event.get('mem_pct', 0):>5}% "
                 f"({event.get('mem_free_gb', 0)} GB free)",
                 f"commit {event.get('commit_pct', 0):>5}%",
                 f"faults {event.get('faults', 0):>5}/s",
                 f"disk {event.get('disk_ms', 0):>6} ms"]
        if event.get("late", 0) >= 0.5:
            parts.append(f"{YELLOW}late {event['late']}s{OFF}")
        if event.get("hung"):
            parts.append(f"{RED}{event['hung']} hung{OFF}")
        if event.get("gap"):
            parts.append(f"{DIM}(gap - not a stall){OFF}")
        hot = ", ".join(event.get("hot") or [])
        return (f"{DIM}{_stamp(event)}{OFF} #{event.get('n', 0):<5} "
                + "  ".join(parts) + (f"   {DIM}{hot}{OFF}" if hot else ""))

    if kind == "rule":
        fired = event.get("fired", 0)
        if not fired:
            return (f"{DIM}{_stamp(event)}   rule {event.get('rule')}: "
                    f"nothing ({event.get('ms')} ms){OFF}")
        titles = "; ".join(f"[{f.get('severity')}] {f.get('title')}"
                           for f in event.get("findings", []))
        return (f"{colour}{_stamp(event)}   rule {event.get('rule')}: "
                f"{fired} finding(s){OFF} - {titles}")

    if kind == "rules.end":
        return (f"{colour}{_stamp(event)}   RULES DONE: "
                f"{event.get('total')} finding(s){OFF}")

    if kind == "stall":
        return (f"{colour}{_stamp(event)}   !! STALL {event.get('lateness')}s "
                f"- cpu {event.get('cpu')}% disk {event.get('disk_latency_ms')} ms "
                f"faults {event.get('hard_faults')}/s "
                f"suspects: {', '.join(event.get('suspects') or [])}{OFF}")

    if kind == "llm.request":
        return (f"{colour}{_stamp(event)}   -> {event.get('model')} "
                f"[{event.get('purpose')}] {event.get('chars')} chars{OFF}")

    if kind == "llm.response":
        return (f"{colour}{_stamp(event)}   <- {event.get('model')} "
                f"[{event.get('purpose')}] {event.get('chars')} chars in "
                f"{event.get('duration_s')}s{OFF}")

    if kind == "investigate.plan":
        accepted = ", ".join(event.get("accepted") or []) or "nothing"
        line = (f"{colour}{_stamp(event)}   PLAN for {event.get('finding')} "
                f"({event.get('confidence')}): {accepted}{OFF}")
        if event.get("discarded"):
            line += f"\n            {RED}discarded: " \
                    f"{', '.join(event['discarded'])}{OFF}"
        for step in event.get("manual_steps") or []:
            line += f"\n            {DIM}manual: {step}{OFF}"
        return line

    if kind in ("action.start", "action.done"):
        mode = "dry-run" if event.get("dry_run") else "REAL"
        tail = (f"ok={event.get('ok')} changed={event.get('changed')} "
                f"{event.get('message', '')}" if kind == "action.done"
                else json.dumps(event.get("params") or {}))
        return (f"{colour}{_stamp(event)}   action {event.get('id')} "
                f"[{mode}] {tail}{OFF}")

    if kind == "search":
        return (f"{_stamp(event)}   search {event.get('query')!r} -> "
                f"{event.get('kept')} kept of {event.get('returned')} "
                f"({', '.join(event.get('domains') or [])})")

    # Everything else: kind plus whatever it carried, which is enough for
    # events added later without this file needing to know about them.
    rest = {k: v for k, v in event.items() if k not in ("kind", "t", "seq")}
    return (f"{colour}{_stamp(event)}   {kind} "
            f"{json.dumps(rest, ensure_ascii=False)[:400]}{OFF}")


def follow(path: Path, since: int, only: set[str], show_samples: bool,
           once: bool) -> None:
    seen = 0
    printed_waiting = False
    while True:
        if not path.exists():
            if not printed_waiting:
                print(f"{DIM}waiting for {path} ...{OFF}", flush=True)
                printed_waiting = True
            if once:
                return
            time.sleep(0.5)
            continue
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index < seen or index < since:
                    continue
                seen = index + 1
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                kind = event.get("kind", "")
                if only and not any(kind.startswith(k) for k in only):
                    continue
                if kind == "sample" and not show_samples and not only:
                    # Keep the heartbeat visible but rare: every fifth line,
                    # plus anything that was late or had a hung window.
                    if (event.get("n", 0) % 5 and not event.get("late")
                            and not event.get("hung")):
                        continue
                rendered = render(event)
                if rendered:
                    print(rendered, flush=True)
        if once:
            return
        time.sleep(0.35)


def show_state(path: Path) -> int:
    if not path.exists():
        print(f"no snapshot yet at {path}")
        return 1
    print(path.read_text(encoding="utf-8"))
    return 0


def show_llm(path: Path, count: int) -> int:
    if not path.exists():
        print(f"no model log yet at {path}")
        return 1
    entries = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    for entry in entries[-count * 2:]:
        head = (f"{BOLD}{_stamp(entry)}  {entry.get('kind')}  "
                f"{entry.get('purpose')}  {entry.get('model')}{OFF}")
        print(f"\n{'=' * 78}\n{head}\n{'=' * 78}")
        for message in entry.get("messages") or []:
            print(f"\n--- {message.get('role')} ---\n{message.get('content')}")
        if entry.get("text") is not None:
            print(f"\n--- answer ({entry.get('chars')} chars in "
                  f"{entry.get('duration_s')}s) ---\n{entry['text']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", default=str(LIVE_DIR))
    parser.add_argument("--all", action="store_true",
                        help="show every sample line, not one in five")
    parser.add_argument("--only", default="",
                        help="comma-separated event kind prefixes")
    parser.add_argument("--since", type=int, default=-1,
                        help="start at this line (0 replays everything)")
    parser.add_argument("--state", action="store_true",
                        help="print the current snapshot and exit")
    parser.add_argument("--llm", type=int, metavar="N",
                        help="print the last N model exchanges in full")
    parser.add_argument("--once", action="store_true",
                        help="print what is there and exit")
    args = parser.parse_args(argv)

    directory = Path(args.dir)
    if args.state:
        return show_state(directory / "state.json")
    if args.llm:
        return show_llm(directory / "llm.jsonl", args.llm)

    path = directory / "bridge.jsonl"
    since = args.since
    if since < 0:
        # Default to the whole file: these runs are short and the beginning is
        # usually the part that explains the end.
        since = 0
    only = {k.strip() for k in args.only.split(",") if k.strip()}
    try:
        follow(path, since, only, args.all, args.once)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
