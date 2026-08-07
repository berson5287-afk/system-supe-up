"""Inject a known fault, then check the monitor actually notices it.

A detector that has never been shown a real fault is a hypothesis, not a
tool. Each case here starts a misbehaving process, samples the machine while
it misbehaves, and then asserts two separate things:

* the **measurement** saw it — the process is at the top of the right column,
  with roughly the magnitude that was injected, and
* the **rule** fired — a finding exists, pointing at the right pid.

Those are worth checking separately, because a rule that never fires and a
rule whose threshold is simply higher than the injected fault look identical
from the outside, and only one of them is a bug.

    python tests/test_detection.py            # everything
    python tests/test_detection.py cpu hang   # just these
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace", line_buffering=True)

import psutil                                                   # noqa: E402

from sysup import rules                                         # noqa: E402
from sysup.collect import History, Sampler                      # noqa: E402

FAULT = HERE / "fault.py"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

GREEN, RED, YELLOW, DIM, RESET = ("\033[32m", "\033[31m", "\033[33m",
                                  "\033[90m", "\033[0m")


@dataclass
class Case:
    name: str
    argv: list[str]
    what: str
    settle: float = 6.0
    samples: int = 14
    interval: float = 0.75
    #: Needs a visible window, so the fault cannot be started hidden.
    windowed: bool = False
    skip_if: object = None


@dataclass
class Outcome:
    name: str
    measured: str = ""
    measured_ok: bool = False
    rule: str = ""
    rule_ok: bool = False
    note: str = ""
    findings: list = field(default_factory=list)


def _free_gb() -> float:
    return psutil.virtual_memory().available / 1e9


CASES = [
    Case("cpu", ["cpu", "34", "--workers", "5"],
         "one process burning several cores"),
    Case("hang", ["hang", "30"],
         "a visible window that stops answering", windowed=True, samples=13),
    Case("threads", ["threads", "30", "--count", "700"],
         "a process with a runaway thread count"),
    Case("handles", ["handles", "30", "--count", "40000"],
         "a process leaking kernel handles"),
    Case("io", ["io", "34"], "a process saturating the disk"),
    Case("memory", ["memory", "26", "--mb", "900"],
         "a process holding a large block of memory",
         # This machine already logs out-of-memory events, so adding 900 MB
         # when it is nearly full could cause a real freeze rather than a
         # test. Refuse rather than risk it.
         skip_if=lambda: (_free_gb() < 3.0,
                          f"only {_free_gb():.1f} GB free — refusing to add "
                          f"900 MB to a machine this close to the edge")),
]


def run_case(case: Case) -> Outcome:
    outcome = Outcome(name=case.name)
    if case.skip_if is not None:
        skip, why = case.skip_if()
        if skip:
            outcome.note = f"skipped — {why}"
            return outcome

    command = [sys.executable, str(FAULT), *case.argv]
    creation = 0 if case.windowed else NO_WINDOW
    process = subprocess.Popen(command, creationflags=creation,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    pid = process.pid
    try:
        time.sleep(case.settle)
        sampler, history = Sampler(), History(size=200)
        sampler.sample()
        for _ in range(case.samples):
            time.sleep(case.interval)
            history.add(sampler.sample(case.interval), threshold=2.0)

        sample = history.latest()
        row = sample.find(pid) if sample else None
        # The fault process may have children; roll them in so a fault that
        # forks is still attributed to what we started.
        if row is None:
            outcome.note = "the fault process was not seen at all"
            return outcome

        outcome.findings = rules.analyse(history)
        _check(case, outcome, history, sample, row, pid)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
    return outcome


def _check(case, outcome, history, sample, row, pid) -> None:
    mine = [f for f in outcome.findings if f.pid == pid]

    if case.name == "cpu":
        cpu = history.sustained(pid, "cpu", 20)
        rank = [r.pid for r in sample.by_cpu(3)]
        outcome.measured = (f"{cpu:.1f}% of the machine sustained; "
                            f"{'top-3 by CPU' if pid in rank else 'not top-3'}")
        outcome.measured_ok = cpu > 15 and pid in rank
        hit = [f for f in mine if f.category == "cpu"]
        outcome.rule = hit[0].title if hit else "no CPU finding"
        outcome.rule_ok = bool(hit)
        if not hit and cpu < rules.RUNAWAY_CPU:
            outcome.note = (f"below the {rules.RUNAWAY_CPU}% threshold, so "
                            f"not firing is correct")

    elif case.name == "hang":
        seen = history.seen_hung(pid, count=30)
        hung_now = bool(row.hung)
        outcome.measured = (f"flagged unresponsive in {seen} of "
                            f"{min(30, len(history.samples))} samples"
                            f"{'; still hung at the end' if hung_now else ''}")
        outcome.measured_ok = seen >= 3
        hit = [f for f in mine if f.category == "freeze"]
        outcome.rule = hit[0].title if hit else "no freeze finding"
        outcome.rule_ok = bool(hit)

    elif case.name == "threads":
        outcome.measured = f"{row.threads} threads"
        outcome.measured_ok = row.threads >= 500
        hit = [f for f in mine if f.category == "threads"]
        outcome.rule = hit[0].title if hit else "no thread finding"
        outcome.rule_ok = bool(hit)

    elif case.name == "handles":
        outcome.measured = f"{row.handles:,} handles"
        outcome.measured_ok = row.handles >= 30_000
        hit = [f for f in mine if f.category == "handles"]
        outcome.rule = hit[0].title if hit else "no handle finding"
        outcome.rule_ok = bool(hit)
        if not hit:
            outcome.note = ("growth was not seen because the handles were all "
                            "opened before sampling began")

    elif case.name == "io":
        rate = history.sustained(pid, "io_bps", 20)
        rank = [r.pid for r in sample.by_io(3)]
        busy = history.average("disk_busy", 20)
        latency = history.average("disk_latency_ms", 20)
        operations = history.average("disk_ops", 20)
        outcome.measured = (
            f"{rate / 1e6:.0f} MB/s sustained; {operations:,.0f} ops/s at "
            f"{latency:.2f} ms each ({busy:.1f}% busy); "
            f"{'top-3 by I/O' if pid in rank else 'not top-3'}")
        outcome.measured_ok = rate > 5e6 and pid in rank
        hit = [f for f in outcome.findings if f.category == "disk"]
        outcome.rule = hit[0].title if hit else "no disk finding"
        outcome.rule_ok = bool(hit)
        if not hit:
            outcome.note = (
                f"the drive served this in {latency:.2f} ms per operation, "
                f"far under the {rules.DISK_SLOW_MS:.0f} ms threshold — the "
                f"NVMe genuinely was not struggling, so staying quiet is "
                f"correct. Percent-busy would have said {busy:.1f}%, which is "
                f"why the rule no longer relies on it.")

    elif case.name == "memory":
        outcome.measured = (f"{row.memory / 1e6:.0f} MB working set, "
                            f"{row.private / 1e6:.0f} MB private")
        outcome.measured_ok = row.private > 600e6
        hit = [f for f in outcome.findings if f.category == "memory"]
        outcome.rule = hit[0].title if hit else "no memory finding"
        outcome.rule_ok = bool(hit)


def main(argv: list[str]) -> int:
    wanted = {a.lower() for a in argv}
    cases = [c for c in CASES if not wanted or c.name in wanted]

    print(f"\n{'=' * 74}")
    print("  Fault injection — does the monitor actually notice?")
    print(f"{'=' * 74}")
    print(f"  {psutil.cpu_count(logical=True)} logical CPUs, "
          f"{_free_gb():.1f} GB free of "
          f"{psutil.virtual_memory().total / 1e9:.1f} GB\n")

    outcomes = []
    for case in cases:
        print(f"{DIM}▸ {case.name}: injecting {case.what}…{RESET}", flush=True)
        outcome = run_case(case)
        outcomes.append(outcome)
        if outcome.note and not outcome.measured:
            print(f"  {YELLOW}○ {outcome.note}{RESET}\n")
            continue
        tick = f"{GREEN}✓{RESET}" if outcome.measured_ok else f"{RED}✗{RESET}"
        print(f"  {tick} measured: {outcome.measured}")
        tick = f"{GREEN}✓{RESET}" if outcome.rule_ok else f"{YELLOW}○{RESET}"
        print(f"  {tick} rule:     {outcome.rule}")
        if outcome.note:
            print(f"    {DIM}{outcome.note}{RESET}")
        print()

    print(f"{'=' * 74}")
    ran = [o for o in outcomes if o.measured]
    measured = sum(1 for o in ran if o.measured_ok)
    fired = sum(1 for o in ran if o.rule_ok)
    print(f"  measurement: {measured}/{len(ran)} detected the injected fault")
    print(f"  rules:       {fired}/{len(ran)} raised a finding")
    skipped = [o for o in outcomes if not o.measured]
    for outcome in skipped:
        print(f"  {YELLOW}skipped{RESET}: {outcome.name} — {outcome.note}")
    print(f"{'=' * 74}\n")
    return 0 if measured == len(ran) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
