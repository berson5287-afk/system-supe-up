"""Drive the real rule engine with a machine that does not exist.

This is what the telemetry seam is for. Every scenario here is one that
cannot be produced to order on real hardware — you cannot ask a healthy NVMe
to take 400 ms per operation, or arrange exactly 3.2 seconds of scheduler
lateness alongside comfortable memory, or hold a commit charge at 97% while
physical RAM sits at 55%.

The rules under test are the production ones, unmodified.

    python tests/test_synthetic.py
"""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace", line_buffering=True)

from sysup import rules                                         # noqa: E402
from sysup.collect import History, ProcRow, Sample              # noqa: E402
from sysup.incidents import Incident, IncidentRecorder          # noqa: E402
from sysup.telemetry import (FakeBackend, MemoryInfo,           # noqa: E402
                             ProcSnapshot, ThreadWaits)

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def row(pid: int, name: str, **kwargs) -> ProcRow:
    return ProcRow(pid=pid, name=name, **kwargs)


def make_sample(**kwargs) -> Sample:
    """A plausible healthy machine, overridden by whatever the test cares about."""
    base = dict(at=time.time(), interval=1.0, cpu=12.0,
                memory_percent=55.0, memory_total=17_000_000_000,
                memory_available=7_600_000_000,
                commit_percent=48.0, commit_total=28_000_000_000,
                commit_limit=59_000_000_000,
                disk_latency_ms=0.4, disk_ops=200.0, hard_faults=3.0,
                ready_threads=0, processes=[])
    base.update(kwargs)
    return Sample(**base)


def history_of(samples: list[Sample], threshold: float = 2.5) -> History:
    history = History(size=400)
    for sample in samples:
        history.add(sample, threshold)
    return history


# ------------------------------------------------------------- fake backend

def test_fake_backend() -> None:
    print("\nfake telemetry backend")
    waits = ThreadWaits(total=10, benign=6)
    waits.buckets = {"paging": 4}
    waits.settle()
    backend = FakeBackend([
        {"processes": [ProcSnapshot(pid=100, name="ghost.exe", threads=10,
                                    working_set=2_000_000_000, waits=waits)],
         "memory": MemoryInfo(commit_total=50 << 30, commit_limit=52 << 30,
                              physical_total=17 << 30,
                              physical_available=1 << 30)},
    ])
    snapshot = backend.snapshot_processes()
    check("returns the scripted process", 100 in snapshot
          and snapshot[100].name == "ghost.exe")
    check("wait bucket settled", snapshot[100].waits.dominant == "paging",
          snapshot[100].waits.dominant)
    info = backend.memory_info()
    check("commit percent computed",
          abs(info.commit_percent - 96.15) < 0.1, f"{info.commit_percent:.2f}%")

    from sysup.collect import Sampler
    sampler = Sampler(cpu_count=8, backend=FakeBackend([
        {"processes": [ProcSnapshot(pid=1, name="a.exe", threads=1)]}]))
    sampler.sample()
    check("Sampler accepts an injected backend",
          isinstance(sampler.backend, FakeBackend))


# ------------------------------------------------------------- slow storage

def test_slow_disk() -> None:
    """A drive at 400 ms per operation — impossible to stage on real hardware."""
    print("\nslow storage (synthetic)")
    samples = [make_sample(
        disk_latency_ms=418.0, disk_ops=90.0,
        disk_read_bps=2e6, disk_write_bps=1e6,
        processes=[row(500, "OUTLOOK.EXE", read_bps=2e6, write_bps=1e6,
                       title="Inbox")]) for _ in range(25)]
    findings = rules.analyse(history_of(samples))
    disk = [f for f in findings if f.category == "disk"]
    check("slow drive raises a disk finding", bool(disk),
          disk[0].title if disk else "none")
    if disk:
        check("reports service time, not percent busy",
              "ms per operation" in disk[0].title, disk[0].title)
        check("severity is serious at 418 ms", disk[0].severity >= 4,
              f"severity {disk[0].severity}")

    # And the negative: a fast drive doing heavy work must stay quiet.
    fast = [make_sample(disk_latency_ms=0.02, disk_ops=8000.0,
                        disk_read_bps=900e6) for _ in range(25)]
    quiet = [f for f in rules.analyse(history_of(fast))
             if f.category == "disk"]
    check("fast drive under heavy load stays quiet", not quiet,
          quiet[0].title if quiet else "")


# ------------------------------------------------------------ commit vs RAM

def test_commit_versus_physical() -> None:
    """The distinction that was impossible before commit was measured."""
    print("\ncommit charge vs physical memory")

    # High physical use, healthy commit — a normal, well-used machine.
    healthy = [make_sample(memory_percent=92.0,
                           memory_available=1_400_000_000,
                           commit_percent=55.0, hard_faults=2.0)
               for _ in range(25)]
    findings = rules.analyse(history_of(healthy))
    verdict = [f for f in findings if f.id == "memory-verdict"]
    check("high RAM use still reports a memory finding", bool(verdict),
          "expected — 8% free is genuinely tight")

    # The reverse: comfortable RAM, commit nearly exhausted.
    strained = [make_sample(memory_percent=60.0,
                            memory_available=6_800_000_000,
                            commit_percent=97.0,
                            commit_total=57_000_000_000,
                            commit_limit=59_000_000_000)
                for _ in range(25)]
    findings = rules.analyse(history_of(strained))
    check("comfortable RAM does not trigger the low-memory rule",
          not [f for f in findings if f.id == "memory-pressure"],
          "correct — the shortage is commit, not RAM")


# ------------------------------------------------------------------- stalls

def test_stall_without_load() -> None:
    """3.2s of lateness with everything else unremarkable."""
    print("\nstall with no load (the driver case)")
    samples = [make_sample() for _ in range(20)]
    samples.append(make_sample(lateness=3.2))
    samples += [make_sample() for _ in range(5)]
    findings = rules.analyse(history_of(samples))
    stall = [f for f in findings if f.id == "system-stall"]
    check("a stall with no load is still reported", bool(stall))
    if stall:
        check("attributed to something that does not show as load",
              "driver" in stall[0].explanation.lower()
              or "kernel-level" in stall[0].explanation.lower(),
              stall[0].explanation[-90:])

    # A discontinuity of the same size must produce nothing.
    paused = [make_sample() for _ in range(20)]
    paused.append(make_sample(lateness=30.0, discontinuity=True))
    history = history_of(paused)
    check("a discontinuity of 30s records no stall",
          len(history.stalls) == 0, f"{len(history.stalls)} stall(s)")
    check("and raises no stall finding",
          not [f for f in rules.analyse(history) if f.id == "system-stall"])


# ---------------------------------------------------------------- incidents

def test_incident_capture(tmp: Path) -> None:
    print("\nincident capture and verdict")
    history = History(size=400)
    recorder = IncidentRecorder(history, before_seconds=8, after_seconds=4,
                                directory=tmp)

    start = time.time()
    finished: Incident | None = None

    def feed(sample: Sample) -> None:
        nonlocal finished
        stall = history.add(sample, 2.5)
        got = recorder.on_sample(sample, stall)
        if got is not None:
            finished = got

    # Quiet run-up.
    for index in range(12):
        feed(make_sample(at=start + index, disk_latency_ms=3.1,
                         hard_faults=4.0, commit_percent=60.0, cpu=10.0))
    # The freeze: storage collapses, paging spikes, an app dies.
    for index in range(2):
        feed(make_sample(
            at=start + 12 + index, lateness=3.8 if index == 0 else 0.1,
            disk_latency_ms=418.0, hard_faults=1284.0, commit_percent=94.0,
            cpu=22.0, ready_threads=9,
            processes=[row(700, "OUTLOOK.EXE", hard_faults=900.0,
                           read_bps=4e6, title="Inbox", cpu=0.0),
                       row(800, "chrome.exe", hard_faults=380.0, cpu=0.01,
                           title="Order page")]))
    # Recovery.
    for index in range(7):
        feed(make_sample(at=start + 14 + index, disk_latency_ms=3.0,
                         hard_faults=5.0, commit_percent=61.0))

    check("an incident was captured", finished is not None)
    if finished is None:
        return
    check("run-up preserved", len(finished.before) >= 8,
          f"{len(finished.before)} samples")
    check("recovery preserved", len(finished.after) >= 3,
          f"{len(finished.after)} samples")
    # Both freeze samples must land in `during`, not just the one that
    # tripped the detector — otherwise the averages the verdict is built
    # from are diluted by half a second of recovery.
    check("the whole freeze counted as during", len(finished.during) >= 2,
          f"{len(finished.during)} samples")

    cause, evidence = finished.verdict()
    check("cause names memory pressure and disk",
          "memory" in cause and "disk" in cause, cause)
    joined = " | ".join(evidence)
    check("evidence shows the latency change",
          "3.10 ms → 418.00 ms" in joined, joined[:110])
    check("evidence shows the fault change", "4/s → 1284/s" in joined)

    culprits = finished.culprits()
    check("names the biggest faulter", culprits and culprits[0][0] == "OUTLOOK.EXE",
          culprits[0][0] if culprits else "none")
    check("notices windows that got no CPU",
          ("OUTLOOK.EXE", 700) in finished.unscheduled())

    written = list(tmp.glob("incident-*.json"))
    check("incident written to disk", len(written) == 1,
          written[0].name if written else "none")
    if written:
        import json
        data = json.loads(written[0].read_text(encoding="utf-8"))
        expected = (len(finished.before) + len(finished.during)
                    + len(finished.after))
        check("timeline persisted whole", len(data["timeline"]) == expected,
              f"{len(data['timeline'])} of {expected} points")
        check("probable cause persisted", bool(data["probable_cause"]))

    print()
    print("  ---- generated summary ----")
    for line in finished.summary().splitlines():
        print("  " + line)


# ------------------------------------------------------------- wait chains

def test_wait_chains() -> None:
    """Chains that need SeDebugPrivilege to observe for real.

    Running unelevated, Windows returns every node as "pid only", so the
    interesting cases — a cross-process COM chain, and a cycle — cannot be
    produced on this machine at all. They are asserted here instead.
    """
    print("\nwait chain traversal (synthetic)")
    from sysup.telemetry import WaitChain, WaitChainNode

    # Outlook -> COM -> Teams -> mutex -> Teams. The example that motivated
    # the whole feature.
    chain = WaitChain(tid=18424, nodes=[
        WaitChainNode(is_thread=True, object_type=8, status=2,
                      pid=700, tid=18424, wait_time_ms=12000),
        WaitChainNode(is_thread=False, object_type=5, status=2),
        WaitChainNode(is_thread=True, object_type=8, status=2,
                      pid=900, tid=11984),
        WaitChainNode(is_thread=False, object_type=3, status=2,
                      name="TeamsLock"),
        WaitChainNode(is_thread=True, object_type=8, status=5,
                      pid=900, tid=14532),
    ])
    names = {700: "OUTLOOK.EXE", 900: "Teams.exe"}
    check("chain is usable", chain.usable)
    check("crosses into the blocking process", chain.processes() == [900],
          str(chain.processes()))
    blocker = chain.blocker()
    check("names the final blocking thread",
          blocker is not None and blocker.pid == 900 and blocker.tid == 14532)

    lines = chain.describe(names)
    joined = " / ".join(lines)
    check("renders the COM hop", "a COM call" in joined, joined[:100])
    check("renders the mutex by name", "TeamsLock" in joined)
    check("names both processes",
          "OUTLOOK.EXE" in joined and "Teams.exe" in joined)
    check("shows how long it has waited", "waiting 12s" in joined)

    # A cycle: Windows' own proof of deadlock.
    cycle = WaitChain(tid=1, is_cycle=True, nodes=[
        WaitChainNode(is_thread=True, object_type=8, status=2, pid=5, tid=1),
        WaitChainNode(is_thread=False, object_type=1, status=2),
        WaitChainNode(is_thread=True, object_type=8, status=2, pid=5, tid=2),
    ])
    row = ProcRow(pid=5, name="app.exe", title="App")
    row.wait_chain = cycle
    sample = make_sample(processes=[row])
    sentence = rules._chain_sentence(row, sample)
    check("a cycle is called a deadlock", "deadlock" in sentence.lower(),
          sentence[:90])
    evidence = rules._chain_evidence(row, sample)
    check("cycle appears in evidence",
          any("CYCLE" in line for line in evidence))

    # Restricted: the unelevated reality, which must advise rather than lie.
    restricted = WaitChain(tid=9, restricted=True, nodes=[
        WaitChainNode(is_thread=True, object_type=8, status=3, pid=5, tid=9)])
    row2 = ProcRow(pid=6, name="other.exe")
    row2.wait_chain = restricted
    evidence = rules._chain_evidence(row2, make_sample(processes=[row2]))
    check("restricted chain advises elevation",
          any("administrator" in line for line in evidence),
          evidence[0][:80] if evidence else "none")
    check("restricted chain makes no claim about the blocker",
          rules._chain_sentence(row2, make_sample(processes=[row2])) == "")

    # And a process with no chain at all must add nothing.
    row3 = ProcRow(pid=7, name="fine.exe")
    check("no chain adds no evidence",
          rules._chain_evidence(row3, make_sample(processes=[row3])) == [])


def main() -> int:
    import tempfile

    print("=" * 74)
    print("  Synthetic telemetry — rules driven by machines that do not exist")
    print("=" * 74)
    with tempfile.TemporaryDirectory() as folder:
        for test in (test_fake_backend, test_slow_disk,
                     test_commit_versus_physical, test_stall_without_load,
                     test_wait_chains):
            try:
                test()
            except Exception as error:
                check(f"{test.__name__} raised", False, repr(error))
        try:
            test_incident_capture(Path(folder))
        except Exception as error:
            check("test_incident_capture raised", False, repr(error))

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
