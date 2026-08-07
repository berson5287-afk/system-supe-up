"""The local diagnostic engine: evidence in, explained findings out.

This runs with no model and no network, and it is deliberately the part that
decides *what is wrong*.  The language model's job later is to explain and
tailor, not to detect — a 32B model asked to spot a paging storm from a table
of numbers will sometimes miss it and will occasionally invent one, whereas
"available RAM under 10% while hard faults exceed 200/s" is simply true or
simply false.  Keeping detection here means the tool still works when the
Ollama box is off, and it means the model is never the reason a finding is
wrong.

Every rule obeys three house rules:

* **Sustained, not instantaneous.**  Accusations are made from an average over
  many samples.  One spike is an application doing its job.
* **Evidence attached.**  Each finding carries the numbers it was made from, so
  the report can show its working and the user can disagree.
* **Never suggest something dangerous.**  `knowledge.is_killable` gates every
  offer to stop a process, so no rule can propose ending lsass.exe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import knowledge
from .collect import History, ProcRow, Sample
from .knowledge import Fix

# Thresholds.  Named, because a bare 0.10 buried in a condition is unarguable
# and unmaintainable.
# Below ~15% available, Windows' own memory manager starts trimming working
# sets aggressively rather than waiting — so this is where paging begins in
# practice, not at some lower "nearly full" mark.  Set at 12% it missed a
# machine sitting at 13% free that was visibly struggling.
LOW_MEMORY_FRACTION = 0.15       # available RAM below this is a real shortage
CRITICAL_MEMORY_FRACTION = 0.06
PAGING_STORM_FAULTS = 150.0      # machine-wide hard faults/sec
HEAVY_PAGING_FAULTS = 400.0
RUNAWAY_CPU = 22.0               # sustained % of the whole machine, one process
HIGH_CPU_TOTAL = 85.0
# Percent-busy only reaches this on a spinning disk. An NVMe servicing
# 120 MB/s sits at well under 1%, so this alone would never fire on modern
# hardware — see `disk_latency_ms` and the pair of thresholds below it.
DISK_SATURATED = 80.0            # percent of the interval the disk had work
# Average milliseconds per operation. A healthy NVMe is under 1, a SATA SSD
# a few, a spinning disk 5–15 under load. Sustained tens of milliseconds is a
# drive that applications are visibly waiting on.
DISK_SLOW_MS = 20.0
DISK_VERY_SLOW_MS = 60.0
HUNG_SAMPLES = 3                 # consecutive-ish samples unresponsive
GDI_WARN = 6_000                 # of a 10,000 ceiling
GDI_CRITICAL = 8_500
HANDLE_WARN = 15_000
THREAD_WARN = 400
LEAK_GROWTH_BYTES = 250 * 1024 * 1024   # growth over the history window
STARVED_READY_THREADS = 6

SEVERITY_NAMES = {1: "info", 2: "minor", 3: "moderate", 4: "serious",
                  5: "critical"}


@dataclass
class Finding:
    """One thing that is wrong, why it is wrong, and what to do about it."""

    id: str
    title: str
    #: 1 informational .. 5 the machine is about to fall over
    severity: int
    #: How sure the rule is.  Below ~0.5 the report words it as a suspicion.
    confidence: float
    category: str
    #: Plain-English chain of cause and effect.  This is the answer to "why is
    #: this app freezing my PC", and it is written here rather than by the
    #: model so that it is still correct when there is no model.
    explanation: str
    evidence: list[str] = field(default_factory=list)
    fixes: list[Fix] = field(default_factory=list)
    pid: int = 0
    process: str = ""
    #: Set when the rule could not identify the culprit and a web lookup or a
    #: model might. Drives the research step.
    unknown_subject: str = ""

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, "unknown")

    def sort_key(self) -> tuple:
        return (-self.severity, -self.confidence)


def _gb(value: float) -> str:
    return f"{value / 1e9:.1f} GB"


def _mb(value: float) -> str:
    return f"{value / 1e6:.0f} MB"


def _name_of(row: ProcRow) -> str:
    """How to refer to a process in prose.

    Always carries the real executable name, even when a friendlier one
    exists.  Given only "Audio Device Graph", a model writing instructions
    will confidently invent "AudioDeviceGraphRunner.exe" for the user to go
    and look for — so the true name travels with every mention.
    """
    fact = knowledge.lookup(row.name)
    display = f"{fact.display} ({row.name})" if fact else row.name
    if row.title:
        return f"{display}, “{row.title[:60]}”, pid {row.pid}"
    return f"{display}, pid {row.pid}"


def _growth(history: History, pid: int, attribute: str) -> float:
    """How much a field grew across the history window, in raw units."""
    values = []
    for sample in history.samples:
        row = sample.find(pid)
        if row is not None:
            values.append(getattr(row, attribute, 0))
    if len(values) < 10:
        return 0.0
    # Compare the means of the first and last fifths rather than single
    # endpoints, so one unlucky sample cannot invent or hide a trend.
    span = max(2, len(values) // 5)
    return (sum(values[-span:]) / span) - (sum(values[:span]) / span)


def analyse(history: History, sample: Sample | None = None) -> list[Finding]:
    """Every rule, run against the current sample and the recent past."""
    sample = sample or history.latest()
    if sample is None:
        return []

    findings: list[Finding] = []
    for rule in (_rule_hung_apps, _rule_memory_pressure, _rule_memory_verdict,
                 _rule_known_leak, _rule_paging_storm,
                 _rule_system_stalls, _rule_runaway_cpu, _rule_disk_saturation,
                 _rule_duplicate_antivirus, _rule_lock_contention,
                 _rule_blocked_on_other_process, _rule_gdi_leak,
                 _rule_handle_leak, _rule_thread_explosion,
                 _rule_memory_leak, _rule_kernel_pool, _rule_cpu_starvation,
                 _rule_driver_waits):
        try:
            findings.extend(rule(history, sample) or [])
        except Exception:
            # A broken rule must not take the monitor down with it; the other
            # fifteen still have something useful to say.
            continue

    findings.sort(key=lambda f: f.sort_key())
    return findings


# ------------------------------------------------------------------- rules

def _rule_hung_apps(history: History, sample: Sample) -> list[Finding]:
    """An application Windows itself has declared unresponsive.

    This is the only rule that can be certain, because it is not inferring a
    freeze from load — it is reading the same flag that puts "(Not Responding)"
    in the title bar.  The interesting part is not *that* it hung but *why*,
    which the thread wait buckets answer.
    """
    findings = []
    for window_pid in {w.pid for w in sample.hung_windows}:
        row = sample.find(window_pid)
        if row is None:
            continue
        seen = history.seen_hung(window_pid, count=30)
        titles = [w.title for w in sample.hung_windows if w.pid == window_pid]
        ghosted = any(w.ghosted for w in sample.hung_windows
                      if w.pid == window_pid)

        cpu = history.sustained(window_pid, "cpu", 20)
        faults = history.sustained(window_pid, "hard_faults", 20)
        bucket = row.waits.dominant

        # The wait state is what turns "it's frozen" into a cause.
        if bucket == "paging":
            why = ("its threads are blocked waiting for memory to be read back "
                   "from the page file, so it is frozen because the machine is "
                   "out of RAM rather than because of a fault in the app")
            severity, fixes = 4, [
                Fix("Free up RAM before blaming the app",
                    "Close other large applications, or add RAM. This "
                    "application will unfreeze on its own once its pages are "
                    "back in memory.")]
        elif bucket == "lock":
            why = ("its threads are blocked on a lock another thread inside it "
                   "is holding — a deadlock. It will not recover on its own")
            severity, fixes = 4, []
        elif bucket == "ipc":
            why = ("it is blocked waiting for a reply from another process, so "
                   "the fault most likely lies in whatever it is calling — a "
                   "shell extension, an add-in, or a service")
            severity, fixes = 3, []
        elif bucket == "kernel":
            why = ("its threads are stuck inside a driver call that has not "
                   "returned, which usually means slow storage, a network "
                   "path that is not answering, or a filter driver such as "
                   "antivirus inspecting what it is doing")
            severity, fixes = 3, []
        elif cpu > RUNAWAY_CPU:
            why = (f"it is burning {cpu:.0f}% of the machine's CPU while not "
                   f"answering its own window, which is the signature of a "
                   f"runaway loop inside the app")
            severity, fixes = 4, []
        elif faults > 50:
            why = (f"it is taking {faults:.0f} hard page faults a second, so it "
                   f"is stalled fetching its own memory back off the disk")
            severity, fixes = 4, []
        else:
            why = ("it has stopped pumping its message queue while using "
                   "almost no CPU, which usually means it is waiting on "
                   "something external — a network call, a file on a slow or "
                   "disconnected path, or another process")
            severity, fixes = 3, []

        fact = knowledge.lookup(row.name)
        if fact:
            fixes = fixes + list(fact.fixes)
        if knowledge.is_killable(row.name):
            fixes.append(Fix(
                f"Force {fact.display if fact else row.name} to close",
                "Unsaved work in this application will be lost. Only worth "
                "doing once it is clear it is not going to recover.",
                f"taskkill /f /pid {row.pid}", risk="medium"))

        evidence = [
            f"Windows reports {len(titles)} window(s) of this process as not "
            f"responding" + (" (already replaced with a ghost window)"
                             if ghosted else ""),
            f"unresponsive in {seen} of the last {min(30, history.count)} samples",
            f"CPU {cpu:.1f}% sustained, {row.threads} threads, "
            f"{_mb(row.memory)} working set",
        ]
        if row.waits.stuck:
            evidence.append("thread waits: " + row.waits.describe())
        evidence += [f"window: “{t[:70]}”" for t in titles[:4]]

        findings.append(Finding(
            id=f"hung:{window_pid}",
            title=f"{fact.display if fact else row.name} is not responding",
            severity=severity if seen >= HUNG_SAMPLES else severity - 1,
            confidence=0.95 if seen >= HUNG_SAMPLES else 0.7,
            category="freeze",
            explanation=(f"{_name_of(row)} has stopped responding, and {why}."),
            evidence=evidence, fixes=fixes, pid=window_pid, process=row.name))
    return findings


def _rule_memory_pressure(history: History, sample: Sample) -> list[Finding]:
    """Not enough RAM — the root cause behind most whole-machine freezes."""
    if not sample.memory_total:
        return []
    free_fraction = sample.memory_available / sample.memory_total
    if free_fraction > LOW_MEMORY_FRACTION:
        return []

    critical = free_fraction < CRITICAL_MEMORY_FRACTION
    hogs = sorted(sample.processes, key=lambda r: -r.memory)[:5]

    # Group by executable name: eight Chrome processes are one Chrome problem,
    # and listing them separately hides the real total.
    grouped: dict[str, tuple[int, int]] = {}
    for row in sample.processes:
        total, count = grouped.get(row.name, (0, 0))
        grouped[row.name] = (total + row.memory, count + 1)
    ranked = sorted(grouped.items(), key=lambda kv: -kv[1][0])[:6]

    evidence = [
        f"{_gb(sample.memory_available)} available of "
        f"{_gb(sample.memory_total)} ({free_fraction * 100:.0f}% free)",
        f"page file in use: {sample.swap_percent:.0f}%",
        f"machine-wide hard faults: {history.average('hard_faults', 30):.0f}/s "
        f"average, {history.peak('hard_faults', 60):.0f}/s peak",
    ]
    evidence += [f"{name}: {_gb(total)} across {count} process(es)"
                 for name, (total, count) in ranked]

    fixes = [Fix("Close the largest applications first",
                 "The list above is ordered by how much each application is "
                 "actually holding. Closing the top one or two is the fastest "
                 "way to stop the freezing.")]
    for name, (total, count) in ranked[:3]:
        fact = knowledge.lookup(name)
        if fact and fact.fixes and total > 500e6:
            fixes.extend(fact.fixes[:2])
    if sample.memory_total < 17e9:
        fixes.append(Fix(
            "Consider more RAM",
            f"This machine has {_gb(sample.memory_total)} installed. For the "
            f"workload above — a browser, Office and a sync client together — "
            f"16 GB is the point where Windows starts paging constantly and "
            f"32 GB removes the problem rather than managing it.",
            risk="low"))

    return [Finding(
        id="memory-pressure",
        title=("Critically low memory — the machine is out of RAM"
               if critical else "Low memory is forcing Windows to page"),
        severity=5 if critical else 4,
        confidence=0.95,
        category="memory",
        explanation=(
            f"Only {_gb(sample.memory_available)} of "
            f"{_gb(sample.memory_total)} is free. When Windows runs this "
            f"short it starts writing pages of running applications out to "
            f"the page file and reading them back on demand. Every one of "
            f"those reads is a disk access standing in for a memory access — "
            f"roughly a hundred thousand times slower — and while it happens "
            f"the thread is stopped dead. That is what a whole-machine freeze "
            f"is: not a busy CPU, but every application waiting its turn for "
            f"the disk. It also explains why the freezes come in bursts and "
            f"clear on their own, and why the CPU graph looks calm "
            f"throughout."),
        evidence=evidence, fixes=fixes)]


def _rule_memory_verdict(history: History, sample: Sample) -> list[Finding]:
    """Where the memory has actually gone, and whether closing things can help.

    This exists because the honest answer to "my RAM is at 90%, can you get it
    down" is very often *no*, and a tool that will not say so is worse than
    useless — it sends someone round a loop of closing things, freeing two
    hundred megabytes, and being back where they started an hour later.

    So the memory is divided into what Windows needs, what the user actually
    has open, and what is genuinely disposable; and the verdict is arithmetic
    rather than encouragement. If everything disposable still does not get the
    machine to a comfortable margin, it says the machine needs more memory and
    — using the physical slot layout — exactly how to add it.
    """
    if not sample.memory_total:
        return []
    free_fraction = sample.memory_available / sample.memory_total
    # Only worth saying while memory is actually tight. Above 20% free there
    # is nothing to explain.
    if free_fraction > 0.20:
        return []

    buckets: dict[str, int] = {}
    members: dict[str, dict[str, tuple[int, int]]] = {}
    for row in sample.processes:
        if row.pid <= 4:
            continue
        bucket = knowledge.reclaim_class(row.name, bool(row.title),
                                         row.session)
        # Working set double-counts shared pages across a browser's children;
        # private commit is what actually returns when a process exits, and is
        # therefore the only honest basis for "you would get this back".
        cost = row.private
        buckets[bucket] = buckets.get(bucket, 0) + cost
        group = members.setdefault(bucket, {})
        total, count = group.get(row.name, (0, 0))
        group[row.name] = (total + cost, count + 1)

    reclaimable = sum(buckets.get(name, 0) for name in knowledge.RECLAIMABLE)
    leaked = sum(
        total for group in members.values()
        for name, (total, _count) in group.items()
        if knowledge.is_known_leak(name))

    # A comfortable margin is about a fifth of the machine free. Below that
    # Windows trims working sets and the paging that causes the freezing
    # begins.
    target = sample.memory_total * 0.20
    shortfall = max(0.0, target - sample.memory_available)
    covers = reclaimable >= shortfall

    slots = None
    try:
        from . import sysinfo
        slots = sysinfo.memory_slots()
    except Exception:
        slots = None

    committed = sum(buckets.values())
    evidence = [
        f"{_gb(sample.memory_available)} available of "
        f"{_gb(sample.memory_total)} — {free_fraction * 100:.0f}% free",
        f"to reach a comfortable 20% free, {_gb(shortfall)} more is needed",
        # Private commit across all processes exceeds installed RAM whenever
        # part of it has been paged out — which on a machine this tight is the
        # whole point. Saying so stops the breakdown below looking like it has
        # been added up wrongly.
        f"{_gb(committed)} committed in total across "
        f"{len(sample.processes)} processes, which exceeds installed RAM "
        f"because the difference is out in the page file",
    ]
    for bucket in ("work", "system", "background", "ai", "security", "managed",
                   "unknown"):
        if not buckets.get(bucket):
            continue
        top = sorted(members.get(bucket, {}).items(),
                     key=lambda kv: -kv[1][0])[:3]
        named = ", ".join(
            f"{name} {_gb(total)}" + (f" ×{count}" if count > 1 else "")
            for name, (total, count) in top)
        evidence.append(
            f"{knowledge.RECLAIM_LABELS[bucket]}: {_gb(buckets[bucket])}"
            + (f" — {named}" if named else ""))
    if slots and slots.installed:
        evidence.append(f"physical memory: {slots.describe()}")

    fixes: list[Fix] = []
    reclaim_names = []
    for bucket in knowledge.RECLAIMABLE:
        for name, (total, _count) in sorted(
                members.get(bucket, {}).items(), key=lambda kv: -kv[1][0])[:4]:
            if total > 150e6:
                reclaim_names.append((name, total))
    reclaim_names.sort(key=lambda item: -item[1])

    if reclaim_names:
        listed = ", ".join(f"{name} ({_mb(total)})"
                           for name, total in reclaim_names[:4])
        fixes.append(Fix(
            "Close the background software you are not using",
            f"These are agents and vendor tools rather than anything you have "
            f"open: {listed}. Between them they hold {_gb(reclaimable)}, and "
            f"closing them costs you nothing you are working on.",
            risk="low"))

    if covers:
        title = (f"Memory is tight, but {_gb(reclaimable)} of it is "
                 f"recoverable")
        severity = 3
        verdict = (
            f"The good news is that this one is fixable by closing things. "
            f"{_gb(reclaimable)} is held by background agents and vendor "
            f"tools rather than by anything you are working in, and freeing "
            f"it covers the {_gb(shortfall)} shortfall.")
    else:
        title = (f"This machine needs more memory — only {_gb(reclaimable)} "
                 f"is recoverable")
        severity = 4
        verdict = (
            f"Closing things will not fix this, and it is worth saying so "
            f"plainly rather than sending you round in circles. Only "
            f"{_gb(reclaimable)} is held by software you are not using; the "
            f"shortfall is {_gb(shortfall)}. Everything else is either "
            f"Windows itself or the applications you actually have open, so "
            f"the memory is not being wasted — there simply is not enough of "
            f"it for this workload.")
        if slots and slots.installed:
            advice = slots.upgrade_advice(int(sample.memory_total * 2))
            if advice:
                verdict += " " + advice
                fixes.append(Fix(
                    "Add memory — this is the actual fix",
                    advice + " Everything else on this list is management "
                             "rather than a cure.",
                    risk="low"))

    if leaked > 200e6:
        leaky = [name for group in members.values() for name in group
                 if knowledge.is_known_leak(name)]
        verdict += (f" Note also that {_gb(leaked)} of it is held by "
                    f"{', '.join(sorted(set(leaky)))}, which has a documented "
                    f"leak — that portion will keep growing until it is "
                    f"restarted or removed.")

    return [Finding(
        id="memory-verdict", title=title, severity=severity, confidence=0.9,
        category="memory",
        explanation=(
            f"Of the {_gb(committed)} committed on this machine, "
            f"{_gb(buckets.get('work', 0))} is the applications you have open, "
            f"{_gb(buckets.get('system', 0))} is Windows itself, "
            f"{_gb(buckets.get('security', 0) + buckets.get('managed', 0))} is "
            f"security and management agents, and {_gb(reclaimable)} is "
            f"background software you are not using. {verdict}"),
        evidence=evidence, fixes=fixes)]


def _rule_known_leak(history: History, sample: Sample) -> list[Finding]:
    """Processes with a documented leak, once they have grown enough to matter."""
    findings = []
    grouped: dict[str, tuple[int, int]] = {}
    for row in sample.processes:
        if not knowledge.is_known_leak(row.name):
            continue
        total, pid = grouped.get(row.name, (0, row.pid))
        grouped[row.name] = (total + row.private, pid)

    for name, (total, pid) in grouped.items():
        if total < 300e6:
            continue
        fact = knowledge.lookup(name)
        growth = _growth(history, pid, "private")
        findings.append(Finding(
            id=f"leak-known:{name}",
            title=f"{fact.display if fact else name} has a known memory leak "
                  f"and is holding {_gb(total)}",
            severity=4 if total > 1.5e9 else 3,
            confidence=0.8, category="memory",
            explanation=(
                f"{fact.display if fact else name} is a program with a "
                f"documented, reproducible memory leak — it grows steadily "
                f"with uptime rather than in response to anything you do, and "
                f"it does not give the memory back. It is currently holding "
                f"{_gb(total)}. This is the kind of fault that makes a machine "
                f"fine in the morning and unusable by the afternoon, and it is "
                f"almost never suspected because it is the vendor's own "
                f"software. Restarting it returns the memory immediately; "
                f"removing it stops the problem coming back."
                + (f" It grew {_mb(growth)} even while this was watching."
                   if growth > 20e6 else "")),
            evidence=[f"{_gb(total)} private memory held",
                      f"growth while monitored: {_mb(growth)}"
                      if abs(growth) > 1e6 else "stable over this window",
                      f"uptime matters here — the longer the machine has been "
                      f"on, the larger this gets"],
            fixes=list(fact.fixes) if fact else [],
            pid=pid, process=name))
    return findings


def _rule_paging_storm(history: History, sample: Sample) -> list[Finding]:
    """Sustained hard faults, and who is causing them."""
    average = history.average("hard_faults", 30)
    if average < PAGING_STORM_FAULTS:
        return []

    culprits = []
    for row in sorted(sample.processes, key=lambda r: -r.hard_faults)[:5]:
        rate = history.sustained(row.pid, "hard_faults", 30)
        if rate > 20:
            culprits.append((row, rate))
    if not culprits:
        return []

    heavy = average > HEAVY_PAGING_FAULTS
    top, top_rate = culprits[0]
    evidence = [f"machine-wide hard faults: {average:.0f}/s average over "
                f"{min(30, history.count)} samples"]
    evidence += [f"{_name_of(row)}: {rate:.0f} hard faults/s"
                 for row, rate in culprits]
    evidence.append(f"disk busy {history.average('disk_busy', 30):.0f}% average")

    fixes = [Fix(
        "Close or restart the process at the top of that list",
        "It is the one whose memory keeps having to be fetched back off the "
        "disk. Restarting it releases the fragmented working set it has "
        "built up.")]
    fact = knowledge.lookup(top.name)
    if fact:
        fixes.extend(fact.fixes[:2])

    return [Finding(
        id="paging-storm",
        title=f"Paging storm — {average:.0f} hard faults per second",
        severity=4 if heavy else 3,
        confidence=0.85,
        category="memory",
        explanation=(
            f"A hard page fault is a memory read that missed and had to go to "
            f"the disk instead. The machine is taking {average:.0f} of them "
            f"every second, led by {_name_of(top)} at {top_rate:.0f}/s. Each "
            f"one stops the faulting thread until the disk answers, so this "
            f"is the mechanism that turns 'low on RAM' into 'the mouse "
            f"stutters and windows go white'. The disk being busy is a "
            f"consequence here, not the cause — replacing the drive would not "
            f"help, and freeing memory would."),
        evidence=evidence, fixes=fixes, pid=top.pid, process=top.name)]


def _rule_system_stalls(history: History, sample: Sample) -> list[Finding]:
    """Time the machine owed us and did not deliver."""
    stalls = list(history.stalls)
    if not stalls:
        return []
    recent = stalls[-6:]
    worst = max(recent, key=lambda s: s["lateness"])

    evidence = [
        f"{len(stalls)} stall(s) recorded since monitoring started",
        f"worst: {worst['lateness']:.1f}s of unscheduled time, with CPU at "
        f"{worst['cpu']:.0f}%, RAM {worst['memory_percent']:.0f}% used, disk "
        f"{worst['disk_busy']:.0f}% busy, {worst['hard_faults']:.0f} hard "
        f"faults/s",
    ]
    for stall in recent[-3:]:
        names = ", ".join(f"{s['name']}({s['pid']})"
                          for s in stall["suspects"][:3])
        evidence.append(f"stall of {stall['lateness']:.1f}s — busiest at the "
                        f"time: {names}")

    # Attribute the stalls, using what was true at the moment they happened.
    paging = sum(1 for s in recent if s["hard_faults"] > PAGING_STORM_FAULTS)
    disk = sum(1 for s in recent if s["disk_busy"] > DISK_SATURATED)
    cpu = sum(1 for s in recent if s["cpu"] > HIGH_CPU_TOTAL)
    if paging >= len(recent) / 2:
        cause = ("memory pressure — hard faults were high during the stalls, "
                 "so the machine was waiting on the page file")
    elif disk >= len(recent) / 2:
        cause = ("the disk — it was saturated during the stalls, so everything "
                 "was queued behind it")
    elif cpu >= len(recent) / 2:
        cause = "the CPU being fully committed, leaving nothing for the desktop"
    else:
        cause = ("something that blocks without showing up as load — most "
                 "often a driver, an antivirus filter, or a network path that "
                 "is not answering. The CPU, memory and disk were all "
                 "unremarkable while the machine was unresponsive, which rules "
                 "out the usual suspects and points at a kernel-level wait")

    return [Finding(
        id="system-stall",
        title=f"The whole machine stalled {len(stalls)} time(s), worst "
              f"{worst['lateness']:.1f}s",
        severity=4 if worst["lateness"] > 5 else 3,
        confidence=0.9,
        category="freeze",
        explanation=(
            f"This monitor asks the operating system to wake it once a "
            f"second. During these events it was woken up to "
            f"{worst['lateness']:.1f} seconds late, which means Windows was "
            f"not running it at all for that long — and it was not running "
            f"your keyboard, mouse or foreground window either. This is a "
            f"measured freeze rather than an inferred one. The evidence "
            f"points at {cause}."),
        evidence=evidence)]


def _rule_runaway_cpu(history: History, sample: Sample) -> list[Finding]:
    findings = []
    for row in sample.by_cpu(6):
        average = history.sustained(row.pid, "cpu", 30)
        if average < RUNAWAY_CPU or history.count < 10:
            continue
        kernel = history.sustained(row.pid, "cpu_kernel", 30)
        fact = knowledge.lookup(row.name)
        in_kernel = kernel > average * 0.6

        explanation = (
            f"{_name_of(row)} has held {average:.0f}% of this machine's total "
            f"CPU capacity across the last {min(30, history.count)} "
            f"samples. Sustained load like that is not a task finishing; it "
            f"is a loop.")
        if in_kernel:
            explanation += (
                f" Most of it ({kernel:.0f}%) is kernel time rather than the "
                f"application's own code, which means it is being spent in "
                f"system calls — file or network I/O, or a driver — rather "
                f"than in computation. That usually points at what the app is "
                f"being made to do rather than at a bug in its own logic.")
        if fact and fact.common_causes:
            explanation += (" The usual causes for this program are: "
                            + "; ".join(fact.common_causes[:3]) + ".")

        fixes = list(fact.fixes) if fact else []
        if not fixes and row.name.lower() in knowledge.AMBIGUOUS:
            fixes.append(Fix(
                "Find out what this process is actually running",
                "The executable name is a container, not an identity — the "
                "command line names the real workload.",
                f"wmic process where ProcessId={row.pid} get CommandLine"))
        if knowledge.is_killable(row.name):
            fixes.append(Fix(
                f"Restart {fact.display if fact else row.name}",
                "A restart clears a runaway loop immediately and is usually "
                "cheaper than diagnosing it.",
                f"taskkill /f /pid {row.pid}", risk="medium"))

        findings.append(Finding(
            id=f"cpu:{row.pid}",
            title=f"{fact.display if fact else row.name} is using "
                  f"{average:.0f}% CPU continuously",
            severity=4 if average > 50 else 3,
            confidence=0.85,
            category="cpu",
            explanation=explanation,
            evidence=[
                f"sustained {average:.1f}% of total CPU "
                f"({kernel:.1f}% of it kernel time)",
                f"peak in window: {max((s.find(row.pid).cpu for s in history.samples if s.find(row.pid)), default=0):.1f}%",
                f"{row.threads} threads, {_mb(row.memory)} working set",
            ],
            fixes=fixes, pid=row.pid, process=row.name,
            unknown_subject="" if fact else row.name))
    return findings


def _rule_disk_saturation(history: History, sample: Sample) -> list[Finding]:
    """The disk is making applications wait.

    Judged on how long each operation takes, not on how busy the drive looks.
    Percent-busy is a spinning-disk measure: an NVMe swallowing 120 MB/s
    reports under 1%, so a saturation check built on it never fires on modern
    hardware — which is exactly what fault injection showed. Service time is
    both reachable and closer to the thing that hurts, because it is literally
    the time an application spends stopped.
    """
    if history.count < 10:
        return []
    latency = history.average("disk_latency_ms", 30)
    busy = history.average("disk_busy", 30)
    slow = latency >= DISK_SLOW_MS
    if not slow and busy < DISK_SATURATED:
        return []

    culprits = [(row, history.sustained(row.pid, "io_bps", 30))
                for row in sample.by_io(5)]
    culprits = [(row, rate) for row, rate in culprits if rate > 1e6]
    top, top_rate = culprits[0] if culprits else (None, 0.0)
    fact = knowledge.lookup(top.name) if top is not None else None

    severe = latency >= DISK_VERY_SLOW_MS or busy > 92
    if slow:
        title = (f"The drive is taking {latency:.0f} ms per operation")
        explanation = (
            f"Every read or write is taking {latency:.0f} milliseconds on "
            f"average, against well under one for a healthy solid-state drive "
            f"and about ten for a spinning one under load. That time is not "
            f"spent anywhere clever — it is an application stopped, waiting, "
            f"and it is why the machine can feel frozen while the processor "
            f"graph sits near nothing. Sustained figures this high mean the "
            f"drive is either overwhelmed, throttling, or failing requests "
            f"and retrying them.")
    else:
        title = f"The disk is saturated ({busy:.0f}% busy)"
        explanation = (
            f"The drive has had work outstanding {busy:.0f}% of the time, so "
            f"every new request queues behind the ones already in flight and "
            f"opening a menu waits for I/O it has nothing to do with.")
    if top is not None:
        explanation += (f" {_name_of(top)} is generating the most traffic, at "
                        f"{top_rate / 1e6:.1f} MB/s.")

    evidence = [
        f"average service time {latency:.1f} ms per operation over "
        f"{min(30, history.count)} samples",
        f"{history.average('disk_ops', 30):,.0f} operations/s, disk busy "
        f"{busy:.1f}%",
        f"read {history.average('disk_read_bps', 30) / 1e6:.1f} MB/s, "
        f"write {history.average('disk_write_bps', 30) / 1e6:.1f} MB/s",
    ]
    evidence += [f"{_name_of(row)}: {rate / 1e6:.1f} MB/s"
                 for row, rate in culprits]

    fixes = (list(fact.fixes) if fact else [])
    if slow:
        fixes.append(Fix(
            "Check the drive's health before blaming an application",
            "Service times like this are as often a drive retrying failed "
            "operations as they are genuine load. SMART data settles it.",
            "wmic diskdrive get model,status"))
    fixes.append(Fix(
        "Let it finish if it is a one-off",
        "Backups, sync catch-ups and indexing are supposed to be heavy; they "
        "are only a problem if they never end."))

    return [Finding(
        id="disk-saturated", title=title,
        severity=4 if severe else 3, confidence=0.8, category="disk",
        explanation=explanation, evidence=evidence, fixes=fixes,
        pid=top.pid if top is not None else 0,
        process=top.name if top is not None else "")]


def _rule_duplicate_antivirus(history: History, sample: Sample) -> list[Finding]:
    """Two real-time scanners is a self-inflicted wound worth naming."""
    vendors: dict[str, list[ProcRow]] = {}
    for row in sample.processes:
        vendor = knowledge.av_vendor(row.name)
        if vendor:
            vendors.setdefault(vendor.split("/")[0], []).append(row)
    if len(vendors) < 2:
        return []

    total_cpu = sum(history.sustained(row.pid, "cpu", 30)
                    for rows in vendors.values() for row in rows)
    evidence = []
    for vendor, rows in vendors.items():
        cpu = sum(history.sustained(row.pid, "cpu", 30) for row in rows)
        memory = sum(row.memory for row in rows)
        evidence.append(f"{vendor}: {len(rows)} process(es), {cpu:.1f}% CPU "
                        f"sustained, {_mb(memory)}")

    return [Finding(
        id="duplicate-av",
        title=f"{len(vendors)} real-time security products are running at once",
        severity=4,
        confidence=0.9,
        category="security",
        explanation=(
            f"{' and '.join(vendors)} are all inspecting file and process "
            f"activity in real time. They do not co-operate: every file your "
            f"applications open is inspected once by each, and each scanner's "
            f"own reads are then inspected by the other. The result is that "
            f"ordinary file work costs several times what it should, which "
            f"shows up as slow application launches, slow saves, and long "
            f"pauses in anything that touches many small files. This is one "
            f"of the largest and most common self-inflicted slowdowns on a "
            f"managed Windows machine, and it does not make it safer — "
            f"overlapping scanners routinely quarantine each other."),
        evidence=evidence + [f"combined sustained CPU: {total_cpu:.1f}%"],
        fixes=[
            Fix("Keep one, remove the other",
                "Decide which product is the managed one — usually the EDR "
                "agent your IT provider deployed — and uninstall the other "
                "rather than merely disabling it. A disabled scanner often "
                "leaves its filter driver loaded, which keeps most of the "
                "cost.", risk="high", admin=True),
            Fix("If both must stay, exclude each from the other",
                "Add each product's install directory and processes to the "
                "other's exclusion list. This recovers much of the loss "
                "without changing what is deployed.",
                risk="high", admin=True)])]


def _rule_lock_contention(history: History, sample: Sample) -> list[Finding]:
    findings = []
    for row in sample.processes:
        stuck = row.waits.buckets.get("lock", 0)
        if stuck < 2 or row.waits.total < 2:
            continue
        # Confirm it persists — a lock held for one sample is normal.
        persistent = sum(
            1 for s in history.recent(15)
            if (r := s.find(row.pid)) and r.waits.buckets.get("lock", 0) >= 2)
        if persistent < 8:
            continue
        fact = knowledge.lookup(row.name)
        findings.append(Finding(
            id=f"lock:{row.pid}",
            title=f"{fact.display if fact else row.name} appears deadlocked",
            severity=4,
            confidence=0.7,
            category="freeze",
            explanation=(
                f"{_name_of(row)} has had {stuck} of its {row.waits.total} "
                f"threads blocked on internal locks for {persistent} of the "
                f"last 15 samples. A lock held this long is not contention, "
                f"it is a thread that is never going to let go — the classic "
                f"shape of a deadlock. Unlike a busy application, this will "
                f"not recover on its own no matter how long you wait, because "
                f"nothing in the process is making progress."),
            evidence=[f"{stuck} threads blocked on locks, persistent across "
                      f"{persistent}/15 samples",
                      f"CPU {history.sustained(row.pid, 'cpu', 15):.1f}% "
                      f"— near zero, as expected for a deadlock",
                      f"{row.threads} threads total"],
            fixes=([Fix(f"Force {row.name} to close",
                        "A deadlocked process cannot be recovered; unsaved "
                        "work is already lost.",
                        f"taskkill /f /pid {row.pid}", risk="medium")]
                   if knowledge.is_killable(row.name) else []),
            pid=row.pid, process=row.name))
    return findings[:3]


def _rule_blocked_on_other_process(history: History,
                                   sample: Sample) -> list[Finding]:
    """Victims: processes stuck calling something else that is not answering."""
    hung_pids = {w.pid for w in sample.hung_windows}
    findings = []
    for row in sample.processes:
        stuck = row.waits.buckets.get("ipc", 0)
        if stuck < 3 or row.pid in hung_pids:
            continue
        persistent = sum(
            1 for s in history.recent(15)
            if (r := s.find(row.pid)) and r.waits.buckets.get("ipc", 0) >= 3)
        if persistent < 10:
            continue
        if knowledge.is_essential(row.name) and stuck < row.waits.total / 2:
            continue    # csrss always has a few; only care when it is most

        blockers = [sample.find(p) for p in hung_pids]
        blockers = [b for b in blockers if b is not None]
        pointer = ""
        if blockers:
            pointer = (f" The likeliest thing it is waiting for is "
                       f"{_name_of(blockers[0])}, which is itself not "
                       f"responding.")

        fact = knowledge.lookup(row.name)
        findings.append(Finding(
            id=f"ipc:{row.pid}",
            title=f"{fact.display if fact else row.name} is blocked waiting "
                  f"on another process",
            severity=3, confidence=0.6, category="freeze",
            explanation=(
                f"{_name_of(row)} has {stuck} threads parked in cross-process "
                f"calls, sustained across {persistent} of the last 15 samples. "
                f"It is a victim rather than a cause: it is waiting for a "
                f"reply that is not coming.{pointer} Fixing this process "
                f"itself would achieve nothing — the thing it is calling is "
                f"what needs attention."),
            evidence=[f"{stuck} of {row.waits.total} threads in cross-process "
                      f"waits", f"persistent across {persistent}/15 samples",
                      f"CPU {history.sustained(row.pid, 'cpu', 15):.1f}%"],
            fixes=list(fact.fixes[:2]) if fact else [],
            pid=row.pid, process=row.name))
    return findings[:3]


def _rule_gdi_leak(history: History, sample: Sample) -> list[Finding]:
    findings = []
    for row in sample.processes:
        worst = max(row.gdi, row.user_objects)
        if worst < GDI_WARN:
            continue
        kind = "GDI" if row.gdi >= row.user_objects else "USER"
        growth = _growth(history, row.pid, "gdi" if kind == "GDI" else "user_objects")
        fact = knowledge.lookup(row.name)
        critical = worst > GDI_CRITICAL

        findings.append(Finding(
            id=f"gdi:{row.pid}",
            title=f"{fact.display if fact else row.name} is close to the "
                  f"{kind} object limit ({worst:,} of 10,000)",
            severity=5 if critical else 3,
            confidence=0.85,
            category="handles",
            explanation=(
                f"Windows allows each process 10,000 {kind} objects — the "
                f"handles behind every window, font, bitmap and pen it draws "
                f"with. {_name_of(row)} is holding {worst:,}. A program that "
                f"climbs towards this ceiling is failing to release what it "
                f"draws with, and the last stretch before the limit is where "
                f"the visible damage happens: menus render blank, controls "
                f"stop painting, and the application eventually fails to "
                f"create a window at all and either freezes or dies. It looks "
                f"like a graphics or memory problem and is neither — no "
                f"ordinary task manager column shows this number."),
            evidence=[f"GDI objects: {row.gdi:,}",
                      f"USER objects: {row.user_objects:,}",
                      (f"growth over the monitored window: {growth:+,.0f}"
                       if abs(growth) > 20 else "count is stable for now")],
            fixes=[Fix(f"Restart {fact.display if fact else row.name}",
                       "The count resets to nothing on restart. This is the "
                       "only cure available from outside the program — the "
                       "leak itself is a bug in the application.",
                       f"taskkill /f /pid {row.pid}" if knowledge.is_killable(row.name) else "",
                       risk="medium")]
                  + (list(fact.fixes[:1]) if fact else []),
            pid=row.pid, process=row.name))
    return sorted(findings, key=lambda f: f.sort_key())[:3]


def _rule_handle_leak(history: History, sample: Sample) -> list[Finding]:
    findings = []
    for row in sorted(sample.processes, key=lambda r: -r.handles)[:5]:
        if row.handles < HANDLE_WARN:
            continue
        growth = _growth(history, row.pid, "handles")
        if growth < 200 and row.handles < HANDLE_WARN * 2:
            continue
        fact = knowledge.lookup(row.name)
        findings.append(Finding(
            id=f"handles:{row.pid}",
            title=f"{fact.display if fact else row.name} is holding "
                  f"{row.handles:,} handles",
            severity=3 if growth > 200 else 2,
            confidence=0.65,
            category="handles",
            explanation=(
                f"{_name_of(row)} has {row.handles:,} open kernel handles"
                + (f", and the count grew by {growth:,.0f} while this was "
                   f"monitoring" if growth > 200 else "") +
                ". Handles are files, registry keys, events and sockets the "
                "process has opened. A steadily climbing count means it is "
                "opening things and never closing them, which consumes kernel "
                "memory that is never returned and slowly degrades the whole "
                "machine rather than just this application — the symptom is a "
                "PC that is fine after a reboot and unbearable by the end of "
                "the day."),
            evidence=[f"{row.handles:,} handles",
                      f"growth while monitored: {growth:+,.0f}",
                      f"{row.threads} threads, {_mb(row.memory)} working set"],
            fixes=[Fix(f"Restart {fact.display if fact else row.name} to "
                       f"reclaim them",
                       "Handles are released when the process exits.",
                       f"taskkill /f /pid {row.pid}" if knowledge.is_killable(row.name) else "",
                       risk="medium")],
            pid=row.pid, process=row.name))
    return findings[:2]


def _rule_thread_explosion(history: History, sample: Sample) -> list[Finding]:
    findings = []
    for row in sorted(sample.processes, key=lambda r: -r.threads)[:5]:
        if row.threads < THREAD_WARN:
            continue
        # The kernel and its compression worker run hundreds of pooled threads
        # by design — one per CPU for several subsystems. Counting that as a
        # leak means reporting "System has 422 threads" on every healthy
        # Windows machine ever booted.
        if row.pid == 4 or row.name.lower() in ("memory compression",
                                                "memcompression", "registry"):
            continue
        growth = _growth(history, row.pid, "threads")
        fact = knowledge.lookup(row.name)
        findings.append(Finding(
            id=f"threads:{row.pid}",
            title=f"{fact.display if fact else row.name} has {row.threads} "
                  f"threads",
            severity=3 if growth > 20 else 2,
            confidence=0.6,
            category="threads",
            explanation=(
                f"{_name_of(row)} is running {row.threads} threads"
                + (f", up {growth:.0f} while this was monitoring" if growth > 20
                   else "") +
                f". Each one reserves a megabyte of stack address space and "
                f"has to be considered by the scheduler. A count this high "
                f"for one process usually means a thread pool that keeps "
                f"growing because its work is not completing — threads are "
                f"being added to handle a backlog that never clears, which is "
                f"a symptom of blocking rather than of load. It also makes "
                f"the process progressively slower to do anything, because "
                f"the scheduler is spending its time switching between "
                f"threads that are all waiting."),
            evidence=[f"{row.threads} threads "
                      f"({row.waits.running} running, {row.waits.ready} ready, "
                      f"{row.waits.benign} idle, {row.waits.stuck} blocked)",
                      f"growth while monitored: {growth:+.0f}",
                      f"handles: {row.handles:,}",
                      (row.waits.describe() or "no pathological waits")],
            fixes=([Fix(f"Restart {fact.display if fact else row.name}",
                        "Thread counts reset on restart.",
                        f"taskkill /f /im {row.name}" if row.name.lower() != "explorer.exe"
                        else "taskkill /f /im explorer.exe & start explorer.exe",
                        risk="medium")]
                   if knowledge.is_killable(row.name) else [])
                  + (list(fact.fixes[:2]) if fact else []),
            pid=row.pid, process=row.name))
    return findings[:2]


def _rule_memory_leak(history: History, sample: Sample) -> list[Finding]:
    if history.count < 60:
        return []       # a leak claim needs a real window to stand on
    findings = []
    for row in sorted(sample.processes, key=lambda r: -r.private)[:8]:
        growth = _growth(history, row.pid, "private")
        if growth < LEAK_GROWTH_BYTES:
            continue
        minutes = (history.count * sample.interval) / 60 or 1
        fact = knowledge.lookup(row.name)
        findings.append(Finding(
            id=f"leak:{row.pid}",
            title=f"{fact.display if fact else row.name} grew "
                  f"{_mb(growth)} while being watched",
            severity=3, confidence=0.6, category="memory",
            explanation=(
                f"{_name_of(row)} has added {_mb(growth)} of private memory "
                f"over about {minutes:.0f} minutes, and is now holding "
                f"{_gb(row.private)}. Private memory is memory only this "
                f"process can use, so it cannot be shared away or trimmed by "
                f"Windows — growth that does not level off is the signature "
                f"of a leak. Extrapolated, this is what turns a machine that "
                f"is fine in the morning into one that pages constantly by "
                f"the afternoon."),
            evidence=[f"private bytes now: {_gb(row.private)}",
                      f"growth over the window: +{_mb(growth)} in "
                      f"{minutes:.0f} minutes",
                      f"working set: {_gb(row.memory)}"],
            fixes=[Fix(f"Restart {fact.display if fact else row.name} "
                       f"periodically",
                       "Until the underlying bug is fixed, restarting is the "
                       "only way to return the memory.",
                       f"taskkill /f /pid {row.pid}" if knowledge.is_killable(row.name) else "",
                       risk="medium")]
                  + (list(fact.fixes[:2]) if fact else []),
            pid=row.pid, process=row.name))
    return findings[:2]


def _rule_kernel_pool(history: History, sample: Sample) -> list[Finding]:
    waiting = [row for row in sample.processes
               if row.waits.buckets.get("pool", 0) > 0]
    if not waiting:
        return []
    return [Finding(
        id="kernel-pool",
        title="Processes are waiting for kernel memory",
        severity=5, confidence=0.75, category="memory",
        explanation=(
            "Threads are blocked waiting for kernel pool memory to become "
            "available. This is a different and more serious shortage than "
            "running low on RAM: the pool is where drivers and the kernel "
            "keep their own bookkeeping, it is small, and it cannot be paged "
            "out. When it runs dry the machine does not merely slow down — "
            "drivers start failing allocations, and the usual outcome is a "
            "hang or a bugcheck. The most common cause is a driver leaking "
            "pool allocations, which builds up over days of uptime."),
        evidence=[f"{len(waiting)} process(es) with threads waiting on pool "
                  f"allocation"]
                 + [f"{_name_of(row)}: {row.waits.buckets['pool']} threads"
                    for row in waiting[:5]],
        fixes=[Fix("Find the leaking pool tag",
                   "Enable pool tagging and compare tags over time; the tag "
                   "that keeps growing identifies the driver.",
                   "poolmon.exe", risk="medium", admin=True),
               Fix("Reboot to clear it, then watch uptime",
                   "If the problem returns after a predictable number of days "
                   "of uptime, it is a leak rather than a load spike.",
                   risk="medium")])]


def _rule_cpu_starvation(history: History, sample: Sample) -> list[Finding]:
    ready = history.average("ready_threads", 30)
    if ready < STARVED_READY_THREADS or history.count < 15:
        return []
    cpu = history.average("cpu", 30)
    top = sample.by_cpu(3)
    return [Finding(
        id="cpu-starvation",
        title=f"Threads are queuing for the CPU ({ready:.0f} waiting on "
              f"average)",
        severity=3, confidence=0.7, category="cpu",
        explanation=(
            f"On average {ready:.0f} threads are ready to run but cannot get "
            f"a processor, with the CPU at {cpu:.0f}%. A ready thread is one "
            f"that has work to do right now and is being made to wait, so "
            f"this is the queue that turns into visible lag: the click has "
            f"registered, the application has been told, and it is waiting "
            f"its turn. Adding more work will not slow the machine down "
            f"gracefully from here — it goes straight to stuttering."),
        evidence=[f"{ready:.1f} ready threads on average over "
                  f"{min(30, history.count)} samples",
                  f"CPU {cpu:.0f}% average, peak "
                  f"{history.peak('cpu', 60):.0f}%",
                  f"context switches: "
                  f"{history.average('context_switches', 30):,.0f}/s"]
                 + [f"{_name_of(row)}: "
                    f"{history.sustained(row.pid, 'cpu', 30):.1f}%"
                    for row in top],
        fixes=[Fix("Close or deprioritise the biggest consumer",
                   "The processes above are what the queue is waiting "
                   "behind."),
               Fix("Check for CPU throttling",
                   "If the CPU is not actually at 100% but threads still "
                   "queue, the processor may be thermally or power throttled "
                   "— check the power plan and the cooling.",
                   "powercfg /list")])]


def _rule_driver_waits(history: History, sample: Sample) -> list[Finding]:
    """The System process is where driver misbehaviour becomes visible."""
    system = next((r for r in sample.processes if r.pid == 4), None)
    if system is None:
        return []
    kernel_waits = system.waits.buckets.get("kernel", 0)
    paging_waits = system.waits.buckets.get("paging", 0)
    cpu = history.sustained(4, "cpu", 30)
    faults = history.average("hard_faults", 30)
    # Kernel worker threads park in Executive waits when they have nothing to
    # do, so a high count on its own means "the machine is on" rather than
    # "the machine is ill".  Only report paging backlog when the machine is
    # actually paging, and only report CPU when it is genuinely elevated.
    paging_real = paging_waits >= 20 and (faults > 50 or
                                          sample.memory_percent > 85)
    if cpu < 8 and not paging_real:
        return []

    return [Finding(
        id="driver-waits",
        title=("Kernel threads are backed up on paging"
               if paging_real else
               f"The kernel is using {cpu:.0f}% CPU"),
        severity=3, confidence=0.6, category="driver",
        explanation=(
            f"The System process holds the kernel's own threads and every "
            f"driver's worker threads. It currently has {kernel_waits} "
            f"threads inside driver calls and {paging_waits} waiting on "
            f"paging, at {cpu:.1f}% CPU. Time here is not attributable to any "
            f"application — it belongs to a driver. When it is paging-related "
            f"it is the memory shortage showing up in the kernel; when it is "
            f"steady CPU with no memory pressure, it is usually a storage, "
            f"network or security filter driver doing more work than it "
            f"should."),
        evidence=[f"System process CPU: {cpu:.1f}% sustained",
                  f"{kernel_waits} threads in driver/kernel calls",
                  f"{paging_waits} threads waiting on paging",
                  f"machine-wide hard faults: "
                  f"{history.average('hard_faults', 30):.0f}/s"],
        fixes=[Fix("List drivers and their dates",
                   "A driver updated just before the trouble started is the "
                   "first suspect.", "driverquery /v /fo table"),
               Fix("Check storage health",
                   "A drive retrying failed reads produces exactly this "
                   "pattern.", "wmic diskdrive get model,status", risk="low")],
        pid=4, process="System")]
