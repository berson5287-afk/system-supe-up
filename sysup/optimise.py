"""What could be *better* on this machine, as opposed to what is broken.

`rules.py` answers "why did it freeze". That is the right question when
something is wrong, and the wrong one when the answer is "nothing is wrong,
it is just slower than it needs to be" -- a machine can pass every rule and
still be carrying three real-time scanners, seventeen sign-in programs and a
storage controller configured to put the drive to sleep between requests.

So this is a second engine over the same evidence, asking a different
question. It obeys the same two house rules as the rest of the tool:

* **The model still detects nothing.** Every opportunity below is a measured
  or read state -- a registry value, a service start type, an event count, a
  process list. The model's job afterwards is to put them in order and explain
  the trade-offs, exactly as it does for findings.
* **Nothing here runs itself.** An opportunity names a catalogue action and
  its parameters, and stops. Approval, preview and undo are the fix dialog's
  job, unchanged.

The other deliberate difference from `rules.py` is that an opportunity carries
an **expected gain**, not a severity. "This machine has a problem of severity
4" does not help anyone choose what to do on a Tuesday afternoon; "this one
change is worth more than the other six put together" does. Gain is a coarse
0-100 score and is meant to be read as an ordering, not as a percentage of
anything.

The scan is honest about what it cannot automate. On the machine this was
written against, the single largest win is fitting more memory, and the second
is removing two of three antivirus products -- neither of which is a button,
and both of which are reported anyway with the evidence attached, because a
tune-up that only lists what it happens to be able to click is a tune-up that
lies by omission.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import actions as actions_mod, knowledge, sysinfo
from .bridge import bridge
from .collect import Sample

Progress = Callable[[str], None]

#: Gain bands. Large means it is worth doing before the others and will be
#: felt; small means it is tidying. The numbers exist to sort by.
LARGE = 80
GOOD = 55
MODERATE = 35
SMALL = 15

#: Below this fraction of RAM free, memory is the machine's binding constraint
#: and anything that returns memory outranks anything that does not.
TIGHT_MEMORY = 0.20

#: Sign-in programs above this many is worth raising on its own.
STARTUP_BUSY = 12

#: Days of uptime after which a restart is a real remedy rather than folklore.
LONG_UPTIME_DAYS = 10.0


@dataclass
class Opportunity:
    """One change worth making, with the evidence that says so."""

    id: str
    title: str
    #: What it does and what it costs, in the words the user will read.
    detail: str
    #: 0-100. An ordering, not a percentage -- see the module docstring.
    gain: int
    #: "instant" (seconds, no restart), "quick" (a minute, maybe a restart),
    #: "planned" (needs a decision, a purchase, or somebody else's approval).
    effort: str
    category: str
    evidence: list[str] = field(default_factory=list)
    #: A catalogue action id, or "" when the remedy is not something this tool
    #: can do. Never a command.
    action_id: str = ""
    action_params: dict = field(default_factory=dict)
    #: Steps only a person can take. Present precisely when `action_id` is not.
    manual_steps: list[str] = field(default_factory=list)
    #: What to look at afterwards to know whether it worked.
    verify: str = ""

    @property
    def gain_label(self) -> str:
        if self.gain >= LARGE:
            return "large"
        if self.gain >= GOOD:
            return "good"
        if self.gain >= MODERATE:
            return "moderate"
        return "small"

    @property
    def automatable(self) -> bool:
        return bool(self.action_id)

    def sort_key(self) -> tuple:
        # Automatable ties break towards the button, because between two
        # equally valuable changes the one that can be done now is worth more
        # than the one that needs a conversation.
        return (-self.gain, 0 if self.automatable else 1, self.id)


@dataclass
class TuneUp:
    at: float = field(default_factory=time.time)
    opportunities: list[Opportunity] = field(default_factory=list)
    #: Probes that could not be read, so the report can say "not checked"
    #: rather than implying a clean result.
    unavailable: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def automatable(self) -> list[Opportunity]:
        return [o for o in self.opportunities if o.automatable]

    @property
    def manual(self) -> list[Opportunity]:
        return [o for o in self.opportunities if not o.automatable]

    def headline(self) -> str:
        if not self.opportunities:
            return "Nothing worth changing was found."
        return self.opportunities[0].title


# ----------------------------------------------------------------- probes
# Each returns plain data and swallows its own failures, because a machine
# where one registry read is refused should still get the other checks.

#: Never proposed for removal from sign-in, whatever else they look like.
#: `SecurityHealthSystray` matches the "tray" heuristic below perfectly and is
#: Windows Security's own indicator; a tune-up that quietly turns off the
#: thing that tells you your antivirus has stopped is not a tune-up. The same
#: goes for the management agents on a corporate machine, which are not the
#: user's to disable.
STARTUP_UNTOUCHABLE = (
    "securityhealth", "sentinel", "avg", "avast", "defender", "malwarebytes",
    "huntress", "ninja", "screenconnect", "sophos", "crowdstrike", "webroot",
    "bitdefender", "eset", "trend", "mcafee", "symantec", "carbonblack")


def _startup_weight(item: sysinfo.StartupItem) -> int:
    """How much a sign-in entry is likely costing, 0-3.

    Updaters and vendor helpers are the ones worth removing: they exist to
    check for a new version once, and then stay resident all day.
    """
    text = f"{item.name} {item.command}".lower()
    if any(word in text for word in STARTUP_UNTOUCHABLE):
        return 0
    if any(word in text for word in
           ("update", "updater", "helper", "assistant", "launcher", "sync",
            "cloud", "tray", "notifier", "reminder", "webhelper")):
        return 3
    if any(word in text for word in ("onedrive", "teams", "spotify", "steam",
                                     "discord", "adobe", "java", "quickset")):
        return 2
    return 1


def _antivirus_vendors(sample: Sample) -> dict[str, list]:
    vendors: dict[str, list] = {}
    for row in sample.processes:
        vendor = knowledge.av_vendor(row.name)
        if vendor:
            vendors.setdefault(vendor.split("/")[0], []).append(row)
    return vendors


def _storage_reset_events(facts: sysinfo.MachineFacts) -> list:
    return [event for event in facts.events
            if event.event_id in (129, 153, 51, 7, 11)
            and any(name in event.source.lower()
                    for name in ("iastor", "storahci", "stornvme", "disk",
                                 "ntfs", "storport"))]


# ------------------------------------------------------------------- scan

def scan(sample: Sample | None, facts: sysinfo.MachineFacts | None = None,
         on_progress: Progress | None = None) -> TuneUp:
    """Everything worth changing on this machine, best first.  Never raises."""
    say = on_progress or (lambda _m: None)
    feed = bridge()
    started = time.perf_counter()
    result = TuneUp()
    if facts is None:
        say("reading machine configuration")
        facts = sysinfo.gather()
    feed.emit("optimise.begin",
              processes=len(sample.processes) if sample else 0,
              events=len(facts.events))

    for name, probe in (
            ("memory", _memory_opportunities),
            ("security software", _antivirus_opportunity),
            ("storage", _storage_opportunities),
            ("services", _service_opportunities),
            ("sign-in programs", _startup_opportunity),
            ("power", _power_opportunity),
            ("housekeeping", _housekeeping_opportunities),
            ("uptime", _uptime_opportunity)):
        say(f"checking {name}")
        try:
            produced = probe(sample, facts) or []
        except Exception as error:
            # One refused registry read must not cost the other seven checks.
            result.unavailable.append(f"{name} ({type(error).__name__})")
            feed.emit("optimise.probe_failed", probe=name,
                      error=f"{type(error).__name__}: {error}"[:200])
            continue
        for opportunity in produced:
            feed.emit("opportunity", id=opportunity.id, gain=opportunity.gain,
                      title=opportunity.title, effort=opportunity.effort,
                      action=opportunity.action_id or "manual")
        result.opportunities.extend(produced)

    result.opportunities.sort(key=lambda o: o.sort_key())
    result.duration_s = time.perf_counter() - started
    feed.emit("optimise.end", count=len(result.opportunities),
              automatable=len(result.automatable),
              duration_s=round(result.duration_s, 2),
              order=[o.id for o in result.opportunities])
    return result


# ------------------------------------------------------------------ memory

def _memory_opportunities(sample: Sample | None,
                          facts: sysinfo.MachineFacts) -> list[Opportunity]:
    out: list[Opportunity] = []
    if sample is None or not sample.memory_total:
        return out
    free_fraction = sample.memory_available / sample.memory_total
    tight = free_fraction < TIGHT_MEMORY

    # Memory compression first, because on a machine that is paging it is the
    # only change here that reduces hard faults without anybody giving
    # anything up.
    compression = actions_mod.memory_compression()
    if compression is False:
        out.append(Opportunity(
            id="memory-compression",
            title="Memory compression is switched off",
            detail=(
                "Windows can compress a page of memory instead of writing it "
                "out to the page file. Compressing takes microseconds and "
                "paging takes milliseconds, so with compression off this "
                "machine is doing the slow one every time it runs short. "
                "Turning it on trades a little CPU -- which this machine has "
                "-- for fewer of the hard page faults that cause the pauses."),
            gain=LARGE if tight else MODERATE,
            effort="instant", category="memory",
            evidence=[
                "Get-MMAgent reports MemoryCompression: False",
                f"{sample.memory_available / 1e9:.1f} GB available of "
                f"{sample.memory_total / 1e9:.1f} GB "
                f"({free_fraction * 100:.0f}% free)",
                f"hard page faults running at {sample.hard_faults:.0f}/s"],
            action_id="set_memory_compression",
            action_params={"enabled": True},
            verify="Task Manager > Performance > Memory shows a 'Compressed' "
                   "figure, and the hard-fault gauge in this tool settles."))
    elif compression is None:
        out.append(Opportunity(
            id="memory-compression-unknown",
            title="Could not read whether memory compression is on",
            detail="Get-MMAgent did not answer, so this check was skipped "
                   "rather than passed.",
            gain=SMALL, effort="instant", category="memory",
            manual_steps=["Run 'Get-MMAgent' in an administrator PowerShell "
                          "and check MemoryCompression."]))

    if not tight:
        return out

    # The honest answer, which is not a button. Kept above the tidying-up
    # items deliberately: proposing to free 200 MB while the machine is 4 GB
    # short is the failure mode this whole section exists to avoid.
    slots = sysinfo.memory_slots()
    wanted = int(sample.memory_total * 2)
    advice = slots.upgrade_advice(wanted) if slots.installed else ""
    if advice:
        out.append(Opportunity(
            id="fit-more-memory",
            title="This machine needs more memory, and has room for it",
            detail=(
                f"{advice} Nothing else in this list changes the fact that "
                f"the work actually open on this machine does not fit in the "
                f"memory fitted. Everything else here buys hundreds of "
                f"megabytes; this buys tens of gigabytes and is the only "
                f"change that ends the problem rather than deferring it."),
            gain=100, effort="planned", category="memory",
            evidence=[
                slots.describe(),
                f"{sample.memory_available / 1e9:.1f} GB available of "
                f"{sample.memory_total / 1e9:.1f} GB",
                f"{sample.commit_total / 1e9:.1f} GB committed against a "
                f"{sample.commit_limit / 1e9:.1f} GB limit"
                if sample.commit_limit else ""],
            manual_steps=[
                f"Fit memory into the free slots: "
                f"{slots.describe()} today. Match the speed already fitted, "
                f"and buy the two sticks as a pair.",
                "Everything else in this list is worth doing anyway, but "
                "treat it as buying time rather than as a substitute."],
            verify="Available memory stops sitting near zero, and the "
                   "hard-fault gauge stays low under the same workload."))

    # Model weights held in RAM by an idle Ollama server are the one large
    # reclaim that costs nothing at all -- they reload on the next request.
    ollama = [row for row in sample.processes
              if row.name.lower().startswith("ollama")]
    resident = sum(row.memory for row in ollama)
    if resident > 1.5e9:
        out.append(Opportunity(
            id="unload-models",
            title=f"Ollama is holding {resident / 1e9:.1f} GB of model weights",
            detail=(
                "A local model server keeps the weights of whatever it last "
                "ran resident so the next request is fast. On a machine that "
                "is short of memory that is a poor trade while nothing is "
                "using it -- unloading returns the memory now and costs a few "
                "seconds the next time a model is asked something."),
            gain=GOOD, effort="instant", category="memory",
            evidence=[f"{row.name} pid {row.pid}: {row.memory / 1e9:.2f} GB"
                      for row in ollama],
            action_id="unload_ollama_models", action_params={},
            verify="Available memory rises by roughly the figure above."))
    return [o for o in out if o]


# --------------------------------------------------------------- antivirus

def _antivirus_opportunity(sample: Sample | None,
                           facts: sysinfo.MachineFacts) -> list[Opportunity]:
    """Overlapping real-time scanners: usually the largest fixable tax there is.

    Never automated, and deliberately so. Removing security software is the
    IT department's decision on a managed machine, and this tool has no way to
    know which product is the sanctioned one.
    """
    if sample is None:
        return []
    vendors = _antivirus_vendors(sample)
    if len(vendors) < 2:
        return []
    evidence = []
    for vendor, rows in vendors.items():
        memory = sum(row.memory for row in rows)
        evidence.append(f"{vendor}: {len(rows)} process(es), "
                        f"{memory / 1e6:.0f} MB")
    return [Opportunity(
        id="one-scanner-only",
        title=f"{len(vendors)} real-time scanners are inspecting every file",
        detail=(
            f"{', '.join(vendors)} are all hooked into file and process "
            f"activity. They do not co-operate: each file your applications "
            f"open is inspected once per product, and each scanner's own "
            f"reads are then inspected by the others. The cost lands on "
            f"exactly the operations that make a machine feel slow -- opening "
            f"applications, saving, and anything that touches many small "
            f"files -- and it does not buy more safety, because overlapping "
            f"scanners routinely interfere with one another. Keeping one is "
            f"both faster and safer than keeping {len(vendors)}."),
        gain=95, effort="planned", category="security",
        evidence=evidence,
        manual_steps=[
            "Decide which product is the sanctioned one -- on a managed "
            "machine that is the EDR agent your IT provider deployed, not the "
            "consumer product.",
            "Uninstall the others properly rather than disabling them: a "
            "disabled scanner usually leaves its filter driver loaded, which "
            "keeps most of the cost.",
            "This is your IT provider's call on a managed endpoint. Send them "
            "the list above rather than removing anything yourself."],
        verify="Application launches and file saves get noticeably quicker; "
               "disk service time under load falls.")]


# ----------------------------------------------------------------- storage

def _storage_opportunities(sample: Sample | None,
                           facts: sysinfo.MachineFacts) -> list[Opportunity]:
    out: list[Opportunity] = []
    resets = _storage_reset_events(facts)
    devices = sysinfo.storage_devices()
    # AHCI link power management is a SATA setting. On an NVMe machine the
    # knob exists in the power scheme and does nothing, and proposing it there
    # would be exactly the token gesture this engine is supposed to avoid --
    # the more so because both kinds of machine report their errors through
    # the same Intel driver, so the event log cannot tell them apart.
    ahci = any(device.is_ahci for device in devices) if devices else False
    alternating = actions_mod.link_power_management()[0] if ahci else -1

    if ahci and alternating > 0:
        gain = LARGE if resets else MODERATE
        evidence = [f"AHCI Link Power Management is set to "
                    f"{actions_mod._LPM_NAMES.get(alternating, alternating)} "
                    f"in the active power plan"]
        if resets:
            newest = max(event.when for event in resets)
            evidence.append(
                f"{len(resets)} storage reset/timeout event(s) in the recent "
                f"log, most recently "
                f"{time.strftime('%d %b %H:%M', time.localtime(newest))}")
            evidence += [f"{event.source} event {event.event_id}"
                         for event in resets[:3]]
        out.append(Opportunity(
            id="link-power-off",
            title="The drive link is allowed to power down between requests",
            detail=(
                "The controller is set to drop the link to the drive into a "
                "low-power state when it is idle and wake it for the next "
                "request. On the Intel RST controllers where this goes wrong, "
                "the wake occasionally does not complete and Windows resets "
                "the device instead -- which is a whole-machine freeze of "
                "several seconds, because every thread waiting on the disk "
                "waits with it."
                + (" This machine is logging exactly those resets."
                   if resets else " No resets have been logged here, so this "
                                  "is precautionary rather than a fix.")),
            gain=gain, effort="quick", category="disk", evidence=evidence,
            action_id="set_link_power_management",
            action_params={"mode": "off"},
            verify="No further controller reset events in the system log. "
                   "They were intermittent, so give it several days."))

    if resets:
        driver = sorted({event.source for event in resets})
        evidence = [f"{time.strftime('%d %b %H:%M', time.localtime(e.when))} "
                    f"{e.source} event {e.event_id}" for e in resets[:5]]
        evidence += [device.describe() for device in devices]
        out.append(Opportunity(
            id="storage-health",
            title=f"{len(resets)} storage error(s) are logged and unexplained",
            detail=(
                "Windows recorded the storage controller resetting a device "
                "that stopped answering. That is either the drive, its "
                "connection or its driver, and it is the single most reliable "
                "explanation for a machine that freezes completely for "
                "several seconds and then carries on -- every thread waiting "
                "on the disk waits with it, which is why the whole machine "
                "stops rather than one application. No amount of closing "
                "programs affects it."
                + ("" if ahci else
                   " This machine's drive is NVMe behind an Intel RST "
                   "controller, so the SATA link-power settings people "
                   "usually reach for do not apply and are not offered. What "
                   "does apply is the controller driver's own version.")),
            gain=90, effort="quick", category="hardware",
            evidence=evidence,
            # SMART is the right first step because it is read-only and it
            # splits the remaining possibilities in half.
            action_id="check_smart", action_params={},
            manual_steps=[
                "If SMART reports a predicted failure, replace the drive. "
                "Nothing in software fixes a drive that is failing.",
                f"If SMART is clean, the next suspect is the "
                f"{' / '.join(driver) or 'storage'} driver. Update Intel "
                f"Rapid Storage Technology and the drive firmware from Dell's "
                f"support pages for this machine's service tag rather than "
                f"from Windows Update, which keeps an older RST than Dell "
                f"ships.",
                "Back up before doing either."],
            verify="SMART status per drive, and whether new event 129 entries "
                   "stop appearing over the following week."))

    disk = facts.system_disk
    if disk and disk.free_fraction < 0.15:
        out.append(Opportunity(
            id="reclaim-space",
            title=f"The system drive is {disk.percent:.0f}% full",
            detail=(
                "NTFS slows markedly once a volume is this full, because free "
                "space becomes fragmented and every write has to hunt for "
                "somewhere to go. The page file grows into the same space, "
                "which matters on a machine that is already paging. Disk "
                "Cleanup including system files is usually the largest single "
                "reclaim, because Windows Update leftovers accumulate there."),
            gain=GOOD if disk.free_fraction < 0.10 else MODERATE,
            effort="quick", category="disk",
            evidence=[f"{disk.mountpoint} {disk.free / 1e9:.1f} GB free of "
                      f"{disk.total / 1e9:.1f} GB"],
            action_id="run_disk_cleanup", action_params={},
            verify="Free space on the system drive."))
    return out


# ---------------------------------------------------------------- services

#: Services worth proposing to stop, and why. Deliberately a subset of
#: `actions.TUNABLE_SERVICES`: that list is what the action will *accept*,
#: this one is what the scan will *suggest*, and they are not the same thing.
#: Windows Search is on the first and not the second, because turning it off
#: breaks search inside Outlook -- a bad trade nobody asked for.
PROPOSABLE: dict[str, tuple[str, int, str]] = {
    "SysMain": (
        "manual", GOOD,
        "SysMain (Superfetch) reads applications into RAM speculatively, "
        "guessing what you will open next. That is a good trade on a machine "
        "with spare memory and a slow disk, and a bad one here: the memory it "
        "speculates with is memory the applications you actually have open "
        "are short of."),
    "DiagTrack": (
        "manual", MODERATE,
        "Connected User Experiences and Telemetry collects diagnostic data "
        "and writes it continuously. Setting it to manual stops the "
        "background writing; nothing you use depends on it."),
    "DoSvc": (
        "manual", SMALL,
        "Delivery Optimization uploads Windows updates to other machines on "
        "the network and beyond, and can hold the disk and the connection for "
        "long stretches. Updates still download normally without it."),
    "MapsBroker": (
        "disabled", SMALL,
        "Downloaded Maps Manager does nothing unless the Maps app is used "
        "offline."),
    "RetailDemo": (
        "disabled", SMALL,
        "Retail Demo mode is only used by shop display machines."),
}


def _service_opportunities(sample: Sample | None,
                           facts: sysinfo.MachineFacts) -> list[Opportunity]:
    out: list[Opportunity] = []
    tight = bool(sample and sample.memory_total
                 and sample.memory_available / sample.memory_total
                 < TIGHT_MEMORY)

    for name, (target, gain, detail) in PROPOSABLE.items():
        current = actions_mod.service_start_type(name)
        if current not in ("automatic", "boot", "system"):
            continue        # not installed, or already out of the way
        if name == "SysMain" and not tight:
            continue        # only worth the trade when memory is the constraint
        out.append(Opportunity(
            id=f"service-{name.lower()}",
            title=f"{name} starts automatically and is not earning it",
            detail=detail,
            gain=gain + (10 if name == "SysMain" and tight else 0),
            effort="quick", category="tuneup",
            evidence=[f"{name} start type: {current}",
                      actions_mod.TUNABLE_SERVICES.get(name, "")],
            action_id="set_service_startup",
            action_params={"service": name, "startup": target},
            verify=f"services.msc shows {name} as {target}."))

    # Software with a documented leak, which is a different argument from the
    # ones above: it is not about what it costs now but about what it will
    # cost by Friday.
    if sample is not None:
        seen: set[str] = set()
        for row in sorted(sample.processes, key=lambda r: -r.memory):
            fact = knowledge.lookup(row.name)
            if not fact or not fact.known_leak:
                continue
            if row.name.lower() in seen:
                continue
            seen.add(row.name.lower())
            service = next(
                (s for s in actions_mod.TUNABLE_SERVICES
                 if s.lower() in row.name.lower()
                 or row.name.lower().removesuffix(".exe") in s.lower()), "")
            # Private commit, not working set: Windows trims a working set
            # under memory pressure, so on precisely the machine where a leak
            # matters most the working set understates it. Private bytes are
            # what the process has actually asked for and not given back.
            held = max(row.private, row.memory)
            out.append(Opportunity(
                id=f"leak-{row.name.lower().removesuffix('.exe')}",
                title=f"{row.name} has a documented memory leak and is at "
                      f"{held / 1e6:.0f} MB",
                detail=(
                    f"{fact.display or row.name}"
                    + (f" from {fact.vendor}" if fact.vendor else "")
                    + f" is known to grow without bound rather than settling "
                    f"at a working size. It is holding "
                    f"{held / 1e6:.0f} MB after "
                    f"{facts.uptime_days:.0f} days of uptime, and that figure "
                    f"tracks uptime rather than use -- which is why the "
                    f"machine gets worse through the week and appears to fix "
                    f"itself after a restart."),
                gain=GOOD if held > 500e6 else MODERATE,
                effort="quick", category="tuneup",
                evidence=[f"{row.name} pid {row.pid}: "
                          f"{row.private / 1e6:.0f} MB private commit, "
                          f"{row.memory / 1e6:.0f} MB working set",
                          f"uptime {facts.uptime_days:.1f} days"],
                action_id="set_service_startup" if service else "",
                action_params=({"service": service, "startup": "manual"}
                               if service else {}),
                manual_steps=([] if service else [
                    f"Uninstall {fact.display or row.name} if it is not "
                    f"needed -- on a managed machine, ask your IT provider "
                    f"first."]),
                verify="Private memory for that process, checked again "
                       "tomorrow."))
    return out


# ---------------------------------------------------------------- start-up

def _startup_opportunity(sample: Sample | None,
                         facts: sysinfo.MachineFacts) -> list[Opportunity]:
    if len(facts.startup) < STARTUP_BUSY:
        return []
    ranked = sorted(facts.startup, key=lambda i: -_startup_weight(i))
    worth = [item for item in ranked if _startup_weight(item) >= 3]
    if not worth:
        return []
    first = worth[0]
    return [Opportunity(
        id="startup-trim",
        title=f"{len(facts.startup)} programs launch at sign-in, "
              f"{len(worth)} of them updaters and helpers",
        detail=(
            "Everything in this list competes for the disk and the CPU in the "
            "same few seconds, which is why the desktop appears well before "
            "the machine is usable -- and most of them then stay resident all "
            "day holding memory. Updaters and vendor helpers are the ones to "
            "remove: they exist to check for a new version, which does not "
            "need to happen at sign-in and does not need a resident process. "
            "The programs themselves are untouched and still start when you "
            "open them."),
        gain=MODERATE + min(20, len(worth) * 3),
        effort="quick", category="startup",
        evidence=[f"{item.name} ({item.scope}): {item.command[:80]}"
                  for item in worth[:8]],
        action_id="disable_startup_item",
        action_params={"name": first.name, "scope": first.scope},
        manual_steps=[
            "The button handles one entry. For the rest, Task Manager > "
            "Startup apps, or run this step again for each name listed above."],
        verify="Task Manager > Startup apps, and how long the machine takes "
               "to become usable after sign-in.")]


# ------------------------------------------------------------------- power

def _power_opportunity(sample: Sample | None,
                       facts: sysinfo.MachineFacts) -> list[Opportunity]:
    plan = (facts.power_plan or "").lower()
    if "saver" not in plan:
        return []
    return [Opportunity(
        id="power-plan",
        title=f"The power plan is set to {facts.power_plan}",
        detail=(
            "Power saver holds the processor clock down permanently. It reads "
            "as general slowness with a low CPU percentage, which is the most "
            "misleading combination there is -- the graph looks calm because "
            "the work is being done slowly, not because there is little of "
            "it. On a desktop there is nothing to save."),
        gain=GOOD, effort="instant", category="cpu",
        evidence=[f"active plan: {facts.power_plan}"]
                 + ([f"CPU running at {facts.cpu_freq_current:.0f} MHz of "
                     f"{facts.cpu_freq_max:.0f} MHz rated"]
                    if facts.cpu_freq_max else []),
        action_id="set_power_plan", action_params={"plan": "balanced"},
        verify="Processor clock under load, in Task Manager > Performance.")]


# ------------------------------------------------------------ housekeeping

def _housekeeping_opportunities(
        sample: Sample | None,
        facts: sysinfo.MachineFacts) -> list[Opportunity]:
    out: list[Opportunity] = []
    try:
        import winreg
        value = None
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"System\GameConfigStore", 0,
                            winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, "GameDVR_Enabled")
    except OSError:
        value = None
    if value not in (0, None):
        out.append(Opportunity(
            id="game-dvr",
            title="Xbox Game Bar background recording is on",
            detail=(
                "Game Bar keeps a rolling recording buffer so that the last "
                "thirty seconds of anything can be saved. It hooks graphics "
                "and keeps a capture path warm whether or not anything is "
                "being played. On a machine that never games it is pure "
                "overhead, and it is a per-user setting, so turning it off "
                "needs no administrator rights and affects nobody else."),
            gain=SMALL + 10, effort="instant", category="tuneup",
            evidence=["HKCU\\System\\GameConfigStore\\GameDVR_Enabled = 1"],
            action_id="disable_game_recording", action_params={},
            verify="Background CPU and GPU use, particularly in full-screen "
                   "applications."))
    return out


# ------------------------------------------------------------------ uptime

def _uptime_opportunity(sample: Sample | None,
                        facts: sysinfo.MachineFacts) -> list[Opportunity]:
    if facts.uptime_days < LONG_UPTIME_DAYS:
        return []
    # Never automated. Restarting somebody's machine underneath their open
    # work is not a performance optimisation, whatever it does to the graphs.
    evidence = [f"uptime {facts.uptime_days:.1f} days",
                f"booted {time.strftime('%d %b %H:%M', time.localtime(facts.boot_time))}"]
    if sample is not None:
        worst = max(sample.processes, key=lambda r: r.handles, default=None)
        if worst is not None and worst.handles > 8000:
            evidence.append(f"{worst.name} is holding {worst.handles:,} "
                            f"handles")
    return [Opportunity(
        id="restart",
        title=f"The machine has been up for {facts.uptime_days:.0f} days",
        detail=(
            "Handle, pool and GDI leaks accumulate with uptime rather than "
            "with load, which is why a machine can be fine for a week and "
            "unbearable in the second week, and why the trouble appears to "
            "fix itself after a restart and then comes back. A restart is not "
            "a cure, but it is the cheapest way to find out how much of the "
            "current state is accumulated rather than structural -- and if "
            "the trouble returns after a predictable number of days, that "
            "timing identifies the leak."),
        gain=MODERATE, effort="quick", category="system",
        evidence=evidence,
        manual_steps=["Restart when it suits you -- Start > Power > Restart, "
                      "not Shut down, because fast startup means shutting "
                      "down does not clear this.",
                      "Note the date. If the same symptoms return after a "
                      "similar number of days, that is a leak and the "
                      "interval is the clue."],
        verify="How long until the same symptoms return.")]


# ------------------------------------------------- handing it to the dialog

def as_investigation(tuneup: TuneUp, sample: Sample | None = None):
    """Present a tune-up in the shape the fix dialog already understands.

    The approval flow that exists for findings is the whole safety story of
    this tool -- preview in dry-run, tick individually, offer a restore point,
    record undo to disk before running, measure afterwards. A tune-up needs
    every one of those, and none of it is specific to a *fault*. So rather
    than a second dialog that would have to reimplement all of it and would
    drift out of step, a tune-up is handed over as a finding with its plan
    already made.

    The one real difference is that the plan does not come from the model
    here. The opportunity engine already chose each action and its parameters
    from measured state, so there is nothing for a model to pick and no reason
    to introduce the possibility of it picking wrongly.
    """
    from .investigate import Investigation
    from .rules import Finding

    automatable = tuneup.automatable
    manual = tuneup.manual

    headline = (f"{len(automatable)} change(s) this tool can make, "
                f"{len(manual)} it cannot")
    finding = Finding(
        id="tune-up",
        title=f"Tune-up: {len(tuneup.opportunities)} thing(s) worth changing",
        severity=2,
        confidence=1.0,
        category="tuneup",
        explanation=headline,
        evidence=[f"[{o.gain_label}] {o.title}" for o in tuneup.opportunities])

    lines: list[str] = []
    if tuneup.opportunities:
        lines.append("Worth doing, in order of how much it will be felt:\n")
    for number, opportunity in enumerate(tuneup.opportunities, 1):
        lines.append(f"{number}. [{opportunity.gain_label}] "
                     f"{opportunity.title}")
        lines.append(f"   {opportunity.detail}")
        if opportunity.evidence:
            lines.append("   Measured: "
                         + "; ".join(e for e in opportunity.evidence[:3] if e))
        if opportunity.verify:
            lines.append(f"   You will know it worked by: {opportunity.verify}")
        lines.append("")
    if tuneup.unavailable:
        lines.append("Not checked (the reading was refused): "
                     + ", ".join(tuneup.unavailable))

    plan: list[actions_mod.PlannedAction] = []
    for opportunity in automatable:
        spec = actions_mod.REGISTRY.get(opportunity.action_id)
        if spec is None:
            continue
        # Which of these start ticked is the dialog's decision, not this
        # module's: it applies one rule -- low risk, reversible, no elevation
        # -- to every plan it is given, and a tune-up should not be the
        # exception that quietly pre-ticks something more.
        plan.append(actions_mod.PlannedAction(
            spec=spec, params=dict(opportunity.action_params),
            reason=f"[{opportunity.gain_label} gain] {opportunity.title}"))

    steps: list[str] = []
    for opportunity in manual:
        for step in opportunity.manual_steps or [opportunity.detail]:
            steps.append(f"{opportunity.title} — {step}")

    return finding, Investigation(
        finding=finding,
        analysis="\n".join(lines).strip(),
        manual_steps=steps[:12],
        confidence="measured",
        plan=plan)
