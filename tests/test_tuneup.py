"""The tune-up engine, the live bridge, and the bug class that hid them both.

The first section here exists because of a real failure. `_rule_duplicate_av`
built a `Fix` with `admin=True` when the field is `needs_admin`, so it raised
`TypeError` every single time it ran -- and `rules.analyse` catches per-rule
exceptions so that one broken rule cannot take the monitor down. The result
was a rule that had never once fired on a machine running three real-time
scanners, and no symptom anywhere: no crash, no log line, no missing feature
anybody could name. It was found by putting the rule loop on the live bridge
and reading what came past.

Two lessons are encoded below. Every rule must survive being run -- that is
what `test_no_rule_raises` is for, and it drives each of them with samples
shaped to make them fire rather than with a healthy machine that exercises
only their first `return []`. And every `Fix` in the codebase must be
constructible, which is a one-line check that would have caught the original
in a second.

    python tests/test_tuneup.py
"""

from __future__ import annotations

import inspect
import io
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace", line_buffering=True)

from sysup import actions as actions_mod                    # noqa: E402
from sysup import bridge as bridge_mod                      # noqa: E402
from sysup import knowledge, optimise, rules, sysinfo        # noqa: E402
from sysup.collect import History, ProcRow, Sample          # noqa: E402

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def make_sample(**kwargs) -> Sample:
    base = dict(at=time.time(), interval=1.0, cpu=12.0,
                memory_percent=55.0, memory_total=17_000_000_000,
                memory_available=7_600_000_000,
                commit_percent=48.0, commit_total=28_000_000_000,
                commit_limit=59_000_000_000,
                disk_latency_ms=0.4, disk_ops=200.0, hard_faults=3.0,
                ready_threads=0, processes=[])
    base.update(kwargs)
    return Sample(**base)


def facts_of(**kwargs) -> sysinfo.MachineFacts:
    base = dict(os_build="Windows 10 Pro 24H2", cpu_model="Test CPU",
                cpu_cores=6, cpu_threads=12, ram_total=17_000_000_000,
                uptime_s=3600.0, boot_time=time.time() - 3600.0,
                power_plan="Balanced")
    base.update(kwargs)
    return sysinfo.MachineFacts(**base)


# ------------------------------------------------------- the bug that hid

def test_every_fix_is_constructible() -> None:
    """No rule and no knowledge entry may build a Fix that raises.

    The original fault was invisible because the failure happened inside a
    rule whose exceptions are deliberately swallowed. This walks the whole
    knowledge table -- where every Fix that is not built by a rule lives --
    and asserts each one actually exists.
    """
    print("\nevery remedy can be constructed")
    broken: list[str] = []
    total = 0
    for name in list(knowledge.KNOWN):
        fact = knowledge.lookup(name)
        if fact is None:
            continue
        for fix in fact.fixes:
            total += 1
            if not isinstance(fix, knowledge.Fix):
                broken.append(f"{name}: {fix!r}")
    check(f"{total} knowledge remedies are real Fix objects", not broken,
          "; ".join(broken[:3]))

    # The keyword itself: `Fix` takes needs_admin, and `knowledge._f` takes
    # admin. Mixing them up is what happened, so assert the shapes differ on
    # purpose and are both still what the callers use.
    fields = set(inspect.signature(knowledge.Fix).parameters)
    check("Fix takes needs_admin, not admin",
          "needs_admin" in fields and "admin" not in fields,
          ", ".join(sorted(fields)))
    helper = set(inspect.signature(knowledge._f).parameters)
    check("the _f helper is the one that takes admin", "admin" in helper)


def test_no_rule_raises() -> None:
    """Every rule, driven hard enough to fire, must come back without raising.

    `analyse` reports a raising rule on the bridge now instead of silently
    dropping it, so this listens to the bridge rather than trying to
    re-implement the loop.
    """
    print("\nno rule raises when it is actually made to fire")

    busy = ProcRow(pid=900, name="hog.exe", cpu=60.0, cpu_kernel=30.0,
                   memory=3_000_000_000, private=3_100_000_000, threads=650,
                   handles=22_000, hard_faults=500.0, read_bps=90e6,
                   write_bps=90e6, io_ops=4000.0, gdi=9_000,
                   user_objects=9_000, session=1, hung=True,
                   title="Not Responding")
    # Two scanners from two different vendors: the exact shape that used to
    # raise. Names are taken from the knowledge table so `av_vendor` matches.
    scanners = [ProcRow(pid=901, name="SentinelAgent.exe", memory=600_000_000,
                        cpu=1.0, session=0),
                ProcRow(pid=902, name="AVGSvc.exe", memory=200_000_000,
                        cpu=1.0, session=0)]
    sick = make_sample(
        cpu=96.0, memory_percent=95.0, memory_available=500_000_000,
        commit_percent=97.0, hard_faults=900.0, disk_latency_ms=420.0,
        disk_busy=99.0, disk_ops=50.0, lateness=3.4, ready_threads=40,
        kernel_paged=2_000_000_000, kernel_nonpaged=3_000_000_000,
        processes=[busy] + scanners)

    history = History(size=400)
    for _ in range(80):
        history.add(sick, 2.5)

    with tempfile.TemporaryDirectory() as folder:
        feed = bridge_mod.start(Path(folder))
        try:
            findings = rules.analyse(history, sick)
        finally:
            bridge_mod.stop()
        events = [json.loads(line) for line
                  in (Path(folder) / "bridge.jsonl").read_text(
                      encoding="utf-8").splitlines() if line.strip()]

    errors = [e for e in events if e.get("kind") == "rule.error"]
    ran = [e for e in events if e.get("kind") == "rule"]
    check("the bridge recorded every rule running", len(ran) >= 17,
          f"{len(ran)} rules reported")
    check("no rule raised", not errors,
          "; ".join(f"{e['rule']}: {e['error']}" for e in errors[:3]))
    check("a machine in this state produces findings", len(findings) >= 5,
          f"{len(findings)} findings")

    fired = {f.id for f in findings}
    check("the duplicate-scanner rule fires again", "duplicate-av" in fired,
          ", ".join(sorted(fired)))


# ---------------------------------------------------------------- bridge

def test_bridge_is_optional_and_quiet() -> None:
    print("\nthe live bridge")
    bridge_mod.stop()
    check("off by default", not bridge_mod.active())
    feed = bridge_mod.bridge()
    feed.emit("ignored", value=1)       # must not raise with no bridge running
    with feed.span("nothing"):
        pass
    check("emitting with no bridge running is a no-op", True)

    with tempfile.TemporaryDirectory() as folder:
        live = bridge_mod.start(Path(folder))
        check("starts on request", bridge_mod.active())
        live.emit("hello", n=1, big="x" * 5000)
        live.llm("llm.response", purpose="test", model="m", text="y" * 9000)
        live.state({"cpu": 12})
        bridge_mod.stop()

        events = [json.loads(line) for line
                  in (Path(folder) / "bridge.jsonl").read_text(
                      encoding="utf-8").splitlines() if line.strip()]
        kinds = [e["kind"] for e in events]
        check("events reach the file", "hello" in kinds, ", ".join(kinds))
        big = next(e for e in events if e["kind"] == "hello")
        check("long fields are truncated on the tailable feed",
              len(big["big"]) < 1000, f"{len(big['big'])} chars")
        summary = next(e for e in events if e["kind"] == "llm.response")
        check("model text does not go on the tailable feed",
              "text" not in summary)
        full = json.loads(
            (Path(folder) / "llm.jsonl").read_text(encoding="utf-8")
            .splitlines()[0])
        check("model text is kept whole in llm.jsonl",
              len(full.get("text", "")) == 9000, f"{len(full.get('text',''))}")
        state = json.loads((Path(folder) / "state.json").read_text(
            encoding="utf-8"))
        check("the snapshot is written whole", state.get("cpu") == 12)
    check("stops cleanly", not bridge_mod.active())


# --------------------------------------------------------------- tune-up

def test_opportunity_ordering() -> None:
    print("\ntune-up ordering")
    large = optimise.Opportunity(id="a", title="a", detail="", gain=90,
                                 effort="planned", category="memory")
    small_button = optimise.Opportunity(id="b", title="b", detail="", gain=20,
                                        effort="instant", category="tuneup",
                                        action_id="flush_dns")
    tied_manual = optimise.Opportunity(id="c", title="c", detail="", gain=20,
                                       effort="planned", category="tuneup")
    order = sorted([tied_manual, small_button, large],
                   key=lambda o: o.sort_key())
    check("the largest gain leads", order[0].id == "a",
          " ".join(o.id for o in order))
    check("a tie breaks towards the one with a button",
          order[1].id == "b", " ".join(o.id for o in order))
    check("gain bands read as words", large.gain_label == "large"
          and small_button.gain_label == "small",
          f"{large.gain_label}/{small_button.gain_label}")


def test_scan_proposes_only_real_actions() -> None:
    """Whatever the scan proposes must exist and be permitted for a tune-up.

    The same guarantee the model-driven path gets from `plan_from_model`, made
    explicit here because the tune-up plan does *not* go through the model and
    so does not get it for free.
    """
    print("\nthe tune-up only proposes real, permitted actions")
    allowed = set(actions_mod.allowed_ids("tuneup"))
    sample = make_sample(memory_available=1_500_000_000, memory_percent=91.0)
    tuneup = optimise.scan(sample, facts_of(uptime_s=20 * 86400,
                                            boot_time=time.time() - 20 * 86400))

    unknown = [o.action_id for o in tuneup.automatable
               if o.action_id not in actions_mod.REGISTRY]
    check("every proposed action id exists", not unknown, ", ".join(unknown))

    finding, investigation = optimise.as_investigation(tuneup, sample)
    check("the plan is built from the catalogue",
          all(p.spec.id in actions_mod.REGISTRY for p in investigation.plan),
          f"{len(investigation.plan)} steps")
    check("the tune-up category permits what it proposes",
          all(p.spec.id in allowed or p.spec.category in ("diagnostic",
                                                          "hardware", "disk")
              for p in investigation.plan),
          ", ".join(p.spec.id for p in investigation.plan))
    check("nothing irreversible is in a tune-up plan",
          all(p.spec.reversible for p in investigation.plan),
          ", ".join(p.spec.id for p in investigation.plan
                    if not p.spec.reversible))
    check("a long-uptime machine is told to restart, not restarted",
          any(o.id == "restart" and not o.automatable
              for o in tuneup.opportunities))


def test_security_software_is_never_automated() -> None:
    """Two scanners is the biggest win here and still must not be a button."""
    print("\nsecurity software stays a decision, not a button")
    scanners = [ProcRow(pid=1, name="SentinelAgent.exe", memory=600_000_000),
                ProcRow(pid=2, name="AVGSvc.exe", memory=200_000_000)]
    found = optimise._antivirus_opportunity(
        make_sample(processes=scanners), facts_of())
    check("overlapping scanners are reported", len(found) == 1)
    if found:
        check("but never automated", not found[0].automatable)
        check("and it says whose decision it is",
              any("IT provider" in step for step in found[0].manual_steps))
        check("it outranks everything with a button", found[0].gain >= 90,
              str(found[0].gain))

    one = optimise._antivirus_opportunity(
        make_sample(processes=[scanners[0]]), facts_of())
    check("one scanner is not a problem", not one)


def test_startup_never_touches_security() -> None:
    print("\nsign-in trimming leaves security alone")
    guarded = sysinfo.StartupItem(
        name="SecurityHealth", scope="machine",
        command=r"%windir%\system32\SecurityHealthSystray.exe")
    updater = sysinfo.StartupItem(
        name="SunJavaUpdateSched", scope="machine",
        command=r"C:\Program Files\Java\jusched.exe")
    check("Windows Security's tray icon is never proposed",
          optimise._startup_weight(guarded) == 0)
    check("an updater is", optimise._startup_weight(updater) == 3)

    facts = facts_of(startup=[guarded] * 8 + [updater] * 8)
    found = optimise._startup_opportunity(make_sample(), facts)
    check("the opportunity fires on a busy sign-in list", len(found) == 1)
    if found:
        names = " ".join(found[0].evidence)
        check("and names only the updater", "SunJava" in names
              and "SecurityHealth" not in names, names[:80])


def test_service_action_refuses_anything_unvetted() -> None:
    print("\nthe service action's allowlist")
    for name in ("SentinelAgent", "WinDefend", "lsass", "Winmgmt",
                 "HuntressAgent"):
        result = actions_mod.apply(
            actions_mod.PlannedAction(
                spec=actions_mod.REGISTRY["set_service_startup"],
                params={"service": name, "startup": "disabled"}),
            dry_run=True)
        check(f"refuses {name}", not result.ok, result.message[:60])
    check("SysMain is on the list", "SysMain" in actions_mod.TUNABLE_SERVICES)
    check("no security service is on the list",
          not any(word in service.lower()
                  for service in actions_mod.TUNABLE_SERVICES
                  for word in ("sentinel", "defend", "avg", "huntress",
                               "malware", "ninja")),
          ", ".join(actions_mod.TUNABLE_SERVICES))


def test_every_action_previews_without_changing_anything() -> None:
    """Dry-run must be honoured by every handler, including the new ones."""
    print("\nevery action previews safely")
    safe_params = {
        "restart_process": {"pid": 999999, "name": "nothing.exe"},
        "disable_startup_item": {"name": "does-not-exist", "scope": "user"},
        "set_service_startup": {"service": "SysMain", "startup": "manual"},
        "set_link_power_management": {"mode": "off"},
        "set_memory_compression": {"enabled": True},
        "retrim_volume": {"drive": "C"},
        "set_power_plan": {"plan": "balanced"},
        "set_wsl_memory_cap": {"gigabytes": 4},
        "show_event_detail": {"event_id": 129, "source": "iaStorAC"},
    }
    failures: list[str] = []
    for identifier, spec in sorted(actions_mod.REGISTRY.items()):
        try:
            result = actions_mod.apply(
                actions_mod.PlannedAction(
                    spec=spec, params=dict(safe_params.get(identifier, {}))),
                dry_run=True)
        except Exception as error:
            failures.append(f"{identifier}: {type(error).__name__}: {error}")
            continue
        if not isinstance(result, actions_mod.ActionResult):
            failures.append(f"{identifier}: returned {type(result).__name__}")
            continue
        if result.changed:
            failures.append(f"{identifier}: reported a change in dry-run")
    check(f"all {len(actions_mod.REGISTRY)} actions preview without raising "
          f"or changing anything", not failures, "; ".join(failures[:3]))


def main() -> int:
    print("=" * 74)
    print("  Tune-up engine, live bridge, and the rule-crash regression")
    print("=" * 74)
    for test in (test_every_fix_is_constructible, test_no_rule_raises,
                 test_bridge_is_optional_and_quiet, test_opportunity_ordering,
                 test_scan_proposes_only_real_actions,
                 test_security_software_is_never_automated,
                 test_startup_never_touches_security,
                 test_service_action_refuses_anything_unvetted,
                 test_every_action_previews_without_changing_anything):
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
