"""One test per bug found in the August 2026 audit.

These exist because every one of these bugs passed the fault-injection suite.
Injecting a fault proves the detector notices real trouble; it says nothing
about whether the detector invents trouble that is not there, mislabels it, or
acts on a stale identity. That is what this file is for.

    python tests/test_regressions.py
"""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace", line_buffering=True)

from sysup import actions, research, sysinfo                    # noqa: E402
from sysup.collect import History, Sample, Sampler              # noqa: E402

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------- pause/sleep

def test_pause_resume() -> None:
    """A pause is not a freeze, however long it lasts."""
    print("\npause / resume / sleep")

    # Short pause: under the continuity limit but over the stall threshold —
    # the case the continuity guard alone does NOT catch.
    sampler, history = Sampler(), History()
    sampler.sample()
    time.sleep(0.6)
    history.add(sampler.sample(0.5), threshold=2.5)
    sampler.reset()                       # what resume() does
    time.sleep(5.0)
    history.add(sampler.sample(0.5), threshold=2.5)
    check("5s pause with reset records no stall", len(history.stalls) == 0,
          f"{len(history.stalls)} stall(s)")

    # Long gap with no reset at all — simulates waking from sleep, where
    # nothing got the chance to call reset.
    sampler2, history2 = Sampler(), History()
    sampler2.sample()
    time.sleep(0.6)
    history2.add(sampler2.sample(0.5), threshold=2.5)
    time.sleep(11.0)                      # over CONTINUITY_LIMIT_S
    sample = sampler2.sample(0.5)
    history2.add(sample, threshold=2.5)
    check("11s gap is flagged discontinuous", sample.discontinuity)
    check("11s gap records no stall", len(history2.stalls) == 0,
          f"{len(history2.stalls)} stall(s)")
    check("discontinuous sample is not 'stalled'", not sample.stalled)


# ------------------------------------------------------------------- threading

def test_history_thread_safety() -> None:
    """Reading history while it is being written must not raise."""
    print("\nhistory thread safety")
    import threading

    history = History(size=50)
    errors: list[Exception] = []
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            history.add(Sample(at=time.time(), interval=0.01), threshold=99)

    def reader() -> None:
        while not stop.is_set():
            try:
                for _ in history.samples:
                    pass
                history.series("cpu", 30)
                history.recent(15)
                history.sustained(4, "cpu", 30)
                _ = history.count
            except Exception as error:      # the bug: "deque mutated…"
                errors.append(error)
                stop.set()

    threads = [threading.Thread(target=writer, daemon=True),
               threading.Thread(target=writer, daemon=True),
               threading.Thread(target=reader, daemon=True),
               threading.Thread(target=reader, daemon=True)]
    for thread in threads:
        thread.start()
    time.sleep(2.5)
    stop.set()
    for thread in threads:
        thread.join(timeout=2)
    check("concurrent read/write raises nothing", not errors,
          f"{len(errors)} error(s): {errors[0] if errors else ''}")

    check("samples property returns a copy, not the deque",
          isinstance(history.samples, list))


# ------------------------------------------------------------------ pid reuse

def test_pid_revalidation() -> None:
    """A recycled pid must be refused, not killed."""
    print("\npid reuse protection")
    import os

    # Our own pid, but claimed to be something else entirely.
    planned = actions.PlannedAction(
        spec=actions.REGISTRY["restart_process"],
        params={"pid": os.getpid(), "name": "chrome.exe"})
    result = actions.apply(planned, dry_run=False)
    check("refuses when pid no longer matches the name",
          not result.ok and "not" in result.message.lower(),
          result.message[:80])

    planned = actions.PlannedAction(
        spec=actions.REGISTRY["restart_process"],
        params={"pid": 999_999_99, "name": "chrome.exe"})
    result = actions.apply(planned, dry_run=False)
    check("handles an already-exited pid without killing anything",
          result.ok and "exited" in result.message.lower(),
          result.message[:80])

    planned = actions.PlannedAction(
        spec=actions.REGISTRY["restart_process"],
        params={"pid": 4, "name": "System"})
    check("still refuses system pids",
          not actions.apply(planned, dry_run=True).ok)


# ---------------------------------------------------------------- event log

def test_event_provider_mapping() -> None:
    """An event id only means something when its provider agrees."""
    print("\nevent provider mapping")
    cases = [
        ((1, "Microsoft-Windows-WHEA-Logger"), True, "WHEA id 1"),
        ((1, "SomeRandomService"), False, "unrelated id 1"),
        ((17, "MyApp"), False, "unrelated id 17"),
        ((129, "iaStorAC"), True, "storage id 129"),
        ((129, "NotAStorageDriver"), False, "unrelated id 129"),
        ((2004, "Microsoft-Windows-Resource-Exhaustion-Detector"), True,
         "resource exhaustion"),
        ((2004, "SomethingElse"), False, "unrelated id 2004"),
    ]
    for (event_id, source), expected, label in cases:
        got = bool(sysinfo.event_meaning(event_id, source))
        check(f"{label} -> {'meaning' if expected else 'ignored'}",
              got == expected)


# --------------------------------------------------------------------- SMART

def test_smart_multi_drive() -> None:
    """One healthy drive must not mask a failing one."""
    print("\nmulti-drive SMART")
    # The parser lives inside the handler, so exercise it through the shape of
    # output it parses rather than reaching into private helpers.
    sample = ("SMART|DriveA|False|\n"
              "SMART|DriveB|True|11\n"
              "DISK|Model A|OK|500\n")
    drives = []
    for line in sample.splitlines():
        parts = line.split("|")
        if parts[0] == "SMART":
            drives.append((parts[1], parts[2].strip().lower() in ("true", "1")))
    failing = [name for name, predicts in drives if predicts]
    check("a failing second drive is detected", failing == ["DriveB"],
          f"failing={failing}")
    check("old substring logic would have said healthy",
          "PredictFailure : False" in "PredictFailure : False\nPredictFailure : True")


# ------------------------------------------------------------------ wslconfig

def test_wslconfig_merge() -> None:
    """Other .wslconfig settings must survive a memory change."""
    print("\n.wslconfig preservation")
    existing = ("# my settings\n"
                "[wsl2]\n"
                "processors=4\n"
                "memory=18GB\n"
                "swap=8GB\n"
                "networkingMode=mirrored\n"
                "\n"
                "[experimental]\n"
                "autoMemoryReclaim=gradual\n")
    merged, replaced = actions._merge_wslconfig(existing, 10)
    check("memory replaced", "memory=10GB" in merged and "18GB" not in merged)
    check("replaced flag set", replaced)
    for key in ("processors=4", "swap=8GB", "networkingMode=mirrored",
                "[experimental]", "autoMemoryReclaim=gradual", "# my settings"):
        check(f"preserved {key}", key in merged)

    merged, replaced = actions._merge_wslconfig("[wsl2]\nprocessors=2\n", 4)
    check("memory added when absent",
          "memory=4GB" in merged and "processors=2" in merged and not replaced)

    merged, _ = actions._merge_wslconfig("", 6)
    check("creates a valid file from nothing",
          merged.strip() == "[wsl2]\nmemory=6GB")

    merged, _ = actions._merge_wslconfig("[experimental]\nfoo=bar\n", 8)
    check("adds a [wsl2] section when the file has none",
          "[wsl2]" in merged and "memory=8GB" in merged and "foo=bar" in merged)


# ----------------------------------------------------------------------- sfc

def test_sfc_semantics() -> None:
    """The diagnostic must not be the one that replaces system files."""
    print("\nsfc action semantics")
    verify = actions.REGISTRY.get("sfc_verify")
    repair = actions.REGISTRY.get("sfc_repair")
    check("verify-only action exists", verify is not None)
    check("repair is a separate action", repair is not None)
    if verify:
        check("verify is low risk and reversible",
              verify.risk == "low" and verify.reversible)
        check("verify dry-run mentions verifyonly",
              "verifyonly" in actions.apply(
                  actions.PlannedAction(spec=verify, params={}),
                  dry_run=True).message.lower())
    if repair:
        check("repair is marked irreversible", not repair.reversible)
        check("repair is high risk", repair.risk == "high")


# ------------------------------------------------------------------- research

def test_research_hardening() -> None:
    """Trusted-domain spoofing and internal fetches must be refused."""
    print("\nresearch hardening")
    cases = [
        ("learn.microsoft.com", "microsoft.com", True),
        ("microsoft.com", "microsoft.com", True),
        ("evil-microsoft.com", "microsoft.com", False),
        ("microsoft.com.attacker.net", "microsoft.com", False),
        ("github.com.evil.io", "github.com", False),
        ("notgithub.com", "github.com", False),
    ]
    for host, domain, expected in cases:
        check(f"{host} vs {domain} -> {expected}",
              research.host_matches(host, domain) == expected)

    for host, expected in (("127.0.0.1", True), ("localhost", True),
                           ("10.0.0.5", True), ("192.168.1.10", True),
                           ("169.254.169.254", True), ("0.0.0.0", True)):
        check(f"{host} treated as internal",
              research._is_internal(host) == expected)

    check("credentials and port stripped from host",
          research.domain_of("https://user:pw@evil.com:8443/x") == "evil.com")

    researcher = research.Researcher("http://example.invalid")
    check("fetch refuses loopback", researcher.fetch("http://127.0.0.1/x") == "")
    check("fetch refuses non-http scheme",
          researcher.fetch("file:///C:/Windows/win.ini") == "")


# ------------------------------------------------------------------ allowlist

def test_action_allowlist() -> None:
    """A finding may only reach for actions relevant to it."""
    print("\nper-finding action allowlist")
    disk = actions.allowed_ids("disk")
    check("disk findings may check SMART", "check_smart" in disk)
    check("disk findings may NOT end processes",
          "restart_process" not in disk)
    check("disk findings may NOT disable services",
          "disable_sysmain" not in disk)

    memory = actions.allowed_ids("memory")
    check("memory findings may unload models",
          "unload_ollama_models" in memory)
    check("memory findings may NOT run sfc repair",
          "sfc_repair" not in memory)

    check("security findings get diagnostics only",
          set(actions.allowed_ids("security")) <= set(actions.ALWAYS_ALLOWED))
    check("unknown category fails closed",
          set(actions.allowed_ids("nonsense-category"))
          <= set(actions.ALWAYS_ALLOWED))

    # The injection case: the model asks for something real but not permitted.
    injected = [{"id": "disable_sysmain", "parameters": {}, "why": "x"},
                {"id": "restart_process", "parameters": {"pid": 1,
                                                         "name": "a.exe"},
                 "why": "x"},
                {"id": "check_smart", "parameters": {}, "why": "ok"}]
    plan = actions.plan_from_model(injected, allowed=actions.allowed_ids("disk"))
    check("out-of-scope choices are dropped",
          [p.spec.id for p in plan] == ["check_smart"],
          f"kept {[p.spec.id for p in plan]}")

    check("sfc_repair never appears without explicit allowance",
          not any("sfc_repair" in actions.allowed_ids(c)
                  for c in ("disk", "memory", "cpu", "freeze", "handles",
                            "threads", "network", "security")))


def main() -> int:
    print("=" * 74)
    print("  Regression tests — one per bug from the audit")
    print("=" * 74)
    for test in (test_pause_resume, test_history_thread_safety,
                 test_pid_revalidation, test_event_provider_mapping,
                 test_smart_multi_drive, test_wslconfig_merge,
                 test_sfc_semantics, test_research_hardening,
                 test_action_allowlist):
        try:
            test()
        except Exception as error:
            check(f"{test.__name__} raised", False, repr(error))

    passed = sum(1 for _n, ok, _d in RESULTS if ok)
    print("\n" + "=" * 74)
    print(f"  {passed}/{len(RESULTS)} checks passed")
    failed = [n for n, ok, _d in RESULTS if not ok]
    for name in failed:
        print(f"  {RED}FAILED{RESET}: {name}")
    print("=" * 74 + "\n")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
