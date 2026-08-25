"""Drive the whole pipeline against the real machine and print what came back.

This is the harness for the question "what does the AI actually recommend",
which is otherwise only answerable by clicking through the interface and
reading a dialog. It samples the live machine, runs the rules, and then --
this is the part that matters -- runs the *investigator* on each finding and
prints the plan it produced, including the actions that were discarded and
why nothing was proposed when nothing was.

    python tools/live_test.py                  30s, rules only, no model
    python tools/live_test.py --seconds 60 --narrative
    python tools/live_test.py --investigate    plan every finding (slow)
    python tools/live_test.py --investigate --top 2
    python tools/live_test.py --dry-run-plan   also preview each planned action
    python tools/live_test.py --json out.json  machine-readable transcript

Every action preview runs with `dry_run=True`, so this changes nothing on the
machine no matter which flags are given. `--dry-run-plan` is about running the
*preview* of each action, which is itself read-only, not about applying it.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sysup import actions as actions_mod            # noqa: E402
from sysup import bridge as bridge_mod              # noqa: E402
from sysup import diagnose as diagnose_mod          # noqa: E402
from sysup import investigate as investigate_mod    # noqa: E402
from sysup.collect import History, Sampler          # noqa: E402
from sysup.config import Settings                   # noqa: E402

BAR = "=" * 78
RULE = "-" * 78


def _utf8() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is not None and hasattr(stream, "buffer"):
            try:
                setattr(sys, name, io.TextIOWrapper(
                    stream.buffer, encoding="utf-8", errors="replace",
                    line_buffering=True))
            except (AttributeError, ValueError):
                pass


def watch(seconds: float, settings: Settings) -> tuple[History, Sampler]:
    """Sample the machine for real, on the same schedule the app uses."""
    interval = float(settings.get("sample_interval", 1.0))
    threshold = float(settings.get("stall_threshold_s", 2.5))
    sampler = Sampler()
    history = History(size=int(settings.get("history_samples", 300)))

    sampler.sample()        # the first sample is a baseline and carries no rates
    ticks = max(1, int(seconds / interval))
    print(f"watching for {seconds:.0f}s ({ticks} samples at {interval}s)")
    next_tick = time.monotonic() + interval
    for index in range(ticks):
        now = time.monotonic()
        if next_tick > now:
            time.sleep(next_tick - now)
        next_tick += interval
        sample = sampler.sample(interval)
        stall = history.add(sample, threshold)
        if stall:
            print(f"  !! stalled {stall['lateness']:.1f}s")
        elif index % 10 == 0:
            print(f"  {index:>4}/{ticks}  cpu {sample.cpu:5.1f}%  "
                  f"ram {sample.memory_percent:5.1f}%  "
                  f"free {sample.memory_available / 1e9:4.1f} GB  "
                  f"commit {sample.commit_percent:5.1f}%  "
                  f"faults {sample.hard_faults:6.0f}/s  "
                  f"disk {sample.disk_latency_ms:5.1f} ms", flush=True)
    return history, sampler


def print_findings(diagnosis) -> None:
    print(f"\n{BAR}\nFINDINGS ({len(diagnosis.findings)})\n{BAR}")
    if not diagnosis.findings:
        print("  nothing fired. On a machine with a known fault that is "
              "itself a result -- see whether the rule that should have "
              "caught it is in the feed with fired=0.")
    for finding in diagnosis.findings:
        print(f"\n[{finding.severity_name:>8}] {finding.title}"
              f"   ({finding.id}, {finding.category}, "
              f"confidence {finding.confidence:.2f})")
        print(f"  {finding.explanation}")
        for item in finding.evidence[:6]:
            print(f"    - {item}")
        for fix in finding.fixes[:3]:
            print(f"    fix: {fix.title}")


def print_investigation(result, preview: bool) -> None:
    finding = result.finding
    print(f"\n{BAR}\nINVESTIGATION: {finding.title}\n{BAR}")
    if result.error:
        print(f"  note: {result.error}")
    if result.queries:
        print(f"  queries : {result.queries}")
    if result.sources:
        print(f"  sources : {[s.domain for s in result.sources]}")
    print(f"  confidence: {result.confidence or 'not stated'}")
    if result.analysis:
        print(f"\n{result.analysis}\n")
    if result.manual_steps:
        print("  manual steps the model wants the user to take:")
        for step in result.manual_steps:
            print(f"    - {step}")
    if not result.plan:
        print("  PLAN: no automated action proposed.")
        return
    print("  PLAN:")
    for planned in result.plan:
        spec = planned.spec
        flags = [spec.risk]
        if spec.needs_admin:
            flags.append("admin")
        if not spec.reversible:
            flags.append("NOT reversible")
        print(f"    - {spec.id} [{', '.join(flags)}] "
              f"params={planned.params}")
        print(f"      why: {planned.reason}")
        if preview:
            outcome = actions_mod.apply(planned, dry_run=True)
            print(f"      preview: ok={outcome.ok} changed={outcome.changed} "
                  f"{outcome.message}")


def main(argv: list[str] | None = None) -> int:
    _utf8()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--narrative", action="store_true",
                        help="also ask the big model for the written report")
    parser.add_argument("--investigate", action="store_true",
                        help="research and plan each finding (slow, real)")
    parser.add_argument("--optimise", "--optimize", action="store_true",
                        dest="optimise",
                        help="run the tune-up scan and show the opportunities")
    parser.add_argument("--top", type=int, default=3,
                        help="how many findings to investigate")
    parser.add_argument("--dry-run-plan", action="store_true",
                        help="preview each planned action (still read-only)")
    parser.add_argument("--no-bridge", action="store_true")
    parser.add_argument("--json", metavar="PATH",
                        help="write a machine-readable transcript here")
    args = parser.parse_args(argv)

    settings = Settings.load()
    if not args.no_bridge:
        feed = bridge_mod.start()
        print(f"live bridge -> {feed.directory}")

    history, _sampler = watch(args.seconds, settings)

    print("\ndiagnosing...")
    diagnosis = diagnose_mod.diagnose(
        history, settings, on_progress=lambda m: print(f"  . {m}", flush=True),
        use_model=args.narrative)
    print_findings(diagnosis)

    if diagnosis.narrative:
        print(f"\n{BAR}\nNARRATIVE ({diagnosis.model})\n{BAR}\n"
              f"{diagnosis.narrative.strip()}")

    investigations = []
    if args.investigate:
        for finding in diagnosis.findings[:args.top]:
            print(f"\n{RULE}\ninvestigating: {finding.title}\n{RULE}")
            result = investigate_mod.investigate(
                finding, settings, facts=diagnosis.facts,
                on_progress=lambda m: print(f"  . {m}", flush=True),
                context=investigate_mod.live_context(history.latest()))
            investigations.append(result)
            print_investigation(result, args.dry_run_plan)

    opportunities = []
    if args.optimise:
        from sysup import optimise as optimise_mod
        print(f"\n{BAR}\nTUNE-UP SCAN\n{BAR}")
        scan = optimise_mod.scan(
            history.latest(), diagnosis.facts,
            on_progress=lambda m: print(f"  . {m}", flush=True))
        opportunities = scan.opportunities
        for opportunity in opportunities:
            print(f"\n[{opportunity.gain_label:>8}] {opportunity.title}"
                  f"   ({opportunity.id}, {opportunity.effort} effort)")
            print(f"  {opportunity.detail}")
            for item in opportunity.evidence[:4]:
                print(f"    - {item}")
            if opportunity.action_id:
                print(f"    action: {opportunity.action_id} "
                      f"{opportunity.action_params or ''}")
            else:
                print("    action: manual only")
        if not opportunities:
            print("  nothing worth changing was found.")

    if args.json:
        payload = {
            "at": time.time(),
            "watched_s": args.seconds,
            "samples": history.count,
            "findings": [
                {"id": f.id, "title": f.title, "severity": f.severity,
                 "confidence": f.confidence, "category": f.category,
                 "process": f.process, "explanation": f.explanation,
                 "evidence": f.evidence}
                for f in diagnosis.findings],
            "narrative": diagnosis.narrative,
            "investigations": [
                {"finding": r.finding.id, "queries": r.queries,
                 "sources": [s.url for s in r.sources],
                 "confidence": r.confidence, "analysis": r.analysis,
                 "manual_steps": r.manual_steps, "error": r.error,
                 "plan": [{"id": p.spec.id, "params": p.params,
                           "why": p.reason} for p in r.plan]}
                for r in investigations],
            "opportunities": [
                {"id": o.id, "title": o.title, "gain": o.gain,
                 "effort": o.effort, "detail": o.detail,
                 "evidence": o.evidence, "action_id": o.action_id,
                 "action_params": o.action_params}
                for o in opportunities],
        }
        Path(args.json).write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\ntranscript -> {args.json}")

    bridge_mod.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
