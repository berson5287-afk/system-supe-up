"""System Supe-Up — launcher.

    python run.py                 live dashboard
    python run.py --once          diagnose now, write a report, exit
    python run.py --watch 10      watch for 10 minutes, then report
    python run.py --check         check the servers and settings, exit
    python run.py --no-model      skip the model; findings and evidence only
    python run.py --optimise      what would make this machine quicker
    python run.py --bridge        stream every stage to ~/SystemSupeUp/live
    python run.py --admin         restart elevated, then carry on as asked
"""

from __future__ import annotations

import argparse
import io
import sys
import time
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sysup import bridge as bridge_mod                            # noqa: E402
from sysup import elevate as elevate_mod                          # noqa: E402
from sysup import diagnose as diagnose_mod, report as report_mod  # noqa: E402
from sysup.collect import History, Sampler                        # noqa: E402
from sysup.config import REPORT_DIR, Settings                     # noqa: E402
from sysup.llm import Ollama                                      # noqa: E402
from sysup.research import Researcher                             # noqa: E402


def _force_utf8() -> None:
    """Windows consoles still default to a code page that cannot print this.

    Window titles contain emoji and every language on earth, and the report
    contains box drawing and curly quotes.  Without this the tool does all its
    work and then dies on the last print with a UnicodeEncodeError.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "buffer"):
            continue
        try:
            setattr(sys, stream_name, io.TextIOWrapper(
                stream.buffer, encoding="utf-8", errors="replace",
                line_buffering=True))
        except (AttributeError, ValueError):
            pass


def check(settings: Settings) -> int:
    print("System Supe-Up — configuration check\n")
    print(f"settings file : {settings.path}")
    print(f"reports go to : {REPORT_DIR}\n")

    client = Ollama(settings.servers(), timeout=30)
    ok = False
    for url, models in client.available():
        if models:
            ok = True
            print(f"  [ok]   {url} — {len(models)} models")
        else:
            print(f"  [down] {url} — not reachable")

    for role, key in (("diagnosis", "diagnose_model"), ("triage", "triage_model")):
        wanted = str(settings.get(key, ""))
        server, resolved = client.resolve(wanted)
        if not server:
            print(f"  [--]   {role}: no server for '{wanted}'")
        elif resolved == wanted:
            print(f"  [ok]   {role}: {resolved}")
        else:
            print(f"  [~]    {role}: '{wanted}' not present, will use "
                  f"'{resolved}'")

    searxng = str(settings.get("searxng_url", ""))
    if searxng:
        count = Researcher(searxng).ping()
        print(f"  [{'ok' if count else 'down'}]   searxng {searxng} — "
              f"{count} results")
    else:
        print("  [--]   searxng not configured (research disabled)")

    if not ok:
        print("\nNo model server reachable. Everything still works — reports "
              "will have findings and evidence but no written narrative.")
    return 0


def one_shot(settings: Settings, watch_seconds: float, use_model: bool,
             open_report: bool) -> int:
    sampler, history = Sampler(), History(
        size=int(settings.get("history_samples", 300)))
    interval = float(settings.get("sample_interval", 1.0))
    threshold = float(settings.get("stall_threshold_s", 2.5))

    sampler.sample()
    ticks = max(1, int(watch_seconds / interval))
    print(f"Watching for {watch_seconds:.0f}s ({ticks} samples)…")

    next_tick = time.monotonic() + interval
    for index in range(ticks):
        now = time.monotonic()
        if next_tick > now:
            time.sleep(next_tick - now)
        next_tick += interval
        sample = sampler.sample(interval)
        stall = history.add(sample, threshold)
        if stall:
            print(f"  !! the machine stalled for {stall['lateness']:.1f}s")
        if index % 10 == 0:
            print(f"  {index:>4}/{ticks}  cpu {sample.cpu:5.1f}%  "
                  f"ram {sample.memory_percent:5.1f}%  "
                  f"faults {sample.hard_faults:6.0f}/s", flush=True)

    print("\nDiagnosing…")
    diagnosis = diagnose_mod.diagnose(
        history, settings, on_progress=lambda m: print(f"  · {m}", flush=True),
        use_model=use_model)

    print(f"\n{len(diagnosis.findings)} finding(s):")
    for finding in diagnosis.findings:
        print(f"  [{finding.severity_name:>8}] {finding.title}")

    if diagnosis.narrative:
        print("\n" + "─" * 72)
        print(diagnosis.narrative.strip())
        print("─" * 72)

    paths = report_mod.save(diagnosis)
    print(f"\nreport: {paths['html']}")
    print(f"        {paths['markdown']}")
    if open_report:
        webbrowser.open(paths["html"].as_uri())
    return 0


def tune_up(settings: Settings, watch_seconds: float = 8.0) -> int:
    """The other question: not what is broken, but what would be quicker.

    Needs a sample, because half of what the scan looks at is live state --
    which processes are resident, how much memory is actually free -- so it
    watches briefly first rather than reading configuration alone.
    """
    from sysup import optimise as optimise_mod

    sampler, history = Sampler(), History(size=60)
    sampler.sample()
    interval = float(settings.get("sample_interval", 1.0))
    print(f"Reading the machine for {watch_seconds:.0f}s...")
    ticks = max(1, int(watch_seconds / interval))
    for _index in range(ticks):
        time.sleep(interval)
        history.add(sampler.sample(interval),
                    float(settings.get("stall_threshold_s", 2.5)))

    tuneup = optimise_mod.scan(history.latest(),
                               on_progress=lambda m: print(f"  . {m}",
                                                           flush=True))
    if not tuneup.opportunities:
        print("\nNothing worth changing was found.")
        return 0

    print(f"\n{len(tuneup.opportunities)} thing(s) worth changing, best "
          f"first:\n")
    for number, opportunity in enumerate(tuneup.opportunities, 1):
        button = (f"[{opportunity.action_id}]" if opportunity.automatable
                  else "[no button - see below]")
        print(f"{number}. ({opportunity.gain_label}) {opportunity.title}  "
              f"{button}")
        print(f"     {opportunity.detail}")
        for item in opportunity.evidence[:3]:
            if item:
                print(f"       - {item}")
        for step in opportunity.manual_steps[:3]:
            print(f"       you: {step}")
        if opportunity.verify:
            print(f"       check: {opportunity.verify}")
        print()

    if tuneup.unavailable:
        print(f"Not checked (the reading was refused): "
              f"{', '.join(tuneup.unavailable)}\n")
    if not elevate_mod.is_admin():
        print("Running with standard rights. Each fix above that needs "
              "administrator will ask for approval on its own; "
              "`python run.py --admin --optimise` asks once.\n")
    try:
        from sysup import report as report_mod
        from sysup import sysinfo

        paths = report_mod.save_tuneup(tuneup, sysinfo.gather(
            include_events=False))
        print(f"written to: {paths['html']}")
        print(f"            {paths['markdown']}\n")
    except Exception as error:
        print(f"(could not write the report: {error})\n")

    print("Nothing above has been changed. Open the desktop interface and "
          "press Tune-up to review, preview and approve them individually.")
    return 0


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = argparse.ArgumentParser(
        prog="System Supe-Up",
        description="An AI PC monitor that explains freezes instead of "
                    "graphing them.")
    parser.add_argument("--gui", action="store_true",
                        help="open the desktop interface")
    parser.add_argument("--once", action="store_true",
                        help="diagnose immediately and write a report")
    parser.add_argument("--watch", type=float, metavar="MINUTES",
                        help="watch for this long, then diagnose")
    parser.add_argument("--check", action="store_true",
                        help="check servers and settings, then exit")
    parser.add_argument("--no-model", action="store_true",
                        help="skip the model — findings and evidence only")
    parser.add_argument("--open", action="store_true",
                        help="open the finished report in a browser")
    parser.add_argument("--optimise", "--optimize", action="store_true",
                        dest="optimise",
                        help="scan for what would make this machine quicker "
                             "and print it; changes nothing")
    parser.add_argument("--admin", action="store_true",
                        help="restart with administrator rights (a new "
                             "window opens and this one exits), then do "
                             "whatever else was asked for")
    # Set by elevate.relaunch() on the copy it starts, so a machine where
    # elevation silently fails cannot relaunch itself for ever.
    parser.add_argument(elevate_mod.RELAUNCH_FLAG, action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--bridge", action="store_true",
                        help="stream every stage to ~/SystemSupeUp/live so it "
                             "can be watched from outside")
    args = parser.parse_args(argv)

    # Started before anything else so the very first sample is on the feed.
    if args.bridge:
        feed = bridge_mod.start()
        print(f"live bridge: {feed.directory}\n"
              f"  watch it with:  python tools/watch.py")
    else:
        bridge_mod.start_if_requested()

    settings = Settings.load()
    if not settings.path.exists():
        settings.save()      # so it can be edited after the first run

    # Asked for explicitly, or configured as "always". Everything works
    # unelevated, so a refusal here is a note and not an error.
    if args.admin or elevate_mod.should_elevate_at_startup(settings):
        if elevate_mod.is_admin():
            print("Already running as administrator.\n")
        else:
            started, why = elevate_mod.relaunch()
            if started:
                return 0
            print(f"Carrying on without administrator rights: {why}\n")

    if args.check:
        return check(settings)
    if args.optimise:
        return tune_up(settings)
    if args.gui:
        from sysup.gui import main as gui_main
        return gui_main(settings)
    if args.once or args.watch:
        seconds = (args.watch * 60) if args.watch else 25.0
        return one_shot(settings, seconds, not args.no_model, args.open)

    from sysup.ui import Dashboard
    try:
        Dashboard(settings).run()
    except KeyboardInterrupt:
        pass
    finally:
        bridge_mod.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
