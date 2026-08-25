"""Turning evidence into a diagnosis.

The order matters and is the whole design:

1. The rules engine decides what is wrong.  It is deterministic and offline.
2. Anything it could not identify gets looked up through SearXNG.
3. The model is handed the *findings*, not the raw numbers, and asked to
   explain them, connect them and put them in order.

Step 3 cannot introduce a false finding, because the model is never asked to
find anything — it is asked to explain a list it is told is already verified.
That is the difference between a tool that occasionally invents a plausible
culprit and one that does not.  It also means every part of the report except
the narrative survives the Ollama box being switched off.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import knowledge, research as research_mod, rules, sysinfo
from .bridge import bridge
from .collect import History, Sample
from .config import Settings
from .knowledge import Fix
from .llm import Ollama
from .rules import Finding

Progress = Callable[[str], None]


SYSTEM_PROMPT = """\
You are a Windows performance engineer writing for the person who owns the \
machine. They are competent but not a kernel developer.

You will be given findings that a local diagnostic engine has ALREADY \
VERIFIED against live kernel data. Your job is to explain and connect them — \
not to detect problems.

Rules you must follow:
- Never contradict a finding or claim it is not real. The measurements are \
from the Windows kernel and are not in doubt.
- Never invent a process, number, event or symptom that is not in the \
evidence. If something is not there, say it is not known.
- Connect the findings into one story where they are related. Most slow PCs \
have one root cause and several symptoms; say which is which, and be \
explicit that fixing a symptom will not help.
- Lead with the single thing most worth doing.
- Never suggest ending a process the evidence marks as essential, and never \
suggest registry edits, "PC cleaner" or "optimiser" software, or disabling \
security software without saying plainly what the trade-off is.
- NEVER call a program malicious, a virus, spyware or suspicious. Web search \
results routinely say this about ordinary software and are usually wrong; \
repeating it would be a serious error. Web research tells you only what a \
program is and who makes it. If a process is genuinely unrecognised, say it \
is unrecognised and suggest checking its file location and digital signature \
— nothing stronger.
- Performance findings are never evidence about security. A program using \
memory or CPU is a program doing work.
- Plain language, contractions, short paragraphs. No preamble, no restating \
the question, no bullet-point dumps of what you were given.
- Do not use headings above level 3. Do not write a conclusion that merely \
repeats what you said.
"""


@dataclass
class Diagnosis:
    at: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    facts: sysinfo.MachineFacts | None = None
    #: The model's narrative.  Empty when no server was reachable, which is a
    #: degraded report rather than a failed one.
    narrative: str = ""
    model: str = ""
    server: str = ""
    researched: dict[str, research_mod.ProcessResearch] = field(
        default_factory=dict)
    duration_s: float = 0.0
    sample_count: int = 0
    watched_s: float = 0.0

    @property
    def worst(self) -> Finding | None:
        return self.findings[0] if self.findings else None

    def by_severity(self, minimum: int = 1) -> list[Finding]:
        return [f for f in self.findings if f.severity >= minimum]

    def headline(self) -> str:
        if not self.findings:
            return "Nothing wrong found while watching."
        return self.findings[0].title


def _finding_from_static(raw: dict) -> Finding:
    return Finding(
        id=raw["id"], title=raw["title"], severity=raw["severity"],
        confidence=raw["confidence"], category=raw["category"],
        explanation=raw["explanation"], evidence=list(raw.get("evidence", [])),
        fixes=[Fix(title=t, detail=d, command=c)
               for t, d, c in raw.get("fixes", [])])


def _unknown_processes(findings: list[Finding], sample: Sample,
                       limit: int = 3) -> list[str]:
    """Processes worth a web lookup: implicated, and not in the table."""
    names: list[str] = []
    for finding in findings:
        name = finding.process
        if not name or knowledge.lookup(name):
            continue
        if name.lower() in {n.lower() for n in names}:
            continue
        names.append(name)

    # Also worth explaining: anything sizeable the user probably cannot name.
    for row in sorted(sample.processes, key=lambda r: -(r.cpu + r.memory / 1e9))[:12]:
        if len(names) >= limit:
            break
        if knowledge.lookup(row.name) or row.pid <= 4:
            continue
        if row.cpu < 2 and row.memory < 300e6:
            continue
        if row.name.lower() not in {n.lower() for n in names}:
            names.append(row.name)
    return names[:limit]


def build_brief(findings: list[Finding], facts: sysinfo.MachineFacts,
                sample: Sample, history: History,
                researched: dict[str, research_mod.ProcessResearch]) -> str:
    """The evidence pack handed to the model.

    Written as prose-with-numbers rather than JSON: local models follow a
    readable brief far more reliably than they parse a nested object, and the
    failure mode of a misread brief is a vague paragraph rather than a
    hallucinated schema.
    """
    lines: list[str] = []

    lines.append("## The machine")
    lines.append(f"- {facts.os_build}")
    lines.append(f"- {facts.cpu_model} ({facts.cpu_cores} cores / "
                 f"{facts.cpu_threads} threads)")
    lines.append(f"- {facts.ram_total / 1e9:.1f} GB RAM installed")
    lines.append(f"- up for {facts.uptime_days:.1f} days")
    if facts.power_plan:
        lines.append(f"- power plan: {facts.power_plan}")
    if facts.throttle_percent:
        lines.append(f"- CPU clock: {facts.cpu_freq_current:.0f} MHz of "
                     f"{facts.cpu_freq_max:.0f} MHz rated "
                     f"({facts.throttle_percent:.0f}%)")
    disk = facts.system_disk
    if disk:
        lines.append(f"- system drive: {disk.free / 1e9:.0f} GB free of "
                     f"{disk.total / 1e9:.0f} GB")
    lines.append(f"- {len(facts.startup)} programs start at sign-in")

    lines.append("\n## What was measured while watching")
    minutes = (history.count * sample.interval) / 60
    lines.append(f"- watched for {minutes:.1f} minutes "
                 f"({history.count} samples)")
    lines.append(f"- CPU: {history.average('cpu', 120):.0f}% average, "
                 f"{history.peak('cpu', 120):.0f}% peak")
    lines.append(f"- memory: {sample.memory_percent:.0f}% used, "
                 f"{sample.memory_available / 1e9:.1f} GB available of "
                 f"{sample.memory_total / 1e9:.1f} GB")
    lines.append(f"- hard page faults: {history.average('hard_faults', 120):.0f}/s "
                 f"average, {history.peak('hard_faults', 120):.0f}/s peak")
    lines.append(f"- disk busy: {history.average('disk_busy', 120):.0f}% average")
    if history.stalls:
        worst = max(history.stalls, key=lambda s: s["lateness"])
        lines.append(f"- {len(history.stalls)} measured whole-system stall(s), "
                     f"worst {worst['lateness']:.1f} seconds of unscheduled time")
    else:
        lines.append("- no whole-system stalls were measured during this window")

    lines.append("\n## Biggest processes right now")
    for row in sample.by_memory(8):
        described = knowledge.describe(row.name)
        lines.append(
            f"- {row.name} (pid {row.pid}): "
            f"{row.memory / 1e6:.0f} MB, {row.cpu:.1f}% CPU, "
            f"{row.threads} threads"
            + (f" — {described}" if described else "")
            + (f" — window “{row.title[:50]}”" if row.title else ""))

    lines.append("\n## VERIFIED FINDINGS (these are measured facts, not guesses)")
    for number, finding in enumerate(findings, 1):
        lines.append(f"\n### {number}. [{finding.severity_name}] {finding.title}")
        lines.append(f"What it means: {finding.explanation}")
        if finding.evidence:
            lines.append("Evidence:")
            lines += [f"  - {item}" for item in finding.evidence]
        if finding.fixes:
            lines.append("Known remedies:")
            lines += [f"  - {fix.title}: {fix.detail}"
                      for fix in finding.fixes[:4]]

    if researched:
        lines.append("\n## Web research on processes not in the built-in table")
        for name, result in researched.items():
            lines.append(f"\n### {name}")
            lines.append(result.as_context(limit=3))

    if facts.events:
        lines.append("\n## Recent system event log entries")
        for event in facts.events[:12]:
            when = time.strftime("%m-%d %H:%M", time.localtime(event.when))
            lines.append(f"- {when} {event.source} (id {event.event_id}) "
                         f"{event.level}: {event.meaning or event.message[:120]}")

    return "\n".join(lines)


USER_TEMPLATE = """\
Here is everything measured on this Windows PC.

{brief}

Write the explanation the owner of this machine needs. Cover, in this order:

1. **What is actually wrong.** One short paragraph. If several findings share \
one root cause, say so and name it.
2. **Why it feels the way it does.** Connect the measurements to what the \
person actually experiences — the freezing, the waiting, the app that stops \
responding. Explain the mechanism, so they understand why the CPU graph can \
look calm while the machine is unusable.
3. **What to do, in order.** Number them. Put the one thing with the biggest \
effect first, and say what each will and will not fix. Be honest when \
something is a workaround rather than a cure.
4. **What to watch for next.** How they will know it worked, and what would \
mean the problem is something else.

Do not repeat the raw numbers back as a list — use them inside your sentences \
as support.
"""


def diagnose(history: History, settings: Settings,
             sample: Sample | None = None,
             on_progress: Progress | None = None,
             cancel: threading.Event | None = None,
             on_token: Callable[[str], None] | None = None,
             use_model: bool = True) -> Diagnosis:
    """The full pipeline.  Never raises; a degraded report is still a report."""
    say = on_progress or (lambda _m: None)
    started = time.perf_counter()
    sample = sample or history.latest()
    result = Diagnosis(sample_count=history.count)
    if sample is None:
        return result
    result.watched_s = history.count * sample.interval

    feed = bridge()
    feed.emit("diagnose.begin", samples=history.count,
              watched_s=round(result.watched_s, 1), use_model=use_model)

    say("reading machine configuration and event log")
    with feed.span("diagnose.facts") as note:
        facts = sysinfo.gather()
        note(events=len(facts.events), startup=len(facts.startup))
    result.facts = facts

    say("running the diagnostic rules")
    findings = list(rules.analyse(history, sample))
    static = [_finding_from_static(raw) for raw in sysinfo.static_findings(facts)]
    feed.emit("rules.static", fired=len(static),
              titles=[f.title for f in static])
    findings += static
    findings.sort(key=lambda f: f.sort_key())
    result.findings = findings

    if settings.get("research", True) and (cancel is None or not cancel.is_set()):
        researcher = research_mod.Researcher(
            settings.get("searxng_url", ""),
            ttl_minutes=int(settings.get("research_cache_ttl_minutes", 4320)))
        if researcher.configured:
            for name in _unknown_processes(findings, sample):
                if cancel is not None and cancel.is_set():
                    break
                say(f"looking up {name}")
                feed.emit("research.process", name=name)
                found = researcher.identify(name, emit=lambda m: say(m))
                if found and found.sources:
                    result.researched[name] = found

    if not use_model or (cancel is not None and cancel.is_set()):
        result.duration_s = time.perf_counter() - started
        return result

    say("asking the model to explain it")
    client = Ollama(settings.servers(),
                    timeout=int(settings.get("llm_timeout", 900)))
    if not client.reachable():
        say("no Ollama server reachable — report will have no narrative")
        result.duration_s = time.perf_counter() - started
        return result

    brief = build_brief(findings, facts, sample, history, result.researched)
    wanted = str(settings.get("diagnose_model", ""))
    server, model = client.resolve(wanted)
    result.model, result.server = model, server
    say(f"using {model} on {server}")

    narrative = client.chat(
        wanted,
        [{"role": "system", "content": SYSTEM_PROMPT},
         {"role": "user", "content": USER_TEMPLATE.format(brief=brief)}],
        on_token=on_token, cancel=cancel,
        temperature=float(settings.get("temperature", 0.2)),
        num_ctx=int(settings.get("max_context_window", 32768)),
        purpose="diagnosis narrative")
    result.narrative = narrative
    result.duration_s = time.perf_counter() - started
    feed.emit("diagnose.end", findings=len(findings),
              narrative_chars=len(narrative),
              duration_s=round(result.duration_s, 1), model=model)
    return result


# ------------------------------------------------------------ quick triage

TRIAGE_SYSTEM = """\
You are a Windows performance engineer. Answer in at most three sentences, \
plainly, with no preamble. You are given verified measurements; do not invent \
anything not present in them, and do not contradict them.
"""


def triage(finding: Finding, settings: Settings,
           cancel: threading.Event | None = None) -> str:
    """A short second opinion on one finding, using the fast model.

    Used from the live view, where a paragraph is welcome and a full report is
    not.  Falls back to the rule's own explanation when no server answers, so
    the caller never has to handle an empty string.
    """
    client = Ollama(settings.servers(), timeout=120)
    if not client.reachable():
        return finding.explanation

    evidence = "\n".join(f"- {item}" for item in finding.evidence)
    answer = client.ask(
        str(settings.get("triage_model", "")),
        TRIAGE_SYSTEM,
        f"Finding: {finding.title}\n"
        f"Process: {finding.process or 'n/a'}\n"
        f"What the engine concluded: {finding.explanation}\n"
        f"Evidence:\n{evidence}\n\n"
        f"In three sentences or fewer: what should the owner of this machine "
        f"do about this right now, and what will it actually change?",
        cancel=cancel, temperature=0.2, num_ctx=8192, num_predict=300,
        purpose=f"triage: {finding.id}")
    return answer or finding.explanation
