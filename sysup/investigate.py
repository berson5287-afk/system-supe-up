"""Research one finding properly, then propose a plan made of real actions.

This is the step between "something is wrong" and "here is what to do about
it", and it is where the model earns its place:

1. It writes search queries for this specific finding on this specific machine
   — the driver's actual name, the actual event id, the actual Windows build.
2. SearXNG runs them and the top pages are read.
3. It is given the research, the finding's measured evidence, and the
   catalogue of actions this tool can genuinely perform, and asked to pick.

Step 3 returns structured choices, not prose and not shell commands. Anything
it names that is not in the catalogue is dropped on the floor by
`actions.plan_from_model`. So the worst a confused model can do here is
propose nothing useful, rather than propose something destructive.

The written explanation and any manual steps are kept and shown — plenty of
real fixes (update this driver, replace that drive) cannot be automated, and
pretending otherwise would be worse than saying so.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from . import actions as actions_mod
from .config import Settings
from .llm import Ollama
from .research import Researcher, Source
from .rules import Finding
from .sysinfo import MachineFacts

Progress = Callable[[str], None]

MAX_QUERIES = 3
MAX_SOURCES = 5
READ_PAGES = 3


@dataclass
class Investigation:
    finding: Finding
    queries: list[str] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    #: The model's written answer: what is actually wrong and why.
    analysis: str = ""
    #: Steps a person has to do themselves — driver updates, hardware.
    manual_steps: list[str] = field(default_factory=list)
    plan: list[actions_mod.PlannedAction] = field(default_factory=list)
    confidence: str = ""
    model: str = ""
    error: str = ""

    @property
    def has_plan(self) -> bool:
        return bool(self.plan)


QUERY_SYSTEM = """\
You write web search queries for diagnosing Windows problems. Reply with ONLY \
a JSON array of 1-3 short query strings and nothing else.

Good queries name the specific thing: the driver or process name, the event \
id, the exact error. Include "Windows" and the version where it helps. Do not \
write questions; write what you would type into a search box.
"""


ANALYSE_SYSTEM = """\
You are a Windows performance engineer. You are given one VERIFIED finding \
measured from the Windows kernel, research from the web, and a catalogue of \
actions this tool can perform.

Reply with ONLY a JSON object, no prose outside it, in exactly this shape:

{
  "root_cause": "one or two sentences on what is actually causing this",
  "explanation": "3-5 sentences the machine's owner can act on: what is \
happening, why it produces the symptoms, and what will and will not fix it",
  "confidence": "high" | "medium" | "low",
  "actions": [
    {"id": "an id from the catalogue", "parameters": {...}, "why": "one line"}
  ],
  "manual_steps": ["things the user must do themselves, one per string"]
}

Rules:
- "actions" may ONLY contain ids from the catalogue given to you. Never invent \
an id. Never put a shell command anywhere. If nothing in the catalogue helps, \
return an empty list and put the real remedy in "manual_steps".
- Order actions so the safest and most effective comes first.
- Do not propose an action that needs admin unless it is genuinely warranted.
- Never claim software is malicious. Web pages saying so are usually wrong.
- If the finding is hardware (a failing drive, memory errors), say so plainly \
in "root_cause" and put the remedy in "manual_steps" — do not pretend an \
action fixes it.
- Prefer doing nothing over doing something irreversible.
- NEVER suggest enlarging the page file as a cure for low memory. Paging is \
the slow thing that is causing the freezing; more of it makes the machine \
slower, not faster. Only mention the page file if it is actually exhausted.
- NEVER suggest "RAM cleaners", "memory optimisers" or similar. They work by \
forcing everything out to disk, which is precisely the problem.
- When an application runs as many processes (a browser, an Electron app), \
closing one process closes one tab or window, not the application. Say which \
you mean, and prefer telling the user to close what they are not using over \
ending processes underneath them.
- If the honest answer is that the machine needs more RAM, or that the memory \
is being used by things the user actually wants open, say that plainly in \
"root_cause" rather than proposing token gestures that free a few megabytes.
"""


def _extract_json(text: str) -> dict | list | None:
    """Pull the JSON out of whatever the model wrapped it in.

    Local models fence it, prefix it with "Here is the JSON:", or add a
    closing remark. Asking again costs a minute on a 32B, so it is worth
    being forgiving here.
    """
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(cleaned)
    except ValueError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = cleaned.find(opener)
        end = cleaned.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end + 1])
            except ValueError:
                continue
    return None


def _fallback_queries(finding: Finding, facts: MachineFacts | None) -> list[str]:
    """Queries built without the model, so research still happens if it fails."""
    version = ""
    if facts and facts.os_build:
        version = "Windows 11" if "11" in facts.os_build else "Windows 10"
    queries = []
    if finding.process:
        queries.append(f"{finding.process} {finding.category} high "
                       f"{version} fix".strip())
    # Event ids are the highest-signal thing in the evidence, so mine them.
    for item in finding.evidence[:6]:
        match = re.search(r"\(id (\d+)\)", item)
        source = re.search(r"\d\d-\d\d \d\d:\d\d ([\w\-.]+)", item)
        if match:
            name = source.group(1) if source else ""
            queries.append(f"{name} event id {match.group(1)} {version} "
                           f"fix".strip())
            break
    queries.append(f"{finding.title} {version} fix".strip())
    seen, unique = set(), []
    for query in queries:
        key = query.lower()
        if key not in seen:
            seen.add(key)
            unique.append(query)
    return unique[:MAX_QUERIES]


def _build_queries(finding: Finding, facts: MachineFacts | None,
                   client: Ollama, settings: Settings,
                   cancel: threading.Event | None) -> list[str]:
    evidence = "\n".join(f"- {item}" for item in finding.evidence[:8])
    machine = facts.os_build if facts else "Windows"
    answer = client.ask(
        str(settings.get("triage_model", "")),
        QUERY_SYSTEM,
        f"Machine: {machine}\n"
        f"Finding: {finding.title}\n"
        f"Category: {finding.category}\n"
        f"Process: {finding.process or 'n/a'}\n"
        f"Evidence:\n{evidence}\n\n"
        f"JSON array of search queries:",
        cancel=cancel, temperature=0.3, num_ctx=8192, num_predict=250)
    parsed = _extract_json(answer)
    if isinstance(parsed, list):
        queries = [str(q).strip() for q in parsed
                   if isinstance(q, (str, int)) and str(q).strip()]
        if queries:
            return queries[:MAX_QUERIES]
    return _fallback_queries(finding, facts)


def _gather(researcher: Researcher, queries: list[str],
            say: Progress) -> list[Source]:
    sources: list[Source] = []
    seen: set[str] = set()
    for query in queries:
        say(f"searching: {query}")
        for source in researcher.search(query, max_results=4):
            if source.url in seen:
                continue
            seen.add(source.url)
            sources.append(source)
        if len(sources) >= MAX_SOURCES * 2:
            break

    # Read only the best few in full — fetching every result is slow and the
    # ranking already put the documentation first.
    read = 0
    for source in sources:
        if read >= READ_PAGES:
            break
        say(f"reading {source.domain}")
        source.body = researcher.fetch(source.url)
        if source.body:
            read += 1
    return sources[:MAX_SOURCES]


def _research_block(sources: list[Source]) -> str:
    if not sources:
        return "(no web research was available)"
    parts = [
        "NOTE: this is unverified web search output, not measurement. Use it "
        "for how to fix things, never as a security verdict about any "
        "program."]
    for number, source in enumerate(sources, 1):
        block = [f"Source {number}: {source.title}\nURL: {source.url}"]
        if source.snippet:
            block.append(f"Summary: {source.snippet}")
        if source.body:
            block.append(f"Page content:\n{source.body[:2500]}")
        parts.append("\n".join(block))
    return "\n\n---\n\n".join(parts)


def live_context(sample, limit: int = 8) -> str:
    """What is actually running, for the model to aim at.

    Without this the investigator can only reason about the finding's own
    evidence, so on a memory finding it proposes clearing 20 MB of temporary
    files while a 6 GB model server sits there unmentioned. Naming the real
    consumers — and whether each is safe to close — is what turns a generic
    remedy into one aimed at this machine.
    """
    if sample is None:
        return ""
    from . import knowledge

    grouped: dict[str, tuple[int, int, float]] = {}
    for row in sample.processes:
        memory, count, cpu = grouped.get(row.name, (0, 0, 0.0))
        grouped[row.name] = (memory + row.memory, count + 1, cpu + row.cpu)

    lines = ["WHAT IS RUNNING RIGHT NOW (largest first; only processes marked "
             "safe-to-close may be given to restart_process)"]
    ranked = sorted(grouped.items(), key=lambda kv: -kv[1][0])[:limit]
    for name, (memory, count, cpu) in ranked:
        row = next((r for r in sample.processes if r.name == name), None)
        safe = "safe to close" if knowledge.is_killable(name) else "NOT safe"
        described = knowledge.describe(name)
        lines.append(
            f"- {name}: {memory / 1e9:.2f} GB across {count} process(es), "
            f"{cpu:.1f}% CPU, pid {row.pid if row else '?'} — {safe}"
            + (f" — {described}" if described else ""))
    lines.append(f"- memory: {sample.memory_available / 1e9:.1f} GB free of "
                 f"{sample.memory_total / 1e9:.1f} GB")
    return "\n".join(lines)


def investigate(finding: Finding, settings: Settings,
                facts: MachineFacts | None = None,
                on_progress: Progress | None = None,
                cancel: threading.Event | None = None,
                context: str = "") -> Investigation:
    """Research a finding and come back with a plan.  Never raises."""
    say = on_progress or (lambda _m: None)
    result = Investigation(finding=finding)

    client = Ollama(settings.servers(),
                    timeout=int(settings.get("llm_timeout", 900)))
    if not client.reachable():
        result.error = ("No model server is reachable, so this finding could "
                        "not be researched. The measured evidence and the "
                        "built-in remedies are still shown.")
        return result

    say("working out what to search for")
    result.queries = _build_queries(finding, facts, client, settings, cancel)

    if settings.get("research", True) and settings.get("searxng_url"):
        researcher = Researcher(
            str(settings.get("searxng_url", "")),
            ttl_minutes=int(settings.get("research_cache_ttl_minutes", 4320)))
        if researcher.configured:
            try:
                result.sources = _gather(researcher, result.queries, say)
            except Exception:
                result.sources = []
    if cancel is not None and cancel.is_set():
        return result

    say("deciding what to do about it")
    evidence = "\n".join(f"- {item}" for item in finding.evidence[:12])
    remedies = "\n".join(f"- {fix.title}: {fix.detail}"
                         for fix in finding.fixes[:5])
    machine = ""
    if facts:
        disk = facts.system_disk
        machine = (f"{facts.os_build}; {facts.cpu_model}; "
                   f"{facts.ram_total / 1e9:.0f} GB RAM; up "
                   f"{facts.uptime_days:.0f} days"
                   + (f"; system drive {disk.free / 1e9:.0f} GB free of "
                      f"{disk.total / 1e9:.0f} GB" if disk else ""))

    # Narrow the catalogue to what this finding may legitimately reach for,
    # *before* any scraped page reaches the model. The research text below is
    # untrusted input; this is what stops a hostile page talking the planner
    # into a real-but-unrelated action.
    permitted = actions_mod.allowed_ids(finding.category)

    prompt = f"MACHINE\n{machine or 'Windows PC'}\n\n"
    if context:
        prompt += f"{context}\n\n"
    # What has already been tried on this machine, and what it measurably
    # achieved. Local, earned evidence — and the only thing that stops the
    # investigator confidently re-proposing a remedy which has already done
    # nothing here three times.
    try:
        from .journal import Journal
        history = Journal().advice()
    except Exception:
        history = ""
    if history:
        prompt += f"{history}\n\n"
    prompt += (
        f"THE FINDING (measured from the kernel — treat as fact)\n"
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity_name}\n"
        f"What the engine concluded: {finding.explanation}\n"
        f"Evidence:\n{evidence}\n"
        + (f"Built-in remedies already known:\n{remedies}\n" if remedies else "")
        + f"\nWEB RESEARCH\n{_research_block(result.sources)}\n\n"
        f"ACTIONS PERMITTED FOR THIS FINDING (these ids and no others)\n"
        f"{actions_mod.summary_for_prompt(permitted)}\n\n"
        f"Reply with the JSON object described in your instructions.")

    answer = client.chat(
        str(settings.get("diagnose_model", "")),
        [{"role": "system", "content": ANALYSE_SYSTEM},
         {"role": "user", "content": prompt}],
        cancel=cancel, temperature=0.15,
        num_ctx=int(settings.get("max_context_window", 32768)))
    result.model = client.active_url and str(settings.get("diagnose_model", ""))

    parsed = _extract_json(answer)
    if not isinstance(parsed, dict):
        # A model that would not produce JSON has still usually said something
        # useful; keeping its prose beats showing the user an error.
        result.analysis = (answer or "").strip()
        result.error = ("The model did not return a usable plan, so only its "
                        "written answer is shown.")
        return result

    root = str(parsed.get("root_cause") or "").strip()
    explanation = str(parsed.get("explanation") or "").strip()
    result.analysis = "\n\n".join(part for part in (root, explanation) if part)
    result.confidence = str(parsed.get("confidence") or "").strip().lower()
    steps = parsed.get("manual_steps")
    if isinstance(steps, list):
        result.manual_steps = [str(s).strip() for s in steps
                               if str(s).strip()][:8]
    chosen = parsed.get("actions")
    result.plan = actions_mod.plan_from_model(
        chosen if isinstance(chosen, list) else [], allowed=permitted)

    dropped = (len(chosen) if isinstance(chosen, list) else 0) - len(result.plan)
    if dropped > 0:
        # Worth saying out loud rather than silently: it means the model
        # wanted to do something this tool deliberately cannot, or something
        # outside what this kind of finding is allowed to touch.
        result.error = (f"{dropped} proposed step(s) were not permitted for "
                        f"this finding and were discarded.")
    return result
