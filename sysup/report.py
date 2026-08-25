"""Writing the diagnosis out as Markdown and as a self-contained HTML page.

Always UTF-8, explicitly.  Window titles routinely contain emoji, curly quotes
and characters from whatever language the user works in, and Python on Windows
defaults to the ANSI code page — which turns a report into a UnicodeEncodeError
at the last possible moment, after all the work is done.
"""

from __future__ import annotations

import html
import re
import time
from pathlib import Path

from .config import REPORT_DIR
from .diagnose import Diagnosis
from .rules import Finding

SEVERITY_LABEL = {5: "CRITICAL", 4: "SERIOUS", 3: "MODERATE", 2: "MINOR",
                  1: "INFO"}
SEVERITY_COLOUR = {5: "#b4232c", 4: "#c8621b", 3: "#b58900", 2: "#4a7ba7",
                   1: "#6b7280"}


def _stamp(at: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(at))


def _slug(at: float) -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime(at))


# ---------------------------------------------------------------- markdown

def to_markdown(diagnosis: Diagnosis) -> str:
    out: list[str] = []
    facts = diagnosis.facts

    out.append("# System Supe-Up — diagnosis")
    out.append(f"\n*{_stamp(diagnosis.at)}"
               + (f" · {facts.computer}" if facts and facts.computer else "")
               + "*\n")

    if diagnosis.findings:
        worst = diagnosis.findings[0]
        out.append(f"> **{worst.title}**\n>\n> {worst.explanation}\n")
    else:
        out.append("> Nothing wrong was found during this window. If the "
                   "machine misbehaves intermittently, leave the monitor "
                   "running and diagnose again while it is happening.\n")

    if facts:
        out.append("## The machine\n")
        out.append(f"| | |\n|---|---|")
        out.append(f"| Operating system | {facts.os_build} |")
        out.append(f"| Processor | {facts.cpu_model} "
                   f"({facts.cpu_cores}C/{facts.cpu_threads}T) |")
        out.append(f"| Memory | {facts.ram_total / 1e9:.1f} GB |")
        out.append(f"| Uptime | {facts.uptime_days:.1f} days |")
        if facts.power_plan:
            out.append(f"| Power plan | {facts.power_plan} |")
        disk = facts.system_disk
        if disk:
            out.append(f"| System drive | {disk.free / 1e9:.0f} GB free of "
                       f"{disk.total / 1e9:.0f} GB |")
        out.append(f"| Starts at sign-in | {len(facts.startup)} programs |")
        out.append(f"| Watched for | {diagnosis.watched_s / 60:.1f} minutes "
                   f"({diagnosis.sample_count} samples) |")
        out.append("")

    if diagnosis.narrative:
        out.append("## What is going on\n")
        out.append(diagnosis.narrative.strip() + "\n")

    out.append(f"## Findings ({len(diagnosis.findings)})\n")
    for number, finding in enumerate(diagnosis.findings, 1):
        out.append(f"### {number}. {finding.title}")
        out.append(f"`{SEVERITY_LABEL.get(finding.severity, '?')}` · "
                   f"confidence {finding.confidence:.0%} · {finding.category}"
                   + (f" · {finding.process} (pid {finding.pid})"
                      if finding.pid else "") + "\n")
        out.append(finding.explanation + "\n")
        if finding.evidence:
            out.append("**Evidence**\n")
            out += [f"- {item}" for item in finding.evidence]
            out.append("")
        if finding.fixes:
            out.append("**What to do**\n")
            for fix in finding.fixes:
                flags = []
                if fix.risk != "low":
                    flags.append(fix.risk + " risk")
                if fix.needs_admin:
                    flags.append("needs admin")
                suffix = f" *({', '.join(flags)})*" if flags else ""
                out.append(f"- **{fix.title}**{suffix} — {fix.detail}")
                if fix.command:
                    out.append(f"  ```\n  {fix.command}\n  ```")
            out.append("")

    if diagnosis.researched:
        out.append("## Processes looked up on the web\n")
        for name, found in diagnosis.researched.items():
            out.append(f"### {name}")
            for source in found.sources[:4]:
                out.append(f"- [{source.title}]({source.url})"
                           + (f" — {source.snippet[:160]}"
                              if source.snippet else ""))
            out.append("")

    if facts and facts.events:
        out.append("## Recent system event log\n")
        out.append("| When | Source | ID | What it means |")
        out.append("|---|---|---|---|")
        for event in facts.events[:20]:
            meaning = (event.meaning or event.message[:100] or "—")
            out.append(f"| {_stamp(event.when)[5:16]} | {event.source} | "
                       f"{event.event_id} | {meaning} |")
        out.append("")

    if facts and facts.startup:
        out.append(f"## Starts at sign-in ({len(facts.startup)})\n")
        out.append("| Name | Scope | Command |")
        out.append("|---|---|---|")
        for item in facts.startup:
            out.append(f"| {item.name} | {item.scope} | "
                       f"`{item.command[:110]}` |")
        out.append("")

    footer = ["---", ""]
    if diagnosis.model:
        footer.append(f"*Narrative written by `{diagnosis.model}` on "
                      f"{diagnosis.server}. Findings and evidence are from "
                      f"direct kernel measurement and do not depend on it.*")
    else:
        footer.append("*No model was available, so this report has findings "
                      "and evidence but no narrative. They are measured "
                      "either way.*")
    footer.append(f"\n*Diagnosis took {diagnosis.duration_s:.1f}s.*")
    out += footer
    return "\n".join(out)


# -------------------------------------------------------------------- HTML

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font: 15px/1.65 -apple-system, "Segoe UI", Roboto, system-ui, sans-serif;
  max-width: 62rem; margin: 0 auto; padding: 2.5rem 1.5rem 6rem;
  background: #fbfbfa; color: #1f2328;
}
h1 { font-size: 1.9rem; margin: 0 0 .25rem; letter-spacing: -.02em; }
h2 { font-size: 1.3rem; margin: 2.6rem 0 .9rem; padding-bottom: .35rem;
     border-bottom: 1px solid #e2e2df; letter-spacing: -.01em; }
h3 { font-size: 1.05rem; margin: 1.8rem 0 .4rem; }
.sub { color: #6b7280; margin: 0 0 2rem; font-size: .9rem; }
.headline { background: #fff; border: 1px solid #e2e2df; border-left: 4px solid #b4232c;
            padding: 1.1rem 1.3rem; border-radius: 6px; margin: 0 0 2rem; }
.headline strong { display: block; font-size: 1.1rem; margin-bottom: .45rem; }
table { border-collapse: collapse; width: 100%; margin: .6rem 0 1.2rem;
        font-size: .9rem; }
th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid #ebebe8;
         vertical-align: top; }
th { font-weight: 600; color: #4b5563; background: #f4f4f2; }
td code { font-size: .82em; word-break: break-all; }
.finding { background: #fff; border: 1px solid #e2e2df; border-radius: 6px;
           padding: 1.1rem 1.3rem; margin: 0 0 1rem; }
.finding.sev5 { border-left: 4px solid #b4232c; }
.finding.sev4 { border-left: 4px solid #c8621b; }
.finding.sev3 { border-left: 4px solid #b58900; }
.finding.sev2 { border-left: 4px solid #4a7ba7; }
.finding.sev1 { border-left: 4px solid #9ca3af; }
.finding h3 { margin: 0 0 .5rem; }
.tags { font-size: .78rem; color: #6b7280; margin-bottom: .8rem; }
.pill { display: inline-block; padding: .1rem .5rem; border-radius: 99px;
        background: #ececeb; margin-right: .4rem; font-weight: 600;
        letter-spacing: .03em; }
ul.evidence { margin: .4rem 0 .9rem; padding-left: 1.2rem; color: #374151;
              font-size: .89rem; }
ul.evidence li { margin: .15rem 0; }
.fix { border-top: 1px solid #f0f0ee; padding-top: .7rem; margin-top: .7rem; }
.fix b { display: block; }
.risk { font-size: .74rem; text-transform: uppercase; letter-spacing: .05em;
        padding: .05rem .4rem; border-radius: 3px; margin-left: .4rem; }
.risk.medium { background: #fdf0d5; color: #8a5a00; }
.risk.high { background: #fbe3e4; color: #9b1c22; }
.admin { background: #e8eef7; color: #274b78; }
pre { background: #f4f4f2; border: 1px solid #e6e6e3; border-radius: 4px;
      padding: .6rem .8rem; overflow-x: auto; font-size: .84rem; margin: .5rem 0; }
code { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
.narrative { background: #fff; border: 1px solid #e2e2df; border-radius: 6px;
             padding: 1.2rem 1.4rem; }
.narrative p { margin: 0 0 .9rem; }
.narrative p:last-child { margin-bottom: 0; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e2e2df;
         color: #6b7280; font-size: .85rem; }
a { color: #1a5fb4; }
@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #e3e5e8; }
  h2 { border-color: #2c3036; }
  .headline, .finding, .narrative { background: #1c1f24; border-color: #2c3036; }
  th { background: #23262c; color: #9aa3af; }
  th, td { border-color: #2c3036; }
  .pill { background: #2c3036; color: #cbd2da; }
  pre { background: #23262c; border-color: #2c3036; }
  .fix { border-color: #2c3036; }
  ul.evidence { color: #b6bcc5; }
  .sub, footer { color: #9aa3af; }
  a { color: #7cb0f0; }
}
@media print { body { max-width: none; } .finding { break-inside: avoid; } }
"""


def _paragraphs(text: str) -> str:
    """Markdown-ish narrative to HTML, without pulling in a dependency."""
    blocks = []
    for block in (text or "").split("\n\n"):
        block = block.strip()
        if not block:
            continue
        escaped = html.escape(block)
        # bold, then inline code — enough for what the prompt asks for.
        escaped = escaped.replace("&#x27;", "'")
        import re
        escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
        escaped = re.sub(r"`([^`]+?)`", r"<code>\1</code>", escaped)
        if block.startswith("###"):
            blocks.append(f"<h3>{escaped.lstrip('# ')}</h3>")
        elif block.lstrip().startswith(("- ", "* ", "1.", "2.", "3.", "4.")):
            items = [line.strip().lstrip("-*0123456789. ")
                     for line in escaped.splitlines() if line.strip()]
            blocks.append("<ul>" + "".join(f"<li>{i}</li>" for i in items)
                          + "</ul>")
        else:
            blocks.append(f"<p>{escaped.replace(chr(10), '<br>')}</p>")
    return "\n".join(blocks)


def _finding_html(number: int, finding: Finding) -> str:
    parts = [f'<div class="finding sev{finding.severity}">',
             f"<h3>{number}. {html.escape(finding.title)}</h3>",
             '<div class="tags">',
             f'<span class="pill">{SEVERITY_LABEL.get(finding.severity, "?")}</span>',
             f"confidence {finding.confidence:.0%} · {html.escape(finding.category)}"]
    if finding.pid:
        parts.append(f" · {html.escape(finding.process)} (pid {finding.pid})")
    parts.append("</div>")
    parts.append(f"<p>{html.escape(finding.explanation)}</p>")

    if finding.evidence:
        parts.append('<ul class="evidence">')
        parts += [f"<li>{html.escape(item)}</li>" for item in finding.evidence]
        parts.append("</ul>")

    for fix in finding.fixes:
        flags = ""
        if fix.risk != "low":
            flags += f'<span class="risk {fix.risk}">{fix.risk} risk</span>'
        if fix.needs_admin:
            flags += '<span class="risk admin">admin</span>'
        parts.append('<div class="fix">')
        parts.append(f"<b>{html.escape(fix.title)}{flags}</b>")
        parts.append(f"{html.escape(fix.detail)}")
        if fix.command:
            parts.append(f"<pre><code>{html.escape(fix.command)}</code></pre>")
        parts.append("</div>")

    parts.append("</div>")
    return "\n".join(parts)


def to_html(diagnosis: Diagnosis) -> str:
    facts = diagnosis.facts
    title = f"System Supe-Up — {_stamp(diagnosis.at)}"
    out = ["<!doctype html>", '<html lang="en"><head>',
           '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           f"<title>{html.escape(title)}</title>",
           f"<style>{_CSS}</style>", "</head><body>"]

    out.append("<h1>System Supe-Up</h1>")
    out.append(f'<p class="sub">{_stamp(diagnosis.at)}'
               + (f" · {html.escape(facts.computer)}"
                  if facts and facts.computer else "")
               + f" · watched {diagnosis.watched_s / 60:.1f} min"
                 f" · {len(diagnosis.findings)} finding(s)</p>")

    if diagnosis.findings:
        worst = diagnosis.findings[0]
        colour = SEVERITY_COLOUR.get(worst.severity, "#6b7280")
        out.append(f'<div class="headline" style="border-left-color:{colour}">'
                   f"<strong>{html.escape(worst.title)}</strong>"
                   f"{html.escape(worst.explanation)}</div>")
    else:
        out.append('<div class="headline" style="border-left-color:#4a7ba7">'
                   "<strong>Nothing wrong found during this window</strong>"
                   "If the machine misbehaves intermittently, leave the "
                   "monitor running and diagnose again while it is "
                   "happening.</div>")

    if facts:
        out.append("<h2>The machine</h2><table>")
        rows = [("Operating system", facts.os_build),
                ("Processor", f"{facts.cpu_model} "
                              f"({facts.cpu_cores}C/{facts.cpu_threads}T)"),
                ("Memory", f"{facts.ram_total / 1e9:.1f} GB"),
                ("Uptime", f"{facts.uptime_days:.1f} days")]
        if facts.power_plan:
            rows.append(("Power plan", facts.power_plan))
        disk = facts.system_disk
        if disk:
            rows.append(("System drive",
                         f"{disk.free / 1e9:.0f} GB free of "
                         f"{disk.total / 1e9:.0f} GB "
                         f"({disk.percent:.0f}% used)"))
        rows.append(("Starts at sign-in", f"{len(facts.startup)} programs"))
        rows.append(("Watched for",
                     f"{diagnosis.watched_s / 60:.1f} minutes "
                     f"({diagnosis.sample_count} samples)"))
        for label, value in rows:
            out.append(f"<tr><th>{html.escape(label)}</th>"
                       f"<td>{html.escape(str(value))}</td></tr>")
        out.append("</table>")

    if diagnosis.narrative:
        out.append("<h2>What is going on</h2>")
        out.append(f'<div class="narrative">{_paragraphs(diagnosis.narrative)}'
                   f"</div>")

    out.append(f"<h2>Findings ({len(diagnosis.findings)})</h2>")
    for number, finding in enumerate(diagnosis.findings, 1):
        out.append(_finding_html(number, finding))

    if diagnosis.researched:
        out.append("<h2>Processes looked up on the web</h2>")
        for name, found in diagnosis.researched.items():
            out.append(f"<h3>{html.escape(name)}</h3><ul>")
            for source in found.sources[:4]:
                out.append(f'<li><a href="{html.escape(source.url)}">'
                           f"{html.escape(source.title)}</a> "
                           f"<small>{html.escape(source.snippet[:180])}</small>"
                           f"</li>")
            out.append("</ul>")

    if facts and facts.events:
        out.append("<h2>Recent system event log</h2><table>"
                   "<tr><th>When</th><th>Source</th><th>ID</th>"
                   "<th>What it means</th></tr>")
        for event in facts.events[:20]:
            out.append(f"<tr><td>{_stamp(event.when)[5:16]}</td>"
                       f"<td>{html.escape(event.source)}</td>"
                       f"<td>{event.event_id}</td>"
                       f"<td>{html.escape(event.meaning or event.message[:110] or '—')}"
                       f"</td></tr>")
        out.append("</table>")

    if facts and facts.startup:
        out.append(f"<h2>Starts at sign-in ({len(facts.startup)})</h2>"
                   "<table><tr><th>Name</th><th>Scope</th>"
                   "<th>Command</th></tr>")
        for item in facts.startup:
            out.append(f"<tr><td>{html.escape(item.name)}</td>"
                       f"<td>{item.scope}</td>"
                       f"<td><code>{html.escape(item.command[:130])}</code>"
                       f"</td></tr>")
        out.append("</table>")

    out.append("<footer>")
    if diagnosis.model:
        out.append(f"Narrative written by <code>{html.escape(diagnosis.model)}"
                   f"</code> on {html.escape(diagnosis.server)}. Findings and "
                   f"evidence come from direct kernel measurement and do not "
                   f"depend on it.")
    else:
        out.append("No model was available, so this report has findings and "
                   "evidence but no narrative. They are measured either way.")
    out.append(f"<br>Diagnosis took {diagnosis.duration_s:.1f}s.")
    out.append("</footer></body></html>")
    return "\n".join(out)


def save(diagnosis: Diagnosis, directory: Path | None = None) -> dict[str, Path]:
    """Write both formats.  Returns {"markdown": path, "html": path}."""
    directory = Path(directory) if directory else REPORT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"diagnosis-{_slug(diagnosis.at)}"
    written: dict[str, Path] = {}

    markdown_path = directory / f"{stem}.md"
    markdown_path.write_text(to_markdown(diagnosis), encoding="utf-8")
    written["markdown"] = markdown_path

    html_path = directory / f"{stem}.html"
    html_path.write_text(to_html(diagnosis), encoding="utf-8")
    written["html"] = html_path
    return written


# ---------------------------------------------------------------- tune-up

_INLINE = (
    (re.compile(r"`([^`]+)`"), r"<code>\1</code>"),
    (re.compile(r"\*\*([^*]+)\*\*"), r"<strong>\1</strong>"),
    (re.compile(r"\*([^*]+)\*"), r"<em>\1</em>"),
)


def _inline(text: str) -> str:
    """Escape, then re-apply the handful of inline marks this report uses.

    Deliberately tiny.  Nothing here renders arbitrary Markdown -- it renders
    the Markdown `tuneup_to_markdown` writes, which is a closed set, and
    everything is HTML-escaped before any mark is applied so that a process
    name containing angle brackets cannot become an element.
    """
    out = html.escape(text)
    for pattern, replacement in _INLINE:
        out = pattern.sub(replacement, out)
    return out


def _markdown_page(title: str, markdown: str) -> str:
    """Wrap the tune-up's own Markdown in the same stylesheet as the report."""
    body: list[str] = []
    in_list = False
    in_table = False

    def close() -> None:
        nonlocal in_list, in_table
        if in_list:
            body.append("</ul>")
            in_list = False
        if in_table:
            body.append("</table>")
            in_table = False

    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped:
            close()
            continue
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue        # the header underline
            if not in_table:
                close()
                body.append('<table class="rows">')
                in_table = True
                tag = "th"
            else:
                tag = "td"
            body.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>"
                                         for c in cells) + "</tr>")
            continue
        if stripped.startswith("- "):
            if not in_list:
                close()
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{_inline(stripped[2:])}</li>")
            continue
        close()
        if stripped.startswith("### "):
            body.append(f"<h3>{_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            body.append(f"<h2>{_inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            body.append(f"<h1>{_inline(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            body.append(f'<div class="headline">{_inline(stripped[2:])}</div>')
        elif stripped == "---":
            body.append("<hr>")
        else:
            body.append(f"<p>{_inline(stripped)}</p>")
    close()

    return "\n".join([
        "<!doctype html>", '<html lang="en"><head>', '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{html.escape(title)}</title>",
        f"<style>{_CSS}</style>", "</head><body>", *body,
        "</body></html>"])


def tuneup_to_markdown(tuneup, facts=None) -> str:
    """The tune-up as a document, ordered by what is worth doing first.

    Written separately from the diagnosis rather than folded into it because
    the two answer different questions and are read by different people. The
    largest items on a managed machine -- fit more memory, remove two of the
    three antivirus products -- are somebody else's decision to approve, and
    this is the page to send them: every claim carries the measurement it was
    made from, so it can be argued with rather than merely believed.
    """
    out: list[str] = ["# System Supe-Up — tune-up"]
    out.append(f"\n*{_stamp(tuneup.at)}"
               + (f" · {facts.computer}" if facts and facts.computer else "")
               + "*\n")

    if not tuneup.opportunities:
        out.append("Nothing worth changing was found. That is a result rather "
                   "than a failure: this machine is configured about as well "
                   "as it can be for what it is being asked to do.\n")
        return "\n".join(out)

    automatable = tuneup.automatable
    out.append(f"> **{tuneup.headline()}**\n>\n"
               f"> {len(tuneup.opportunities)} thing(s) worth changing. "
               f"{len(automatable)} can be done from this tool with a preview "
               f"and an undo; {len(tuneup.manual)} need a person.\n")

    if facts:
        out.append("## The machine\n")
        out.append("| | |\n|---|---|")
        out.append(f"| Operating system | {facts.os_build} |")
        out.append(f"| Processor | {facts.cpu_model} "
                   f"({facts.cpu_cores}C/{facts.cpu_threads}T) |")
        out.append(f"| Memory | {facts.ram_total / 1e9:.1f} GB |")
        out.append(f"| Uptime | {facts.uptime_days:.1f} days |")
        out.append("")

    out.append("## What to do, in order\n")
    out.append("| # | Gain | Effort | What | How |")
    out.append("|---|---|---|---|---|")
    for number, opportunity in enumerate(tuneup.opportunities, 1):
        how = (f"`{opportunity.action_id}`" if opportunity.automatable
               else "by hand")
        out.append(f"| {number} | {opportunity.gain_label} | "
                   f"{opportunity.effort} | {opportunity.title} | {how} |")
    out.append("")

    for number, opportunity in enumerate(tuneup.opportunities, 1):
        out.append(f"### {number}. {opportunity.title}\n")
        out.append(f"*{opportunity.gain_label} gain · {opportunity.effort} · "
                   f"{opportunity.category}*\n")
        out.append(opportunity.detail + "\n")
        if opportunity.evidence:
            out.append("**Measured**\n")
            out += [f"- {item}" for item in opportunity.evidence if item]
            out.append("")
        if opportunity.automatable:
            spec = None
            try:
                from .actions import REGISTRY
                spec = REGISTRY.get(opportunity.action_id)
            except Exception:
                spec = None
            flags = []
            if spec is not None:
                flags.append(f"{spec.risk} risk")
                if spec.needs_admin:
                    flags.append("needs administrator")
                flags.append("reversible" if spec.reversible
                             else "NOT reversible")
            out.append(f"**This tool can do it** — `{opportunity.action_id}`"
                       + (f" ({', '.join(flags)})" if flags else "")
                       + ". Previewed in dry-run first, and confirmed "
                         "individually.\n")
        for step in opportunity.manual_steps:
            out.append(f"- {step}")
        if opportunity.manual_steps:
            out.append("")
        if opportunity.verify:
            out.append(f"**You will know it worked by:** {opportunity.verify}\n")

    # A report that does not say which rights produced it invites the reader
    # to treat "nothing found" as "nothing there", which is the one thing a
    # standard-rights scan cannot promise.
    try:
        from .elevate import RESTRICTED, is_admin
        if not is_admin():
            out.append("## Read with standard rights\n")
            out.append("This scan ran without administrator rights, so the "
                       "following were out of reach:\n")
            out += [f"- {item}" for item in RESTRICTED]
            out.append("")
    except Exception:
        pass

    if tuneup.unavailable:
        out.append("## Not checked\n")
        out.append("These readings were refused, so they are unknown rather "
                   "than clean:\n")
        out += [f"- {item}" for item in tuneup.unavailable]
        out.append("")

    out.append("---\n")
    out.append("*Nothing in this document has been applied. Every automated "
               "step is previewed in dry-run, approved individually, and "
               "recorded with enough detail to be reversed.*")
    return "\n".join(out)


def save_tuneup(tuneup, facts=None, directory=None) -> dict:
    """Write the tune-up as Markdown and HTML.  Returns the paths."""
    directory = Path(directory) if directory else REPORT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"tuneup-{_slug(tuneup.at)}"
    markdown = tuneup_to_markdown(tuneup, facts)

    written = {}
    markdown_path = directory / f"{stem}.md"
    markdown_path.write_text(markdown, encoding="utf-8")
    written["markdown"] = markdown_path

    html_path = directory / f"{stem}.html"
    html_path.write_text(_markdown_page("System Supe-Up — tune-up", markdown),
                         encoding="utf-8")
    written["html"] = html_path
    return written
