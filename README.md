# System Supe-Up

An AI PC monitor that explains *why* a Windows machine freezes, and what to do
about it — rather than drawing another CPU graph and leaving you to guess.

It runs entirely on your own hardware: the local Ollama servers for the
writing, your SearXNG instance for research, and nothing leaves the network.

---

## Why this is different from Task Manager

Task Manager answers "what is using CPU". That is almost never the question,
because **a frozen application is not using CPU — it is waiting**, and the
interesting part is what it is waiting *for*.

This tool reads what the Windows kernel actually knows:

| Signal | What it answers | Where it comes from |
|---|---|---|
| **Thread wait reasons** | Why a process is stuck — paging, a lock, another process, a driver | `NtQuerySystemInformation` |
| **Hung windows** | Which apps Windows itself has given up on | `IsHungAppWindow`, with ghost-window resolution |
| **Per-process hard faults** | Who is causing a paging storm | `SYSTEM_PROCESS_INFORMATION.HardFaultCount` |
| **GDI / USER handles** | Leaks that kill an app at 10,000 objects | `GetGuiResources` |
| **Loop lateness** | A *measured* whole-system stall, not an inferred one | its own scheduling |
| **Event log** | Storage resets and out-of-memory events Windows already recorded | `System` log |

That last pair is the point. If this tool asks to be woken once a second and
is woken four seconds late, the machine did not run *it* for four seconds —
and it did not run your mouse either. That is a freeze you can prove.

## How the AI is used — and where it is deliberately not

```
kernel measurements ─▶ rules engine ─▶ findings ─▶ ┌─ SearXNG ─▶ Ollama ─▶ narrative
                      (deterministic,              └─ Investigate & fix:
                       offline, local)                 queries → pages → PLAN
                                                       ↓
                                                    action catalogue (vetted)
                                                       ↓
                                                    preview → you approve → run
```

**The model never detects anything.** Detection is done by the rules engine,
which is deterministic and works with the network unplugged. The model is
handed findings that are already verified and asked to explain, connect and
prioritise them.

**The model never writes a command that gets run.** For fixes it picks an
action from a fixed catalogue by id and supplies parameters that are validated
in code. Anything it names that is not in the catalogue is discarded. This is
the whole safety model, and it is deliberate — a language model asked to fix a
Windows problem will produce `del /s /q C:\Windows\*` with a confident
rationale, and no amount of prompting reliably prevents that.

### Investigate & fix

Select a finding and press **Investigate & fix**. It will:

1. write search queries for *this* finding on *this* machine — the actual
   driver name, the actual event id, the actual Windows build;
2. run them through SearXNG and read the best pages;
3. propose a plan drawn only from the action catalogue, with everything it
   cannot automate written out as manual steps instead.

Every step is previewed by running it in dry-run mode first, so what you read
is the action's own account of what it would do rather than a description that
might have drifted from the code. Only safe, reversible, non-admin steps are
ticked by default. A restore point is offered before anything irreversible,
and reversible changes can be undone from the same window.

It is honest about what it cannot fix. Given storage-controller resets it
proposes two read-only diagnostics and puts "update the driver, replace the
drive if SMART is bad" in the manual steps — rather than pretending a button
solves failing hardware.

This matters for two reasons:

- A finding can never be wrong *because the model was*. Ask a 32B model to
  spot a paging storm in a table of numbers and it will occasionally miss one
  and occasionally invent one.
- Everything except the narrative still works when the Ollama box is off.

The prompt is also hardened against a specific failure found in testing: web
search results about ordinary executables frequently claim they are malware,
and a model will repeat that as fact. Research output is labelled as untrusted,
scareware domains are filtered, and the model is explicitly forbidden from
making security claims.

---

## Running it

**Double-click `System Supe-Up.pyw`** for the desktop interface. That is the
normal way to use it.

```bash
python run.py --gui          # the same desktop interface
python run.py                # terminal dashboard instead
python run.py --check        # verify servers and models
python run.py --once         # watch 25s, diagnose, write a report
python run.py --watch 10     # watch 10 minutes, then diagnose
python run.py --once --open  # ...and open the report in a browser
python run.py --no-model     # findings and evidence only, no narrative
```

### In the desktop interface

Four live gauges across the top — processor, memory, disk, and **hard page
faults**, which gets equal billing deliberately because it is the number that
explains freezing and no ordinary task manager shows it. Each carries a
sparkline, because "steady at 80%" and "spiking to 80%" mean entirely
different things when you are chasing a stutter.

A red strip appears above the tables only when something is actually wrong —
a measured whole-system stall, or an app Windows has given up on.

| Control | Does |
|---|---|
| **Diagnose now** | Full report with a written explanation from the 32B model. Runs in the background; sampling continues throughout. |
| **Snapshot** | Same report with no model involved — instant, works offline. |
| **Reports** | Opens the reports folder. |
| **Pause** | Stops sampling without losing history. |
| Click a column header | Sort the process table by it. |
| Double-click a process | What it is, its vendor, and whether it is safe to end. |
| Click a finding | Full explanation, evidence, and fixes. |
| **Ask the model** | A three-sentence second opinion on the selected finding, via the fast model. |
| **Copy fix** | Puts that finding's commands on the clipboard — it never runs them. |

The sampler runs on its own thread rather than on Tkinter's timer. This is
load-bearing: stall detection works by measuring how late its own tick is, so
if a slow redraw could delay sampling, the app would report itself as a system
freeze.

### In the terminal dashboard

| Key | Does |
|---|---|
| `d` | Full diagnosis + HTML/Markdown report (runs in the background) |
| `x` | Quick explanation of the selected finding, via the fast model |
| `s` | Save a snapshot report with no model involved |
| `c` `m` `i` `f` `t` | Sort by CPU / memory / I/O / page faults / threads |
| `↑` `↓` | Move between findings |
| `p` | Pause sampling |
| `q` | Quit |

Sampling continues while a diagnosis runs — the freeze you are hunting may
happen *during* the report, which is exactly when you want the evidence.

Reports are written to `~/SystemSupeUp/reports/` as both HTML and Markdown.

---

## Configuration

Press **⚙** in the app. Servers, models, research, sampling and fix safety are
all editable there, and **Test and load models** fetches what each server
actually has so the model boxes are dropdowns rather than free text — typing a
tag by hand is how you end up silently running a different model than you
think.

Settings are stored in `~/.system_supeup_settings.json`.

**Server addresses are inherited from AI Chat Lab** (`~/.ai_chat_lab_settings.json`)
so the same three addresses are not maintained in two places. Nothing is ever
written back to that file. Clear a field in the settings window to go back to
inheriting it. Set any of these explicitly to override:

| Setting | Default | Notes |
|---|---|---|
| `ollama_url` | AI Chat Lab's *host* server | Tried first — this is where the 32B models are |
| `ollama_fallback_url` | AI Chat Lab's *local* server | Used when the host is unreachable |
| `searxng_url` | AI Chat Lab's SearXNG | Blank disables research |
| `diagnose_model` | `qwen2.5:32b-instruct-q4_K_M` | The on-demand report |
| `triage_model` | `qwen3:8b` | The `x` key — fast, three sentences |
| `sample_interval` | `1.0` | Seconds between samples |
| `stall_threshold_s` | `2.5` | Lateness that counts as a system stall |
| `research` | `true` | Look up processes not in the built-in table |

A missing model is resolved to the closest available one rather than failing,
so renaming a tag on the server does not break the tool.

---

## Safety

- **Nothing runs without you approving it**, and every step is previewed in
  dry-run first. Each action is confirmed individually by default.
- The model can only choose from `actions.py`. It cannot supply a command, and
  invented action ids are dropped rather than executed.
- `knowledge.py` marks processes as essential or killable, and **nothing may
  stop a process that table has not cleared** — `restart_process` refuses
  `lsass.exe` even when explicitly asked.
- Actions declare their risk, whether they need admin, and whether they can be
  undone. Admin is requested per action, so the monitor is never left running
  elevated all day.
- A restore point is offered before anything irreversible. Registry, service
  and file changes record enough to be reversed from the same window.
- The model is forbidden from calling software malicious, and from
  recommending registry cleaners, "optimisers", or disabling security software
  without stating the trade-off.

## Layout

```
sysup/
  winapi.py     ctypes: thread wait reasons, hung windows, GUI handles
  collect.py    sampling — two snapshots into rates; stall detection
  rules.py      the diagnostic engine: 16 rules, evidence attached
  knowledge.py  what common processes are, and what is safe to do
  sysinfo.py    one-shot facts: startup, event log, disks, throttling
  research.py   SearXNG lookups, filtered and cached
  llm.py        Ollama with failover and model resolution
  diagnose.py   orchestration and prompts
  actions.py    the vetted catalogue of things it may actually DO
  investigate.py  research one finding, come back with a plan
  report.py     Markdown + self-contained HTML
  gui.py        the desktop interface (Tkinter)
  settings_dialog.py  servers, models, research, safety
  fix_dialog.py       investigate → preview → approve → apply → undo
  ui.py         the terminal dashboard (rich)
run.py                  entry point — terminal by default, --gui for the app
System Supe-Up.pyw      double-click launcher for the desktop interface
```

## Requirements

Python 3.10+, Windows 10/11. `pip install -r requirements.txt`.

Runs fine as a normal user. Administrator adds visibility into a few
protected processes but is not needed for any of the findings above.
