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

### Tune-up

**Diagnose** answers "why did it freeze". **Tune-up** answers a different
question -- "what would make this quicker" -- and they need different engines,
because a machine can pass every diagnostic rule and still be carrying three
real-time scanners, seventeen sign-in programs and a service pre-loading
applications into memory it does not have.

So `optimise.py` is a second pass over the same evidence, looking for
*headroom* rather than faults. It reads service start types, registry state,
power settings, physical memory slots, the disk's bus type, the sign-in list
and the live process table, and returns opportunities ordered by **expected
gain** rather than by severity. Severity tells you how bad something is; gain
tells you what to do first, which is the question somebody actually has on a
Tuesday afternoon.

It obeys the same rules as everything else here. The model still detects
nothing -- every opportunity is a measured or read state. Nothing runs
without approval: the tune-up hands its plan to the same dialog the
investigator uses, so every step is previewed in dry-run, ticked
individually, and recorded to disk with its undo before it runs.

It is deliberately honest about what it cannot press a button for. On the
machine this was written against the two largest wins are fitting more memory
(there are two free slots) and removing two of three antivirus products
(which is the IT provider's decision) -- so both are reported, at the top,
with their evidence, above everything that *does* have a button. A tune-up
that only lists what it happens to be able to click is one that lies by
omission.

Where a remedy is hardware-specific it checks first. Turning off AHCI link
power management is the standard fix for storage-controller resets on SATA
machines and does nothing at all on NVMe -- and the event log cannot tell the
two apart, because both report through whichever Intel driver is loaded. So
the bus type is read before that one is offered.

### The live bridge

Everything above is invisible while it happens. A rule that nearly fired
leaves no trace, a model given the wrong question returns a plausible answer,
and an action discarded for being outside its category disappears silently by
design. That is right for a user-facing tool and useless when the thing being
debugged is the tool.

`python run.py --bridge` (or `--bridge` on the test harness, or `live_bridge`
in settings) streams every stage to `~/SystemSupeUp/live` as
newline-delimited JSON: each sample, each rule with what it fired and how long
it took, every model prompt and completion, every search, every action preview
and result.

```bash
python run.py --bridge              # run the dashboard with the feed on
python tools/watch.py               # follow it, formatted
python tools/watch.py --only rule   # just the rule engine
python tools/watch.py --llm 3       # the last 3 model exchanges, in full
python tools/watch.py --state       # the current snapshot, once
```

It writes two files, because they have different readers: `bridge.jsonl` is
one compact line per event and is meant to be tailed, and `llm.jsonl` holds
the prompts and completions whole. It never blocks the caller -- events go on
a queue that a separate thread drains, which matters here more than usual,
because the sampler's punctuality *is* the stall measurement and an
instrumentation call that waited on a disk write would make the app report
itself as a system freeze.

It earned its keep the first time it was switched on. `_rule_duplicate_av`
had been building a `Fix` with the wrong keyword, so it raised `TypeError`
every time it ran -- and `analyse` catches per-rule exceptions so one broken
rule cannot take the monitor down. The rule had therefore never fired, on a
machine running three real-time scanners, with no symptom anybody could name.
The loop now reports a raising rule instead of dropping it, and
`tests/test_tuneup.py` drives every rule hard enough to fire and asserts that
none of them raise.

### Watching what the AI actually recommends

```bash
python tools/live_test.py --seconds 30                    # rules only, offline
python tools/live_test.py --narrative                     # + the written report
python tools/live_test.py --investigate --top 2           # + research and a plan
python tools/live_test.py --investigate --dry-run-plan    # + preview every step
python tools/live_test.py --optimise                      # + the tune-up scan
python tools/live_test.py --json out.json                 # machine-readable
```

This runs the real pipeline against the real machine and prints what came
back, including the actions the model proposed that were **discarded** and
why. Everything it runs is `dry_run=True`; no flag on it changes the machine.

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
python run.py --optimise     # what would make this machine quicker
python run.py --bridge       # ...with every stage streamed to a live feed
python run.py --admin        # restart elevated first, then do the above
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
| **Tune-up** | Scans for headroom rather than faults and offers the changes worth making, ordered by expected gain. Nothing is applied without approval. |
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

The settings body scrolls, so the Save button stays reachable at any window
height.

Settings are stored in `~/.system_supeup_settings.json`.

**Window sizes and positions are remembered** — every window, including the
dialogs — in `~/.system_supeup_windows.json`, separately from the settings so
that configuration file stays readable. A maximised window comes back
maximised, and the size it had before is kept for when it is restored. A
position that no longer lands on any monitor (a screen unplugged since last
time) is discarded and only the size is reused, so a window can never open
somewhere it cannot be dragged back from. **Reset window sizes** in the
settings footer forgets the lot.

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
| `live_bridge` | `false` | Stream every stage to `~/SystemSupeUp/live` |
| `admin_mode` | `ask` | `ask`, `always` or `never` — see **Administrator rights** |

A missing model is resolved to the closest available one rather than failing,
so renaming a tag on the server does not break the tool.

---

## Administrator rights

By default the tool holds no administrator rights and asks for them one action
at a time, at the moment each one runs. That is still the recommendation: a
process that reads every process on the machine every second is a different
thing to trust when it also holds administrator rights all day.

It is not free, though, and the interface now says so rather than quietly
returning less:

- Windows will not reveal **what a frozen program is blocked on** to a standard
  process. That reading cannot be taken later — by the time a UAC prompt could
  be answered, the moment has passed. A standard-rights scan says so in the
  report instead of implying the answer was "nothing".
- The command line and open files of **processes owned by other accounts**,
  which is most services, are not readable either.
- A tune-up is a *plan*. Approving eight changes and then answering eight
  consecutive UAC prompts is how people learn to click Yes without reading.

So there are three ways to run, set by `admin_mode` (settings → **Administrator
rights**):

| Mode | What happens |
|---|---|
| `ask` (default) | A bar in the main window says what is limited, with a **Restart as administrator** button. The fix window says how many of the proposed steps will each raise their own prompt. Nothing elevates on its own. |
| `always` | The app relaunches elevated as it starts. One prompt, at startup. If elevation is refused it carries on unelevated rather than failing to open. |
| `never` | Not mentioned anywhere. Each fix still asks for itself when it needs to. |

The restart closes the app and opens a new copy, so **samples held in memory
are lost** — reports already written are not. The command it relaunches is
built from `sys.executable` and `sys.argv` and nothing else; `elevate.py` is
the only place in the codebase that can start the program, and a relaunched
copy carries a flag so a machine where elevation cannot succeed can never
relaunch itself in a loop.

`python run.py --admin` does the same thing from the terminal.

---

## Safety

- **Nothing runs without you approving it**, and every step is previewed in
  dry-run first. Each action is confirmed individually by default.
- The model can only choose from `actions.py`. It cannot supply a command, and
  invented action ids are dropped rather than executed.
- `knowledge.py` marks processes as essential or killable, and **nothing may
  stop a process that table has not cleared** — `restart_process` refuses
  `lsass.exe` even when explicitly asked.
- Changing how a service starts is gated the same way, by an allowlist in
  `actions.TUNABLE_SERVICES`. No security agent and no core Windows service is
  on it, so `set_service_startup` refuses `WinDefend` or `SentinelAgent`
  whatever asks. Security software is never automated at all: overlapping
  scanners are reported as the largest available win and left as a decision.
- Actions declare their risk, whether they need admin, and whether they can be
  undone. Admin is requested per action by default, so the monitor is not left
  running elevated all day — see **Administrator rights** for the choice.
- A restore point is offered before anything irreversible. Registry, service
  and file changes record enough to be reversed from the same window.
- The model is forbidden from calling software malicious, and from
  recommending registry cleaners, "optimisers", or disabling security software
  without stating the trade-off.

## Layout

```
sysup/
  winapi.py     ctypes: thread wait reasons, hung windows, GUI handles
  telemetry.py  the shapes telemetry comes in — no Windows, so it imports anywhere
  collect.py    sampling — two snapshots into rates; stall detection
  rules.py      the diagnostic engine: 18 rules, evidence attached
  incidents.py  keep the samples either side of a stall, and reduce them to a verdict
  knowledge.py  what common processes are, and what is safe to do
  sysinfo.py    one-shot facts: startup, event log, disks, throttling
  research.py   SearXNG lookups, filtered and cached
  llm.py        Ollama with failover and model resolution
  diagnose.py   orchestration and prompts
  actions.py    the vetted catalogue of things it may actually DO
  optimise.py   the tune-up engine: headroom, scored by expected gain
  investigate.py  research one finding, come back with a plan
  journal.py    every change made, its undo, and whether it actually helped
  bridge.py     the live event feed — every stage, as it happens
  elevate.py    the admin_mode setting, and the only code that can relaunch
  window_state.py  where each window was last time, validated against the screen
  config.py     settings, with the server addresses inherited from AI Chat Lab
  report.py     Markdown + self-contained HTML
  gui.py        the desktop interface (Tkinter)
  settings_dialog.py  servers, models, research, safety
  fix_dialog.py       investigate → preview → approve → apply → undo
  ui.py         the terminal dashboard (rich)
tools/
  watch.py      follow the live bridge, formatted
  live_test.py  drive the whole pipeline and print what the AI recommended
tests/
  fault.py        misbehave in one specific way, in its own process, for N seconds
  test_detection.py     inject a real fault and check the monitor notices it
  test_synthetic.py     drive the rules with machines that cannot be built
  test_regressions.py   one test per bug found in the August 2026 audit
  test_tuneup.py  the tune-up engine, the bridge, and the rule-crash regression
  test_elevate.py the elevation setting, the loop guard, and the command
  test_window_state.py  restoring geometry, and the monitor that is not there
run.py                  entry point — terminal by default, --gui for the app
System Supe-Up.pyw      double-click launcher for the desktop interface
```

## Requirements

Python 3.10+, Windows 10/11. `pip install -r requirements.txt`.

Runs fine as a normal user, and that is the default. Administrator adds
visibility into protected processes and into wait chains — the one reading
that cannot be recovered afterwards — and lets a whole plan of fixes run on
one approval instead of one each. See **Administrator rights**; nothing
elevates on its own unless you set it to.
