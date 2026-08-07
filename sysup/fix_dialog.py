"""Investigate one finding, then apply a plan — with the user driving.

The shape of this window is the safety design made visible:

1. It researches while you watch, naming what it is searching and reading, so
   the plan does not arrive from nowhere.
2. Every proposed step is previewed by running it in `dry_run` mode first. The
   preview is the action's own account of what it would do, not a description
   written separately that might have drifted from the code.
3. Nothing is ticked by default beyond what is safe. Anything irreversible or
   needing admin is left for you to tick deliberately.
4. Steps that need a person — update this driver, replace that drive — are
   shown as text and never dressed up as something the tool can do.
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from . import actions as actions_mod, investigate as investigate_mod
from .config import Settings
from .journal import Journal, capture_state, verify
from .rules import Finding

BG = "#12141a"
PANEL = "#1a1d25"
PANEL_ALT = "#20242e"
RAISED = "#262b36"
BORDER = "#2a2f3a"
TEXT = "#e6e9ef"
DIM = "#8b93a7"
FAINT = "#5c6478"
ACCENT = "#4f8ef7"
ACCENT_DARK = "#3b76d9"
OK = "#3ecf8e"
WARN = "#e0a03a"
DANGER = "#f2565a"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_TINY = ("Segoe UI", 8)
FONT_TITLE = ("Segoe UI", 14, "bold")
FONT_MONO = ("Consolas", 9)

RISK_COLOUR = {"low": OK, "medium": WARN, "high": DANGER}


def _button(parent, text, command, primary=False, **kwargs):
    return tk.Button(
        parent, text=text, command=command,
        font=FONT_BOLD if primary else FONT,
        bg=ACCENT if primary else RAISED, fg="white" if primary else TEXT,
        activebackground=ACCENT_DARK if primary else "#303644",
        activeforeground="white" if primary else TEXT,
        relief="flat", cursor="hand2", padx=14, pady=6, bd=0,
        highlightthickness=0, disabledforeground=FAINT, **kwargs)


class FixDialog(tk.Toplevel):
    def __init__(self, parent, finding: Finding, settings: Settings,
                 facts=None, sample=None, sampler=None) -> None:
        super().__init__(parent)
        self.finding = finding
        self.settings = settings
        self.facts = facts
        self.sample = sample
        #: Used to take a fresh reading after a change, so "did it work" is
        #: measured rather than asserted.
        self.sampler = sampler
        self.journal = Journal()
        self.investigation: investigate_mod.Investigation | None = None
        self.rows: list[tuple[actions_mod.PlannedAction, tk.BooleanVar]] = []
        self.cancel = threading.Event()
        self._applying = False
        self._undo_stack: list[tuple[str, dict]] = []

        self.title(f"Investigate — {finding.title[:60]}")
        self.configure(bg=BG)
        self.geometry("900x800")
        self.minsize(760, 620)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._close)

        self._build()
        self._start()

    # ------------------------------------------------------------- building
    def _build(self) -> None:
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=20, pady=(16, 6))
        tk.Label(head, text=self.finding.title, bg=BG, fg=TEXT,
                 font=FONT_TITLE, wraplength=820, justify="left",
                 anchor="w").pack(fill="x")
        tk.Label(head, text=f"{self.finding.severity_name} · "
                            f"{self.finding.category}"
                            + (f" · {self.finding.process}"
                               if self.finding.process else ""),
                 bg=BG, fg=DIM, font=FONT_SMALL, anchor="w").pack(fill="x")

        self.progress = tk.Label(self, text="", bg=BG, fg=ACCENT,
                                 font=FONT_SMALL, anchor="w")
        self.progress.pack(fill="x", padx=20, pady=(2, 6))

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=20)

        # -- analysis
        self.analysis = tk.Text(
            body, bg=PANEL, fg="#c9cfdb", font=FONT_SMALL, wrap="word",
            bd=0, highlightthickness=1, highlightbackground=BORDER,
            padx=14, pady=11, height=9, cursor="arrow", spacing3=6)
        self.analysis.pack(fill="x", pady=(0, 10))
        self.analysis.tag_configure("h", font=FONT_BOLD, foreground=TEXT,
                                    spacing1=6, spacing3=3)
        self.analysis.tag_configure("src", font=FONT_TINY, foreground=FAINT)
        self.analysis.tag_configure("warn", foreground=WARN)
        self.analysis.insert("end", "Researching…\n", "h")
        self.analysis.configure(state="disabled")

        # -- plan
        plan_head = tk.Frame(body, bg=BG)
        plan_head.pack(fill="x")
        self.plan_label = tk.Label(plan_head, text="PROPOSED STEPS", bg=BG,
                                   fg=DIM, font=FONT_TINY)
        self.plan_label.pack(side="left")
        tk.Label(plan_head, text="nothing runs until you press Apply",
                 bg=BG, fg=FAINT, font=FONT_TINY).pack(side="right")

        holder = tk.Frame(body, bg=PANEL, highlightbackground=BORDER,
                          highlightthickness=1)
        holder.pack(fill="both", expand=True, pady=(4, 0))
        canvas = tk.Canvas(holder, bg=PANEL, highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(holder, orient="vertical", command=canvas.yview)
        self.plan_frame = tk.Frame(canvas, bg=PANEL)
        self.plan_frame.bind("<Configure>", lambda _e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=self.plan_frame,
                                      anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=20, pady=(10, 16))
        self.status = tk.Label(foot, text="", bg=BG, fg=DIM, font=FONT_SMALL,
                               anchor="w", wraplength=440, justify="left")
        self.status.pack(side="left", fill="x", expand=True)
        self.apply_button = _button(foot, "Apply selected", self._apply,
                                    primary=True, state="disabled")
        self.apply_button.pack(side="right")
        self.undo_button = _button(
            foot, "Undo last", self._undo,
            # Enabled if anything anywhere is still reversible, including
            # changes made in a previous session.
            state="normal" if self.journal.undoable() else "disabled")
        self.undo_button.pack(side="right", padx=(0, 8))
        _button(foot, "Close", self._close).pack(side="right", padx=(0, 8))

    # ---------------------------------------------------------- researching
    def _start(self) -> None:
        context = investigate_mod.live_context(self.sample)

        def work() -> None:
            def say(message: str) -> None:
                self.after(0, lambda: self.progress.configure(
                    text=f"⋯  {message}"))

            try:
                result = investigate_mod.investigate(
                    self.finding, self.settings, self.facts,
                    on_progress=say, cancel=self.cancel, context=context)
            except Exception as error:
                self.after(0, lambda: self._failed(error))
                return
            self.after(0, lambda: self._investigated(result))

        threading.Thread(target=work, daemon=True).start()

    def _failed(self, error: Exception) -> None:
        self.progress.configure(text="")
        self.analysis.configure(state="normal")
        self.analysis.delete("1.0", "end")
        self.analysis.insert("end", "Could not research this\n", "h")
        self.analysis.insert("end", f"{error}\n")
        self.analysis.configure(state="disabled")

    def _investigated(self, result: investigate_mod.Investigation) -> None:
        self.investigation = result
        self.progress.configure(text="")

        self.analysis.configure(state="normal")
        self.analysis.delete("1.0", "end")
        if result.analysis:
            confidence = (f"  (confidence: {result.confidence})"
                          if result.confidence else "")
            self.analysis.insert("end", f"What is actually wrong{confidence}\n",
                                 "h")
            self.analysis.insert("end", result.analysis.strip() + "\n")
        else:
            self.analysis.insert("end", "No analysis was produced\n", "h")
            self.analysis.insert("end", self.finding.explanation + "\n")

        if result.manual_steps:
            self.analysis.insert("end", "\nYou will have to do these yourself\n",
                                 "h")
            for step in result.manual_steps:
                self.analysis.insert("end", f"  •  {step}\n")

        if result.sources:
            self.analysis.insert(
                "end", "\nRead: " + ", ".join(
                    dict.fromkeys(s.domain for s in result.sources)) + "\n",
                "src")
        if result.error:
            self.analysis.insert("end", f"\n{result.error}\n", "warn")
        self.analysis.configure(state="disabled")

        self._show_plan(result.plan)

    # ----------------------------------------------------------------- plan
    def _show_plan(self, plan: list[actions_mod.PlannedAction]) -> None:
        for child in self.plan_frame.winfo_children():
            child.destroy()
        self.rows = []

        if not plan:
            tk.Label(self.plan_frame,
                     text="There is nothing this tool can safely do "
                          "automatically for this finding.\nWhat is written "
                          "above is the remedy.",
                     bg=PANEL, fg=DIM, font=FONT_SMALL, justify="left",
                     wraplength=760).pack(anchor="w", padx=14, pady=16)
            self.plan_label.configure(text="PROPOSED STEPS — none")
            return

        self.plan_label.configure(text=f"PROPOSED STEPS ({len(plan)})")
        self.status.configure(text="previewing…")
        for planned in plan:
            self._plan_row(planned)
        self.apply_button.configure(state="normal")
        self._preview_all()

    def _plan_row(self, planned: actions_mod.PlannedAction) -> None:
        spec = planned.spec
        # Safe and reversible is ticked; anything else is a deliberate choice.
        safe = spec.risk == "low" and spec.reversible and not spec.needs_admin
        variable = tk.BooleanVar(value=safe)

        row = tk.Frame(self.plan_frame, bg=PANEL)
        row.pack(fill="x", padx=10, pady=(8, 0))
        tk.Frame(row, bg=RISK_COLOUR.get(spec.risk, DIM),
                 width=3).pack(side="left", fill="y")

        body = tk.Frame(row, bg=PANEL)
        body.pack(side="left", fill="x", expand=True, padx=9)

        top = tk.Frame(body, bg=PANEL)
        top.pack(fill="x")
        tk.Checkbutton(
            top, text=spec.title, variable=variable, bg=PANEL, fg=TEXT,
            selectcolor=PANEL_ALT, activebackground=PANEL,
            activeforeground=TEXT, font=FONT_BOLD, bd=0, highlightthickness=0,
            cursor="hand2", anchor="w").pack(side="left")

        for flag, colour in ((spec.risk if spec.risk != "low" else "",
                              RISK_COLOUR.get(spec.risk, DIM)),
                             ("admin" if spec.needs_admin else "", ACCENT),
                             ("cannot be undone" if not spec.reversible else "",
                              WARN)):
            if flag:
                tk.Label(top, text=flag, bg=PANEL_ALT, fg=colour,
                         font=FONT_TINY, padx=6, pady=1).pack(side="left",
                                                              padx=(6, 0))

        if planned.reason:
            tk.Label(body, text=planned.reason, bg=PANEL, fg=DIM,
                     font=FONT_SMALL, wraplength=740, justify="left",
                     anchor="w").pack(fill="x", pady=(2, 0))

        preview = tk.Label(body, text="checking…", bg=PANEL, fg=FAINT,
                           font=FONT_MONO, wraplength=740, justify="left",
                           anchor="w")
        preview.pack(fill="x", pady=(3, 0))

        result = tk.Label(body, text="", bg=PANEL, fg=OK, font=FONT_SMALL,
                          wraplength=740, justify="left", anchor="w")

        tk.Frame(self.plan_frame, bg=BORDER, height=1).pack(
            fill="x", padx=10, pady=(8, 0))
        self.rows.append((planned, variable))
        planned._preview_widget = preview       # type: ignore[attr-defined]
        planned._result_widget = result         # type: ignore[attr-defined]

    def _preview_all(self) -> None:
        def work() -> None:
            for planned, _variable in list(self.rows):
                if self.cancel.is_set():
                    return
                result = actions_mod.apply(planned, dry_run=True)
                self.after(0, lambda p=planned, r=result: self._set_preview(p, r))
            self.after(0, lambda: self.status.configure(
                text="Previewed. Tick what you want and press Apply."))

        threading.Thread(target=work, daemon=True).start()

    def _set_preview(self, planned, result: actions_mod.ActionResult) -> None:
        widget = getattr(planned, "_preview_widget", None)
        if widget is None:
            return
        try:
            widget.configure(text=result.message,
                             fg=FAINT if result.ok else DANGER)
        except tk.TclError:
            pass
        if not result.ok:
            # A step that refuses in preview will refuse for real; untick it so
            # it cannot be applied by someone clicking straight through.
            for candidate, variable in self.rows:
                if candidate is planned:
                    variable.set(False)

    # ---------------------------------------------------------------- apply
    def _apply(self) -> None:
        if self._applying:
            return
        chosen = [planned for planned, variable in self.rows if variable.get()]
        if not chosen:
            messagebox.showinfo("Nothing selected",
                                "Tick at least one step first.", parent=self)
            return

        risky = [p for p in chosen
                 if not p.spec.reversible or p.spec.risk != "low"]
        lines = "\n".join(f"  •  {p.spec.title}" for p in chosen)
        message = f"Apply {len(chosen)} step(s)?\n\n{lines}"
        if risky:
            message += ("\n\nSome of these cannot simply be undone:\n"
                        + "\n".join(f"  •  {p.spec.title} — "
                                    f"{p.spec.undo_hint or 'no automatic undo'}"
                                    for p in risky))
        if not messagebox.askyesno("Apply", message, parent=self):
            return

        needs_restore = any(not p.spec.reversible for p in chosen)
        if needs_restore and self.settings.get("restore_point_first", True):
            if messagebox.askyesno(
                    "Restore point",
                    "Create a system restore point first?\n\nIt takes a "
                    "moment and needs administrator approval, but it means "
                    "the irreversible steps can still be walked back.",
                    parent=self):
                chosen.insert(0, actions_mod.PlannedAction(
                    spec=actions_mod.REGISTRY["create_restore_point"],
                    params={"description": "Before System Supe-Up"},
                    reason="Safety net requested before irreversible steps."))

        self._applying = True
        self.apply_button.configure(state="disabled", text="Applying…")

        def work() -> None:
            confirm_each = bool(self.settings.get("confirm_every_action", True))
            verified: list = []
            for planned in chosen:
                if self.cancel.is_set():
                    break
                if confirm_each and not self._ask_on_main(planned):
                    self.after(0, lambda p=planned: self._set_result(
                        p, actions_mod.ActionResult(True, "skipped")))
                    continue
                self.after(0, lambda p=planned: self.status.configure(
                    text=f"running: {p.spec.title}…"))

                # Written before the action runs, so a half-completed change
                # that kills the app still leaves a record and its undo data.
                before = capture_state(self._fresh_sample(), planned.params)
                entry = self.journal.record(planned, before,
                                            finding=self.finding.title)

                result = actions_mod.apply(planned, dry_run=False)
                planned.result = result
                if result.ok and result.undo:
                    self._undo_stack.append((planned.spec.title, result.undo))
                self.journal.complete(entry, result)
                if result.ok and result.changed:
                    verified.append((planned, entry))
                self.after(0, lambda p=planned, r=result: self._set_result(p, r))

            if verified and not self.cancel.is_set():
                self._verify_all(verified)
            self.after(0, self._applied)

        threading.Thread(target=work, daemon=True).start()

    def _fresh_sample(self):
        """A reading taken now, falling back to the one the dialog opened with."""
        if self.sampler is not None:
            try:
                return self.sampler.sample(1.0)
            except Exception:
                pass
        return self.sample

    def _verify_all(self, verified: list) -> None:
        """Let the changes settle, then measure whether they actually helped."""
        from .journal import SETTLE_SECONDS

        self.after(0, lambda: self.status.configure(
            text=f"measuring the effect ({SETTLE_SECONDS:.0f}s)…"))
        # Wait on the cancel event rather than sleeping, so closing the window
        # does not leave a thread counting to eight.
        self.cancel.wait(SETTLE_SECONDS)
        if self.cancel.is_set():
            return
        sample = self._fresh_sample()
        for planned, entry in verified:
            after = capture_state(sample, planned.params)
            verdict, changes = verify(entry, after)
            self.journal.complete(entry, planned.result, after, verdict)
            self.after(0, lambda p=planned, v=verdict, c=changes:
                       self._show_verdict(p, v, c))

    def _show_verdict(self, planned, verdict: str, changes: list) -> None:
        widget = getattr(planned, "_result_widget", None)
        if widget is None:
            return
        colour = {"helped": OK, "made things worse": DANGER}.get(verdict, DIM)
        lines = [f"{verdict}"]
        lines += [f"   {change.describe()}" for change in changes[:3]]
        try:
            existing = widget.cget("text")
            widget.configure(text=existing + "\n" + "\n".join(lines),
                             fg=colour if verdict == "helped" else
                             widget.cget("fg"))
        except tk.TclError:
            pass

    def _ask_on_main(self, planned) -> bool:
        """Ask on the UI thread and block the worker until answered."""
        answer: dict = {}
        done = threading.Event()

        def ask() -> None:
            try:
                answer["yes"] = messagebox.askyesno(
                    planned.spec.title,
                    f"{planned.spec.detail}\n\n"
                    f"{planned.reason}\n\nRun it now?", parent=self)
            finally:
                done.set()

        self.after(0, ask)
        done.wait(timeout=300)
        return bool(answer.get("yes"))

    def _set_result(self, planned, result: actions_mod.ActionResult) -> None:
        widget = getattr(planned, "_result_widget", None)
        if widget is None:
            return
        try:
            widget.configure(
                text=("✓  " if result.ok else "✕  ") + result.message,
                fg=OK if result.ok else DANGER)
            widget.pack(fill="x", pady=(3, 0))
        except tk.TclError:
            pass

    def _applied(self) -> None:
        self._applying = False
        self.apply_button.configure(state="normal", text="Apply selected")
        done = sum(1 for planned, _v in self.rows
                   if planned.result and planned.result.ok
                   and planned.result.changed)
        self.status.configure(
            text=f"Finished. {done} change(s) made. Watch the gauges for a "
                 f"minute to see whether it helped.")
        if self._undo_stack:
            self.undo_button.configure(state="normal")

    def _undo(self) -> None:
        """Reverse the most recent reversible change, from the journal.

        Read from disk rather than from this window's own stack, so a change
        made in an earlier session — or before a crash — can still be walked
        back. That was the point of persisting it.
        """
        pending = self.journal.undoable()
        if not pending:
            messagebox.showinfo("Undo", "There is nothing recorded that can "
                                        "be undone.", parent=self)
            self.undo_button.configure(state="disabled")
            return
        entry = pending[0]
        when = time.strftime("%d %b %H:%M", time.localtime(entry.at))
        if not messagebox.askyesno(
                "Undo", f"Reverse this change?\n\n{entry.title}\n{when}",
                parent=self):
            return
        result = actions_mod.undo(entry.undo or {})
        if result.ok:
            self.journal.mark_undone(entry)
        messagebox.showinfo("Undo", f"{entry.title}\n\n{result.message}",
                            parent=self)
        if not self.journal.undoable():
            self.undo_button.configure(state="disabled")

    def _close(self) -> None:
        if self._applying and not messagebox.askyesno(
                "Still applying",
                "A step is still running. Close anyway?", parent=self):
            return
        self.cancel.set()
        self.destroy()
