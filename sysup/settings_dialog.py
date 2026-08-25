"""The settings window: servers, models, research and sampling.

The model pickers are populated from whatever the servers actually have,
fetched live when you press Test. Typing a model name by hand is how you end
up with a tag that quietly does not exist and a tool that silently falls back
to something else, so the list is the source of truth and the box is a
dropdown rather than a text field.

Nothing is written until Save, and Save writes only this tool's own settings
file — AI Chat Lab's is read for defaults and never touched.
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from . import elevate as elevate_mod
from . import window_state
from .config import CHAT_LAB_SETTINGS, Settings
from .llm import Ollama
from .research import Researcher

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


def _entry(parent, textvariable, width=26, **kwargs):
    return tk.Entry(parent, textvariable=textvariable, width=width,
                    bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT,
                    relief="flat", font=FONT, highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=ACCENT,
                    disabledbackground=PANEL, disabledforeground=FAINT,
                    **kwargs)


def _button(parent, text, command, primary=False, **kwargs):
    return tk.Button(
        parent, text=text, command=command,
        font=FONT_BOLD if primary else FONT,
        bg=ACCENT if primary else RAISED, fg="white" if primary else TEXT,
        activebackground=ACCENT_DARK if primary else "#303644",
        activeforeground="white" if primary else TEXT,
        relief="flat", cursor="hand2", padx=14, pady=6, bd=0,
        highlightthickness=0, disabledforeground=FAINT, **kwargs)


class SettingsDialog(tk.Toplevel):
    """Modal settings editor.  `on_saved` is called with the new Settings."""

    def __init__(self, parent, settings: Settings, on_saved=None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.on_saved = on_saved
        self.app = parent
        self._models: dict[str, list[str]] = {}

        self.title("Settings")
        self.configure(bg=BG)
        self.minsize(700, 640)
        window_state.remember(self, "settings", default="760x760",
                              minimum=(700, 640))
        self.transient(parent)

        self._vars()
        self._build()
        self.grab_set()
        # Populate the dropdowns straight away, so the current model is shown
        # in context rather than as a bare string that may not exist.
        self.after(120, lambda: self._test_servers(quiet=True))

    # ------------------------------------------------------------ variables
    def _vars(self) -> None:
        get = self.settings.get

        def split(url: str, default_port: str = "11434") -> tuple[str, str]:
            url = (url or "").replace("http://", "").replace("https://", "")
            url = url.rstrip("/")
            if ":" in url:
                host, _, port = url.rpartition(":")
                return host, (port or default_port)
            return url, default_port

        host, host_port = split(str(get("ollama_url", "")))
        local, local_port = split(str(get("ollama_fallback_url", "")))

        self.v_host = tk.StringVar(value=host)
        self.v_host_port = tk.StringVar(value=host_port)
        self.v_local = tk.StringVar(value=local or "127.0.0.1")
        self.v_local_port = tk.StringVar(value=local_port)
        self.v_diagnose = tk.StringVar(value=str(get("diagnose_model", "")))
        self.v_triage = tk.StringVar(value=str(get("triage_model", "")))
        self.v_searxng = tk.StringVar(value=str(get("searxng_url", "")))
        self.v_research = tk.BooleanVar(value=bool(get("research", True)))
        self.v_ttl = tk.StringVar(
            value=str(get("research_cache_ttl_minutes", 4320)))
        self.v_interval = tk.StringVar(value=str(get("sample_interval", 1.0)))
        self.v_stall = tk.StringVar(value=str(get("stall_threshold_s", 2.5)))
        self.v_history = tk.StringVar(value=str(get("history_samples", 300)))
        self.v_ctx = tk.StringVar(value=str(get("max_context_window", 32768)))
        self.v_timeout = tk.StringVar(value=str(get("llm_timeout", 900)))
        self.v_temp = tk.StringVar(value=str(get("temperature", 0.2)))
        self.v_confirm = tk.BooleanVar(
            value=bool(get("confirm_every_action", True)))
        self.v_restore = tk.BooleanVar(
            value=bool(get("restore_point_first", True)))
        self.v_admin = tk.StringVar(value=elevate_mod.mode(self.settings))

    # ------------------------------------------------------------- building
    def _build(self) -> None:
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=22, pady=(18, 4))
        tk.Label(head, text="Settings", bg=BG, fg=TEXT,
                 font=FONT_TITLE).pack(anchor="w")
        tk.Label(head, text=f"saved to {self.settings.path}", bg=BG, fg=FAINT,
                 font=FONT_TINY).pack(anchor="w")

        # The settings run to six cards now, and the last of them is the one
        # most likely to be looked for. Scrolling the body keeps the Save
        # button on screen at any window height rather than pushing it off the
        # bottom -- a dialog you cannot save is worse than one you must scroll.
        holder = tk.Frame(self, bg=BG)
        holder.pack(fill="both", expand=True, padx=(22, 10), pady=8)
        canvas = tk.Canvas(holder, bg=BG, highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(holder, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=BG)
        body.bind("<Configure>", lambda _e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        inner_id = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(inner_id, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y", padx=(8, 0))
        self._scroller = canvas
        # Bound on the dialog, not with bind_all: wheel events reach a
        # toplevel through its children's bind tags anyway, and bind_all would
        # scroll this canvas from every other window in the app.
        self.bind("<MouseWheel>", self._on_wheel)

        self._servers_section(body)
        self._models_section(body)
        self._research_section(body)
        self._monitoring_section(body)
        self._safety_section(body)
        self._admin_section(body)

        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=22, pady=(6, 18))
        self.status = tk.Label(foot, text="", bg=BG, fg=DIM, font=FONT_SMALL,
                               anchor="w", wraplength=420, justify="left")
        self.status.pack(side="left", fill="x", expand=True)
        _button(foot, "Save", self._save, primary=True).pack(side="right")
        _button(foot, "Cancel", self.destroy).pack(side="right", padx=(0, 8))
        _button(foot, "Reset to inherited", self._reset).pack(side="right",
                                                              padx=(0, 8))
        _button(foot, "Reset window sizes", self._reset_windows).pack(
            side="right", padx=(0, 8))

    def _on_wheel(self, event) -> None:
        """Scroll the settings, unless the pointer is over something that has
        its own idea of what the wheel means."""
        widget = getattr(event, "widget", None)
        if isinstance(widget, (ttk.Combobox, tk.Listbox, tk.Text)):
            return
        try:
            self._scroller.yview_scroll(int(-event.delta / 120), "units")
        except Exception:
            pass

    def _card(self, parent, title: str, note: str = "") -> tk.Frame:
        card = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="x", pady=(0, 12))
        header = tk.Frame(card, bg=PANEL)
        header.pack(fill="x", padx=14, pady=(10, 2))
        tk.Label(header, text=title.upper(), bg=PANEL, fg=DIM,
                 font=FONT_TINY).pack(anchor="w")
        if note:
            tk.Label(header, text=note, bg=PANEL, fg=FAINT, font=FONT_TINY,
                     wraplength=660, justify="left").pack(anchor="w",
                                                          pady=(1, 0))
        inner = tk.Frame(card, bg=PANEL)
        inner.pack(fill="x", padx=14, pady=(6, 12))
        return inner

    def _servers_section(self, parent) -> None:
        inner = self._card(
            parent, "Model servers",
            "Blank inherits from AI Chat Lab. The host is tried first — that "
            "is where the large models live; the local server is the fallback "
            "when the network is not there.")

        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill="x", pady=2)
        tk.Label(row, text="Host", bg=PANEL, fg=TEXT, font=FONT,
                 width=7, anchor="w").pack(side="left")
        _entry(row, self.v_host, width=24).pack(side="left")
        tk.Label(row, text=":", bg=PANEL, fg=DIM).pack(side="left", padx=3)
        _entry(row, self.v_host_port, width=7).pack(side="left")
        self.host_status = tk.Label(row, text="", bg=PANEL, fg=DIM,
                                    font=FONT_SMALL)
        self.host_status.pack(side="left", padx=10)

        row2 = tk.Frame(inner, bg=PANEL)
        row2.pack(fill="x", pady=2)
        tk.Label(row2, text="Local", bg=PANEL, fg=TEXT, font=FONT,
                 width=7, anchor="w").pack(side="left")
        _entry(row2, self.v_local, width=24).pack(side="left")
        tk.Label(row2, text=":", bg=PANEL, fg=DIM).pack(side="left", padx=3)
        _entry(row2, self.v_local_port, width=7).pack(side="left")
        self.local_status = tk.Label(row2, text="", bg=PANEL, fg=DIM,
                                     font=FONT_SMALL)
        self.local_status.pack(side="left", padx=10)

        actions = tk.Frame(inner, bg=PANEL)
        actions.pack(fill="x", pady=(8, 0))
        self.test_button = _button(actions, "Test and load models",
                                   self._test_servers)
        self.test_button.pack(side="left")

    def _models_section(self, parent) -> None:
        inner = self._card(
            parent, "Models",
            "Diagnosis runs once on request, so it should be the best model "
            "available. Triage runs often and should be quick.")

        style = ttk.Style(self)
        style.configure("Dark.TCombobox", fieldbackground=PANEL_ALT,
                        background=RAISED, foreground=TEXT,
                        arrowcolor=DIM, bordercolor=BORDER)

        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill="x", pady=3)
        tk.Label(row, text="Diagnosis", bg=PANEL, fg=TEXT, font=FONT,
                 width=10, anchor="w").pack(side="left")
        self.diagnose_box = ttk.Combobox(
            row, textvariable=self.v_diagnose, width=44,
            style="Dark.TCombobox")
        self.diagnose_box.pack(side="left")

        row2 = tk.Frame(inner, bg=PANEL)
        row2.pack(fill="x", pady=3)
        tk.Label(row2, text="Triage", bg=PANEL, fg=TEXT, font=FONT,
                 width=10, anchor="w").pack(side="left")
        self.triage_box = ttk.Combobox(
            row2, textvariable=self.v_triage, width=44, style="Dark.TCombobox")
        self.triage_box.pack(side="left")

        self.model_note = tk.Label(
            inner, text="Press “Test and load models” to list what each "
                        "server has.", bg=PANEL, fg=FAINT, font=FONT_TINY,
            wraplength=660, justify="left")
        self.model_note.pack(anchor="w", pady=(6, 0))

        advanced = tk.Frame(inner, bg=PANEL)
        advanced.pack(fill="x", pady=(8, 0))
        for label, variable, width in (("Context window", self.v_ctx, 9),
                                       ("Timeout (s)", self.v_timeout, 7),
                                       ("Temperature", self.v_temp, 6)):
            tk.Label(advanced, text=label, bg=PANEL, fg=DIM,
                     font=FONT_SMALL).pack(side="left", padx=(0, 4))
            _entry(advanced, variable, width=width).pack(side="left",
                                                         padx=(0, 14))

    def _research_section(self, parent) -> None:
        inner = self._card(
            parent, "Research (SearXNG)",
            "Used to look up processes and error codes this tool does not "
            "already know, and to work out how to fix them.")
        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill="x", pady=2)
        tk.Label(row, text="URL", bg=PANEL, fg=TEXT, font=FONT, width=7,
                 anchor="w").pack(side="left")
        _entry(row, self.v_searxng, width=36).pack(side="left")
        self.searxng_status = tk.Label(row, text="", bg=PANEL, fg=DIM,
                                       font=FONT_SMALL)
        self.searxng_status.pack(side="left", padx=10)

        row2 = tk.Frame(inner, bg=PANEL)
        row2.pack(fill="x", pady=(8, 0))
        tk.Checkbutton(
            row2, text="Look things up on the web", variable=self.v_research,
            bg=PANEL, fg=TEXT, selectcolor=PANEL_ALT, activebackground=PANEL,
            activeforeground=TEXT, font=FONT, bd=0, highlightthickness=0,
            cursor="hand2").pack(side="left")
        tk.Label(row2, text="cache (min)", bg=PANEL, fg=DIM,
                 font=FONT_SMALL).pack(side="left", padx=(18, 4))
        _entry(row2, self.v_ttl, width=8).pack(side="left")
        _button(row2, "Test", self._test_searxng).pack(side="right")

    def _monitoring_section(self, parent) -> None:
        inner = self._card(
            parent, "Monitoring",
            "A stall is measured as how late this tool's own tick arrives — "
            "lower the threshold to catch shorter freezes, raise it if a busy "
            "machine reports stalls you do not feel.")
        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill="x")
        for label, variable, width in (
                ("Sample every (s)", self.v_interval, 7),
                ("Stall threshold (s)", self.v_stall, 7),
                ("History (samples)", self.v_history, 8)):
            tk.Label(row, text=label, bg=PANEL, fg=DIM,
                     font=FONT_SMALL).pack(side="left", padx=(0, 4))
            _entry(row, variable, width=width).pack(side="left", padx=(0, 16))

    def _safety_section(self, parent) -> None:
        inner = self._card(
            parent, "Fixes",
            "Nothing is ever changed without you approving it. These control "
            "what happens around that.")
        tk.Checkbutton(
            inner, text="Confirm each action individually before it runs",
            variable=self.v_confirm, bg=PANEL, fg=TEXT, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=TEXT, font=FONT, bd=0,
            highlightthickness=0, cursor="hand2").pack(anchor="w")
        tk.Checkbutton(
            inner, text="Offer a system restore point before anything that "
                        "is not trivially reversible",
            variable=self.v_restore, bg=PANEL, fg=TEXT, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=TEXT, font=FONT, bd=0,
            highlightthickness=0, cursor="hand2").pack(anchor="w", pady=(4, 0))

    def _admin_section(self, parent) -> None:
        """The elevation choice, stated as the trade it actually is."""
        elevated = elevate_mod.is_admin()
        inner = self._card(
            parent, "Administrator rights",
            "Fixes ask for elevation one at a time, which is why this is not "
            "needed for most of what the tool does. Running the whole tool "
            "elevated buys two things: readings Windows refuses to a standard "
            "process, and one prompt instead of one per action.")

        tk.Label(inner,
                 text=("This copy is running as administrator."
                       if elevated else
                       "This copy is running with standard rights."),
                 bg=PANEL, fg=(OK if elevated else TEXT),
                 font=FONT_BOLD, anchor="w").pack(anchor="w")
        for item in elevate_mod.RESTRICTED:
            tk.Label(inner, text=("• " + item), bg=PANEL,
                     fg=(FAINT if elevated else DIM), font=FONT_SMALL,
                     wraplength=640, justify="left",
                     anchor="w").pack(anchor="w", pady=(1, 0))

        for value, label in (
                ("ask", "Ask — say what is limited and offer a button "
                        "(recommended)"),
                ("always", "Always — request elevation every time it "
                           "starts"),
                ("never", "Never — do not mention it; each fix asks for "
                          "itself")):
            tk.Radiobutton(
                inner, text=label, value=value, variable=self.v_admin,
                bg=PANEL, fg=TEXT, selectcolor=PANEL_ALT,
                activebackground=PANEL, activeforeground=TEXT, font=FONT,
                bd=0, highlightthickness=0, cursor="hand2",
                anchor="w").pack(anchor="w",
                                 pady=(6 if value == "ask" else 0, 0))

        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill="x", pady=(10, 0))
        button = _button(row, "Restart as administrator now",
                         self._restart_as_admin)
        button.pack(side="left")
        if elevated:
            button.configure(state="disabled", text="Already an administrator")

    def _restart_as_admin(self) -> None:
        """Save first, then hand the restart to the window that owns the app.

        Restarting with the settings unsaved would lose whatever is in this
        dialog, and the elevated copy would come back with the old choice --
        which looks exactly like the setting not working.
        """
        if not self._save():
            return
        restart = getattr(self.app, "_restart_as_admin", None)
        if restart is None:
            messagebox.showwarning(
                "System Supe-Up",
                "Close and reopen System Supe-Up to apply this.")
            return
        restart()

    # -------------------------------------------------------------- testing
    def _url(self, host_var: tk.StringVar, port_var: tk.StringVar) -> str:
        host = host_var.get().strip().rstrip("/")
        port = port_var.get().strip() or "11434"
        if not host:
            return ""
        if host.startswith(("http://", "https://")):
            rest = host.split("//", 1)[1]
            return host if ":" in rest else f"{host}:{port}"
        return f"http://{host}:{port}"

    def _test_servers(self, quiet: bool = False) -> None:
        self.test_button.configure(state="disabled", text="Testing…")
        host = self._url(self.v_host, self.v_host_port)
        local = self._url(self.v_local, self.v_local_port)

        def work() -> None:
            found: dict[str, list[str]] = {}
            for label, url in (("host", host), ("local", local)):
                if not url:
                    found[label] = []
                    continue
                found[label] = Ollama([url], timeout=20).models(url)
            self.after(0, lambda: self._servers_tested(found, quiet))

        threading.Thread(target=work, daemon=True).start()

    def _servers_tested(self, found: dict[str, list[str]],
                        quiet: bool) -> None:
        self.test_button.configure(state="normal", text="Test and load models")
        self._models = found

        for label, widget in (("host", self.host_status),
                              ("local", self.local_status)):
            models = found.get(label, [])
            if not models:
                widget.configure(
                    text="not configured" if not self._url(
                        self.v_host if label == "host" else self.v_local,
                        self.v_host_port if label == "host" else self.v_local_port)
                    else "unreachable",
                    fg=FAINT if not models else DANGER)
            else:
                widget.configure(text=f"✓ {len(models)} models", fg=OK)

        # Host models first: that is the order the tool tries them in, so the
        # list reads the same way the resolver thinks.
        combined: list[str] = []
        for label in ("host", "local"):
            for name in found.get(label, []):
                if name not in combined:
                    combined.append(name)

        self.diagnose_box.configure(values=combined)
        self.triage_box.configure(values=combined)
        if combined:
            missing = [v.get() for v in (self.v_diagnose, self.v_triage)
                       if v.get() and v.get() not in combined]
            note = (f"{len(combined)} models available. "
                    f"Host models are listed first.")
            if missing:
                note += (f"  Not present on any server: {', '.join(missing)} — "
                         f"the closest match will be used instead.")
            self.model_note.configure(text=note,
                                      fg=WARN if missing else FAINT)
        elif not quiet:
            self.model_note.configure(
                text="No server answered, so no models could be listed.",
                fg=DANGER)

    def _test_searxng(self) -> None:
        url = self.v_searxng.get().strip()
        if not url:
            self.searxng_status.configure(text="not set", fg=FAINT)
            return
        self.searxng_status.configure(text="testing…", fg=DIM)

        def work() -> None:
            try:
                count = Researcher(url).ping()
            except Exception:
                count = 0
            self.after(0, lambda: self.searxng_status.configure(
                text=f"✓ {count} results" if count else "no results / JSON off",
                fg=OK if count else DANGER))

        threading.Thread(target=work, daemon=True).start()

    # --------------------------------------------------------------- saving
    def _reset_windows(self) -> None:
        """Every window back to the size it was designed at, next time.

        Here because a window that ends up somewhere unreachable is the one
        problem the user cannot fix from inside the app -- `window_state`
        already refuses a position that is off every monitor, but a window
        that is merely awkward is not something it can detect.
        """
        window_state.forget_all()
        self.status.configure(
            text="Window sizes and positions forgotten. Each window returns "
                 "to its normal size the next time it opens.")

    def _reset(self) -> None:
        if not messagebox.askyesno(
                "Reset", f"Clear the server addresses so they are inherited "
                         f"from AI Chat Lab again?\n\n{CHAT_LAB_SETTINGS}",
                parent=self):
            return
        for key in ("ollama_url", "ollama_fallback_url", "searxng_url"):
            self.settings[key] = ""
        self.settings.save()
        fresh = Settings.load()
        self.settings = fresh
        self._vars()
        messagebox.showinfo("Reset", "Addresses will be inherited again. "
                                     "Reopen settings to see them.",
                            parent=self)

    def _number(self, variable: tk.StringVar, kind, default, low, high):
        try:
            value = kind(variable.get().strip())
        except (TypeError, ValueError):
            return default
        return max(low, min(high, value))

    def _save(self) -> bool:
        """True when the settings were actually written and this closed."""
        host = self._url(self.v_host, self.v_host_port)
        local = self._url(self.v_local, self.v_local_port)
        if not host and not local:
            if not messagebox.askyesno(
                    "No server", "No model server is configured. Findings and "
                                 "evidence will still work, but reports will "
                                 "have no written explanation.\n\nSave "
                                 "anyway?", parent=self):
                return

        settings = self.settings
        settings["ollama_url"] = host
        settings["ollama_fallback_url"] = local
        settings["searxng_url"] = self.v_searxng.get().strip()
        settings["diagnose_model"] = self.v_diagnose.get().strip()
        settings["triage_model"] = self.v_triage.get().strip()
        settings["research"] = bool(self.v_research.get())
        settings["research_cache_ttl_minutes"] = self._number(
            self.v_ttl, int, 4320, 0, 100_000)
        settings["sample_interval"] = self._number(
            self.v_interval, float, 1.0, 0.25, 10.0)
        settings["stall_threshold_s"] = self._number(
            self.v_stall, float, 2.5, 0.5, 30.0)
        settings["history_samples"] = self._number(
            self.v_history, int, 300, 30, 5000)
        settings["max_context_window"] = self._number(
            self.v_ctx, int, 32768, 2048, 262_144)
        settings["llm_timeout"] = self._number(
            self.v_timeout, int, 900, 30, 7200)
        settings["temperature"] = self._number(
            self.v_temp, float, 0.2, 0.0, 2.0)
        settings["confirm_every_action"] = bool(self.v_confirm.get())
        settings["restore_point_first"] = bool(self.v_restore.get())
        settings["admin_mode"] = (self.v_admin.get()
                                  if self.v_admin.get() in elevate_mod.MODES
                                  else "ask")

        if not settings.save():
            messagebox.showerror("Settings", "Could not write the settings "
                                             "file.", parent=self)
            return False
        # A SearXNG that stopped answering is given up on for the session, so
        # that a dead instance does not cost every later diagnosis a string of
        # connect timeouts. Someone who has just been in here and changed the
        # address has earned a fresh attempt.
        from .research import reset_reachability
        reset_reachability()
        if self.on_saved is not None:
            self.on_saved(settings)
        self.destroy()
        return True
