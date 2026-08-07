"""Settings, stored beside the ones AI Chat Lab already uses.

The Ollama servers and the SearXNG instance on this network are already
configured once, in `~/.ai_chat_lab_settings.json`.  Asking for them a second
time would be asking the user to maintain the same three addresses in two
places, so this file *reads* that one for its defaults and only stores what is
genuinely its own.  Nothing is ever written back to AI Chat Lab's file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SETTINGS_PATH = Path.home() / ".system_supeup_settings.json"
CHAT_LAB_SETTINGS = Path.home() / ".ai_chat_lab_settings.json"

REPORT_DIR = Path.home() / "SystemSupeUp" / "reports"

DEFAULTS: dict[str, Any] = {
    # Where the models live.  Blank means "inherit from AI Chat Lab".
    "ollama_url": "",
    "ollama_fallback_url": "",
    "searxng_url": "",

    # Two models, deliberately.  Triage runs often and must be quick; the
    # diagnosis runs once, on request, and should be the best thing available.
    # Both are resolved against what the server actually has at startup, so a
    # missing model degrades to the closest match rather than an error.
    "triage_model": "qwen3:8b",
    "diagnose_model": "qwen2.5:32b-instruct-q4_K_M",

    "sample_interval": 1.0,      # seconds between live samples
    "history_samples": 300,      # ~5 minutes of ring buffer at 1s
    "top_n": 12,                 # rows in the live table

    # A freeze is not a threshold on a graph, it is time the machine owed you
    # and did not deliver.  See freeze.py — this is how late our own 1s tick
    # has to be before we call it a system-wide stall.
    "stall_threshold_s": 2.5,
    "hang_threshold_s": 5.0,     # window unresponsive this long -> app freeze

    "research": True,            # look up unknown processes via SearXNG
    "research_cache_ttl_minutes": 4320,   # 3 days; what svchost does is stable
    "llm_timeout": 900,
    "max_context_window": 32768,
    "temperature": 0.2,          # diagnosis is not a creative writing task

    # Fixes that change the machine are never applied without a confirmation,
    # but this decides whether they are even offered.
    "suggest_actions": True,
    # Every action is previewed before it runs. With this on, each one is also
    # confirmed individually at the moment it runs, rather than the whole plan
    # being approved once.
    "confirm_every_action": True,
    # Offer a restore point before the first action that is not trivially
    # reversible. Costs a few seconds and is the difference between a change
    # that can be walked back and one that cannot.
    "restore_point_first": True,
}


def _chat_lab_values() -> dict[str, Any]:
    """Whatever AI Chat Lab has configured, or {} if it is not installed."""
    try:
        if CHAT_LAB_SETTINGS.exists():
            return json.loads(CHAT_LAB_SETTINGS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {}


def _url_from(ip: str, port: str) -> str:
    ip = str(ip or "").strip()
    port = str(port or "11434").strip() or "11434"
    if not ip:
        return ""
    if ip.startswith(("http://", "https://")):
        rest = ip.split("//", 1)[1]
        return ip.rstrip("/") if ":" in rest else f"{ip.rstrip('/')}:{port}"
    return f"http://{ip}:{port}"


@dataclass
class Settings:
    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULTS))
    path: Path = SETTINGS_PATH

    def __getitem__(self, key: str) -> Any:
        return self.values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.values[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        settings = cls(path=Path(path) if path else SETTINGS_PATH)
        try:
            if settings.path.exists():
                raw = json.loads(settings.path.read_text(encoding="utf-8"))
                for key, default in DEFAULTS.items():
                    if key in raw and isinstance(raw[key], type(default)):
                        settings.values[key] = raw[key]
        except (OSError, ValueError):
            pass    # a broken settings file must never stop the monitor starting

        lab = _chat_lab_values()
        if not settings.values["ollama_url"]:
            # The host box holds the 32B models, so it is the first choice and
            # the loopback server is the fallback — the reverse of AI Chat Lab,
            # which is a chat window where waiting is the user's decision.
            settings.values["ollama_url"] = _url_from(
                lab.get("host_ip", ""), lab.get("host_port", "11434"))
        if not settings.values["ollama_fallback_url"]:
            settings.values["ollama_fallback_url"] = _url_from(
                lab.get("local_ip", "127.0.0.1"), lab.get("local_port", "11434"))
        if not settings.values["searxng_url"]:
            settings.values["searxng_url"] = str(lab.get("searxng_url", "") or "")
        return settings

    def save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.values, indent=2),
                                 encoding="utf-8")
            return True
        except OSError:
            return False

    def servers(self) -> list[str]:
        """Ollama URLs to try, best first, with blanks and repeats removed."""
        seen: list[str] = []
        for url in (self.values.get("ollama_url"),
                    self.values.get("ollama_fallback_url")):
            url = (url or "").rstrip("/")
            if url and url not in seen:
                seen.append(url)
        return seen
