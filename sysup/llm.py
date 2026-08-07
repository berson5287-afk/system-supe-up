"""Talking to the local Ollama servers.

Deliberately small.  The diagnosis this sends is already correct before it
leaves — the rules engine decided what is wrong — so this layer's job is to
explain, connect and tailor, and its failure mode must be "the report has no
narrative section" rather than "the tool crashed".  Every entry point returns
"" instead of raising.

Two servers are tried in order.  The 32B models live on the host box, so it is
first; the loopback server with a 3B model is the fallback, which is worse at
explaining but is still there when the network is not.  A machine that has
frozen badly enough to need this tool is exactly the machine whose network
stack may also be struggling, so a local fallback is not a nicety.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Iterable

import requests

USER_AGENT = "SystemSupeUp/1.0"


class LLMError(RuntimeError):
    """A request failed in a way worth reporting."""


def _rank(candidate: str, wanted: str) -> int:
    """How good a stand-in `candidate` is for `wanted`.  Higher is better."""
    candidate, wanted = candidate.lower(), wanted.lower()
    if candidate == wanted:
        return 1000
    base = wanted.split(":")[0]
    score = 0
    if candidate.startswith(base):
        score += 100
    # Prefer bigger models when the exact tag is gone: the diagnosis is a
    # one-off, so quality matters far more than speed.
    match = re.search(r"(\d+)\s*b", candidate)
    if match:
        score += min(int(match.group(1)), 120)
    if "instruct" in candidate:
        score += 5
    return score


class Ollama:
    """One or more Ollama servers, tried in order."""

    def __init__(self, urls: Iterable[str], timeout: int = 900,
                 connect_timeout: int = 6) -> None:
        self.urls = [u.rstrip("/") for u in urls if u]
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self._models: dict[str, list[str]] = {}
        self.active_url = ""

    # -- discovery ---------------------------------------------------------
    def models(self, url: str) -> list[str]:
        if url in self._models:
            return self._models[url]
        try:
            response = requests.get(f"{url}/api/tags",
                                    timeout=self.connect_timeout,
                                    headers={"User-Agent": USER_AGENT})
            if response.status_code >= 400:
                self._models[url] = []
            else:
                self._models[url] = sorted(
                    m["name"] for m in response.json().get("models", [])
                    if m.get("name"))
        except (requests.RequestException, ValueError):
            self._models[url] = []
        return self._models[url]

    def available(self) -> list[tuple[str, list[str]]]:
        return [(url, self.models(url)) for url in self.urls]

    def resolve(self, wanted: str) -> tuple[str, str]:
        """Pick (server url, model name) for a requested model.

        Asking for a model the server does not have is the single most common
        way this stops working — someone renames a tag, or the box is rebuilt
        with different weights.  Falling back to the closest available model
        keeps the tool useful instead of turning a missing tag into an error
        the user has to go and read a settings file to understand.
        """
        for url in self.urls:
            names = self.models(url)
            if not names:
                continue
            if wanted in names:
                return url, wanted
            best = max(names, key=lambda n: _rank(n, wanted))
            if _rank(best, wanted) >= 100:
                return url, best
        # Nothing resembling it anywhere: take whatever the first live server
        # has rather than giving up.
        for url in self.urls:
            names = self.models(url)
            if names:
                return url, max(names, key=lambda n: _rank(n, wanted))
        return "", ""

    def reachable(self) -> bool:
        return any(self.models(url) for url in self.urls)

    # -- generation --------------------------------------------------------
    def chat(self, model: str, messages: list[dict[str, str]],
             on_token: Callable[[str], None] | None = None,
             cancel: threading.Event | None = None,
             temperature: float = 0.2,
             num_ctx: int = 16384,
             num_predict: int = -1,
             think: bool | None = None) -> str:
        """Stream a completion.  Returns "" rather than raising."""
        url, resolved = self.resolve(model)
        if not url:
            return ""
        self.active_url = url

        payload = {
            "model": resolved,
            "messages": messages,
            "stream": True,
            "options": {"temperature": temperature, "num_ctx": num_ctx},
        }
        if num_predict > 0:
            payload["options"]["num_predict"] = num_predict
        if think is not None:
            payload["think"] = think

        try:
            response = requests.post(
                f"{url}/api/chat", json=payload, stream=True,
                headers={"User-Agent": USER_AGENT},
                timeout=(self.connect_timeout, self.timeout))
        except requests.RequestException:
            return ""
        if response.status_code >= 400:
            response.close()
            # A server that rejects `think` for a non-reasoning model says so
            # with a 400; retrying without it is cheaper than knowing which
            # models reason.
            if think is not None:
                return self.chat(model, messages, on_token, cancel,
                                 temperature, num_ctx, num_predict, think=None)
            return ""

        chunks: list[str] = []
        try:
            for line in response.iter_lines(decode_unicode=False):
                if cancel is not None and cancel.is_set():
                    break
                if not line:
                    continue
                try:
                    data = json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if data.get("error"):
                    break
                piece = (data.get("message") or {}).get("content") or ""
                if piece:
                    chunks.append(piece)
                    if on_token is not None:
                        on_token(piece)
                if data.get("done"):
                    break
        except requests.RequestException:
            pass
        finally:
            response.close()

        return strip_reasoning("".join(chunks))

    def ask(self, model: str, system: str, user: str, **kwargs) -> str:
        return self.chat(model, [{"role": "system", "content": system},
                                 {"role": "user", "content": user}], **kwargs)


THINK_TAGS = re.compile(r"<think(?:ing)?>.*?</think(?:ing)?>",
                        re.IGNORECASE | re.DOTALL)


def strip_reasoning(text: str) -> str:
    """Remove inline <think> blocks.

    Qwen3 and friends emit their working in the answer when the server is too
    old for the separate `thinking` field.  In a chat window that is
    interesting; in a diagnosis report it is three pages of the model talking
    itself into the answer, above the answer.
    """
    cleaned = THINK_TAGS.sub("", text or "")
    # An unterminated opening tag means the model was still reasoning when it
    # hit its token limit — everything after it is working, not answer.
    if "<think" in cleaned.lower():
        cleaned = re.split(r"<think(?:ing)?>", cleaned, flags=re.IGNORECASE)[0]
    return cleaned.strip()
