"""Looking up processes the built-in table has never heard of, via SearXNG.

The knowledge base covers the usual suspects, but every machine has half a
dozen things nobody has heard of — an OEM agent, a line-of-business tool, a
driver helper — and those are exactly the ones worth explaining, because the
user cannot tell a legitimate vendor agent from something that should not be
there.

Results are cached on disk for days.  What `Dell.TechHub.Instrumentation.
SubAgent.exe` is does not change, and a monitor that hits the network every
time it redraws would be its own performance problem.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

import requests

USER_AGENT = "SystemSupeUp/1.0"
CACHE_PATH = Path.home() / "SystemSupeUp" / "process-research.json"

PAGE_CHAR_LIMIT = 3000
SNIPPET_LIMIT = 400

#: Sites that exist to rank for "<something>.exe" and then tell the visitor it
#: might be a virus, next to a download button for a cleaner.  These are not
#: merely low quality — they are actively dangerous input, because a model
#: reading one will faithfully report that the user's legitimate software is
#: malware.  That happened in testing with a perfectly ordinary executable, so
#: this list is a safety control rather than a quality filter.
JUNK_DOMAINS = (
    "file.net", "processlibrary.com", "exefiles.com", "runscanner.net",
    "systemexplorer.net", "pcrisk.com", "errortools.com", "fixdll",
    "dllme.com", "solvusoft.com", "winpcware", "reviversoft",
    "threatinfo", "gridinsoft", "howtofix", "howtoremove", "pcrisk",
    "malwaretips", "spyware", "virusresearch", "enigmasoftware",
    "exefile", "dll-files", "wikidll", "fix4dll", "processchecker",
    "freefixer", "shouldiblockit", "shouldiremoveit", "systemlookup",
    "bestpcsoftwares", "pcfixhelp", "cleanpcguide", "deletemalware",
    "virusremovalguides", "myantispyware", "botcrawl", "sensorstechforum",
    "2-remove-virus", "pcthreat", "trojan-killer", "exterminate-it",
)

#: Where an answer about a Windows process is actually likely to be correct.
#: Ranked up rather than exclusively required, since vendor documentation for
#: a niche OEM agent lives in all sorts of places.
TRUSTED_DOMAINS = (
    "microsoft.com", "learn.microsoft.com", "docs.microsoft.com",
    "support.microsoft.com", "github.com", "stackoverflow.com",
    "superuser.com", "serverfault.com", "askubuntu.com", "wikipedia.org",
    "dell.com", "hp.com", "lenovo.com", "intel.com", "amd.com", "nvidia.com",
    "adobe.com", "google.com", "mozilla.org", "apache.org", "python.org",
    "anthropic.com", "sentinelone.com", "crowdstrike.com", "sophos.com",
    "connectwise.com", "tailscale.com", "docker.com", "jetbrains.com",
    "sysinternals.com", "bleepingcomputer.com", "ghacks.net",
)


class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer",
            "iframe", "form", "button", "aside"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "article",
             "section", "blockquote", "pre"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag in self.BLOCK:
            self._chunks.append("\n")

    def handle_data(self, data):
        if not self._skip and data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        raw = "".join(self._chunks)
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n\s*\n+", "\n", raw)
        return raw.strip()


def html_to_text(html: str) -> str:
    parser = _Text()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    return parser.text()


def domain_of(url: str) -> str:
    match = re.match(r"https?://([^/]+)", url or "", re.IGNORECASE)
    return match.group(1).lower() if match else (url or "")[:40]


@dataclass
class Source:
    title: str
    url: str
    snippet: str = ""
    body: str = ""

    @property
    def domain(self) -> str:
        return domain_of(self.url)


@dataclass
class ProcessResearch:
    name: str
    sources: list[Source] = field(default_factory=list)
    at: float = 0.0

    def as_context(self, limit: int = 4) -> str:
        """The sourced block handed to the model.

        Prefixed with an explicit trust warning.  Everything else in the brief
        is measured from the kernel; this section is the open web, and it must
        not be read with the same confidence as the rest.
        """
        parts = [
            "NOTE: the following is unverified web search output, not "
            "measurement. Use it only to say what a program is and who "
            "publishes it. It is NOT evidence about this machine, and it is "
            "NOT a security verdict — pages that call ordinary software "
            "malicious are common and usually wrong."]
        for number, source in enumerate(self.sources[:limit], 1):
            block = [f"Source {number}: {source.title}\nURL: {source.url}"]
            if source.snippet:
                block.append(f"Summary: {source.snippet}")
            if source.body:
                block.append(f"Page content:\n{source.body}")
            parts.append("\n".join(block))
        return "\n\n---\n\n".join(parts)


class Researcher:
    """SearXNG plus a disk cache, scoped to identifying processes."""

    def __init__(self, base_url: str, ttl_minutes: int = 4320,
                 timeout: int = 12) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.ttl = ttl_minutes * 60
        self.timeout = timeout
        self._cache = self._load_cache()

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    # -- cache -------------------------------------------------------------
    def _load_cache(self) -> dict:
        try:
            if CACHE_PATH.exists():
                return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        return {}

    def _save_cache(self) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            CACHE_PATH.write_text(json.dumps(self._cache, indent=1),
                                  encoding="utf-8")
        except OSError:
            pass

    def _cached(self, key: str) -> ProcessResearch | None:
        entry = self._cache.get(key)
        if not entry:
            return None
        if time.time() - entry.get("at", 0) > self.ttl:
            return None
        return ProcessResearch(
            name=key, at=entry.get("at", 0),
            sources=[Source(**s) for s in entry.get("sources", [])])

    # -- search ------------------------------------------------------------
    def search(self, query: str, max_results: int = 6) -> list[Source]:
        if not self.base_url:
            return []
        try:
            response = requests.get(
                f"{self.base_url}/search",
                params={"q": query, "format": "json", "safesearch": "1"},
                headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
            if response.status_code >= 400:
                return []
            payload = response.json()
        except (requests.RequestException, ValueError):
            return []

        sources = []
        for item in payload.get("results", []):
            url = item.get("url", "")
            if not url or any(junk in url.lower() for junk in JUNK_DOMAINS):
                continue
            sources.append(Source(
                title=(item.get("title") or url)[:200],
                url=url,
                snippet=(item.get("content") or "")[:SNIPPET_LIMIT]))

        # Trusted sources first, so that when only the top two get read in
        # full it is the documentation that gets read and not the blog.
        sources.sort(key=lambda s: 0 if any(
            t in s.domain for t in TRUSTED_DOMAINS) else 1)
        return sources[:max_results]

    @staticmethod
    def _relevant(source: Source, process_name: str) -> bool:
        """Does this result actually discuss the executable we asked about?

        Search engines happily return a car navigation site for a query about
        an executable whose name looks like a brand.  Requiring the name to
        appear means an off-topic page is dropped rather than being handed to
        a model as evidence about the user's machine.
        """
        stem = process_name.lower().removesuffix(".exe")
        if len(stem) < 4:
            return True     # too short to filter on without dropping real hits
        haystack = f"{source.title} {source.snippet} {source.url}".lower()
        return stem in haystack

    def fetch(self, url: str) -> str:
        try:
            response = requests.get(
                url, timeout=self.timeout, allow_redirects=True,
                headers={"User-Agent": USER_AGENT})
            if response.status_code >= 400:
                return ""
            if "html" not in response.headers.get("Content-Type", ""):
                return ""
            text = html_to_text(response.text[:500_000])
        except requests.RequestException:
            return ""
        return text[:PAGE_CHAR_LIMIT]

    def identify(self, process_name: str, read_pages: int = 2,
                 emit=None) -> ProcessResearch | None:
        """What is this executable?  Cached, and safe to call for anything."""
        key = (process_name or "").strip().lower()
        if not key or not self.base_url:
            return None
        cached = self._cached(key)
        if cached is not None:
            return cached

        say = emit or (lambda _m: None)
        say(f"searching for {process_name}")
        # Naming Windows and "process" steers away from unrelated products
        # that happen to share a name, which is most of them.
        query = f'"{process_name}" Windows process what is it publisher'
        sources = [s for s in self.search(query, max_results=8)
                   if self._relevant(s, process_name)]
        if not sources:
            sources = [s for s in self.search(f"{process_name} windows process", 8)
                       if self._relevant(s, process_name)]
        if not sources:
            return None
        sources = sources[:6]

        for source in sources[:read_pages]:
            say(f"reading {source.domain}")
            source.body = self.fetch(source.url)

        research = ProcessResearch(name=key, sources=sources, at=time.time())
        self._cache[key] = {
            "at": research.at,
            "sources": [{"title": s.title, "url": s.url,
                         "snippet": s.snippet, "body": s.body}
                        for s in sources],
        }
        self._save_cache()
        return research

    def ping(self) -> int:
        return len(self.search("test", max_results=5))
