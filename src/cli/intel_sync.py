"""Layer 17: threat intelligence sync.

Pulls extra detection data from public feeds and adds it to the running scanner, next to the 150 built-in
signatures in ``signatures.py``. Nothing is written into the source tree: the merged data lives in memory and
in a local cache file, so the hardcoded database stays exactly as shipped.

Two kinds of feed:

* **Advisories** from OSV (https://osv.dev), the open database that aggregates the GitHub Security Advisories,
  the PyPA advisory database and the npm advisories. For every watched npm / PyPI package FoundryGuard asks
  ``api.osv.dev`` for the known vulnerable ranges. The dependency check (FG-90) then reports a pinned version
  that falls in any of them, on top of the short offline list.
* **Rule packs**: JSON files with line patterns, each tied to an SWC, CWE or CVE id. The default pack is
  ``intel/foundryguard-rules.json`` in the FoundryGuard repository; more can be listed in foundryguard.toml.

Every fetched entry is checked before it is used, and anything that fails is dropped, never half-loaded:

* feeds must be https, on an allowed host (the two defaults, plus hosts named in foundryguard.toml), at most
  2 MB; a pack can be pinned to a SHA-256 in the config;
* a rule needs an ``FGX-`` id, a known severity, a SWC/CWE/CVE reference, a pattern under 300 characters
  without backreferences or nested repeats, and one ``hit`` and one ``miss`` sample line: the pattern has to
  match the first and not the second. That is what "verified" means in the window's counter;
* an advisory needs an id, a package, an ecosystem FoundryGuard reads (npm, PyPI) and a numeric range.

When the network is down the last good sync is read back from the cache (and re-checked the same way). With
neither, the scanner runs on the 150 built-in signatures alone. Remote data is only ever parsed as JSON and
compiled as a regex; it is never executed.

foundryguard.toml::

    [intel]
    auto_update_signatures = true     # the window syncs in the background at start-up
    # max_age_hours = 24               # a newer cache is used without going to the network
    # osv = true                       # query OSV for the watched packages
    # packages = { npm = ["next"], pypi = ["django"] }   # watched on top of the built-in list
    # feeds = ["https://example.org/rules.json"]        # extra rule packs (their hosts become allowed)
    # [intel.pins]
    # "https://example.org/rules.json" = "<sha256 hex>"

``foundryguard intel sync`` and ``foundryguard intel status`` do the same from the command line. ``foundryguard
score`` uses the cache (never the network) when ``auto_update_signatures`` is true.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

if __package__:
    from . import signatures
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import signatures  # type: ignore

LAYER_ID = "L17"
OSV_QUERY = "https://api.osv.dev/v1/query"
DEFAULT_PACK = ("https://raw.githubusercontent.com/Rey-LLM/foundry-invariant-vault-patterns/main/"
                "intel/foundryguard-rules.json")
DEFAULT_HOSTS = frozenset({"api.osv.dev", "raw.githubusercontent.com"})
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 10.0
MAX_AGE_HOURS = 24.0
MAX_RULES = 500
MAX_ADVISORIES = 5000
PATTERN_MAX = 300
CACHE_VERSION = 1
USER_AGENT = "foundryguard-intel-sync"

ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}  # FoundryGuard key -> OSV ecosystem name
LANGS = frozenset({"sol", "py", "js", "php", "html"})
REF_RE = re.compile(r"\b(SWC-1\d\d|CWE-\d{1,5}|CVE-\d{4}-\d{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})\b")
ID_RE = re.compile(r"FGX-[A-Z0-9][A-Z0-9-]{0,39}")
ADV_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{2,63}")
PKG_RE = re.compile(r"(@[a-z0-9._~-]+/)?[A-Za-z0-9._~-]{1,214}")
VER_RE = re.compile(r"v?\d+(\.\d+){0,3}")
# backreferences, and a group with a repeat inside that is itself repeated: the usual catastrophic shapes
_BACKREF = re.compile(r"\\[1-9]|\(\?P=")
_NESTED_REPEAT = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]")

RULE_KEYS = ("id", "severity", "ref", "title", "mitigation", "fix", "langs", "pattern", "ignore_case", "raw_lines",
             "needs", "unless", "test")

Fetcher = Callable[[str, Optional[bytes]], bytes]


class IntelError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

@dataclass
class IntelConfig:
    enabled: bool = True
    max_age_hours: float = MAX_AGE_HOURS
    osv: bool = True
    packages: dict[str, tuple[str, ...]] = field(default_factory=dict)  # npm / pypi -> extra package names
    feeds: tuple[str, ...] = (DEFAULT_PACK,)
    pins: dict[str, str] = field(default_factory=dict)  # feed url -> sha256 hex
    source: str | None = None

    @classmethod
    def from_dict(cls, cfg: dict, source: str | None = None, default_enabled: bool = True) -> "IntelConfig":
        sec = cfg.get("intel") or {}
        if not isinstance(sec, dict):
            raise ValueError("foundryguard.toml [intel] must be a table")
        # the toggle is read from [intel] and, for convenience, from the top level
        flag = sec.get("auto_update_signatures", cfg.get("auto_update_signatures", default_enabled))
        pk = sec.get("packages") or {}
        packages = {}
        for eco, names in (pk.items() if isinstance(pk, dict) else ()):
            key = str(eco).lower()
            if key not in ECOSYSTEMS:
                raise ValueError(f"foundryguard.toml [intel] packages: unknown ecosystem {eco!r} (npm or pypi)")
            packages[key] = tuple(str(n) for n in names or ())
        feeds = tuple(str(u) for u in sec.get("feeds", ()) or ())
        return cls(bool(flag), float(sec.get("max_age_hours", MAX_AGE_HOURS)), bool(sec.get("osv", True)), packages,
                   (DEFAULT_PACK, *[u for u in feeds if u != DEFAULT_PACK]),
                   {str(k): str(v).lower() for k, v in (sec.get("pins") or {}).items()}, source)

    @property
    def hosts(self) -> frozenset[str]:
        return DEFAULT_HOSTS | {urllib.parse.urlsplit(u).hostname or "" for u in self.feeds}

    def watchlist(self) -> dict[str, tuple[str, ...]]:
        out = {}
        for eco in ECOSYSTEMS:
            names = list(signatures.ADVISORIES.get(eco, {}))
            names += [n for n in self.packages.get(eco, ()) if n.lower() not in names]
            out[eco] = tuple(names)
        return out


def load_config(start: Path | None = None, path: str | Path | None = None,
                default_enabled: bool = True) -> IntelConfig:
    """``[intel]`` from the nearest foundryguard.toml at or above ``start`` (or ``path``)."""
    if __package__:
        from . import compiler, scoring
    else:
        import compiler  # type: ignore
        import scoring  # type: ignore
    cfg_path = Path(path) if path else scoring.find_config((start or Path.cwd()).resolve())
    if not cfg_path or not cfg_path.is_file():
        return IntelConfig(enabled=default_enabled)
    return IntelConfig.from_dict(compiler._toml(cfg_path), str(cfg_path), default_enabled)


def cache_path() -> Path:
    override = os.environ.get("FOUNDRYGUARD_INTEL_CACHE")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "foundryguard" / "intel.json"


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #

def http_fetch(url: str, body: bytes | None = None, timeout: float = TIMEOUT) -> bytes:
    """GET (or POST ``body`` as JSON) with a size cap. Proxies come from the usual environment variables."""
    req = urllib.request.Request(url, data=body, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                                          **({"Content-Type": "application/json"} if body else {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced by check_url
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise IntelError(f"{url}: response larger than {MAX_BYTES // (1024 * 1024)} MB")
    return data


def check_url(url: str, hosts: Iterable[str]) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise IntelError(f"{url}: only https feeds are used")
    if (parts.hostname or "") not in set(hosts):
        raise IntelError(f"{url}: host {parts.hostname} is not an allowed feed host")


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RuleSpec:
    sig: signatures.Signature
    pattern: re.Pattern[str]
    langs: frozenset[str]
    raw_lines: bool  # True: match the raw line (bidi characters live in comments and strings)
    needs: re.Pattern[str] | None
    unless: re.Pattern[str] | None
    origin: str
    raw: dict = field(default_factory=dict, compare=False, repr=False)  # the validated entry, for the cache


def safe_pattern(text: object, what: str, flags: int = 0) -> re.Pattern[str]:
    if not isinstance(text, str) or not text:
        raise IntelError(f"{what}: pattern missing")
    if len(text) > PATTERN_MAX:
        raise IntelError(f"{what}: pattern longer than {PATTERN_MAX} characters")
    if _BACKREF.search(text):
        raise IntelError(f"{what}: backreferences are not accepted")
    if _NESTED_REPEAT.search(text):
        raise IntelError(f"{what}: nested repeats are not accepted")
    try:
        return re.compile(text, flags)
    except re.error as exc:
        raise IntelError(f"{what}: bad pattern ({exc})") from None


def _text(d: dict, key: str, what: str, limit: int = 400) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v.strip():
        raise IntelError(f"{what}: {key} missing")
    if len(v) > limit:
        raise IntelError(f"{what}: {key} longer than {limit} characters")
    return v.strip()


def validate_rule(d: object, origin: str) -> RuleSpec:
    if not isinstance(d, dict):
        raise IntelError(f"{origin}: rule is not an object")
    rid = d.get("id")
    if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
        raise IntelError(f"{origin}: rule id {rid!r} must look like FGX-SWC-129")
    what = f"{origin} {rid}"
    sev = str(d.get("severity", "")).upper()
    if sev not in signatures.SEVERITIES:
        raise IntelError(f"{what}: severity {d.get('severity')!r}")
    ref = _text(d, "ref", what, 80)
    if not REF_RE.search(ref):
        raise IntelError(f"{what}: ref must name an SWC, CWE, CVE or GHSA id")
    langs = d.get("langs")
    if not isinstance(langs, list) or not langs or not set(langs) <= LANGS:
        raise IntelError(f"{what}: langs must be a non-empty subset of {sorted(LANGS)}")
    flags = re.I if d.get("ignore_case") else 0
    pattern = safe_pattern(d.get("pattern"), what, flags)
    needs = safe_pattern(d["needs"], what + " needs", flags) if d.get("needs") else None
    unless = safe_pattern(d["unless"], what + " unless", flags) if d.get("unless") else None
    tests = d.get("test")
    if not isinstance(tests, dict) or not isinstance(tests.get("hit"), str) or not isinstance(tests.get("miss"), str):
        raise IntelError(f"{what}: test.hit and test.miss sample lines are required")
    if not pattern.search(tests["hit"]):
        raise IntelError(f"{what}: pattern does not match its own hit sample")
    if pattern.search(tests["miss"]):
        raise IntelError(f"{what}: pattern matches its miss sample")
    stack = signatures.SOL if set(langs) == {"sol"} else signatures.BACK
    sig = signatures.Signature(rid, "INTEL-" + rid[4:], stack, sev, ref, _text(d, "title", what, 160),
                               _text(d, "mitigation", what), str(d.get("fix") or "")[:600], fixed=True)
    keep = {k: d[k] for k in RULE_KEYS if k in d}
    keep["origin"] = origin
    return RuleSpec(sig, pattern, frozenset(langs), bool(d.get("raw_lines")), needs, unless, origin, keep)


def parse_pack(data: bytes, origin: str, errors: list[str]) -> list[RuleSpec]:
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise IntelError(f"{origin}: not JSON ({exc})") from None
    if not isinstance(doc, dict) or doc.get("format") != "foundryguard-rules/1" or not isinstance(doc.get("rules"), list):
        raise IntelError(f"{origin}: not a foundryguard-rules/1 pack")
    out = []
    for raw in doc["rules"][:MAX_RULES]:
        try:
            out.append(validate_rule(raw, origin))
        except IntelError as exc:
            errors.append(str(exc))
    return out


@dataclass(frozen=True)
class Advisory:
    eco: str  # npm | pypi
    package: str
    introduced: str | None
    fixed: str | None  # None: no fixed release yet
    id: str
    summary: str

    def as_dict(self) -> dict:
        return {"eco": self.eco, "package": self.package, "introduced": self.introduced, "fixed": self.fixed,
                "id": self.id, "summary": self.summary}


def validate_advisory(d: object) -> Advisory:
    if not isinstance(d, dict):
        raise IntelError("advisory is not an object")
    eco, pkg, adv_id = d.get("eco"), d.get("package"), d.get("id")
    if eco not in ECOSYSTEMS or not isinstance(pkg, str) or not PKG_RE.fullmatch(pkg):
        raise IntelError(f"advisory {adv_id!r}: bad ecosystem or package")
    if not isinstance(adv_id, str) or not ADV_ID_RE.fullmatch(adv_id):
        raise IntelError(f"advisory {adv_id!r}: bad id")
    lo, fx = d.get("introduced"), d.get("fixed")
    for v in (lo, fx):
        if v is not None and (not isinstance(v, str) or not VER_RE.match(v)):
            raise IntelError(f"advisory {adv_id}: bad version {v!r}")
    if lo is None and fx is None:
        raise IntelError(f"advisory {adv_id}: empty range")
    summary = re.sub(r"\s+", " ", str(d.get("summary") or ""))[:200]
    return Advisory(eco, pkg.lower(), lo, fx, adv_id, summary)


def osv_advisories(doc: object, eco: str) -> list[Advisory]:
    """Ranges from an OSV ``/v1/query`` answer (or a single OSV record) for one ecosystem."""
    vulns = doc.get("vulns", [doc] if isinstance(doc, dict) and "affected" in doc else []) if isinstance(doc, dict) else []
    out: list[Advisory] = []
    for v in vulns if isinstance(vulns, list) else []:
        if not isinstance(v, dict) or v.get("withdrawn"):
            continue
        try:
            out += _osv_ranges(v, eco)
        except (AttributeError, TypeError):  # malformed record: skip it, keep the rest
            continue
    good = []
    for a in out:
        try:
            good.append(validate_advisory(a))
        except IntelError:
            continue
    return good


def _osv_ranges(v: dict, eco: str) -> list[dict]:
    out: list[dict] = []
    aliases = [a for a in v.get("aliases") or [] if isinstance(a, str)]
    adv_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id"))
    summary = v.get("summary") or (v.get("details") or "").split(". ")[0]
    for aff in v.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        if pkg.get("ecosystem") != ECOSYSTEMS[eco]:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            open_lo, is_open = None, False
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    open_lo, is_open = (None if ev["introduced"] in ("0", "0.0.0") else ev["introduced"]), True
                elif "fixed" in ev and is_open:
                    out.append(_adv(eco, pkg.get("name"), open_lo, ev["fixed"], adv_id, summary))
                    is_open = False
                elif "last_affected" in ev:  # inclusive upper bound: not representable, skip the range
                    is_open = False
            if is_open:  # no fixed release yet
                out.append(_adv(eco, pkg.get("name"), open_lo, None, adv_id, summary))
    return out


def _adv(eco, name, lo, fixed, adv_id, summary) -> dict:
    return {"eco": eco, "package": name, "introduced": lo, "fixed": fixed, "id": adv_id, "summary": summary}


# --------------------------------------------------------------------------- #
# Sync
# --------------------------------------------------------------------------- #

@dataclass
class SyncResult:
    rules: list[RuleSpec] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)
    source: str = "none"  # network | cache | off | none | idle (nothing tried yet)
    fetched_at: float | None = None
    errors: list[str] = field(default_factory=list)
    feeds: list[dict] = field(default_factory=list)  # per feed: url, ok, count

    @property
    def dynamic(self) -> int:
        return len(self.rules) + len(self.advisories)

    def label(self) -> str:
        base = f"Signatures: {len(signatures.SIGNATURES)} hardcoded"
        if self.source == "idle":
            return base
        if self.source == "off":
            return base + " (sync off)"
        if self.source == "none":
            return base + " (sync failed, no cache)"
        tail = f" + {self.dynamic} dynamic verified"
        return base + tail + (" (cached)" if self.source == "cache" else "")


def _fetch_osv(cfg: IntelConfig, fetch: Fetcher, res: SyncResult) -> list[Advisory]:
    out: list[Advisory] = []
    for eco, names in cfg.watchlist().items():
        for name in names:
            body = json.dumps({"package": {"name": name, "ecosystem": ECOSYSTEMS[eco]}}).encode()
            try:
                data = fetch(OSV_QUERY, body)
                out += osv_advisories(json.loads(data.decode("utf-8")), eco)
            except (OSError, urllib.error.URLError, IntelError, ValueError) as exc:
                res.errors.append(f"osv {eco}/{name}: {exc}")
                if not out and isinstance(exc, (OSError, urllib.error.URLError)):
                    res.feeds.append({"url": OSV_QUERY, "ok": False, "count": 0})
                    return out  # offline: do not wait on every package
    res.feeds.append({"url": OSV_QUERY, "ok": True, "count": len(out)})
    return out


def _dedupe(rules: list[RuleSpec], advisories: list[Advisory]) -> tuple[list[RuleSpec], list[Advisory]]:
    seen, r_out = set(), []
    for r in rules:
        if r.sig.id not in seen:
            seen.add(r.sig.id)
            r_out.append(r)
    keys, a_out = set(), []
    for a in advisories:
        k = (a.eco, a.package, a.introduced, a.fixed, a.id)
        if k not in keys:
            keys.add(k)
            a_out.append(a)
    return r_out, a_out[:MAX_ADVISORIES]


def sync(cfg: IntelConfig, fetch: Fetcher | None = None, cache: Path | None = None, now: float | None = None,
         force: bool = False) -> SyncResult:
    """Network first, cache as the fallback. Activates whatever it ends up with and returns it."""
    cache = cache or cache_path()
    now = time.time() if now is None else now
    if not cfg.enabled:
        res = SyncResult(source="off")
        activate(res)
        return res
    cached = load_cache(cache)
    if cached and not force and cached.fetched_at and now - cached.fetched_at < cfg.max_age_hours * 3600:
        activate(cached)
        return cached
    fetch = fetch or (lambda url, body=None: http_fetch(url, body))
    res = SyncResult(source="network", fetched_at=now)
    pack_rules: list[RuleSpec] = []
    any_ok = False
    for url in cfg.feeds:
        try:
            check_url(url, cfg.hosts)
            data = fetch(url, None)
            pin = cfg.pins.get(url)
            if pin and hashlib.sha256(data).hexdigest() != pin:
                raise IntelError(f"{url}: SHA-256 does not match the pin in foundryguard.toml")
            got = parse_pack(data, url, res.errors)
            pack_rules += got
            res.feeds.append({"url": url, "ok": True, "count": len(got)})
            any_ok = True
        except (OSError, urllib.error.URLError, IntelError, ValueError) as exc:
            res.errors.append(f"{url}: {exc}")
            res.feeds.append({"url": url, "ok": False, "count": 0})
    advisories: list[Advisory] = []
    if cfg.osv:
        advisories = _fetch_osv(cfg, fetch, res)
        any_ok = any_ok or res.feeds[-1]["ok"]
    if not any_ok:
        fallback = cached or SyncResult(source="none")
        fallback.errors = res.errors + fallback.errors
        if cached:
            fallback.source = "cache"
        activate(fallback)
        return fallback
    res.rules, res.advisories = _dedupe(pack_rules, advisories)
    save_cache(cache, res)
    activate(res)
    return res


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #

def save_cache(path: Path, res: SyncResult) -> None:
    doc = {"version": CACHE_VERSION, "fetched_at": res.fetched_at, "feeds": res.feeds,
           "rules": [r.raw for r in res.rules],
           "advisories": [a.as_dict() for a in res.advisories]}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=1))
        os.replace(tmp, path)
    except OSError as exc:
        res.errors.append(f"cache {path}: {exc}")


def load_cache(path: Path) -> SyncResult | None:
    """The last good sync, re-validated entry by entry (the file is just as untrusted as the feed)."""
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("version") != CACHE_VERSION:
        return None
    res = SyncResult(source="cache", fetched_at=doc.get("fetched_at") if isinstance(doc.get("fetched_at"), (int, float)) else None,
                     feeds=[f for f in doc.get("feeds") or [] if isinstance(f, dict)])
    for raw in (doc.get("rules") or [])[:MAX_RULES]:
        try:
            res.rules.append(validate_rule(raw, str(raw.get("origin") or "cache")))
        except (IntelError, AttributeError) as exc:
            res.errors.append(f"cache: {exc}")
    for raw in (doc.get("advisories") or [])[:MAX_ADVISORIES]:
        try:
            res.advisories.append(validate_advisory(raw))
        except IntelError as exc:
            res.errors.append(f"cache: {exc}")
    return res


# --------------------------------------------------------------------------- #
# Runtime merge
# --------------------------------------------------------------------------- #

_LOCK = threading.Lock()
_STATUS = SyncResult(source="idle")


def activate(res: SyncResult) -> None:
    """Swap the dynamic rules and advisories the scanner reads. Safe to call from a worker thread: the scanner
    reads each tuple once per file, so a scan in flight sees either the old set or the new one."""
    global _STATUS
    adv: dict[str, dict[str, list[tuple[str | None, str | None, str]]]] = {eco: {} for eco in ECOSYSTEMS}
    for a in res.advisories:
        text = f"{a.id} {a.summary}".strip()
        adv[a.eco].setdefault(a.package, []).append((a.introduced, a.fixed, text))
    with _LOCK:
        signatures.set_dynamic(tuple(res.rules), adv)
        _STATUS = res


def deactivate() -> None:
    activate(SyncResult(source="idle"))


def status() -> SyncResult:
    return _STATUS


def use_cache_if_enabled(target: Path, config_path: str | Path | None = None) -> SyncResult | None:
    """For ``foundryguard score``: load the cache (no network) when foundryguard.toml turns sync on."""
    cfg = load_config(target, config_path, default_enabled=False)
    if not cfg.enabled:
        return None
    cached = load_cache(cache_path())
    if cached:
        activate(cached)
    return cached


class BackgroundSync:
    """Runs ``sync`` on a daemon thread; ``poll()`` returns the result once, without blocking."""

    def __init__(self, cfg: IntelConfig, fetch: Fetcher | None = None, cache: Path | None = None) -> None:
        self.cfg, self.fetch, self.cache = cfg, fetch, cache
        self.result: SyncResult | None = None
        self._done = threading.Event()
        self.thread = threading.Thread(target=self._run, name="foundryguard-intel-sync", daemon=True)

    def start(self) -> "BackgroundSync":
        self.thread.start()
        return self

    def _run(self) -> None:
        try:
            self.result = sync(self.cfg, self.fetch, self.cache)
        except Exception as exc:  # never let a feed take the window down
            self.result = SyncResult(source="none", errors=[f"sync: {exc}"])
        self._done.set()

    def poll(self) -> SyncResult | None:
        return self.result if self._done.is_set() else None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def add_intel_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("action", choices=("sync", "status"), help="sync: fetch now; status: show the cached state")
    p.add_argument("--config", default=None, help="foundryguard.toml to read [intel] from")
    p.add_argument("--json", action="store_true", help="print the result as JSON")


def cmd_intel(args) -> int:
    try:
        cfg = load_config(Path.cwd(), args.config)
    except (ValueError, OSError) as exc:
        print(f"foundryguard: {exc}", file=sys.stderr)
        return 2
    if args.action == "sync":
        cfg.enabled = True
        res = sync(cfg, force=True)
    else:
        res = load_cache(cache_path()) or SyncResult(source="none")
    if args.json:
        print(json.dumps({"label": res.label(), "source": res.source, "fetched_at": res.fetched_at,
                          "rules": [r.sig.as_dict() for r in res.rules],
                          "advisories": [a.as_dict() for a in res.advisories], "feeds": res.feeds,
                          "errors": res.errors}, indent=2))
    else:
        print(res.label())
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(res.fetched_at)) if res.fetched_at else "never"
        print(f"  last sync: {when}   cache: {cache_path()}")
        for f in res.feeds:
            print(f"  {'ok  ' if f.get('ok') else 'FAIL'} {f.get('count', 0):>5}  {f.get('url')}")
        for r in res.rules:
            print(f"  {r.sig.id:<18} {r.sig.severity:<8} {r.sig.ref:<16} {r.sig.title}")
        for e in res.errors[:20]:
            print(f"  skipped: {e}")
    return 0 if res.source in ("network", "cache") else 1
