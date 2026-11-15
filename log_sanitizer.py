#!/usr/bin/env python3
"""Log Sanitizer - redact sensitive values from logs, configs and Office documents.

GUI:  python log_sanitizer.py
CLI:  python log_sanitizer.py app.log [more.log ...] [-o out.log] [-c config.json]
      type app.log | python log_sanitizer.py - -o -
"""
from __future__ import annotations

import argparse
import codecs
import dataclasses
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, Iterator, List, Optional, Pattern, Tuple

# --------------------------------------------------------------------------- constants

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(APP_DIR, "config.json")
MAX_FILE_SIZE_MB = 100
HASH_LENGTH = 12
SLOW_PATTERN_SECONDS = 5.0
PARALLEL_MIN_CHARS = 4_000_000  # inputs at least this large are scanned in worker processes
CHUNK_CONTEXT = 256  # chars of leading context per chunk (lookbehinds, \b)
CHUNK_OVERLAP = 64 * 1024  # trailing overlap so matches crossing a chunk boundary stay whole
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3
VALUE_GROUP = "value"  # name a group (?P<value>...) to redact only that part of a match

IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
IPV4 = rf"{IPV4_OCTET}(?:\.{IPV4_OCTET}){{3}}"

# key/value building blocks: `key = value`, `key: "value"`, `"key": "value"`, `KEY=value&...`
_KV_SEP = r"""["']?\s*[:=]\s*["']?"""
_KV_VALUE = r"""(?P<value>(?<=")[^"\r\n]+(?=")|(?<=')[^'\r\n]+(?=')|[^\s,;"'&]+)"""

SECURITY_PATTERNS = [
    "APIKey", "SecretKey", "Password", "DatabaseURL", "ConnectionString", "JWTToken",
    "AccessToken", "RefreshToken", "AuthHeader", "URLCredentials", "CloudToken", "PrivateKey",
]
SENSITIVE_NAME_HINTS = ("secret", "credential", "password", "key", "token")

OPTIONAL_PACKAGES = {"python-docx": "docx", "openpyxl": "openpyxl", "python-pptx": "pptx"}

_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")
_TEMPLATE_RE = re.compile(r"\\(?:\d|g<)")

log = logging.getLogger("log_sanitizer")
log.addHandler(logging.NullHandler())


# --------------------------------------------------------------------------- helpers

def resolve_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def is_risky_regex(pattern: str) -> bool:
    """Heuristic ReDoS guard for nested/ambiguous quantifiers."""
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return True
    return pattern.count(".*") >= 3 or pattern.count(".+") >= 3


def compile_regex(pattern: str, flags: int = 0) -> Pattern:
    return re.compile(pattern, flags)  # `re` keeps its own compile cache


def _kv(keys: str, value: str = _KV_VALUE, boundary: bool = True, spaced: str = "") -> str:
    """Regex for `<key><sep><value>` (key case-insensitive) where only the value gets redacted.
    boundary=False also matches prefixed keys like DB_PASSWORD / xtoken (and is faster).
    `spaced` keys are unambiguous enough to also accept a plain space: `api_key abc123`."""
    lead = "(?<![A-Za-z0-9])" if boundary else ""
    key = rf"(?i:{keys}){_KV_SEP}"
    if spaced:
        key = rf"(?:(?i:{spaced})(?:{_KV_SEP}|\s+[\"']?)|{key})"
    return f"{lead}{key}{value}"


def _luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _ipv6_ok(value: str) -> bool:
    addr = value.split("%", 1)[0]
    if "::" not in addr and addr.count(":") != 7:  # cheap reject (times like 14:35:22)
        return False
    if not any(c in "0123456789abcdefABCDEF" for c in addr):
        return False
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- patterns

@dataclass
class SanitizationPattern:
    """One redaction rule. If the regex has a (?P<value>...) group, only that group is replaced."""

    name: str
    pattern: Pattern
    replacement: str
    hash_flag: bool = False
    enabled: bool = True
    case_sensitive: bool = False
    comment: str = ""
    priority: int = 0
    examples: List[str] = field(default_factory=list)
    validator: Optional[Callable[[str], bool]] = None
    builtin: bool = False  # shipped default (saved to config as overrides only)
    gate: Tuple[str, ...] = ()  # lowercase literals; skip the regex if none occur in the text

    def __post_init__(self):
        if not self.name:
            raise ValueError("Pattern name cannot be empty")

    @property
    def tag(self) -> str:
        return re.sub(r"[^A-Z0-9]+", "_", self.name.upper()).strip("_") or "VALUE"

    def matches(self, text: str, salt: bytes = b"", pos: int = 0,
                limit: Optional[int] = None) -> Iterator[Tuple[int, int, str]]:
        """Yield (start, end, replacement) for each span this pattern redacts in `text`,
        scanning matches that start in [pos, limit)."""
        value_group = VALUE_GROUP in self.pattern.groupindex
        template = self.pattern.groups > 0 and bool(_TEMPLATE_RE.search(self.replacement))
        for m in self.pattern.finditer(text, pos):
            if limit is not None and m.start() >= limit:
                break
            start, end = m.span(VALUE_GROUP) if value_group else m.span()
            if start < 0 or start == end:
                continue
            value = text[start:end]
            if self.validator and not self.validator(value):
                continue
            if self.hash_flag:
                digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
                yield start, end, f"<HASHED_{self.tag}_{digest[:HASH_LENGTH].upper()}>"
            elif template:
                try:
                    yield start, end, m.expand(self.replacement)
                except (re.error, IndexError):
                    yield start, end, self.replacement
            else:
                yield start, end, self.replacement

    def apply(self, text: str, hash_salt: Optional[bytes] = None) -> Tuple[str, int]:
        """Apply only this pattern; returns (new_text, replacement_count)."""
        if not self.enabled:
            return text, 0
        result = sanitize_text(text, [self], hash_salt or b"")
        return result.text, sum(result.counts.values())


def make_pattern(name: str, regex: str, replacement: str, *, case_sensitive: bool = False,
                 hash_flag: bool = False, enabled: bool = True, priority: int = 0,
                 comment: str = "", examples: Optional[List[str]] = None,
                 check_risky: bool = True) -> SanitizationPattern:
    """Validate and build a user pattern. Raises ValueError with a readable message."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Pattern name is required")
    if not regex:
        raise ValueError("Regular expression is required")
    if check_risky and is_risky_regex(regex):
        raise ValueError("Regex rejected: nested quantifiers may cause catastrophic backtracking (ReDoS)")
    try:
        compiled = re.compile(regex, 0 if case_sensitive else re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"Invalid regex: {e}") from None
    return SanitizationPattern(
        name=name, pattern=compiled, replacement=replacement, hash_flag=bool(hash_flag),
        enabled=bool(enabled), case_sensitive=bool(case_sensitive), comment=comment or "",
        priority=int(priority), examples=list(examples or []),
    )


def _d(regex: str, replacement: str, priority: int, comment: str, *, hashed: bool = False,
       gate: Tuple[str, ...] = (), validator: Optional[Callable[[str], bool]] = None) -> dict:
    return dict(regex=regex, replacement=replacement, priority=priority, comment=comment,
                hashed=hashed, gate=gate, validator=validator)


_HEX = "[0-9a-fA-F]"
# Built-ins are compiled case-sensitive (much faster in `re`); keywords use scoped (?i:...).
DEFAULT_PATTERNS: Dict[str, dict] = {
    "PrivateKey": _d(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
                     "<PRIVATE_KEY>", 110, "PEM / PGP private key blocks", gate=("private key",)),
    "IPPort": _d(rf"\b{IPV4}:\d{{1,5}}\b", "<IP>:<PORT>", 100, "IPv4 address with port", gate=(":",)),
    "URLCredentials": _d(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?P<value>[^/\s:@]+:[^/\s]+)@", "<CREDENTIALS>", 95,
                         "user:password inside URLs", gate=("://",)),
    "CloudToken": _d(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"
                     r"|\bglpat-[A-Za-z0-9_-]{20,}|\bxox[abposr]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b"
                     r"|\b[sr]k_(?:live|test)_[0-9A-Za-z]{10,}",
                     "<TOKEN>", 95, "AWS, GitHub, GitLab, Slack, Google and Stripe keys", hashed=True,
                     gate=("akia", "asia", "gh", "glpat-", "xox", "aiza", "k_live_", "k_test_")),
    "JWTToken": _d(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", "<JWT_TOKEN>", 92,
                   "JSON Web Tokens anywhere in the text", hashed=True, gate=("eyj",)),
    "AuthHeader": _d(r"(?<![A-Za-z0-9])(?i:Bearer|Basic|Token|Negotiate|NTLM|Digest)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})",
                     "<AUTH_TOKEN>", 90, "Authorization header credentials", hashed=True,
                     gate=("bearer", "basic", "token", "negotiate", "ntlm", "digest")),
    # `spaced` keys also accept "key value" (no = or :); generic keys like token/secret require = or :
    "APIKey": _d(_kv(r"(?:x-)?api[-_]?key", boundary=False, spaced=r"api[-_]?key"), "<API_KEY>", 90,
                 "api_key / x-api-key values", hashed=True, gate=("api",)),
    "SecretKey": _d(_kv(r"secret(?:[-_]?key)?", boundary=False, spaced=r"secret[-_]?key"), "<SECRET_KEY>", 90,
                    "secret / client_secret / secret_key values", hashed=True, gate=("secret",)),
    "Password": _d(_kv(r"passw(?:or)?d|passphrase|pwd", boundary=False, spaced=r"passw(?:or)?d|pwd"), "<PASSWORD>", 90,
                   "password=, pwd:, \"password\": \"...\", DB_PASSWORD=...", hashed=True, gate=("pass", "pwd")),
    "AccessToken": _d(_kv(r"token", boundary=False, spaced=r"(?:access|auth|id|session)[-_]?token"), "<ACCESS_TOKEN>",
                      90, "token / access_token / auth-token values", hashed=True, gate=("token",)),
    "RefreshToken": _d(_kv(r"refresh[-_]?token", boundary=False, spaced=r"refresh[-_]?token"), "<REFRESH_TOKEN>", 91,
                       "refresh_token values", hashed=True, gate=("refresh",)),
    "DatabaseURL": _d(_kv(r"(?:database|db)[-_]?ur[li]", r"(?P<value>[^\s\"']+)", boundary=False,
                          spaced=r"(?:database|db)[-_]?ur[li]"), "<DB_URL>", 90,
                      "DATABASE_URL / db_url values", hashed=True, gate=("url", "uri")),
    "ConnectionString": _d(_kv(r"conn(?:ection)?[-_]?str(?:ing)?", r"(?P<value>[^\r\n\"']+)", boundary=False,
                               spaced=r"conn(?:ection)?[-_]?str(?:ing)?"),
                           "<CONNECTION_STRING>", 90, "connection_string values", hashed=True, gate=("conn",)),
    "Email": _d(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<EMAIL>", 80, "Email addresses", gate=("@",)),
    "GUID": _d(rf"\b{_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}\b", "<GUID>", 70, "GUID / UUID", gate=("-",)),
    "SID": _d(r"\bS-1-5-21-\d+-\d+-\d+-\d+\b", "<SID>", 70, "Windows domain SIDs", hashed=True, gate=("s-1-5-21-",)),
    # (character class first, assertion second: lets `re` skip non-candidate positions quickly)
    "CreditCard": _d(r"\d(?<![\d-]\d)(?:[ -]?\d){12,18}(?![\d-])", "<CARD>", 65, "Payment card numbers (Luhn-checked)",
                     validator=_luhn_ok),
    "MACAddress": _d(rf"{_HEX}(?<!\w{_HEX}){_HEX}[:-]{_HEX}{{2}}(?:[:-]{_HEX}{{2}}){{4}}\b", "<MAC>", 65, "MAC addresses"),
    "IPv6": _d(rf"(?<![\w:.])(?:{_HEX}{{0,4}}:){{2,7}}{_HEX}{{0,4}}(?:%[\w.-]+)?(?![\w:.])", "<IPV6>", 62,
               "IPv6 addresses (validated)", gate=(":",), validator=_ipv6_ok),
    "PortSpec": _d(r"(?<![A-Za-z0-9])(?i:port)(?:\s*[:=]\s*|\s+)(?P<value>\d{1,5})\b", "<PORT>", 60,
                   "port=8080 / port 443", gate=("port",)),
    "DistinguishedName_CN": _d(r"(?<![A-Za-z0-9])(?i:CN)=(?P<value>(?:\\,|[^,\r\n])+)", "<USER>", 55,
                               "Common names in LDAP distinguished names", gate=("cn=",)),
    "SAMAccountName": _d(_kv("sAMAccountName", r"(?P<value>[^,\s\"']+)"), "<USER>", 55, "AD sAMAccountName",
                         gate=("samaccountname",)),
    "DisplayName": _d(_kv("displayName", r"(?P<value>[^,\r\n\"']+)"), "<USER>", 55, "AD displayName",
                      gate=("displayname",)),
    "LegacyExchangeDN": _d(_kv("legacyExchangeDN", r"(?P<value>[^,\r\n\"']+)"), "<LEGACY_DN>", 55, "AD legacyExchangeDN",
                           gate=("legacyexchangedn",)),
    "MailNickname": _d(_kv("mailNickname", r"(?P<value>[^,\s\"']+)"), "<NICKNAME>", 55, "AD mailNickname",
                       gate=("mailnickname",)),
    "ObjectCategory": _d(_kv("objectCategory", r"(?P<value>[^,\r\n\"']+)"), "<CATEGORY>", 55, "AD objectCategory",
                         gate=("objectcategory",)),
    "ProxyAddresses": _d(_kv("proxyAddresses", r"(?P<value>[^,\r\n\"']+)"), "<PROXY>", 55, "AD proxyAddresses",
                         gate=("proxyaddresses",)),
    "ShowInAddressBook": _d(_kv("showInAddressBook", r"(?P<value>[^,\r\n\"']+)"), "<ADDRESS_BOOK>", 55,
                            "AD showInAddressBook", gate=("showinaddressbook",)),
    "UserField": _d(_kv(r"user(?:[-_ ]?(?:name|id))?|uid|login", r"(?P<value>[^\s,;\"'&]+)"), "<USER>", 55,
                    "user= / username: / User Id= values", gate=("user", "uid", "login")),
    "IP": _d(rf"\b{IPV4}\b", "<IP>", 40, "IPv4 addresses", gate=(".",)),
    "Timestamp": _d(r"(?<=Logged at )\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "<TIMESTAMP>", 30,
                    "Timestamps after 'Logged at '", gate=("logged at ",)),
}

# Regexes shipped in older config.json.example files. A config entry that merely re-declares a
# built-in with one of these is treated as "keep the built-in" so the improved defaults apply.
_LEGACY_DEFAULT_REGEXES = {
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b",
    r"\b(?:port|PORT)(?:\s+|=|:)\d{1,5}\b",
    r"\b(?:api[-_]?key|API[-_]?KEY)(?:\s+|=|:)([^\s,;]+)",
    r"\b(?:secret[-_]?key|SECRET[-_]?KEY)(?:\s+|=|:)([^\s,;]+)",
    r"\b(?:password|PASSWORD|pwd|PWD)(?:\s+|=|:)([^\s,;]+)",
    r"(?:DATABASE_URL|database_url|DB_URL|db_url)(?:\s+|=|:)([^\s]+)",
    r"(?:connection[-_]?string|CONNECTION[-_]?STRING)(?:\s+|=|:)([^\n\"']+)",
    r"(?:jwt|JWT|bearer|Bearer)(?:\s+|:)([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)",
    r"\b(?:access[-_]?token|ACCESS[-_]?TOKEN)(?:\s+|=|:)([^\s,;]+)",
    r"\b(?:refresh[-_]?token|REFRESH[-_]?TOKEN)(?:\s+|=|:)([^\s,;]+)",
}


# --------------------------------------------------------------------------- core algorithm

@dataclass
class SanitizeResult:
    text: str
    counts: Dict[str, int]
    spans: List[Tuple[int, int, str]]  # (start, end, pattern name) of each replacement in `text`
    warnings: List[str]
    seconds: float


def _merge_spans(accepted: list, candidates: list) -> list:
    """Merge one pattern's matches into the accepted (sorted, non-overlapping) spans.

    A candidate that overlaps nothing is kept. A candidate that fully covers accepted spans
    replaces them (more is redacted, never less). A candidate inside or crossing an accepted
    span is dropped - that text is already redacted by a higher-priority pattern.
    """
    if not accepted:
        return candidates
    out, i, n = [], 0, len(accepted)
    for cand in candidates:
        cs, ce = cand[0], cand[1]
        while i < n and accepted[i][1] <= cs:
            out.append(accepted[i])
            i += 1
        j = i
        while j < n and accepted[j][0] < ce:
            j += 1
        if j == i:
            out.append(cand)
        elif (accepted[i][0] >= cs and accepted[j - 1][1] <= ce
              and not (j - i == 1 and accepted[i][0] == cs and accepted[i][1] == ce)):
            out.append(cand)  # strictly wider: absorb (an identical span keeps the higher priority)
            i = j
    out.extend(accepted[i:])
    return out


def _scan(text: str, patterns: List[SanitizationPattern], salt: bytes, pos: int = 0,
          limit: Optional[int] = None, progress: Optional[Callable[[int, int], None]] = None):
    """Find matches of every pattern in text[pos:limit]. Returns (matches, seconds, errors) per pattern."""
    lowered = text.lower()
    found, seconds, errors = [], [], []
    for i, p in enumerate(patterns, 1):
        t0, hits, err = time.perf_counter(), [], None
        if p.enabled and (not p.gate or any(k in lowered for k in p.gate)):
            try:
                hits = list(p.matches(text, salt, pos, limit))
            except Exception as ex:
                err = str(ex)
        found.append(hits)
        seconds.append(time.perf_counter() - t0)
        errors.append(err)
        if progress:
            progress(i, len(patterns))
    return found, seconds, errors


def _scan_chunk(args):
    """Process-pool worker: scan one chunk; offsets are returned relative to the full text."""
    text, offset, pos, limit, patterns, salt = args
    found, seconds, errors = _scan(text, patterns, salt, pos, limit)
    return [[(s + offset, e + offset, r) for s, e, r in hits] for hits in found], seconds, errors


def _scan_parallel(text: str, patterns: List[SanitizationPattern], salt: bytes,
                   progress: Optional[Callable[[int, int], None]] = None):
    """Split on line boundaries and scan chunks in worker processes. Each chunk carries some
    leading context (for lookbehinds) and trailing overlap (so matches crossing a boundary
    are complete); a match belongs to the chunk where it starts."""
    from concurrent.futures import ProcessPoolExecutor
    workers = min(os.cpu_count() or 2, 8)
    size = max(len(text) // (workers * 2), PARALLEL_MIN_CHARS // 4)
    bounds, start = [], 0
    while start < len(text):
        end = len(text) if len(text) - start <= size else text.find("\n", start + size) + 1 or len(text)
        bounds.append((start, end))
        start = end
    jobs = []
    for start, end in bounds:
        a, b = max(0, start - CHUNK_CONTEXT), min(len(text), end + CHUNK_OVERLAP)
        jobs.append((text[a:b], a, start - a, end - a, patterns, salt))
    found = [[] for _ in patterns]
    seconds = [0.0] * len(patterns)
    errors: List[Optional[str]] = [None] * len(patterns)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for n, (hits, secs, errs) in enumerate(pool.map(_scan_chunk, jobs), 1):
            for i, h in enumerate(hits):
                if h:
                    # drop a match that starts inside the previous chunk's last match
                    if found[i] and h[0][0] < found[i][-1][1]:
                        h = [m for m in h if m[0] >= found[i][-1][1]]
                    found[i].extend(h)
                seconds[i] += secs[i] / workers
                errors[i] = errors[i] or errs[i]
            if progress:
                progress(n, len(jobs))
    return found, seconds, errors


def sanitize_text(text: str, patterns: List[SanitizationPattern], salt: bytes,
                  progress: Optional[Callable[[int, int], None]] = None, parallel: bool = True) -> SanitizeResult:
    """Run `patterns` (already in priority order) against the ORIGINAL text, resolve overlaps,
    then build the output in a single pass. Placeholders are never re-matched by later patterns."""
    started = time.perf_counter()
    found = None
    if parallel and len(text) >= PARALLEL_MIN_CHARS and (os.cpu_count() or 1) > 1:
        try:
            found, seconds, errors = _scan_parallel(text, patterns, salt, progress)
        except Exception as ex:  # e.g. a pattern that cannot be pickled; fall back to one process
            log.warning("Parallel scan unavailable (%s); scanning in one process", ex)
    if found is None:
        found, seconds, errors = _scan(text, patterns, salt, progress=progress)

    accepted: list = []
    warnings: List[str] = []
    for p, hits, secs, err in zip(patterns, found, seconds, errors):
        if err:
            warnings.append(f"Pattern '{p.name}' failed and was skipped: {err}")
            log.error("Pattern %r failed: %s", p.name, err)
        if secs > SLOW_PATTERN_SECONDS:
            warnings.append(f"Pattern '{p.name}' is slow ({secs:.1f}s) - consider simplifying its regex")
        if hits:
            accepted = _merge_spans(accepted, [(s, e, r, p.name) for s, e, r in hits])

    pieces, spans, pos, out_len = [], [], 0, 0
    for s, e, r, name in accepted:
        pieces.append(text[pos:s])
        out_len += s - pos
        pieces.append(r)
        spans.append((out_len, out_len + len(r), name))
        out_len += len(r)
        pos = e
    pieces.append(text[pos:])
    counts = dict(Counter(name for _, _, _, name in accepted))
    return SanitizeResult("".join(pieces), counts, spans, warnings, time.perf_counter() - started)


# --------------------------------------------------------------------------- engine

class SanitizerEngine:
    """Holds the pattern set; thread-safe for concurrent reads from a worker thread."""

    def __init__(self):
        self.patterns: Dict[str, SanitizationPattern] = {}
        self._lock = threading.RLock()
        self.username = resolve_username()
        self.hostname = socket.gethostname()
        self._sorted_patterns_cache: Optional[List[SanitizationPattern]] = None
        self._hash_salt: bytes = secrets.token_bytes(32)
        self.initialize_default_patterns()

    # ---- pattern set management
    def invalidate_pattern_cache(self) -> None:
        self._sorted_patterns_cache = None

    def sorted_patterns(self) -> List[SanitizationPattern]:
        """Patterns in application order: priority desc, then longer regex, then name."""
        with self._lock:
            if self._sorted_patterns_cache is None:
                self._sorted_patterns_cache = sorted(
                    self.patterns.values(),
                    key=lambda p: (-p.priority, -len(p.pattern.pattern), p.name),
                )
            return list(self._sorted_patterns_cache)

    def get(self, name: str) -> Optional[SanitizationPattern]:
        with self._lock:
            return self.patterns.get(name)

    def set_pattern(self, pattern: SanitizationPattern, replaces: Optional[str] = None) -> None:
        with self._lock:
            if replaces and replaces != pattern.name:
                self.patterns.pop(replaces, None)
            self.patterns[pattern.name] = pattern
            self.invalidate_pattern_cache()

    def remove_pattern(self, name: str) -> bool:
        with self._lock:
            removed = self.patterns.pop(name, None) is not None
            self.invalidate_pattern_cache()
            return removed

    def enable_named_patterns(self, names: List[str], enabled: bool = True) -> List[str]:
        """Set enabled state; returns the names that actually changed."""
        changed = []
        with self._lock:
            for name in names:
                p = self.patterns.get(name)
                if p and p.enabled != enabled:
                    p.enabled = enabled
                    changed.append(name)
        return changed

    def toggle_pattern_enabled(self, name: str) -> bool:
        with self._lock:
            p = self.patterns.get(name)
            if p is None:
                return False
            p.enabled = not p.enabled
            return True

    def initialize_default_patterns(self) -> None:
        for name, spec in DEFAULT_PATTERNS.items():
            self.patterns[name] = SanitizationPattern(
                name, re.compile(spec["regex"]), spec["replacement"], spec["hashed"], priority=spec["priority"],
                case_sensitive=True, comment=spec["comment"], validator=spec["validator"],
                gate=spec["gate"], builtin=True,
            )
        # Machine-specific values; skipped when too short to be meaningful.
        for name, value, repl, comment in (("Username", self.username, "<USERNAME>", "Current Windows/OS user name"),
                                           ("Hostname", self.hostname, "<HOSTNAME>", "This computer's host name")):
            if len(value) >= 3:
                self._add_builtin(name, rf"\b{re.escape(value)}\b", repl, comment, (value.lower(),))
        self._add_builtin(
            "FilePath_Username",
            r"(?:(?<=[\\/]Users[\\/])|(?<=[\\/]home[\\/]))(?!(?:Public|Default|All Users|Shared)[\\/])"
            r"(?:[^\\/\r\n\"'<>|:*?]+(?=[\\/])|[^\\/\s\"'<>|:*?]+)",
            "<USERNAME>", "Any user name in C:\\Users\\<name> or /home/<name> paths", ("users", "home"),
        )
        self.invalidate_pattern_cache()

    def _add_builtin(self, name: str, regex: str, repl: str, comment: str, gate: Tuple[str, ...]) -> None:
        self.patterns[name] = SanitizationPattern(
            name, re.compile(regex, re.IGNORECASE), repl, False, priority=50, comment=comment,
            gate=gate, builtin=True,
        )

    # ---- configuration
    def load_config(self, config_path: str) -> Tuple[bool, str]:
        """Merge patterns from a JSON config. Entries without "regex" override fields of an
        existing pattern (e.g. {"name": "Hostname", "enabled": false})."""
        try:
            with open(config_path, "r", encoding="utf-8-sig") as fh:
                config = json.load(fh)
        except FileNotFoundError:
            return False, f"Config file not found: {config_path}"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in config file: {e}"
        except OSError as e:
            return False, f"Error loading config: {e}"

        entries = config.get("patterns") if isinstance(config, dict) else None
        if not isinstance(entries, list):
            return False, "Config must be an object with a \"patterns\" list"

        loaded, skipped = 0, []
        with self._lock:
            for entry in entries:
                try:
                    pattern = self._pattern_from_config(entry)
                except (ValueError, TypeError) as e:
                    label = entry.get("name", "?") if isinstance(entry, dict) else "?"
                    skipped.append(f"{label}: {e}")
                    log.warning("Skipping config pattern %s: %s", label, e)
                    continue
                self.patterns[pattern.name] = pattern
                loaded += 1
            self.invalidate_pattern_cache()

        log.info("Loaded %d patterns from %s (%d skipped)", loaded, config_path, len(skipped))
        msg = f"Loaded {loaded} patterns"
        if skipped:
            msg += f", skipped {len(skipped)}: " + "; ".join(skipped[:3]) + (" ..." if len(skipped) > 3 else "")
        return True, msg

    def _pattern_from_config(self, entry: dict) -> SanitizationPattern:
        if not isinstance(entry, dict) or not entry.get("name"):
            raise ValueError("missing \"name\"")
        name = str(entry["name"])
        existing = self.patterns.get(name)
        regex = entry.get("regex")
        if regex and existing and existing.builtin and regex in _LEGACY_DEFAULT_REGEXES:
            regex = None  # outdated copy of a built-in: keep the improved built-in
        if not regex:
            if existing is None:
                raise ValueError("missing \"regex\"")
            overrides = {k: v for k, v in (("enabled", entry.get("enabled")),
                                           ("priority", entry.get("priority")),
                                           ("hash_flag", entry.get("hash"))) if v is not None}
            if "priority" in overrides:
                overrides["priority"] = int(overrides["priority"])
            return dataclasses.replace(existing, **overrides)
        priority = entry.get("priority", existing.priority if existing else 0)
        return make_pattern(
            name, regex, entry.get("replacement", "<REDACTED>"),
            case_sensitive=entry.get("case_sensitive", False), hash_flag=entry.get("hash", False),
            enabled=entry.get("enabled", True), priority=priority,
            comment=entry.get("comment", ""), examples=entry.get("examples") or [],
        )

    def to_config(self) -> dict:
        """Built-ins are saved as overrides only (so future improvements still apply);
        custom or edited patterns are saved in full."""
        out = []
        for p in self.sorted_patterns():
            if p.builtin:
                out.append({"name": p.name, "enabled": p.enabled, "priority": p.priority, "hash": p.hash_flag})
                continue
            entry = {"name": p.name, "regex": p.pattern.pattern, "replacement": p.replacement,
                     "case_sensitive": p.case_sensitive, "hash": p.hash_flag, "enabled": p.enabled,
                     "priority": p.priority, "comment": p.comment}
            if p.examples:
                entry["examples"] = p.examples
            out.append(entry)
        return {"patterns": out}

    def save_config(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_config(), fh, indent=2, ensure_ascii=False)
        log.info("Saved config to %s", path)

    # ---- sanitizing
    def sanitize_detailed(self, text: str, progress: Optional[Callable[[int, int], None]] = None) -> SanitizeResult:
        """Sanitize with a fresh HMAC salt: hashes are stable within this run only."""
        salt = secrets.token_bytes(32)
        with self._lock:
            self._hash_salt = salt
        return sanitize_text(text, self.sorted_patterns(), salt, progress)

    def sanitize(self, log_text: str, callback: Optional[Callable[[int, int], None]] = None) -> Tuple[str, Dict[str, int]]:
        result = self.sanitize_detailed(log_text, callback)
        return result.text, result.counts

    def test_pattern(self, pattern_name: str, test_text: str) -> Tuple[bool, str, int]:
        p = self.get(pattern_name)
        if p is None:
            return False, f"Pattern '{pattern_name}' not found", 0
        result = sanitize_text(test_text, [dataclasses.replace(p, enabled=True)], self._hash_salt)
        return True, result.text, sum(result.counts.values())


# --------------------------------------------------------------------------- file I/O

def decode_bytes(data: bytes) -> Tuple[str, str]:
    """Decode with BOM detection, UTF-16 sniffing, strict UTF-8, then cp1252 fallback."""
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace"), "utf-16"
    head = data[:4096]
    if head and head.count(0) > len(head) // 4:  # BOM-less UTF-16 (e.g. some PowerShell output)
        enc = "utf-16-le" if head[1:2] == b"\x00" else "utf-16-be"
        return data.decode(enc, errors="replace"), enc
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace"), "cp1252"


def _check_size(path: str) -> None:
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise ValueError(f"File too large ({size / 1048576:.1f} MB). Maximum: {MAX_FILE_SIZE_MB} MB")


def _require(module: str, package: str):
    try:
        return __import__(module)
    except ImportError:
        raise RuntimeError(f"Reading this file needs {package}: pip install {package}") from None


def load_document(path: str) -> Tuple[str, str]:
    """Return (text, description) for text files and .docx/.xlsx/.pptx documents."""
    _check_size(path)
    ext = os.path.splitext(path)[1].lower()
    if ext in (".doc", ".xls", ".ppt"):
        raise ValueError("Legacy Office formats are not supported - save as .docx/.xlsx/.pptx first")
    if ext == ".docx":
        docx = _require("docx", "python-docx")
        doc = docx.Document(path)
        parts = [p.text for p in doc.paragraphs]
        for table in doc.tables:
            parts.extend("\t".join(cell.text for cell in row.cells) for row in table.rows)
        return "\n".join(parts), "Word document"
    if ext == ".xlsx":
        openpyxl = _require("openpyxl", "openpyxl")
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        try:
            parts = []
            for ws in wb.worksheets:
                parts.append(f"--- Sheet: {ws.title} ---")
                for row in ws.iter_rows(values_only=True):
                    cells = ["" if v is None else str(v) for v in row]
                    while cells and not cells[-1]:
                        cells.pop()
                    if cells:
                        parts.append("\t".join(cells))
        finally:
            wb.close()
        return "\n".join(parts), "Excel workbook"
    if ext == ".pptx":
        pptx = _require("pptx", "python-pptx")
        prs = pptx.Presentation(path)
        parts = []
        for i, slide in enumerate(prs.slides, 1):
            parts.append(f"--- Slide {i} ---")
            for shape in slide.shapes:
                if getattr(shape, "has_text_frame", False) and shape.text_frame.text:
                    parts.append(shape.text_frame.text)
                if getattr(shape, "has_table", False):
                    parts.extend("\t".join(c.text for c in row.cells) for row in shape.table.rows)
        return "\n".join(parts), "PowerPoint presentation"
    with open(path, "rb") as fh:
        text, encoding = decode_bytes(fh.read())
    return text, encoding


def save_document(path: str, text: str) -> None:
    """Save as .docx (one paragraph per line) or as UTF-8 text, preserving line endings."""
    if path.lower().endswith(".docx"):
        docx = _require("docx", "python-docx")
        doc = docx.Document()
        for line in text.splitlines():
            doc.add_paragraph(line)
        doc.save(path)
    else:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def is_sensitive_filename(path: str) -> bool:
    name = os.path.basename(path).lower()
    return name.endswith(".env") or name.startswith(".env") or any(h in name for h in SENSITIVE_NAME_HINTS)


def setup_logging(to_file: bool = True) -> None:
    handlers: List[logging.Handler] = []
    if to_file:
        try:
            os.makedirs(os.path.join(APP_DIR, "logs"), exist_ok=True)
            handlers.append(RotatingFileHandler(os.path.join(APP_DIR, "logs", "sanitizer.log"),
                                                maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT,
                                                encoding="utf-8"))
        except OSError:
            pass
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
                        handlers=handlers or [logging.NullHandler()])


# --------------------------------------------------------------------------- CLI

def run_cli(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="log_sanitizer", description="Redact sensitive values from logs and documents.")
    ap.add_argument("inputs", nargs="+", help="files to sanitize ('-' reads stdin)")
    ap.add_argument("-o", "--output", help="output path ('-' = stdout); single input only. "
                                           "Default: <name>.sanitized<ext> next to the input")
    ap.add_argument("-c", "--config", help="pattern config JSON (default: config.json next to this script)")
    ap.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    args = ap.parse_args(argv)
    if args.output and len(args.inputs) > 1:
        ap.error("--output can only be used with a single input")

    engine = SanitizerEngine()
    config = args.config or (DEFAULT_CONFIG if os.path.exists(DEFAULT_CONFIG) else None)
    if config:
        ok, msg = engine.load_config(config)
        if not ok:
            print(f"error: {msg}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"config: {msg}", file=sys.stderr)

    status = 0
    for src in args.inputs:
        try:
            if src == "-":
                text, _ = decode_bytes(sys.stdin.buffer.read())
            else:
                text, _ = load_document(src)
            result = engine.sanitize_detailed(text)
            dest = args.output
            if not dest:
                if src == "-":
                    dest = "-"
                else:
                    base, ext = os.path.splitext(src)
                    dest = f"{base}.sanitized{ext if ext.lower() not in ('.xlsx', '.pptx') else '.txt'}"
            if dest == "-":
                sys.stdout.buffer.write(result.text.encode("utf-8"))
                sys.stdout.flush()
            else:
                save_document(dest, result.text)
            if not args.quiet:
                detail = ", ".join(f"{k}: {v}" for k, v in sorted(result.counts.items(), key=lambda kv: -kv[1]))
                where = "" if dest == "-" else f" -> {dest}"
                print(f"{src}{where}: {sum(result.counts.values())} replacements in {result.seconds:.2f}s"
                      + (f" ({detail})" if detail else ""), file=sys.stderr)
                for w in result.warnings:
                    print(f"warning: {w}", file=sys.stderr)
        except Exception as e:
            print(f"error: {src}: {e}", file=sys.stderr)
            log.error("CLI failed on %s: %s", src, e)
            status = 1
    return status


# --------------------------------------------------------------------------- GUI

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # CLI still works without Tk
    tk = None

OPEN_TYPES = [
    ("Supported files", "*.log *.txt *.env *.json *.ini *.cfg *.conf *.yaml *.yml *.properties "
                        "*.xml *.csv *.out *.err *.docx *.xlsx *.pptx"),
    ("All files", "*.*"),
]
HIGHLIGHT_LIMIT = 50000


class LogSanitizerApp:
    """Tk front end: toolbar, pattern list on the left, input/output on the right."""

    def __init__(self, root, engine: Optional[SanitizerEngine] = None):
        self.root = root
        self.engine = engine or SanitizerEngine()
        self.source_path: Optional[str] = None
        self.last_counts: Dict[str, int] = {}
        self.busy = False
        self._progress = 0.0
        self._job_result = None
        self.status = tk.StringVar(value="Ready - open a file or paste text, then press Sanitize (Ctrl+Enter)")
        self.progress = tk.DoubleVar(value=0)
        mono = ("Consolas", 10) if sys.platform == "win32" else "TkFixedFont"
        self.mono = mono
        self._build_ui()
        self._bind_keys()
        self._load_default_config()
        self.refresh_patterns()

    # ---- layout
    def _build_ui(self):
        root = self.root
        style = ttk.Style(root)
        style.configure("Accent.TButton", font=("", 10, "bold"), padding=(14, 4))
        style.configure("Treeview", rowheight=22)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        bar = ttk.Frame(root, padding=(8, 8, 8, 4))
        bar.grid(row=0, column=0, sticky="ew")
        for text, cmd in (("Open…", self.open_file), ("Paste", self.paste_input), ("Clear", self.clear_all)):
            ttk.Button(bar, text=text, command=cmd).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        self.sanitize_btn = ttk.Button(bar, text="Sanitize ▶", style="Accent.TButton", command=self.sanitize)
        self.sanitize_btn.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        for text, cmd in (("Save…", self.save_output), ("Copy", self.copy_output)):
            ttk.Button(bar, text=text, command=cmd).pack(side=tk.LEFT, padx=(0, 4))
        for text, cmd in (("Save config…", self.save_config), ("Load config…", self.load_config)):
            ttk.Button(bar, text=text, command=cmd).pack(side=tk.RIGHT, padx=(4, 0))

        panes = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        panes.grid(row=1, column=0, sticky="nsew", padx=8)
        left = ttk.Frame(panes)
        right = ttk.PanedWindow(panes, orient=tk.VERTICAL)
        panes.add(left, weight=1)
        panes.add(right, weight=3)
        self._build_pattern_panel(left)
        self.input_text = self._text_panel(right, "Input", undo=True)
        self.output_text = self._text_panel(right, "Sanitized output", undo=False)
        self.output_frame = self.output_text.master
        self.output_text.tag_configure("hit", background="#fff1a8")

        status = ttk.Frame(root, padding=(8, 4, 8, 6))
        status.grid(row=2, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        ttk.Label(status, textvariable=self.status, anchor="w").grid(row=0, column=0, sticky="ew")
        ttk.Progressbar(status, variable=self.progress, maximum=100, length=180).grid(row=0, column=1)

    def _text_panel(self, panes, title: str, undo: bool):
        frame = ttk.LabelFrame(panes, text=title, padding=4)
        panes.add(frame, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text = tk.Text(frame, wrap=tk.NONE, undo=undo, font=self.mono, relief=tk.FLAT, borderwidth=0)
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        xs = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        return text

    def _build_pattern_panel(self, parent):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)
        ttk.Label(parent, text="Patterns  (applied top → bottom)", font=("", 9, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 4))
        frame = ttk.Frame(parent)
        frame.grid(row=1, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=("on", "hash", "prio", "hits"), selectmode="browse")
        for col, label, width in (("#0", "Pattern", 150), ("on", "On", 34), ("hash", "Hash", 40),
                                  ("prio", "Prio", 40), ("hits", "Hits", 50)):
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=30, stretch=(col == "#0"),
                        anchor=tk.W if col == "#0" else tk.CENTER)
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        tree.tag_configure("off", foreground="#999999")
        tree.bind("<ButtonRelease-1>", self._on_tree_click)
        tree.bind("<Double-1>", lambda e: self.edit_pattern() if tree.identify_column(e.x) != "#1" else None)
        tree.bind("<space>", lambda e: self.toggle_pattern())
        tree.bind("<Delete>", lambda e: self.delete_pattern())
        tree.bind("<Return>", lambda e: self.edit_pattern())
        tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree = tree

        btns = ttk.Frame(parent)
        btns.grid(row=2, column=0, sticky="ew", pady=(4, 0))
        for text, cmd in (("Add", self.add_pattern), ("Edit / Test", self.edit_pattern), ("Delete", self.delete_pattern)):
            ttk.Button(btns, text=text, command=cmd).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(parent, text="Click 'On' or press Space to toggle.", foreground="#777").grid(row=3, column=0, sticky="w", pady=(2, 0))

    def _bind_keys(self):
        r = self.root
        r.bind_all("<Control-Return>", lambda e: (self.sanitize(), "break")[1])
        r.bind_all("<F5>", lambda e: self.sanitize())
        r.bind_all("<Control-o>", lambda e: (self.open_file(), "break")[1])
        r.bind_all("<Control-s>", lambda e: (self.save_output(), "break")[1])
        for w in (self.input_text, self.output_text):
            w.bind("<Control-a>", lambda e: (e.widget.tag_add("sel", "1.0", "end-1c"), "break")[1])
            w.bind("<Control-Return>", lambda e: (self.sanitize(), "break")[1])  # before Text's own <Return>
        if sys.platform == "win32":
            # Ctrl+C/V/X/A/Z by physical key, so they also work with Hebrew or other non-Latin layouts
            r.bind_all("<Control-KeyPress>", self._ctrl_any_layout, add="+")
        self._enable_drag_and_drop()

    def _ctrl_any_layout(self, event):
        if event.keysym.isascii() and len(event.keysym) == 1:
            return None  # Latin layout: normal bindings already handle it
        virtual = {86: "<<Paste>>", 67: "<<Copy>>", 88: "<<Cut>>", 90: "<<Undo>>"}.get(event.keycode)
        if virtual:
            event.widget.event_generate(virtual)
            return "break"
        if event.keycode == 65 and isinstance(event.widget, tk.Text):
            event.widget.tag_add("sel", "1.0", "end-1c")
            return "break"
        return None

    def _enable_drag_and_drop(self):
        try:
            from tkinterdnd2 import DND_FILES
            self.input_text.drop_target_register(DND_FILES)
            self.input_text.dnd_bind("<<Drop>>", lambda e: self._open_path(self.root.tk.splitlist(e.data)[0]))
        except Exception:
            pass  # optional: pip install tkinterdnd2

    # ---- background jobs (worker thread never touches Tk; results are polled)
    def _run_async(self, label: str, work: Callable[[], object], on_done: Callable[[object], None]) -> None:
        if self.busy:
            self.status.set("Busy - please wait for the current task to finish")
            return
        self.busy = True
        self._progress, self._job_result = 0.0, None
        self.sanitize_btn.state(["disabled"])
        self.status.set(label)
        self.root.configure(cursor="watch")

        def runner():
            try:
                self._job_result = (work(), None)
            except Exception as e:
                log.exception("%s failed", label)
                self._job_result = (None, e)

        threading.Thread(target=runner, daemon=True).start()
        self._poll(on_done)

    def _poll(self, on_done):
        self.progress.set(self._progress)
        if self._job_result is None:
            self.root.after(60, self._poll, on_done)
            return
        result, error = self._job_result
        self.busy = False
        self.sanitize_btn.state(["!disabled"])
        self.root.configure(cursor="")
        self.progress.set(0)
        if error is not None:
            self.status.set(f"Error: {error}")
            messagebox.showerror("Error", str(error), parent=self.root)
        else:
            on_done(result)

    # ---- input / output
    def _set_text(self, widget, content: str):
        widget.delete("1.0", tk.END)
        widget.insert("1.0", content)
        if widget is self.input_text:
            widget.edit_reset()

    def open_file(self):
        path = filedialog.askopenfilename(title="Open log or document", filetypes=OPEN_TYPES)
        if path:
            self._open_path(path)

    def _open_path(self, path: str):
        name = os.path.basename(path)

        def done(result):
            text, desc = result
            self._set_text(self.input_text, text.replace("\r\n", "\n"))
            self.source_path = path
            self.status.set(f"Loaded {name} ({desc}, {text.count(chr(10)) + 1:,} lines)")
            log.info("Loaded %s (%s)", path, desc)
            if is_sensitive_filename(path):
                changed = self.engine.enable_named_patterns(SECURITY_PATTERNS, True)
                if changed:
                    self.refresh_patterns()
                    messagebox.showwarning(
                        "Sensitive file", f"'{name}' looks like it holds secrets.\n"
                        f"Re-enabled security patterns: {', '.join(changed)}", parent=self.root)

        self._run_async(f"Loading {name}…", lambda: load_document(path), done)

    def paste_input(self):
        try:
            self._set_text(self.input_text, self.root.clipboard_get())
            self.source_path = None
            self.status.set("Pasted from clipboard")
        except tk.TclError:
            self.status.set("Clipboard is empty or not text")

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.source_path = None
        self.last_counts = {}
        self.output_frame.configure(text="Sanitized output")
        self.refresh_patterns()
        self.status.set("Cleared")

    def sanitize(self):
        text = self.input_text.get("1.0", "end-1c")
        if not text.strip():
            self.status.set("Nothing to sanitize - open a file or paste text first")
            return

        def progress(done, total):
            self._progress = done * 100.0 / max(total, 1)

        self._run_async("Sanitizing…", lambda: self.engine.sanitize_detailed(text, progress), self._show_result)

    def _show_result(self, result: SanitizeResult):
        self._set_text(self.output_text, result.text)
        self._highlight(self.output_text, result.text, result.spans)
        self.last_counts = result.counts
        self.refresh_patterns()
        total = sum(result.counts.values())
        top = ", ".join(f"{k} {v}" for k, v in sorted(result.counts.items(), key=lambda kv: -kv[1])[:6])
        self.output_frame.configure(text=f"Sanitized output - {total:,} replacements")
        self.status.set(f"{total:,} replacements in {result.seconds:.2f}s" + (f"  ·  {top}" if top else ""))
        log.info("Sanitized: %d replacements in %.2fs", total, result.seconds)
        if result.warnings:
            messagebox.showwarning("Sanitize warnings", "\n".join(result.warnings), parent=self.root)

    @staticmethod
    def _highlight(widget, text: str, spans):
        widget.tag_remove("hit", "1.0", tk.END)
        if not spans or re.search("[\U00010000-\U0010FFFF]", text):
            return  # Tk 8.6 counts astral characters differently; skip rather than mis-highlight
        line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
        import bisect

        def index(offset):
            line = bisect.bisect_right(line_starts, offset) - 1
            return f"{line + 1}.{offset - line_starts[line]}"

        args = []
        for s, e, _ in spans[:HIGHLIGHT_LIMIT]:
            args += (index(s), index(e))
            if len(args) >= 2000:
                widget.tag_add("hit", *args)
                args = []
        if args:
            widget.tag_add("hit", *args)

    def save_output(self):
        text = self.output_text.get("1.0", "end-1c")
        if not text.strip():
            self.status.set("Nothing to save - sanitize first")
            return
        if self.source_path:
            base, ext = os.path.splitext(os.path.basename(self.source_path))
            ext = ext if ext.lower() not in (".xlsx", ".pptx", "") else ".txt"
            initial = f"{base}_sanitized{ext}"
        else:
            ext, initial = ".txt", "sanitized.txt"
        path = filedialog.asksaveasfilename(
            title="Save sanitized output", initialfile=initial, defaultextension=ext,
            filetypes=[("Text / log", "*.txt *.log"), ("Word document", "*.docx"), ("All files", "*.*")])
        if not path:
            return
        try:
            save_document(path, text if path.lower().endswith(".docx") else text.replace("\n", os.linesep))
            self.status.set(f"Saved {os.path.basename(path)}")
            log.info("Saved sanitized output to %s", path)
        except Exception as e:
            messagebox.showerror("Save failed", str(e), parent=self.root)

    def copy_output(self):
        text = self.output_text.get("1.0", "end-1c")
        if text.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status.set("Sanitized output copied to clipboard")
        else:
            self.status.set("Nothing to copy - sanitize first")

    # ---- config
    def _load_default_config(self):
        if os.path.exists(DEFAULT_CONFIG):
            ok, msg = self.engine.load_config(DEFAULT_CONFIG)
            self.status.set(f"config.json: {msg}" if ok else f"config.json not loaded: {msg}")

    def load_config(self):
        path = filedialog.askopenfilename(title="Load pattern config", filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        ok, msg = self.engine.load_config(path)
        self.refresh_patterns()
        self.status.set(f"{os.path.basename(path)}: {msg}")
        if not ok:
            messagebox.showerror("Config error", msg, parent=self.root)

    def save_config(self):
        path = filedialog.asksaveasfilename(title="Save pattern config", defaultextension=".json",
                                            filetypes=[("JSON", "*.json")], initialfile="config.json")
        if not path:
            return
        try:
            self.engine.save_config(path)
            self.status.set(f"Config saved: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e), parent=self.root)

    # ---- pattern list
    def refresh_patterns(self):
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for p in self.engine.sorted_patterns():
            hits = self.last_counts.get(p.name, "")
            self.tree.insert("", tk.END, iid=p.name, text=p.name, tags=() if p.enabled else ("off",),
                             values=("☑" if p.enabled else "☐", "✓" if p.hash_flag else "", p.priority, hits))
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected[0])
            self.tree.see(selected[0])

    def _selected_name(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _on_tree_click(self, event):
        row = self.tree.identify_row(event.y)
        if row and self.tree.identify_column(event.x) == "#1":
            self.tree.selection_set(row)
            self.toggle_pattern()

    def _on_tree_select(self, _event=None):
        p = self.engine.get(self._selected_name() or "")
        if p and not self.busy:
            self.status.set(f"{p.name}: {p.comment or p.pattern.pattern}")

    def toggle_pattern(self):
        name = self._selected_name()
        if name and self.engine.toggle_pattern_enabled(name):
            self.refresh_patterns()

    def delete_pattern(self):
        name = self._selected_name()
        if not name:
            return
        if messagebox.askyesno("Delete pattern", f"Delete pattern '{name}'?", parent=self.root):
            self.engine.remove_pattern(name)
            self.refresh_patterns()

    def add_pattern(self):
        self._pattern_dialog(None)

    def edit_pattern(self):
        name = self._selected_name()
        if not name:
            self.status.set("Select a pattern first")
            return
        p = self.engine.get(name)
        if p:
            self._pattern_dialog(p)

    def _pattern_dialog(self, existing: Optional[SanitizationPattern]):
        d = tk.Toplevel(self.root)
        d.title(f"Edit pattern - {existing.name}" if existing else "Add pattern")
        d.transient(self.root)
        d.minsize(620, 520)
        d.columnconfigure(1, weight=1)
        d.rowconfigure(8, weight=1)
        d.rowconfigure(10, weight=1)

        v = {
            "name": tk.StringVar(d, existing.name if existing else ""),
            "regex": tk.StringVar(d, existing.pattern.pattern if existing else ""),
            "repl": tk.StringVar(d, existing.replacement if existing else "<REDACTED>"),
            "prio": tk.StringVar(d, str(existing.priority if existing else 50)),
            "comment": tk.StringVar(d, existing.comment if existing else ""),
            "case": tk.BooleanVar(d, existing.case_sensitive if existing else False),
            "hash": tk.BooleanVar(d, existing.hash_flag if existing else False),
            "enabled": tk.BooleanVar(d, existing.enabled if existing else True),
        }
        pad = {"padx": 8, "pady": 3}
        rows = (("Name", "name", None), ("Regex", "regex", self.mono), ("Replacement", "repl", self.mono),
                ("Comment", "comment", None))
        for r, (label, key, font) in enumerate(rows):
            ttk.Label(d, text=label).grid(row=r, column=0, sticky="w", **pad)
            entry = ttk.Entry(d, textvariable=v[key], font=font) if font else ttk.Entry(d, textvariable=v[key])
            entry.grid(row=r, column=1, columnspan=2, sticky="ew", **pad)
            if r == (1 if existing else 0):
                entry.focus_set()
        opts = ttk.Frame(d)
        opts.grid(row=4, column=1, columnspan=2, sticky="w", **pad)
        ttk.Label(d, text="Options").grid(row=4, column=0, sticky="w", **pad)
        ttk.Label(opts, text="Priority").pack(side=tk.LEFT)
        ttk.Spinbox(opts, from_=-1000, to=1000, width=6, textvariable=v["prio"]).pack(side=tk.LEFT, padx=(4, 12))
        for text, key in (("Case sensitive", "case"), ("Hash value", "hash"), ("Enabled", "enabled")):
            ttk.Checkbutton(opts, text=text, variable=v[key]).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(d, foreground="#777", wraplength=580, justify=tk.LEFT,
                  text="Tip: name a group (?P<value>…) to redact only that part, e.g. "
                       "token=(?P<value>\\S+). Higher priority wins when matches overlap."
                  ).grid(row=5, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 6))

        ttk.Label(d, text="Try it - sample text").grid(row=7, column=0, columnspan=3, sticky="w", padx=8)
        sample = tk.Text(d, height=6, font=self.mono, wrap=tk.WORD, undo=True)
        sample.grid(row=8, column=0, columnspan=3, sticky="nsew", padx=8)
        seed = "\n".join(existing.examples) if existing and existing.examples else ""
        if not seed:
            try:
                seed = self.input_text.get("sel.first", "sel.last")
            except tk.TclError:
                seed = ""
        sample.insert("1.0", seed)
        info = ttk.Label(d, text="")
        info.grid(row=9, column=0, columnspan=3, sticky="w", padx=8, pady=(4, 0))
        preview = tk.Text(d, height=6, font=self.mono, wrap=tk.WORD, state=tk.DISABLED, background="#f6f6f6")
        preview.grid(row=10, column=0, columnspan=3, sticky="nsew", padx=8)
        preview.tag_configure("hit", background="#fff1a8")

        def build(preview_only: bool = False) -> SanitizationPattern:
            try:
                prio = int(v["prio"].get() or 0)
            except ValueError:
                raise ValueError("Priority must be a whole number") from None
            name = v["name"].get().strip() or ("preview" if preview_only else "")
            p = make_pattern(name, v["regex"].get(), v["repl"].get(),
                             case_sensitive=v["case"].get(), hash_flag=v["hash"].get(),
                             enabled=v["enabled"].get(), priority=prio, comment=v["comment"].get(),
                             examples=existing.examples if existing else [])
            if existing and p.pattern.pattern == existing.pattern.pattern and p.case_sensitive == existing.case_sensitive:
                p.pattern, p.validator, p.gate = existing.pattern, existing.validator, existing.gate
                p.builtin = existing.builtin and p.replacement == existing.replacement
            return p

        pending = [None]

        def run_preview():
            pending[0] = None
            text = sample.get("1.0", "end-1c")
            try:
                p = build(preview_only=True)
            except ValueError as e:
                info.configure(text=str(e), foreground="#c62828")
                return
            result = sanitize_text(text, [dataclasses.replace(p, enabled=True)], self.engine._hash_salt)
            preview.configure(state=tk.NORMAL)
            preview.delete("1.0", tk.END)
            preview.insert("1.0", result.text)
            self._highlight(preview, result.text, result.spans)
            preview.configure(state=tk.DISABLED)
            n = sum(result.counts.values())
            info.configure(text=f"{n} match(es)" if text else "Type or paste sample text above to test",
                           foreground="#2e7d32" if n else "#777")

        def schedule(*_):
            if pending[0]:
                d.after_cancel(pending[0])
            pending[0] = d.after(200, run_preview)

        for key in ("regex", "repl", "case", "hash"):
            v[key].trace_add("write", schedule)
        sample.bind("<KeyRelease>", schedule)
        sample.bind("<<Paste>>", lambda e: d.after(10, schedule))

        def save():
            try:
                p = build()
            except ValueError as e:
                info.configure(text=str(e), foreground="#c62828")
                return
            old = existing.name if existing else None
            if p.name != old and self.engine.get(p.name):
                info.configure(text=f"A pattern named '{p.name}' already exists", foreground="#c62828")
                return
            self.engine.set_pattern(p, replaces=old)
            self.refresh_patterns()
            self.tree.selection_set(p.name)
            self.tree.see(p.name)
            d.destroy()

        btns = ttk.Frame(d)
        btns.grid(row=11, column=0, columnspan=3, sticky="e", padx=8, pady=8)
        ttk.Button(btns, text="Cancel", command=d.destroy).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Save", style="Accent.TButton", command=save).pack(side=tk.RIGHT, padx=(0, 6))
        d.bind("<Escape>", lambda e: d.destroy())
        d.bind("<Control-Return>", lambda e: (save(), "break")[1])

        d.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - d.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - d.winfo_height()) // 2
        d.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        d.grab_set()
        run_preview()


def run_gui() -> None:
    if tk is None:
        print("Tkinter is not available. Install it (e.g. python3-tk) or use the CLI: "
              "python log_sanitizer.py <file>", file=sys.stderr)
        sys.exit(1)
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    root.title("Log Sanitizer")
    root.geometry("1200x760")
    root.minsize(860, 560)

    def report(exc_type, exc_value, exc_tb):
        log.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_tb))
        messagebox.showerror("Unexpected error", f"{exc_type.__name__}: {exc_value}")

    root.report_callback_exception = report
    import importlib.util
    for package, module in OPTIONAL_PACKAGES.items():
        if importlib.util.find_spec(module) is None:
            log.info("Optional package %s not installed; related file types unavailable", package)
    LogSanitizerApp(root)
    root.mainloop()


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    setup_logging()
    if argv:
        return run_cli(argv)
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
