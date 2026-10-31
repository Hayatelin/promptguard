"""Scanning engine: walk files, apply rules, honor ignore directives."""

import json
import os
import re

from . import rules as _rules
from .rules import (
    KIND_SKIP_RULES,
    RULES,
    SEVERITY_ORDER,
    config_file_kind,
    file_mask_tables,
    finding_severity,
    finding_text_filter,
    line_mask,
    mask_line_findings,
    may_hold_secrets,
)

# File suffixes we scan.
SCAN_SUFFIXES = (
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".txt",
    ".mcp",
    ".cursorrules",
)

# Exact / glob-ish file names we always scan regardless of suffix.
SCAN_NAMES = (
    "mcp.json",
    ".mcp.json",
    ".mcp",
    ".cursorrules",
)

# Config files matched by name (see rules.config_file_kind): .env, .env.*,
# Dockerfile, Dockerfile.*, *.dockerfile, .npmrc. Rules built around prompt,
# agent, tool-schema or workflow shapes are skipped for them
# (rules.KIND_SKIP_RULES).

# Directories we never descend into.
SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
}

# Most distinct finding-free lines scan_text() remembers per file.
_CLEAN_LINES_MAX = 4096

# Suppression directives, linter style.
_IGNORE_RE = re.compile(
    r"#\s*(?:promptguard\s*:\s*ignore|nosec|noqa\s*:\s*promptguard)",
    re.IGNORECASE,
)

# File-level auto-approve heuristic markers.
_FILE_AUTO_APPROVE_RE = re.compile(
    r"(\"auto[_-]?approve\"\s*:\s*true|auto[_-]?approve\s*[:=]\s*true|"
    r"\"requires?[_-]?confirmation\"\s*:\s*false|"
    r"requires?[_-]?confirmation\s*[:=]\s*false|"
    r"\"human[_-]?in[_-]?the[_-]?loop\"\s*:\s*false|"
    r"\"confirm\"\s*:\s*false|--yolo|dangerously[_-]?skip)",
    re.IGNORECASE,
)


class Finding:
    """A single scanner finding."""

    __slots__ = ("path", "line", "rule_id", "severity", "message", "snippet")

    def __init__(self, path, line, rule_id, severity, message, snippet):
        self.path = path
        self.line = line
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.snippet = snippet

    def to_dict(self):
        return {
            "path": self.path,
            "line": self.line,
            "rule": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "snippet": self.snippet,
        }

    def __repr__(self):
        return "Finding(%s %s:%d %s)" % (
            self.severity,
            self.path,
            self.line,
            self.rule_id,
        )


def should_scan_file(path):
    """Return True if `path`'s name/suffix is in scope."""
    name = os.path.basename(path)
    lname = name.lower()
    if lname in SCAN_NAMES:
        return True
    if config_file_kind(path):
        return True
    if lname.endswith(".agent.json"):
        return True
    _, ext = os.path.splitext(lname)
    return ext in SCAN_SUFFIXES


def scan_text(text, path="<text>"):
    """Scan a block of text, returning a list of Finding objects."""
    findings = []
    full_lower = text.lower()
    lines = text.splitlines()
    skip = KIND_SKIP_RULES.get(config_file_kind(path), ())
    rules = [rule for rule in RULES if rule.id not in skip]
    # File-level rules read "text"/"lines" once, cache per-line results in
    # ctx, and look them up via "lineno" so findings still land on a line.
    ctx = {
        "full_lower": full_lower,
        "file_auto_approve": bool(_FILE_AUTO_APPROVE_RE.search(text)),
        "path": path,
        "text": text,
        "lines": lines,
    }

    # File-level rules (rules._file_level) analyze the whole file on their
    # first call and then only look up the line. They are all called on the
    # first scanned line, so the lines holding any of their findings are
    # known; every other line needs only the per-line rules, and an empty
    # line none at all (each per-line detector needs a character to match).
    # Findings keep the same order: by line, then by rule.
    file_keys = [rule.detector.cache_key for rule in rules if hasattr(rule.detector, "cache_key")]
    line_rules = [rule for rule in rules if not hasattr(rule.detector, "cache_key")]
    hit_lines = None
    # Per-line rules depend only on the line text and file-wide context, so a
    # line that already gave no finding gives none again (files of 400,000
    # blank or one-character lines). The one exception is PG007's PEM check,
    # which reads the lines after a "-----BEGIN" header: such lines are not
    # remembered. The set is capped to bound its memory. A remembered line
    # is skipped by the rules only: it still goes to `quiet` below, so its
    # values are masked across lines exactly as when its rules are run.
    clean_lines = set()
    maskable = may_hold_secrets(full_lower)
    # Findings are masked once the whole file is read: a secret found on one
    # line is also masked in the findings of every other line (before or
    # after it). `pending` keeps each line with findings and its line_mask();
    # `file_values` every value found on any line, ignored lines included.
    # The values of a line without findings are only needed when some line
    # has findings: such lines are kept in `quiet` and masked after the scan,
    # only if `pending` is not empty and only when they share text with the
    # findings (rules.finding_text_filter).
    pending = []
    file_values = {}
    quiet = []

    for idx, line in enumerate(lines, start=1):
        if _IGNORE_RE.search(line):
            if maskable and line:
                quiet.append(idx)
            continue
        ctx["lineno"] = idx
        if hit_lines is None:
            hit_lines = set()
            for rule in rules:
                if hasattr(rule.detector, "cache_key"):
                    rule.detector(line, ctx)
            for key in file_keys:
                hit_lines.update(ctx.get(key) or ())
        if idx in hit_lines:
            active = rules
        elif not line:
            continue
        elif line in clean_lines:
            if maskable:
                quiet.append(idx)
            continue
        else:
            active = line_rules
        line_results = []
        for rule in active:
            try:
                results = rule.detector(line, ctx)
            except Exception:
                # A rule must never crash the whole scan (tests: rules.RAISE_RULE_ERRORS).
                if _rules.RAISE_RULE_ERRORS:
                    raise
                continue
            if not results:
                continue
            line_results.extend((rule, message, snippet) for message, snippet in results)
        if not line_results:
            if active is line_rules and len(clean_lines) < _CLEAN_LINES_MAX and "-----BEGIN" not in line:
                clean_lines.add(line)
            if maskable and line:
                quiet.append(idx)
            continue
        # Every finding masks the secrets recognized on its line and in the
        # rest of the file. A file without any secret hint
        # (rules.may_hold_secrets) has nothing to mask.
        if maskable:
            masked_line = line_mask(line, ctx)
            if masked_line[1]:
                file_values.update(dict.fromkeys(masked_line[1]))
            pending.append((idx, line, line_results, masked_line))
        else:
            pending.append((idx, line, line_results, None))

    file_tables = None
    if maskable and pending:
        may_matter = None
        if quiet:
            may_matter = finding_text_filter(
                text for _idx, _line, results, _m in pending
                for _rule, message, snippet in results for text in (message, snippet)
            )
        for idx in quiet:
            line = lines[idx - 1]
            if not may_matter(line):
                continue
            ctx["lineno"] = idx
            values = line_mask(line, ctx)[1]
            if values:
                file_values.update(dict.fromkeys(values))
        file_tables = file_mask_tables(file_values)
    mask_cache = {}
    for idx, line, line_results, masked_line in pending:
        pairs = [(message, snippet) for _rule, message, snippet in line_results]
        if maskable:
            ctx["lineno"] = idx
            pairs = mask_line_findings(line, ctx, pairs, mask_cache, file_tables, masked_line)
        for (rule, _message, _snippet), (message, snippet) in zip(line_results, pairs):
            findings.append(
                Finding(
                    path=path,
                    line=idx,
                    rule_id=rule.id,
                    severity=finding_severity(rule, _message),
                    message=message,
                    snippet=snippet,
                )
            )
    return findings


def scan_file(path):
    """Scan a single file. Returns [] for unreadable/binary files."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except (IOError, OSError):
        return []
    return scan_text(text, path=path)


def scan_path(target):
    """Scan a file or directory tree. Returns a list of Finding objects."""
    findings = []
    if os.path.isfile(target):
        if should_scan_file(target):
            findings.extend(scan_file(target))
        return findings

    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                if should_scan_file(fpath):
                    findings.extend(scan_file(fpath))
        return findings

    return findings


def filter_by_severity(findings, min_severity):
    """Keep findings at or above `min_severity`."""
    threshold = SEVERITY_ORDER.get(min_severity, 1)
    return [
        f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold
    ]


def summarize(findings):
    """Return (total, high, medium, low) counts."""
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    return len(findings), high, medium, low
