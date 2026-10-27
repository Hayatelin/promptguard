"""Rule definitions for promptguard.

Each rule is a small, self-contained detector. A rule has a stable id, a
severity (high/medium/low), a human description, and a callable that yields
zero or more matches for a given physical line of text.

The detectors are deliberately conservative and pattern-based (a linter, not
a guardrail). To avoid flagging promptguard's own rule strings, the trigger
phrases below are assembled from fragments where they would otherwise be
literal, and rules are scoped to realistic config/prompt shapes.
"""

import bisect
import json
import json.decoder
import json.scanner
import os
import re
import shlex
import string

# Severity ordering helper. Higher number == more severe.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


class Rule:
    """A single detection rule.

    detector(line, ctx) -> iterable of (message, snippet) tuples.
    `ctx` is a dict with whole-file context (e.g. lowered full text) so a rule
    can make file-level decisions while still reporting on a specific line.
    """

    __slots__ = ("id", "severity", "description", "detector")

    def __init__(self, id, severity, description, detector):
        self.id = id
        self.severity = severity
        self.description = description
        self.detector = detector


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

# Prompt-injection trigger phrases. Built from fragments so this source file
# itself does not contain the literal phrase that would otherwise self-flag.
_INJECTION_PHRASES = [
    "ignore " + "previous instructions",
    "ignore " + "all previous",
    "ignore " + "all prior",
    "ignore " + "the above",
    "disregard " + "the above",
    "disregard " + "previous",
    "disregard " + "all prior",
    "forget " + "previous instructions",
    "forget " + "all previous",
    "you are " + "now",
    "reveal " + "your system prompt",
    "reveal " + "the system prompt",
    "print " + "your system prompt",
    "show " + "me your system prompt",
    "what " + "is your system prompt",
    "repeat " + "the words above",
]

_INJECTION_RE = re.compile(
    "|".join(re.escape(p) for p in _INJECTION_PHRASES), re.IGNORECASE
)

# A "SYSTEM:" style override embedded inside content (quoted strings, list
# items, markdown blockquotes, tool/user content) rather than a top-level key.
_SYSTEM_OVERRIDE_RE = re.compile(
    r"""(["'>\-\|]\s*|\bcontent['"]?\s*[:=]\s*["']?.*?)"""
    r"""\b(system|assistant)\s*:\s*\S""",
    re.IGNORECASE,
)

# Placeholders that interpolate external / untrusted content into a prompt.
_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*([a-z0-9_]*"
    r"(?:web|url|tool|input|user|email|search|doc|page|content|output|fetch|scrape|rss|comment|review|message)"
    r"[a-z0-9_]*)\s*\}\}"
    r"|\$\{\s*([a-z0-9_]*"
    r"(?:web|url|tool|input|user|email|search|doc|page|content|output|fetch|scrape|rss|comment|review|message)"
    r"[a-z0-9_]*)\s*\}"
    r"|\{\s*([a-z0-9_]*"
    r"(?:web_content|tool_output|web_results|search_results|user_input|email_body|page_content|scraped|fetched_url)"
    r"[a-z0-9_]*)\s*\}",
    re.IGNORECASE,
)

# Delimiter / guard markers that, if present near a placeholder, indicate the
# author wrapped untrusted content. Their absence is what we flag.
_DELIMITER_HINTS = (
    "```",
    '"""',
    "<untrusted",
    "</untrusted",
    "<external",
    "</external",
    "<data",
    "</data",
    "<user_data",
    "<tool_output>",
    "</tool_output>",
    "<<<",
    ">>>",
    "===",
    "---begin",
    "begin untrusted",
    "do not follow instructions",
    "do not obey",
    "treat as data",
    "treat the following as data",
    "untrusted content",
    "delimited by",
    "enclosed in",
)

# Dangerous tool / function capability names.
_DANGEROUS_TOOL_RE = re.compile(
    r"\b("
    r"shell|exec|execute|eval|run_command|runcommand|run_shell|system_call|"
    r"subprocess|os_system|spawn|bash|powershell|cmd_exec|"
    r"write_file|writefile|file_write|arbitrary_write|"
    r"http_request|httprequest|fetch_url|fetchurl|web_request|curl|wget"
    r")\b",
    re.IGNORECASE,
)

# Destructive actions.
_DESTRUCTIVE_RE = re.compile(
    r"\b("
    r"delete|delete_file|drop|drop_table|drop_database|truncate|"
    r"send_email|sendemail|send_message|transfer|transfer_funds|wire|payment|"
    r"deploy|publish|rm_rf|rmrf|force_push|purge|wipe|destroy|"
    r"revoke|grant_access"
    r")\b",
    re.IGNORECASE,
)

# Auto-approve / no-confirmation markers.
_AUTO_APPROVE_RE = re.compile(
    r"(auto[_-]?approve|auto[_-]?run|auto[_-]?execute|no[_-]?confirm|"
    r"requires?[_-]?(?:confirmation|approval|human)?\s*[:=]\s*(?:false|no|0)|"
    r"confirm\s*[:=]\s*(?:false|no|0)|"
    r"human[_-]?in[_-]?the[_-]?loop\s*[:=]\s*(?:false|no|0)|"
    r"approval\s*[:=]\s*[\"']?(?:none|never|auto)|"
    r"\"yolo\"|--yolo|skip[_-]?confirmation|unattended)",
    re.IGNORECASE,
)

# Over-broad MCP / filesystem roots.
_BROAD_ROOT_RE = re.compile(
    r"""(["'=:\s])(/|~|~/|C:\\\\|C:/|/root|/home|/etc|/var|/usr)(["'\s,\]}]|$)"""
)

_DANGEROUS_FLAGS_RE = re.compile(
    r"(--yolo|--dangerously[_-]?skip[_-]?permissions|--no[_-]?sandbox|"
    r"--allow[_-]?all|--disable[_-]?(?:safety|guardrails|sandbox)|"
    r"--unsafe|--god[_-]?mode|dangerously_?skip)",
    re.IGNORECASE,
)

# Full environment passthrough in an MCP server block.
_ENV_PASSTHROUGH_RE = re.compile(
    r"(\"env\"\s*:\s*\"?\*|passthrough[_-]?env|inherit[_-]?env\s*[:=]\s*"
    r"(?:true|all)|\"env\"\s*:\s*\{\s*\"\*\"|env_all|all_env)",
    re.IGNORECASE,
)

# Secrets.
# (label, regex, high_confidence). High-confidence structured tokens are not
# subjected to the placeholder filter; the generic key/value pattern is.
_SECRET_RES = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), True),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), True),
    (
        "Hardcoded API key",
        re.compile(
            r"""(?:api[_-]?key|apikey|secret|access[_-]?token|password)"""
            r"""\s*[:=]\s*["'][^"'\s]{12,}["']""",
            re.IGNORECASE,
        ),
        False,
    ),
]

# A placeholder-only secret value (e.g. "YOUR_API_KEY", env var refs) we should
# NOT flag, to keep noise down.
_SECRET_PLACEHOLDER_RE = re.compile(
    r"(your[_-]?|example|placeholder|xxx|<.*?>|\$\{|env:|process\.env|changeme|"
    r"redacted|dummy|fake|test[_-]?key|\.\.\.)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def _detect_injection(line, ctx):
    for m in _INJECTION_RE.finditer(line):
        yield (
            "Prompt-injection seed phrase: %r" % m.group(0).strip(),
            line.strip(),
        )


def _detect_system_override(line, ctx):
    low = line.lower()
    # Only fire when it looks embedded in content, not a top-level system key.
    stripped = line.lstrip()
    # Skip lines that are clearly a legitimate top-level role key:
    #   "system": "..."   /   system: |   /   - role: system
    if re.match(r"""["']?system["']?\s*[:=]""", stripped, re.IGNORECASE):
        return
    if re.match(r"""-?\s*role\s*[:=]\s*["']?system""", stripped, re.IGNORECASE):
        return
    if _SYSTEM_OVERRIDE_RE.search(line) and ("system:" in low or "assistant:" in low):
        yield (
            "Embedded role override ('SYSTEM:'/'ASSISTANT:') inside content",
            line.strip(),
        )


def _detect_untrusted_placeholder(line, ctx):
    m = _PLACEHOLDER_RE.search(line)
    if not m:
        return
    placeholder = next(g for g in m.groups() if g) if any(m.groups()) else m.group(0)
    low = ctx.get("full_lower", "")
    # If the file shows any delimiter / guard hint, assume the author handled it.
    if any(h in low for h in _DELIMITER_HINTS):
        return
    yield (
        "Untrusted content placeholder %r interpolated without delimiters/guards"
        % ("{{%s}}" % placeholder if placeholder else m.group(0)),
        line.strip(),
    )


def _detect_dangerous_tool(line, ctx):
    tm = _DANGEROUS_TOOL_RE.search(line)
    if not tm:
        return
    low = ctx.get("full_lower", "")
    auto = bool(_AUTO_APPROVE_RE.search(line)) or ctx.get("file_auto_approve", False)
    cap = tm.group(0)
    if auto:
        yield (
            "Dangerous capability %r exposed with auto-approve / no confirmation"
            % cap,
            line.strip(),
        )
    else:
        yield (
            "Dangerous capability %r exposed to the agent (review confirmation flow)"
            % cap,
            line.strip(),
        )


def _detect_destructive(line, ctx):
    dm = _DESTRUCTIVE_RE.search(line)
    if not dm:
        return
    auto = bool(_AUTO_APPROVE_RE.search(line)) or ctx.get("file_auto_approve", False)
    if not auto:
        return
    yield (
        "Destructive action %r marked auto / no human-in-the-loop" % dm.group(0),
        line.strip(),
    )


def _root_context(ctx):
    """Does the file mention mcp/filesystem/allowed/root/args? (once per text, not per line)"""
    low = ctx.get("full_lower", "")
    cached = ctx.get("_root_context")
    if cached is None or cached[0] is not low:
        cached = (
            low,
            "mcp" in low or "filesystem" in low or "allowed" in low or "root" in low or "args" in low,
        )
        ctx["_root_context"] = cached
    return cached[1]


def _detect_broad_mcp(line, ctx):
    if _DANGEROUS_FLAGS_RE.search(line):
        yield (
            "Over-broad permission flag in server/agent config",
            line.strip(),
        )
        return
    if _ENV_PASSTHROUGH_RE.search(line):
        yield (
            "Full environment passthrough granted to MCP server",
            line.strip(),
        )
        return
    # Filesystem root grants are only interesting in mcp / filesystem contexts.
    if _root_context(ctx):
        m = _BROAD_ROOT_RE.search(line)
        if m and any(
            k in line.lower()
            for k in ("path", "root", "dir", "args", "allow", "filesystem", "mount", "volume")
        ):
            yield (
                "Over-broad filesystem root %r granted (consider scoping)"
                % m.group(2),
                line.strip(),
            )


def _detect_secret(line, ctx):
    for label, rx, high_confidence in _SECRET_RES:
        m = rx.search(line)
        if not m:
            continue
        matched = m.group(0)
        # Only the generic key/value pattern is filtered against placeholders;
        # structured tokens (AKIA.../sk-.../ghp_...) are high-confidence even if
        # they happen to contain words like "example".
        if not high_confidence and _SECRET_PLACEHOLDER_RE.search(matched):
            continue
        yield (
            "Possible %s committed in config/prompt" % label,
            line.strip(),
        )


# ---------------------------------------------------------------------------
# File-level helpers (PG008-PG011)
# ---------------------------------------------------------------------------
#
# These rules need whole-file context (an MCP "command" and its "args" sit on
# different lines; a workflow's `on:` is far from its checkout step). Each one
# analyzes a file once, caches {lineno: [(message, snippet), ...]} in ctx, and
# its per-line detector just looks up ctx["lineno"].

def _file_ext(ctx):
    """Lower-cased extension of ctx["path"]; "" for scan_text() input."""
    path = ctx.get("path") or "<text>"
    if path == "<text>":
        return ""
    name = os.path.basename(path).lower()
    if name in ("mcp.json", ".mcp.json"):
        return ".json"
    ext = os.path.splitext(name)[1]
    if not ext and name.startswith("."):
        # Dotfiles such as ".cursorrules" / ".mcp" carry their type in the name.
        return name
    return ext


def _ctx_lines(ctx):
    lines = ctx.get("lines")
    if lines is None:
        lines = ctx.get("text", "").splitlines()
    return lines


_TOP_ON_RE = re.compile(r"""^(?:on|"on"|'on')\s*:""", re.MULTILINE)
_TOP_JOBS_RE = re.compile(r"^jobs\s*:", re.MULTILINE)
_TOP_RUNS_RE = re.compile(r"^runs\s*:", re.MULTILINE)
_USING_RE = re.compile(r"\busing\s*:")


def _is_yaml_like(ctx):
    return _file_ext(ctx) in (".yml", ".yaml", "")


def _is_github_workflow(ctx):
    text = ctx.get("text", "")
    return (
        _is_yaml_like(ctx)
        and bool(_TOP_ON_RE.search(text))
        and bool(_TOP_JOBS_RE.search(text))
    )


def _is_github_action(ctx):
    text = ctx.get("text", "")
    return (
        _is_yaml_like(ctx)
        and bool(_TOP_RUNS_RE.search(text))
        and bool(_USING_RE.search(text))
    )


def _file_level(key, analyzer):
    """Wrap a whole-file analyzer as a per-line detector (cached in ctx)."""

    def detector(line, ctx):
        cache = ctx.get(key)
        if cache is None:
            try:
                cache = analyzer(ctx)
            except Exception:
                cache = {}
            ctx[key] = cache
        return cache.get(ctx.get("lineno"), ())

    return detector


class _HitBucket(list):
    """List of (message, snippet) with a set of seen messages for O(1) dedup.

    `seen_len` records how many items `seen` covers; if other code appended to
    the list directly, the set is rebuilt so dedup stays exact.
    """

    __slots__ = ("seen", "seen_len")


def _add_hit(hits, lines, lineno, message):
    """Record a finding for `lineno`, once per (line, message)."""
    bucket = hits.get(lineno)
    if not isinstance(bucket, _HitBucket):
        bucket = _HitBucket(bucket or ())
        bucket.seen_len = -1
        hits[lineno] = bucket
    if bucket.seen_len != len(bucket):
        bucket.seen = {m for m, _ in bucket}
        bucket.seen_len = len(bucket)
    if message in bucket.seen:
        return
    if bucket:
        snippet = bucket[0][1]  # same line, same snippet: share one string
    else:
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
    bucket.append((message, snippet))
    bucket.seen.add(message)
    bucket.seen_len = len(bucket)


def _indent(s):
    return len(s) - len(s.lstrip(" \t"))


def _block_end(lines, i, key_col):
    """Exclusive end index of the lines after lines[i] indented past key_col."""
    end = i + 1
    j = i + 1
    while j < len(lines):
        s = lines[j]
        if s.strip():
            if _indent(s) <= key_col:
                break
            end = j + 1
        j += 1
    return end


def _strip_yaml_comment(s):
    return re.sub(r"(^|\s)#.*$", "", s)


def _unquote(s):
    return s.strip().strip("\"'").strip()


# ---------------------------------------------------------------------------
# PG008: unpinned launch commands
# ---------------------------------------------------------------------------

_PG008_EXTS = (".json", ".yaml", ".yml", ".toml", ".mcp", "")

_PIPE_TO_SHELL_RE = re.compile(
    r"\b(curl|wget)\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/\S*/)?(sh|bash|zsh)\b",
    re.IGNORECASE,
)
_PIPE_TO_IEX_RE = re.compile(
    r"\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]*\|\s*"
    r"(iex|invoke-expression)\b",
    re.IGNORECASE,
)
# _pipe_search() splits the two patterns above at their "[^|\n]*\|" so a line
# with many 'curl' words and no pipe is not rescanned from every word, and
# _ShellTail replaces the shell tail's "(?:/\S*/)?" (which rescans the rest of
# a long run like 'curl|/curl|/...' from every pipe).
_PIPE_HEADS = {}
_PIPE_STOP_RE = re.compile(r"[|\n]")
_SHELL_WORD_RE = re.compile(r"(sh|bash|zsh)\b", re.IGNORECASE)
_SLASH_SHELL_RE = re.compile(r"/(?=(?:sh|bash|zsh)\b)", re.IGNORECASE)
_SUDO_RE = re.compile(r"sudo\s+", re.IGNORECASE)
_SUDO_FLAG_RE = re.compile(r"-\S+\s+")
_WHITESPACE_RE = re.compile(r"\s")


class _ShellTail(object):
    r"""Matches _PIPE_TO_SHELL_RE's tail at a '|', returning group(2) or None.

    Same result as re.match of
    r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/\S*/)?(sh|bash|zsh)\b" (IGNORECASE),
    with each line position examined a bounded number of times.
    """

    def __init__(self, line):
        self.line = line
        self.spaces = None
        self.slashes = None
        self.chain = {}

    def _path_shell(self, y):
        r"""group of (?:/\S*/)?(sh|bash|zsh)\b matched at y, or None."""
        line = self.line
        if y < len(line) and line[y] == "/":
            if self.spaces is None:
                self.spaces = [m.start() for m in _WHITESPACE_RE.finditer(line)]
                self.slashes = [m.start() for m in _SLASH_SHELL_RE.finditer(line)]
            k = bisect.bisect_left(self.spaces, y)
            end = self.spaces[k] if k < len(self.spaces) else len(line)
            # greedy \S* backtracks from the end of the run: the last such '/' wins
            j = bisect.bisect_left(self.slashes, end) - 1
            if j >= 0 and self.slashes[j] > y:
                return _SHELL_WORD_RE.match(line, self.slashes[j] + 1).group(1)
        m = _SHELL_WORD_RE.match(line, y)
        return m.group(1) if m else None

    def _after_flags(self, p):
        r"""Try (?:-\S+\s+)* greedily from p, then the path/shell part."""
        todo = []
        while p not in self.chain:
            todo.append(p)
            m = _SUDO_FLAG_RE.match(self.line, p)
            if not m:
                self.chain[p] = self._path_shell(p)
                todo.pop()
                break
            p = m.end()
        result = self.chain[p]
        for q in reversed(todo):
            if result is None:
                result = self._path_shell(q)
            self.chain[q] = result
        return result

    def match(self, q):
        y = _SPACES_RE.match(self.line, q + 1).end()
        m = _SUDO_RE.match(self.line, y)
        if m:
            found = self._after_flags(m.end())
            if found is not None:
                return found
        return self._path_shell(y)


def _pipe_search(rx, line):
    """(group(1), group(2)) of rx.search(line), or None (linear time).

    rx is _PIPE_TO_SHELL_RE or _PIPE_TO_IEX_RE: r"\\b(word)\\b[^|\\n]*" + tail,
    where tail starts with r"\\|". [^|\\n]* can only stop at the first '|' or
    newline after the word, so the tail is tried once per such '|'.
    """
    parts = _PIPE_HEADS.get(rx.pattern)
    if parts is None:
        head, tail = rx.pattern.split(r"[^|\n]*", 1)
        parts = (re.compile(head, rx.flags), re.compile(tail, rx.flags))
        _PIPE_HEADS[rx.pattern] = parts
    head_re, tail_re = parts
    shell_tail = _ShellTail(line) if rx is _PIPE_TO_SHELL_RE else None
    stop = -1
    tried = set()
    for m in head_re.finditer(line):
        if m.end() > stop:
            s = _PIPE_STOP_RE.search(line, m.end())
            stop = s.start() if s else len(line)
        if stop >= len(line) or line[stop] != "|" or stop in tried:
            continue
        tried.add(stop)
        if shell_tail is not None:
            found = shell_tail.match(stop)
        else:
            t = tail_re.match(line, stop)
            found = t.group(1) if t else None
        if found is not None:
            return m.group(1), found
    return None


_SHELL_SEPARATORS = ("&&", "||", ";", "|", "&")

_NPX_VALUE_FLAGS = {
    "-p", "--package", "-c", "--call", "--registry", "--cache",
    "--userconfig", "--prefix", "--workspace", "--shell", "--node-options",
}
_UV_VALUE_FLAGS = {
    "--from", "--with", "--with-editable", "--with-requirements",
    "--python", "-p", "--index-url", "-i", "--extra-index-url", "--index",
    "--default-index", "--find-links", "-f", "--constraints", "-c",
    "--overrides", "--build-constraints", "-b", "--directory", "--project",
    "--config-file", "--cache-dir", "--color", "--python-preference",
    "--exclude-newer", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--link-mode", "--refresh-package",
    "--reinstall-package", "--upgrade-package", "-P", "--env-file",
    "--config-setting", "-C", "--allow-insecure-host", "--no-build-package",
    "--no-binary-package",
}
_PIPX_VALUE_FLAGS = {"--spec", "--python", "--index-url", "-i", "--pip-args"}
_DOCKER_VALUE_FLAGS = {
    "-a", "--attach", "--add-host", "--blkio-weight", "--cap-add",
    "--cap-drop", "--cgroupns", "--cgroup-parent", "--cidfile",
    "-c", "--cpu-shares", "--cpu-period", "--cpu-quota", "--cpus",
    "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device",
    "--dns", "--dns-option", "--dns-search", "--domainname",
    "-e", "--env", "--env-file", "--entrypoint", "--expose", "--gpus",
    "--group-add", "--health-cmd", "--health-interval", "--health-retries",
    "--health-start-period", "--health-timeout", "-h", "--hostname",
    "--ip", "--ip6", "--ipc", "--isolation", "--kernel-memory",
    "-l", "--label", "--label-file", "--link", "--log-driver", "--log-opt",
    "--mac-address", "-m", "--memory", "--memory-reservation",
    "--memory-swap", "--mount", "--name", "--network", "--net",
    "--network-alias", "--oom-score-adj", "-p", "--publish", "--pid",
    "--pids-limit", "--platform", "--pull", "--restart", "--runtime",
    "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
    "--storage-opt", "--sysctl", "--tmpfs", "-u", "--user", "--ulimit",
    "--userns", "--uts", "-v", "--volume", "--volume-driver",
    "--volumes-from", "-w", "--workdir",
}

_SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_PY_VERSION_RE = re.compile(r"^\d+(?:!\d+)?(?:\.\d+)*[a-z0-9.+_-]*$", re.IGNORECASE)
_COMMIT_SHA_RE = re.compile(r"[#@][0-9a-fA-F]{40}(?![0-9a-fA-F])")
_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")

_NPM_HINT = "pin pkg@x.y.z"
_PY_HINT = "pin pkg==x.y.z"
_DOCKER_HINT = "pin image@sha256:<digest>"
_GIT_HINT = "pin a full 40-char commit SHA"


def _launcher_name(token):
    # == re.split(r"[\\/]", token)[-1].lower(), without the regex call per token
    base = token[max(token.rfind("/"), token.rfind("\\")) + 1:].lower()
    if not base.endswith((".cmd", ".exe", ".bat", ".ps1")):
        return base
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def _clean_spec(tok):
    return tok.strip().strip("\"'`").rstrip(";,&|")


def _parse_cli(argv, start, value_flags):
    """Walk argv[start:] as CLI options.

    Returns ([(flag, value, value_index)], index of first positional or None).
    """
    opts = []
    i = start
    while i < len(argv):
        tok = argv[i]
        if tok in _SHELL_SEPARATORS:
            return opts, None
        if tok == "--":
            return opts, (i + 1 if i + 1 < len(argv) else None)
        if tok.startswith("-") and len(tok) > 1:
            name, eq, value = tok.partition("=")
            if eq:
                opts.append((name, value, i))
            elif name in value_flags and i + 1 < len(argv):
                opts.append((name, argv[i + 1], i + 1))
                i += 1
            else:
                opts.append((name, None, None))
            i += 1
            continue
        return opts, i
    return opts, None


def _is_unchecked_spec(spec):
    """Local paths, variables and URL tarballs are out of PG008's scope."""
    low = spec.lower()
    return (
        not spec
        or "$" in spec
        or "%" in spec
        or spec in (".", "..")
        or low.startswith(
            ("./", "../", ".\\", "..\\", "/", "~", "file:", "http://", "https://")
        )
        or bool(_WIN_DRIVE_RE.match(spec))
    )


def _npm_spec_problem(spec):
    if _is_unchecked_spec(spec):
        return None
    low = spec.lower()
    is_git = low.startswith(
        ("github:", "gitlab:", "bitbucket:", "gist:", "git+", "git:", "git@")
    ) or (not spec.startswith("@") and "/" in spec)
    if is_git:
        if _COMMIT_SHA_RE.search(spec):
            return None
        return ("is a git source without a commit SHA", _GIT_HINT)
    m = re.match(r"^(@[^/\s]+/[^@\s]+|[^@\s]+)(?:@(.*))?$", spec)
    if not m:
        return None
    version = m.group(2)
    if not version:
        return ("has no version", _NPM_HINT)
    if _SEMVER_RE.match(version):
        return None
    return ("uses a floating version '@%s'" % version, _NPM_HINT)


def _py_spec_problem(spec):
    if _is_unchecked_spec(spec):
        return None
    if spec.lower().startswith("git+"):
        if _COMMIT_SHA_RE.search(spec):
            return None
        return ("is a git source without a commit SHA", _GIT_HINT)
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", spec)
    if not m:
        return None
    rest = m.group(3).strip()
    if not rest:
        return ("has no version", _PY_HINT)
    if rest.startswith("@"):
        ref = rest[1:].strip()
        if ref.lower().startswith("git+"):
            if _COMMIT_SHA_RE.search(ref):
                return None
            return ("is a git source without a commit SHA", _GIT_HINT)
        if "://" in ref or _PY_VERSION_RE.match(ref):
            return None
        return ("uses a floating version '@%s'" % ref, _PY_HINT)
    pinned = re.match(r"^===?\s*(\S+)$", rest)
    if pinned and _PY_VERSION_RE.match(pinned.group(1)):
        return None
    return ("is not pinned to an exact version ('%s')" % rest, _PY_HINT)


def _docker_image_problem(image):
    if not image or "$" in image or "%" in image:
        return None
    if "@sha256:" in image.lower():
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return ("has no tag or digest", _DOCKER_HINT)
    tag = last.split(":", 1)[1]
    if tag.lower() == "latest":
        return ("uses the mutable ':latest' tag", _DOCKER_HINT)
    if not re.search(r"\d", tag):
        return ("uses the floating tag ':%s'" % tag, _DOCKER_HINT)
    return None


def _check_npx(argv, start):
    opts, pos = _parse_cli(argv, start, _NPX_VALUE_FLAGS)
    packages = [
        (v, idx) for n, v, idx in opts if n in ("-p", "--package") and v is not None
    ]
    if packages:
        candidates = packages
    elif any(n in ("-c", "--call") for n, _, _ in opts):
        candidates = []
    elif pos is not None:
        candidates = [(argv[pos], pos)]
    else:
        candidates = []
    for spec, idx in candidates:
        spec = _clean_spec(spec)
        problem = _npm_spec_problem(spec)
        if problem:
            yield ("npx", spec, problem[0], problem[1], idx)


def _check_python_launcher(argv, start, label, value_flags, spec_flag):
    opts, pos = _parse_cli(argv, start, value_flags)
    explicit = [(v, idx) for n, v, idx in opts if n == spec_flag and v is not None]
    if explicit:
        candidates = explicit
    elif pos is not None:
        candidates = [(argv[pos], pos)]
    else:
        candidates = []
    for spec, idx in candidates:
        spec = _clean_spec(spec)
        problem = _py_spec_problem(spec)
        if problem:
            yield (label, spec, problem[0], problem[1], idx)


def _check_docker(argv, start):
    _, pos = _parse_cli(argv, start, _DOCKER_VALUE_FLAGS)
    if pos is None:
        return
    image = _clean_spec(argv[pos])
    problem = _docker_image_problem(image)
    if problem:
        yield ("docker run", image, problem[0], problem[1], pos)


def _launch_problems(argv):
    """Find unpinned launches anywhere in argv.

    Returns [(launcher, spec, problem, hint, token_index)]. Reference
    definition: the scanner uses _each_launch_problem(), which visits the same
    items in the same order without rewalking the options after every
    launcher name (quadratic on 'npx -p npx -p ...' / 'uvx --from uvx ...').
    """
    out = []
    for i, tok in enumerate(argv):
        name = _launcher_name(tok)
        nxt = argv[i + 1].lower() if i + 1 < len(argv) else ""
        if name == "npx":
            out.extend(_check_npx(argv, i + 1))
        elif name == "uvx":
            out.extend(
                _check_python_launcher(argv, i + 1, "uvx", _UV_VALUE_FLAGS, "--from")
            )
        elif name == "uv" and nxt == "tool" and i + 2 < len(argv) and argv[i + 2].lower() == "run":
            out.extend(
                _check_python_launcher(
                    argv, i + 3, "uv tool run", _UV_VALUE_FLAGS, "--from"
                )
            )
        elif name == "pipx" and nxt == "run":
            out.extend(
                _check_python_launcher(
                    argv, i + 2, "pipx run", _PIPX_VALUE_FLAGS, "--spec"
                )
            )
        elif name == "docker" and nxt == "run":
            out.extend(_check_docker(argv, i + 2))
    return out


class _LaunchTable(object):
    """_parse_cli(argv, start, value_flags) for every start of one launcher kind.

    The walk from a start is a chain through the option tokens (each option
    moves on 1 or 2 tokens), so walks from different starts merge; the chain
    facts are filled in once, right to left.
    """

    def __init__(self, argv, label, value_flags, pick, block, spec_problem):
        n = len(argv)
        self.argv = argv
        self.label = label
        self.spec_problem = spec_problem
        self.nxt = [-1] * (n + 1)     # next node of an option node, else -1
        self.pick = [None] * (n + 1)  # (value, value_index) of a picked option
        self.term = [None] * (n + 1)  # positional index _parse_cli returns
        self.has_pick = [False] * (n + 1)
        self.has_block = [False] * (n + 1)
        for s in range(n - 1, -1, -1):
            tok = argv[s]
            if tok in _SHELL_SEPARATORS:
                continue
            if tok == "--":
                self.term[s] = s + 1 if s + 1 < n else None
                continue
            if not (tok.startswith("-") and len(tok) > 1):
                self.term[s] = s
                continue
            name, eq, value = tok.partition("=")
            if eq:
                vidx, nx = s, s + 1
            elif name in value_flags and s + 1 < n:
                value, vidx, nx = argv[s + 1], s + 1, s + 2
            else:
                value, vidx, nx = None, None, s + 1
            self.nxt[s] = nx
            self.term[s] = self.term[nx]
            self.has_pick[s] = self.has_pick[nx]
            self.has_block[s] = self.has_block[nx] or name in block
            if name in pick and value is not None:
                self.pick[s] = (value, vidx)
                self.has_pick[s] = True
        # jump[s]: s itself for a picked option still to visit, else where to look next.
        self.jump = [s if self.pick[s] is not None else self.nxt[s] for s in range(n + 1)]
        self.items = {}
        self.pos_done = set()  # positional candidates already settled

    def _item(self, value, idx):
        spec = _clean_spec(value)
        problem = self.spec_problem(spec)
        if problem:
            return (self.label, spec, problem[0], problem[1], idx)
        return None

    def _find(self, s):
        path = []
        while s >= 0 and self.jump[s] != s:
            path.append(s)
            s = self.jump[s]
        for p in path:
            self.jump[p] = s
        return s

    def visit_from(self, start, visit):
        if self.has_pick[start]:
            s = self._find(start)
            while s >= 0:
                if s not in self.items:
                    self.items[s] = self._item(*self.pick[s])
                item = self.items[s]
                if item is None or visit(item):
                    self.jump[s] = self.nxt[s]  # settled: later walks skip it
                s = self._find(self.nxt[s])
        elif not self.has_block[start] and self.term[start] is not None:
            pos = self.term[start]
            if pos in self.pos_done:
                return
            item = self._item(self.argv[pos], pos)
            if item is None or visit(item):
                self.pos_done.add(pos)


def _each_launch_problem(argv, visit):
    """Call visit(item) for each item of _launch_problems(argv), in order.

    visit() returns True when further occurrences of that same item can no
    longer change anything; those repeats are skipped.
    """
    tables = {}

    def table(kind):
        t = tables.get(kind)
        if t is None:
            if kind == "npx":
                t = _LaunchTable(argv, "npx", _NPX_VALUE_FLAGS, ("-p", "--package"),
                                 ("-c", "--call"), _npm_spec_problem)
            elif kind == "docker run":
                t = _LaunchTable(argv, kind, _DOCKER_VALUE_FLAGS, (), (), _docker_image_problem)
            else:
                flags, spec_flag = (
                    (_PIPX_VALUE_FLAGS, "--spec") if kind == "pipx run" else (_UV_VALUE_FLAGS, "--from")
                )
                t = _LaunchTable(argv, kind, flags, (spec_flag,), (), _py_spec_problem)
            tables[kind] = t
        return t

    n = len(argv)
    for i, tok in enumerate(argv):
        name = _launcher_name(tok)
        nxt = argv[i + 1].lower() if i + 1 < n else ""
        if name == "npx":
            table("npx").visit_from(i + 1, visit)
        elif name == "uvx":
            table("uvx").visit_from(i + 1, visit)
        elif name == "uv" and nxt == "tool" and i + 2 < n and argv[i + 2].lower() == "run":
            table("uv tool run").visit_from(i + 3, visit)
        elif name == "pipx" and nxt == "run":
            table("pipx run").visit_from(i + 2, visit)
        elif name == "docker" and nxt == "run":
            table("docker run").visit_from(i + 2, visit)


def _unpinned_message(launcher, spec, problem, hint):
    return "Unpinned launch: %s '%s' %s (%s)" % (launcher, spec, problem, hint)


def _split_arg(s):
    """Split one command/arg string into argv tokens."""
    if not re.search(r"\s", s):
        return [s]
    if "\\" in s:
        # shlex would eat Windows path separators.
        return s.split()
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def _command_argv(cmd, args):
    argv = []
    if isinstance(cmd, dict):
        # Zed: "command": {"path": "npx", "args": [...]}
        if args is None:
            args = cmd.get("args")
        cmd = cmd.get("path")
    if isinstance(cmd, str):
        argv.extend(_split_arg(cmd))
    elif isinstance(cmd, list):
        for el in cmd:
            if isinstance(el, str):
                argv.extend(_split_arg(el))
    if isinstance(args, list):
        for el in args:
            if isinstance(el, str):
                argv.extend(_split_arg(el))
    return argv


def _json_commands(node, out):
    """Collect argv lists for every dict with a "command"/"cmd" key."""
    if isinstance(node, dict):
        for key in ("command", "cmd"):
            if key in node:
                out.append(_command_argv(node[key], node.get("args")))
                break
        for value in node.values():
            _json_commands(value, out)
    elif isinstance(node, list):
        for value in node:
            _json_commands(value, out)


_JSON_CMD_KEY_RE = re.compile(r"""["'](?:command|cmd)["']\s*:""")


def _find_line(lines, needle, start):
    """1-based number of the first line at/after index `start` containing needle."""
    variants = [needle]
    escaped = json.dumps(needle)[1:-1]
    if escaped != needle:
        variants.append(escaped)
    for i in range(start, len(lines)):
        if any(v in lines[i] for v in variants):
            return i + 1
    return None


def _pg008_json(lines, data, hits):
    argvs = []
    _json_commands(data, argvs)
    cmd_lines = [i for i, l in enumerate(lines, 1) if _JSON_CMD_KEY_RE.search(l)]
    cursors = {}
    exhausted = set()  # specs _find_line no longer finds (their cursor stays put)
    for k, argv in enumerate(argvs):
        fallback = cmd_lines[k] if k < len(cmd_lines) else 1

        def visit(item):
            launcher, spec, problem, hint, _ = item
            lineno = None
            if spec not in exhausted:
                lineno = _find_line(lines, spec, cursors.get(spec, 0))
                if lineno:
                    cursors[spec] = lineno
                else:
                    exhausted.add(spec)
            _add_hit(hits, lines, lineno or fallback, _unpinned_message(launcher, spec, problem, hint))
            # A repeat of an exhausted spec lands on `fallback` again: no change.
            return spec in exhausted

        _each_launch_problem(argv, visit)


# Heuristic (a): a launcher at the start of a command string on one line.
_INLINE_LAUNCH_RE = re.compile(
    r"""(?:^\s*(?:-\s+)?|["'`=:;&|(]\s*|\s(?:-c|/c|/k)\s+)"""
    r"""((?:[^\s"'`]*[\\/])?(?:npx|uvx)(?:\.cmd|\.exe)?"""
    r"""|uv\s+tool\s+run|pipx\s+run|docker\s+run)\s+\S""",
    re.IGNORECASE,
)
# _INLINE_LAUNCH_RE is the reference definition. Calling .search() on it is
# quadratic on long runs such as ':::' or 'http://http://' (the optional
# "[^\s\"'`]*[\\/]" path prefix rescans the rest of the run at every start
# position), so _inline_launch_start() finds the same m.start(1) in linear
# time: locate the launcher names first, then test only the start positions
# that can precede them.
_INLINE_PREFIX_CHARS = "\"'`=:;&|("
_LAUNCH_AT_RE = re.compile(
    r"""(?=((?:npx|uvx)(?:\.cmd|\.exe)?\s+\S)|(?:uv\s+tool\s+run|pipx\s+run|docker\s+run)\s+\S)""",
    re.IGNORECASE,
)
_PATH_BREAK_RE = re.compile(r"""[\s"'`]""")
_PREFIX_CHAR_RE = re.compile(r"""[=:;&|(]""")
_SPACE_RE = re.compile(r"\s")
_SPACES_RE = re.compile(r"\s*")
_DASH_LEAD_RE = re.compile(r"\s*-\s+")
_SHELL_FLAG_RE = re.compile(r"\s(?:-c|/c|/k)\s", re.IGNORECASE)


def _inline_launch_start(line):
    """m.start(1) of _INLINE_LAUNCH_RE.search(line), or None (linear time)."""
    plain = set()  # launcher matched right at the position (no path prefix)
    pathed = []    # npx/uvx positions right after '/' or '\'
    for m in _LAUNCH_AT_RE.finditer(line):
        p = m.start()
        plain.add(p)
        if m.group(1) is not None and p > 0 and line[p - 1] in "\\/":
            pathed.append(p)
    if not plain:
        return None
    breaks = [b.start() for b in _PATH_BREAK_RE.finditer(line)] if pathed else []

    def run_start(k):
        """Start of the run of non-[\\s"'`] characters containing line[k]."""
        j = bisect.bisect_left(breaks, k) - 1
        return breaks[j] + 1 if j >= 0 else 0

    def group_ok(g):
        """Does group 1 of _INLINE_LAUNCH_RE match at g?"""
        if g in plain:
            return True
        k = bisect.bisect_right(pathed, g)
        if k == len(pathed):
            return False
        p = pathed[k]
        j = bisect.bisect_left(breaks, g)
        return j == len(breaks) or breaks[j] >= p

    def group_at(s):
        """Group-1 start when the whole pattern matches at s, else None."""
        if s == 0:
            m = _DASH_LEAD_RE.match(line)
            if m and group_ok(m.end()):
                return m.end()
            g = _SPACES_RE.match(line).end()
            if group_ok(g):
                return g
        if s < len(line) and line[s] in _INLINE_PREFIX_CHARS:
            g = _SPACES_RE.match(line, s + 1).end()
            if group_ok(g):
                return g
        elif _SHELL_FLAG_RE.match(line, s):
            g = _SPACES_RE.match(line, s + 3).end()
            if group_ok(g):
                return g
        return None

    def starts_before(g, out):
        """Every s whose prefix alternative could end exactly at g."""
        w = g
        while w > 0 and _SPACE_RE.match(line, w - 1):
            w -= 1
        out.update(s for s in (w - 1, w - 3) if s >= 0)

    cands = {0}
    for g in plain:
        starts_before(g, cands)
    for p in pathed:
        r = run_start(p - 1)
        starts_before(r, cands)
        m = _PREFIX_CHAR_RE.search(line, r, p - 1)
        if m:
            cands.add(m.start())
    for s in sorted(cands):
        g = group_at(s)
        if g is not None:
            return g
    return None


_DESCRIPTIVE_LINE_RE = re.compile(
    r"""^\s*(?:-\s+)?["']?(?:description|desc|summary|title|docstring|help|comment|note)["']?\s*[:=]""",
    re.IGNORECASE,
)
# Heuristic (b): a command/cmd/path key whose value is only a launcher name.
_CMD_ONLY_RE = re.compile(
    r"""(?:^|[\s{,])["']?(?:command|cmd|path)["']?\s*[:=]\s*"""
    r"""(?:"([^"\s]+)"|'([^'\s]+)'|([^\s"',{}\[\]#]+)\s*(?=$|[,}#]))""",
    re.IGNORECASE,
)
_CMD_ANY_RE = re.compile(r"""(?:^|[\s{,])["']?(?:command|cmd)["']?\s*[:=]""", re.IGNORECASE)
_ARGS_KEY_RE = re.compile(r"""(?:^|[\s{,])["']?args["']?\s*[:=]\s*""", re.IGNORECASE)
_LIST_ITEM_RE = re.compile(r""""((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^,\s"']+)""")
# Launchers, plus wrappers that may carry one in their args (cmd /c npx ...).
_LAUNCHER_COMMANDS = (
    "npx", "uvx", "uv", "pipx", "docker",
    "cmd", "sh", "bash", "zsh", "powershell", "pwsh",
)


def _heuristic_tokens(s):
    return re.findall(r"""[^\s"'`,\[\]{}]+""", s)


def _find_unquoted(s, ch):
    quote = None
    k = 0
    while k < len(s):
        c = s[k]
        if quote:
            if c == "\\":
                k += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == ch:
            return k
        k += 1
    return -1


def _list_items(part):
    """[value of each _LIST_ITEM_RE.finditer(part) match] (via _ItemScanner: linear time)."""
    scanner = _ItemScanner(part, len(part))
    items = []
    e = 0
    while True:
        found = scanner.search(e)
        if found is None:
            return items
        items.append(found[1])
        e = found[0]


_ITEM_START_RE = re.compile(r"[^,\s]")
_ITEM_WORD_RE = re.compile(r"""[^,\s"']+""")


class _ItemScanner(object):
    """_LIST_ITEM_RE.search(line, pos, end) without its quadratic cases.

    The regex retries its "..." / '...' alternatives at every quote; on text
    like '\\"\\"\\"...' or "''''..." with no closing quote each try reads to
    `end`. Here each quoted scan is memoised by position, so the answers
    (same matches, same groups) come in linear time over all searches.
    """

    def __init__(self, line, end):
        self.line = line
        self.end = end
        self.dq = {}  # position inside "...": index of the closing '"', or -1
        self.sq = {}  # position inside '...': (end of a match closed by a lone "'", or -1, last "''" start or -1)

    def _dq_close(self, k):
        line, end, memo = self.line, self.end, self.dq
        trail = []
        res = -1
        while k < end:
            if k in memo:
                res = memo[k]
                break
            trail.append(k)
            c = line[k]
            if c == '"':
                res = k
                break
            if c == "\\":
                if k + 1 < end and line[k + 1] != "\n":  # \\. ('.' is not a newline)
                    k += 2
                    continue
                break  # the content stops at this backslash: no closing quote
            k += 1
        for t in trail:
            memo[t] = res
        return res

    def _sq_walk(self, k):
        """(close, last_pair) for (?:[^']|'')* run greedily from k up to `end`."""
        line, end, memo = self.line, self.end, self.sq
        trail = []  # (position, is the start of a '' pair)
        res = (-1, -1)
        while k < end:
            if k in memo:
                res = memo[k]
                break
            if line[k] == "'":
                if k + 1 < end and line[k + 1] == "'":
                    trail.append((k, True))
                    k += 2
                    continue
                trail.append((k, False))
                res = (k + 1, -1)
                break
            trail.append((k, False))
            k += 1
        close, last = res
        for t, pair in reversed(trail):
            if pair and last < 0:
                last = t
            memo[t] = (close, last)
        return memo[trail[0][0]] if trail else res

    def search(self, pos):
        """(match end, value) of _LIST_ITEM_RE.search(line, pos, end), or None."""
        line, end = self.line, self.end
        x = pos
        while True:
            m = _ITEM_START_RE.search(line, x, end)
            if not m:
                return None
            x = m.start()
            c = line[x]
            if c == '"':
                q = self._dq_close(x + 1)
                if q >= 0:
                    return q + 1, line[x + 1:q]
            elif c == "'":
                close, last = self._sq_walk(x + 1)
                stop = close if close >= 0 else (last + 1 if last >= 0 else -1)
                if stop >= 0:
                    return stop, line[x + 1:stop - 1]
            else:
                w = _ITEM_WORD_RE.match(line, x, end)
                return w.end(), w.group(0)
            x += 1


def _collect_args(lines, j, pos):
    """[(item, lineno)] for an args value starting at lines[j][pos:]."""
    rest = lines[j][pos:]
    stripped = rest.strip()
    items = []
    if stripped.startswith("["):
        seg = rest[rest.index("[") + 1:]
        k = j
        while True:
            close = _find_unquoted(seg, "]")
            part = seg if close < 0 else seg[:close]
            items.extend((item, k + 1) for item in _list_items(part))
            if close >= 0 or k + 1 >= len(lines) or k - j > 50:
                break
            k += 1
            seg = lines[k]
    elif not stripped or stripped.startswith("#"):
        # YAML block list.
        item_indent = None
        for k in range(j + 1, len(lines)):
            t = lines[k].strip()
            if not t or t.startswith("#"):
                continue
            ind = _indent(lines[k])
            m = re.match(r"-\s+(.*)$", t)
            if not m or (item_indent is not None and ind < item_indent):
                break
            if item_indent is None:
                item_indent = ind
            if ind == item_indent:
                items.append((_unquote(_strip_yaml_comment(m.group(1))), k + 1))
    else:
        items = [(tok, j + 1) for tok in _heuristic_tokens(_strip_yaml_comment(stripped))]
    return items


def _find_args(lines, i, after):
    """Locate the args key for a command on line i: same line, below, above."""
    m = _ARGS_KEY_RE.search(lines[i], after)
    if m:
        return i, m.end()
    for step in (1, -1):
        for d in range(1, 16):
            j = i + step * d
            if j < 0 or j >= len(lines):
                break
            if _CMD_ANY_RE.search(lines[j]):
                break  # another server's command
            m = _ARGS_KEY_RE.search(lines[j])
            if m:
                return j, m.end()
    return None


def _pg008_heuristic(lines, hits):
    for i, line in enumerate(lines):
        lineno = i + 1
        # (a) launcher and its arguments on the same line.
        if not _DESCRIPTIVE_LINE_RE.match(line):
            start = _inline_launch_start(line)
            if start is not None:
                tokens = _heuristic_tokens(line[start:])
                _each_launch_problem(tokens, _launch_hit(hits, lines, lambda idx: lineno))
        # (b) command key holding only the launcher; args elsewhere.
        m = _CMD_ONLY_RE.search(line)
        if not m:
            continue
        value = next(g for g in m.groups() if g is not None)
        if _launcher_name(value) not in _LAUNCHER_COMMANDS:
            continue
        found = _find_args(lines, i, m.end())
        if not found:
            continue
        argv = [(tok, lineno) for tok in _split_arg(value)]
        for item, item_line in _collect_args(lines, found[0], found[1]):
            argv.extend((tok, item_line) for tok in _split_arg(item))
        tokens = [t for t, _ in argv]
        _each_launch_problem(tokens, _launch_hit(hits, lines, lambda idx: argv[idx][1]))


def _launch_hit(hits, lines, line_of):
    """visit() for _each_launch_problem: one hit per item (repeats add nothing)."""

    def visit(item):
        launcher, spec, problem, hint, idx = item
        _add_hit(hits, lines, line_of(idx), _unpinned_message(launcher, spec, problem, hint))
        return True

    return visit


def _analyze_unpinned_launch(ctx):
    if _file_ext(ctx) not in _PG008_EXTS:
        return {}
    if _is_github_workflow(ctx) or _is_github_action(ctx):
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    for i, line in enumerate(lines, 1):
        for rx in (_PIPE_TO_SHELL_RE, _PIPE_TO_IEX_RE):
            m = _pipe_search(rx, line)
            if m:
                _add_hit(
                    hits,
                    lines,
                    i,
                    "Remote script piped straight into a shell (%s ... | %s)"
                    % (m[0].lower(), m[1].lower()),
                )
    data = None
    text = ctx.get("text", "").lstrip("\ufeff")
    if _file_ext(ctx) in (".json", ".mcp", "") and text.lstrip()[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    if data is not None:
        _pg008_json(lines, data, hits)
    else:
        _pg008_heuristic(lines, hits)
    return hits


# ---------------------------------------------------------------------------
# PG009: tool description / resource metadata poisoning
# ---------------------------------------------------------------------------

# Zero-width, bidi embedding/override/isolate controls, and BOM.
_INVISIBLE_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def _invisible_message(line, lineno):
    counts = {}
    for m in _INVISIBLE_RE.finditer(line):
        ch, pos = m.group(0), m.start()
        if ch == "\ufeff" and lineno == 1 and pos == 0:
            continue  # byte-order mark
        if ch in ("\u200c", "\u200d"):
            prev = line[pos - 1] if pos > 0 else ""
            nxt = line[pos + 1] if pos + 1 < len(line) else ""
            if prev and nxt and ord(prev) > 127 and ord(nxt) > 127:
                continue  # emoji ZWJ sequences, Persian/Indic joiners
        counts[ch] = counts.get(ch, 0) + 1
    if not counts:
        return None
    return "Invisible/bidi control character(s) hidden in text: %s" % ", ".join(
        "U+%04X x%d" % (ord(ch), n) for ch, n in counts.items()
    )


_DESC_KEY_RE = re.compile(
    r"""(?:(?<=[\s{,\[])|^)(?:-\s+)?(["']?)(description|desc|summary|title|docstring)\1"""
    r"""\s*[:=](?=\s|$|["'|>])[ \t]*""",
    re.IGNORECASE,
)
_BLOCK_SCALAR_RE = re.compile(r"^[|>][-+0-9]*\s*(?:#.*)?$")


def _read_value(lines, i, start, key_col):
    """Return (segments, last_line_index, resume_pos) for a value at lines[i][start:].

    segments is [(lineno, text)].
    """
    line = lines[i]
    rest = line[start:]
    for q in ('"""', "'''"):
        if rest.startswith(q):
            close = rest.find(q, 3)
            if close >= 0:
                return [(i + 1, rest[3:close])], i, start + close + 3
            segs = [(i + 1, rest[3:])]
            for j in range(i + 1, len(lines)):
                c = lines[j].find(q)
                if c >= 0:
                    segs.append((j + 1, lines[j][:c]))
                    return segs, j, len(lines[j])
                segs.append((j + 1, lines[j]))
            return segs, len(lines) - 1, 0
    if rest[:1] in ('"', "'"):
        q = rest[0]
        k = 1
        while k < len(rest):
            c = rest[k]
            if q == '"' and c == "\\":
                k += 2
                continue
            if c == q:
                if q == "'" and rest[k + 1:k + 2] == "'":
                    k += 2
                    continue
                break
            k += 1
        return [(i + 1, rest[1:k])], i, start + k + 1
    stripped = rest.strip()
    if not stripped or _BLOCK_SCALAR_RE.match(stripped):
        end = _block_end(lines, i, key_col)
        segs = [(j + 1, lines[j]) for j in range(i + 1, end)]
        return segs, max(i, end - 1), len(line)
    return [(i + 1, rest)], i, len(line)


def _description_values(lines):
    """Yield [(lineno, text)] segments for every descriptive value."""
    i = 0
    while i < len(lines):
        line = lines[i]
        pos = 0
        next_i = i + 1
        while True:
            m = _DESC_KEY_RE.search(line, pos)
            if not m:
                break
            key_col = m.start(2) - len(m.group(1))
            segs, last, resume = _read_value(lines, i, m.end(), key_col)
            if segs:
                yield segs
            if last > i:
                next_i = last + 1
                break
            pos = max(resume, m.end())
        i = next_i


def _verb_forms(*verbs):
    forms = set()
    for v in verbs:
        stem = v[:-1] if v.endswith("e") else v
        forms.update((v, stem + "ed", stem + "ing"))
        forms.add(v + "es" if v.endswith(("s", "sh", "ch", "x")) else v + "s")
        if v.endswith("y"):
            forms.update((v[:-1] + "ies", v[:-1] + "ied"))
    return re.compile(
        r"\b(?:%s)\b" % "|".join(sorted(forms, key=len, reverse=True)),
        re.IGNORECASE,
    )


_PSEUDO_TAG_RE = re.compile(
    r"</?\s*(?:important|system|instructions|secret|hidden)\s*>", re.IGNORECASE
)
_CONCEAL_RES = [
    re.compile(
        r"\b(?:do\s+not|don['\u2019]?t|never)\s+"
        r"(?:tell|mention|inform|reveal|disclose|notify|show|alert)\b.{0,60}?\busers?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?users?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:hide|conceal)\s+(?:this|it|that)\s+from\s+(?:the\s+)?users?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bthe\s+user\s+(?:must|should)(?:\s+not|n['\u2019]?t)\s+(?:know|see|be\s+told)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:do\s+not|don['\u2019]?t)\s+mention\s+(?:this|that|it)\b", re.IGNORECASE),
]
_SENSITIVE_FILE_RE = re.compile(
    r"\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials\b|\.netrc\b|"
    r"\.npmrc\b|\.pypirc\b|/etc/(?:passwd|shadow)\b|\.kube/config\b|"
    r"\.docker/config\.json\b|\bmcp\.json\b|\.git-credentials\b",
    re.IGNORECASE,
)
_PATH_CHARS = set(string.ascii_letters + string.digits + "_~./-")
_FILE_VERB_RE = _verb_forms(
    "read", "cat", "open", "load", "send", "sent", "include", "pass", "upload",
    "post", "attach", "forward", "copy", "leak", "exfiltrate", "append",
    "provide", "return", "print", "output", "embed",
)
_EXFIL_VERB_RE = _verb_forms(
    "send", "sent", "include", "pass", "upload", "post", "attach", "forward",
    "leak", "exfiltrate", "append", "embed",
)
_DOTENV = r"\.env\b(?!\.(?:example|sample|template|dist)\b)"
_DOTENV_RE = re.compile(r"(?<![\w.])" + _DOTENV, re.IGNORECASE)
# Weak: a read-type verb whose direct object is the .env file.
_DOTENV_READ_RE = re.compile(
    r"\b(?:read|reads|reading|cat|open|opens|opening|load|loads|loading|dump|"
    r"dumps|print|prints|output|outputs|return|returns|access|accesses)\s+"
    r"(?:(?:the|your|its|all)\s+)?"
    r"(?:(?:contents?|values?|variables?)\s+(?:of|in|from)\s+(?:(?:the|your)\s+)?)?"
    r"(?:[\w~./-]*/)?" + _DOTENV,
    re.IGNORECASE,
)
_EMPHASIS_RES = [
    re.compile(r"\bIMPORTANT\b"),
    re.compile(
        r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:this|the|any)\s+tool",
        re.IGNORECASE,
    ),
    re.compile(r"\byou\s+must\s+(?:always|first)\b", re.IGNORECASE),
]
_HIDDEN_CUES = [
    ("secrecy", re.compile(r"\b(?:silently|secretly|covertly|quietly)\b", re.IGNORECASE)),
    ("sidenote", re.compile(r"\bside\s?note\b", re.IGNORECASE)),
    (
        "threat",
        re.compile(
            r"\botherwise\s+the\s+tool\s+(?:will\s+(?:not\s+work|fail)|won['\u2019]?t\s+work)",
            re.IGNORECASE,
        ),
    ),
    ("cross-tool", re.compile(r"\b(?:all|any|every)\s+other\s+tools?\b", re.IGNORECASE)),
    ("history", re.compile(r"\b(?:conversation|chat)\s+history\b", re.IGNORECASE)),
    ("system-prompt", re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE)),
    (
        "redirect",
        re.compile(r"\binstead\s+of\s+the\s+(?:user|recipient|requested)\b", re.IGNORECASE),
    ),
    ("dotenv", _DOTENV_READ_RE),
]
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{80,}={0,2}")
_ESCAPED_INVISIBLE_RE = re.compile(
    r"(?:\\u\{?|\\x\{|&#x)(?:200[b-f]|202[a-e]|206[6-9]|feff)\}?;?", re.IGNORECASE
)


def _path_around(text, m):
    """Widen a sensitive-file match to the whole path token for display."""
    start, end = m.start(), m.end()
    while start > 0 and text[start - 1] in _PATH_CHARS:
        start -= 1
    while end < len(text) and text[end] in _PATH_CHARS:
        end += 1
    return text[start:end].rstrip(".")


def _short(s, limit=60):
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _poison_reasons(text):
    """Return [(offset, reason)] for one description value."""
    strong = []
    for m in _PSEUDO_TAG_RE.finditer(text):
        strong.append((m.start(), "pseudo-tag '%s'" % m.group(0)))
        break
    for rx in _CONCEAL_RES:
        m = rx.search(text)
        if m:
            strong.append((m.start(), "concealment instruction '%s'" % _short(m.group(0))))
            break
    fm = _SENSITIVE_FILE_RE.search(text)
    vm = _FILE_VERB_RE.search(text)
    if fm and vm:
        strong.append(
            (
                fm.start(),
                "sensitive file '%s' with '%s'" % (_path_around(text, fm), vm.group(0)),
            )
        )
    em = _DOTENV_RE.search(text)
    xm = _EXFIL_VERB_RE.search(text)
    if em and xm:
        strong.append((em.start(), "'.env' with exfiltration verb '%s'" % xm.group(0)))
    reasons = list(strong)
    if not strong:
        emphasis = [m for m in (rx.search(text) for rx in _EMPHASIS_RES) if m]
        cues = []
        for name, rx in _HIDDEN_CUES:
            m = rx.search(text)
            if m:
                cues.append((name, m))
        if cues and (emphasis or len(cues) >= 2):
            matches = emphasis + [m for _, m in cues]
            label = "hidden-instruction cues: " + ", ".join(
                "'%s'" % _short(m.group(0), 30) for m in matches
            )
            reasons.append((min(m.start() for m in matches), label))
    for m in _BASE64_RE.finditer(text):
        blob = m.group(0)
        if (
            re.search(r"[A-Z]", blob)
            and re.search(r"[a-z]", blob)
            and re.search(r"[0-9]", blob)
        ):
            reasons.append((m.start(), "base64-like blob (%d chars)" % len(blob)))
            break
    m = _ESCAPED_INVISIBLE_RE.search(text)
    if m:
        reasons.append((m.start(), "escaped invisible character '%s'" % m.group(0)))
    return reasons


def _analyze_metadata_poisoning(ctx):
    lines = _ctx_lines(ctx)
    hits = {}
    for lineno, line in enumerate(lines, 1):
        message = _invisible_message(line, lineno)
        if message:
            _add_hit(hits, lines, lineno, message)
    per_line = {}
    for segs in _description_values(lines):
        starts = []
        offset = 0
        for lineno, seg in segs:
            starts.append((offset, lineno))
            offset += len(seg) + 1
        reasons = _poison_reasons("\n".join(seg for _, seg in segs))
        if not reasons:
            continue
        first = min(pos for pos, _ in reasons)
        lineno = [ln for off, ln in starts if off <= first][-1]
        bucket = per_line.setdefault(lineno, [])
        for _, reason in sorted(reasons):
            if reason not in bucket:
                bucket.append(reason)
    for lineno, reasons in per_line.items():
        _add_hit(
            hits,
            lines,
            lineno,
            "Tool/metadata description poisoning: " + "; ".join(reasons),
        )
    # Never echo invisible characters raw in a snippet.
    for lineno, bucket in hits.items():
        hits[lineno] = [
            (
                msg,
                _INVISIBLE_RE.sub(
                    lambda m: m.group(0).encode("ascii", "backslashreplace").decode("ascii"),
                    snippet,
                ),
            )
            for msg, snippet in bucket
        ]
    return hits


# ---------------------------------------------------------------------------
# PG010: untrusted workflow trigger with privileges
# ---------------------------------------------------------------------------

# Events that run in the base repository with secrets while carrying
# attacker-authored content. pull_request / pull_request_review_comment from
# forks get a read-only token and no secrets, so they are not listed.
_UNTRUSTED_TRIGGERS = (
    "pull_request_target",
    "issue_comment",
    "workflow_run",
    "issues",
    "discussion",
    "discussion_comment",
)
_ON_LINE_RE = re.compile(r"""^(?:on|"on"|'on')\s*:(.*)$""")
_REF_LINE_RE = re.compile(r"^\s*(?:-\s+)?ref\s*:\s*(.*)$")
_PR_HEAD_EXPR_RE = re.compile(
    r"\$\{\{[^}]*(?:pull_request\.head\.(?:sha|ref)\b|github\.head_ref\b|"
    r"workflow_run\.head_(?:sha|branch)\b)[^}]*\}\}",
    re.IGNORECASE,
)
_PR_CHECKOUT_CMD_RE = re.compile(
    r"\bgh\s+pr\s+checkout\b|"
    r"\bgit\s+(?:fetch|checkout|pull)\b.*\bpull/(?:\$\{\{[^}]*\}\}|[^/\s]+)/(?:head|merge)\b",
    re.IGNORECASE,
)
_SAME_REPO_GUARD_RE = re.compile(
    r"head\.repo\.full_name\s*==\s*github\.repository\b|"
    r"github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name\b|"
    r"head_repository\.full_name\s*==\s*github\.repository\b|"
    r"head\.repo\.fork\s*==\s*false\b|"
    r"!\s*github\.event\.pull_request\.head\.repo\.fork\b",
    re.IGNORECASE,
)
_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses\s*:\s*["']?([^\s"'#]+)""")
_AI_ACTION_RE = re.compile(
    r"claude|anthropic|gemini|codex|openai|copilot|gpt|llm|aider|cursor|qodo|"
    r"coderabbit|(?:^|[/_.-])ai(?:$|[/_.-])",
    re.IGNORECASE,
)
_WRITE_ALL_RE = re.compile(r"\bpermissions[ \t]*:[ \t]*write-all\b")
_WRITE_SCOPE_RE = re.compile(
    r"(?:^|[\s{,])(?:actions|attestations|checks|contents|deployments|"
    r"discussions|id-token|issues|models|packages|pages|pull-requests|"
    r"repository-projects|security-events|statuses)[ \t]*:[ \t]*write\b",
    re.MULTILINE,
)
_SECRET_REF_RE = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")
_SECRETS_INHERIT_RE = re.compile(r"\bsecrets[ \t]*:[ \t]*inherit\b")


def _flow_keys(inner):
    """Top-level keys of a YAML flow mapping body."""
    keys = []
    depth = 0
    for m in re.finditer(r"""[{\[]|[}\]]|["']?([\w-]+)["']?\s*:""", inner):
        tok = m.group(0)
        if tok in ("{", "["):
            depth += 1
        elif tok in ("}", "]"):
            depth -= 1
        elif depth == 0:
            keys.append(m.group(1))
    return keys


def _workflow_triggers(lines):
    for i, line in enumerate(lines):
        m = _ON_LINE_RE.match(line)
        if m:
            break
    else:
        return []
    rest = _strip_yaml_comment(m.group(1)).strip()
    events = []
    if rest[:1] in ("[", "{"):
        close = "]" if rest[0] == "[" else "}"
        buf, j = rest, i
        while buf.count(rest[0]) > buf.count(close) and j + 1 < len(lines):
            j += 1
            buf += " " + _strip_yaml_comment(lines[j]).strip()
        inner = buf[1:buf.rfind(close)] if close in buf else buf[1:]
        if rest[0] == "[":
            events = [_unquote(x) for x in inner.split(",") if x.strip()]
        else:
            events = _flow_keys(inner)
    elif rest:
        events = [_unquote(rest)]
    else:
        child = None
        for j in range(i + 1, len(lines)):
            s = lines[j]
            t = s.strip()
            if not t or t.startswith("#"):
                continue
            ind = _indent(s)
            if ind == 0:
                break
            if child is None:
                child = ind
            if ind != child:
                continue
            mm = re.match(r"-\s+(.+)$", t)
            if mm:
                events.append(_unquote(_strip_yaml_comment(mm.group(1))))
                continue
            mm = re.match(r"""["']?([\w-]+)["']?\s*:""", t)
            if mm:
                events.append(mm.group(1))
    return [e.lower() for e in events]


def _analyze_untrusted_trigger(ctx):
    if not _is_github_workflow(ctx):
        return {}
    lines = _ctx_lines(ctx)
    text = ctx.get("text", "")
    triggers = []
    for event in _workflow_triggers(lines):
        if event in _UNTRUSTED_TRIGGERS and event not in triggers:
            triggers.append(event)
    if not triggers:
        return {}
    trig = ", ".join(triggers)
    hits = {}

    # (a) privileged checkout of attacker-controlled PR head code.
    if not _SAME_REPO_GUARD_RE.search(text):
        for lineno, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            ref = _REF_LINE_RE.match(line)
            if (
                ref
                and (_PR_HEAD_EXPR_RE.search(ref.group(1)) or "refs/pull/" in ref.group(1))
            ) or _PR_CHECKOUT_CMD_RE.search(line):
                _add_hit(
                    hits,
                    lines,
                    lineno,
                    "Untrusted trigger (%s) checks out PR head code in a "
                    "privileged context" % trig,
                )

    # (b) AI agent action holding write permissions or secrets.
    write = bool(_WRITE_ALL_RE.search(text) or _WRITE_SCOPE_RE.search(text))
    secrets = []
    for name in _SECRET_REF_RE.findall(text):
        if name.upper() != "GITHUB_TOKEN" and name not in secrets:
            secrets.append(name)
    if _SECRETS_INHERIT_RE.search(text):
        secrets.append("inherit")
    if write or secrets:
        grants = []
        if write:
            grants.append("write permissions")
        if secrets:
            grants.append("secrets (%s)" % ", ".join(secrets))
        for lineno, line in enumerate(lines, 1):
            m = _USES_RE.match(line)
            if not m:
                continue
            action = m.group(1).split("@", 1)[0]
            if _AI_ACTION_RE.search(action):
                _add_hit(
                    hits,
                    lines,
                    lineno,
                    "Untrusted trigger (%s) runs AI agent action '%s' with %s"
                    % (trig, action, " and ".join(grants)),
                )
    return hits


# ---------------------------------------------------------------------------
# PG011: workflow expression injection
# ---------------------------------------------------------------------------

_YAML_KEY_RE = re.compile(r"""^(\s*)(-\s+)?["']?([\w-]+)["']?\s*:(?:\s|$)""")
_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}")
_TAINTED_EXPR_RE = re.compile(
    r"\bgithub\.event\.(?:"
    r"issue\.(?:title|body)|"
    r"pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|"
    r"comment\.body|review\.body|review_comment\.body|"
    r"discussion\.(?:title|body)|"
    r"pages(?:\[[^\]]*\]|\.\*)\.page_name|"
    r"commits(?:\[[^\]]*\]|\.\*)\.(?:message|author\.(?:email|name))|"
    r"head_commit\.(?:message|author\.(?:email|name))|"
    r"workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.\w+))"
    r")\b|"
    r"\bgithub\.head_ref\b|"
    r"\btojson\(\s*github\.event(?:\.[\w.\[\]*]+)?\s*\)",
    re.IGNORECASE,
)


def _is_sink_key(key):
    k = key.lower()
    return k in ("run", "script", "custom_instructions") or "prompt" in k


def _analyze_expression_injection(ctx):
    if not _is_yaml_like(ctx):
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    i = 0
    while i < len(lines):
        m = _YAML_KEY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        key = m.group(3)
        key_col = len(m.group(1)) + len(m.group(2) or "")
        if key.lower() == "env":
            # env: is the recommended indirection; never a sink.
            i = _block_end(lines, i, key_col)
            continue
        if not _is_sink_key(key):
            i += 1
            continue
        end = _block_end(lines, i, key_col)
        for j in range(i, end):
            found = []
            for em in _EXPRESSION_RE.finditer(lines[j]):
                for tm in _TAINTED_EXPR_RE.finditer(em.group(1)):
                    expr = tm.group(0)
                    if expr not in found:
                        found.append(expr)
            if found:
                _add_hit(
                    hits,
                    lines,
                    j + 1,
                    "Attacker-controlled expression %s expanded inside '%s' "
                    "(pass it through env: instead)"
                    % (", ".join("${{ %s }}" % e for e in found), key),
                )
        i = end
    return hits


# ---------------------------------------------------------------------------
# Shared JSON helpers (PG013, PG014)
# ---------------------------------------------------------------------------
#
# These rules must report on the line of a specific key, so JSON is parsed
# with the pure-Python scanner and every object/array remembers its
# [start, end) offsets in the text.


class _JDict(dict):
    __slots__ = ("start", "end")


class _JList(list):
    __slots__ = ("start", "end")


def _json_positions(text):
    """json.loads() whose dicts/lists carry .start/.end text offsets."""
    decoder = json.JSONDecoder()

    def parse_object(s_and_end, *args):
        start = s_and_end[1] - 1
        obj, end = json.decoder.JSONObject(s_and_end, *args)
        node = _JDict(obj)
        node.start, node.end = start, end
        return node, end

    def parse_array(s_and_end, scan_once):
        start = s_and_end[1] - 1
        arr, end = json.decoder.JSONArray(s_and_end, scan_once)
        node = _JList(arr)
        node.start, node.end = start, end
        return node, end

    decoder.parse_object = parse_object
    decoder.parse_array = parse_array
    decoder.scan_once = json.scanner.py_make_scanner(decoder)
    return decoder.decode(text)


def _json_text(ctx):
    """The file text ready for _json_positions (BOM blanked, offsets kept)."""
    text = ctx.get("text", "")
    if text.startswith("\ufeff"):
        text = " " + text[1:]
    if text.lstrip()[:1] not in ("{", "["):
        return None
    return text


def _line_starts(text):
    """Offsets where each line starts, split exactly like str.splitlines()."""
    starts = [0]
    pos = 0
    for piece in text.splitlines(True):
        pos += len(piece)
        starts.append(pos)
    return starts


def _offset_line(starts, offset):
    return max(1, bisect.bisect_right(starts, offset))


def _key_needles(key):
    needles = [json.dumps(key)]
    raw = json.dumps(key, ensure_ascii=False)
    if raw != needles[0]:
        needles.append(raw)
    return needles


def _key_offset(text, node, key):
    """Offset of `"key":` directly inside JSON object `node` (else node.start)."""
    # Sibling values occupy disjoint spans, so after sorting by start a match
    # can only lie inside the child with the greatest start <= the match.
    spans = sorted(
        (v.start, v.end) for v in node.values() if isinstance(v, (_JDict, _JList))
    )
    starts = [s for s, _ in spans]
    for needle in _key_needles(key):
        rx = re.compile(re.escape(needle) + r"\s*:")
        for m in rx.finditer(text, node.start, node.end):
            p = m.start()
            k = bisect.bisect_right(starts, p) - 1
            if k < 0 or p >= spans[k][1]:
                return p
    return node.start


_JSON_STRING_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_JSON_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
_HASH_MOD = (1 << 61) - 1
_HASH_BASE = 1000003


def _poly_hash(s):
    h = 0
    for ch in s:
        h = (h * _HASH_BASE + ord(ch)) % _HASH_MOD
    return h


class _ItemOffsets(object):
    """_item_offset() for many items of one JSON array, after a single scan.

    text.find(json.dumps(item), node.start, node.end) per item rescans the
    array from its start (quadratic for long allowedTools lists).  In valid
    JSON every '"' opens a string literal, closes one, or is an escaped quote
    inside one, and a needle (itself a JSON string literal without raw
    newlines or unescaped quotes) starting at such a '"' can only end at one
    place: an opening quote -> that whole literal; an escaped quote -> the
    rest of its literal; a closing quote -> '"' + the gap up to the next
    opening quote + '"'.  So the first occurrence of any needle is the
    smallest start recorded for it in those three tables.
    """

    def __init__(self, text, node):
        self.text = text
        self.node = node
        self.first = {}
        self.suffix = None
        lits = list(_JSON_STRING_RE.finditer(text, node.start, node.end))
        first = self.first
        for k, m in enumerate(lits):
            a, b = m.span()
            first.setdefault(m.group(), a)
            if k + 1 < len(lits):
                first.setdefault('"' + text[b:lits[k + 1].start()] + '"', b - 1)
        for m in lits:
            if '\\"' not in m.group():
                continue
            if self.suffix is None:
                self.suffix = {}
            a, b = m.span()
            quotes = [
                e.start(1) for e in _JSON_ESCAPE_RE.finditer(text, a + 1, b - 1)
                if e.group(1) == '"'
            ]
            h = 0
            power = 1
            pos = b - 1
            for q in reversed(quotes):
                while pos >= q:
                    h = (h + ord(text[pos]) * power) % _HASH_MOD
                    power = power * _HASH_BASE % _HASH_MOD
                    pos -= 1
                self.suffix.setdefault((b - q, h), q)

    def find(self, needle):
        best = self.first.get(needle, -1)
        if self.suffix is not None:
            q = self.suffix.get((len(needle), _poly_hash(needle)), -1)
            if q >= 0 and (best < 0 or q < best):
                if self.text.startswith(needle, q):
                    best = q
                else:  # hash collision: fall back to a plain search
                    return self.text.find(needle, self.node.start, self.node.end)
        return best

    def offset(self, item):
        for needle in _key_needles(item):
            p = self.find(needle)
            if p >= 0:
                return p
        return self.node.start


def _item_offset(text, node, item):
    """Offset of string `item` inside JSON array `node` (else node.start)."""
    return _ItemOffsets(text, node).offset(item)


def _basename(ctx):
    path = ctx.get("path") or "<text>"
    if path == "<text>":
        return ""
    return re.split(r"[\\/]", path)[-1].lower()


# ---------------------------------------------------------------------------
# PG013: sub-agent / skill / plugin permission inheritance
# ---------------------------------------------------------------------------

_FM_KEY_RE = re.compile(r"""^(["']?)([A-Za-z_][\w-]*)\1[ \t]*:(?=\s|$)(.*)$""")
_AGENT_DENY_KEYS = ("disallowedTools", "disallowed-tools", "disallowed_tools")
_ALLOWED_TOOLS_KEYS = ("allowed-tools", "allowed_tools", "allowedTools")
# "*", "mcp__*", or Tool(...) whose specifier is only "*"/":" (plus an
# optional "domain:" prefix), e.g. Bash(*), Bash(:*), Read(**), WebFetch(domain:*).
# Same language as "\(\s*(?:domain\s*:\s*)?[*:\s]*\*[*:\s]*\)", but the
# lookahead finds the required "*" once instead of re-scanning the run for
# every split point (that form was quadratic on "Bash(* * * ..." with no ")").
_WILDCARD_TOOL_RE = re.compile(
    r"^(?:\*|mcp__\*.*|[A-Za-z][\w-]*\((?:\s*domain\s*:)?(?=[*:\s]*\*)[*:\s]*\))$",
    re.IGNORECASE,
)
_NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
_MCP_TOKEN_RE = re.compile(r"(?:^|[^a-z0-9])mcp(?:$|[^a-z0-9])")
_EXTENSION_KEYWORDS = (
    "modelcontextprotocol", "model-context-protocol", "claude-code",
    "claude-plugin", "claude-code-plugin", "claude-skill", "agent-skill",
    "agent-skills",
)
_MCP_SDK_DEPS = ("@modelcontextprotocol/sdk", "fastmcp", "mcp-framework")
_AUTO_HOOK_EVENTS = (
    ("SessionStart", "at every session start"),
    ("Setup", "on claude --init/--maintenance"),
)


def _frontmatter_fields(lines):
    """{key: (index, inline_value, [(index, line), ...])} of a leading --- block."""
    if not lines or lines[0].lstrip("\ufeff").strip() != "---":
        return None
    end = None
    for j in range(1, min(len(lines), 500)):
        if lines[j].strip() == "---":
            end = j
            break
    if end is None:
        return None
    keys = []
    for i in range(1, end):
        s = lines[i]
        if not s or s[0] in " \t-#":
            continue
        m = _FM_KEY_RE.match(s)
        if m:
            keys.append((i, m.group(2), m.group(3)))
    fields = {}
    for k, (i, key, rest) in enumerate(keys):
        stop = keys[k + 1][0] if k + 1 < len(keys) else end
        if key not in fields:
            fields[key] = (i, rest, [(j, lines[j]) for j in range(i + 1, stop)])
    return fields


def _split_tool_entries(s):
    """'Read, Grep Bash(git add *)' -> ['Read', 'Grep', 'Bash(git add *)']."""
    out = []
    buf = []
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif depth == 0 and (ch == "," or ch.isspace()):
            if buf:
                out.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [e for e in (_unquote(x) for x in out) if e]


def _fm_entries(field):
    """[(entry, index)] for a front-matter string, flow list or block list."""
    i, rest, cont = field
    rest = _strip_yaml_comment(rest).strip()
    out = []
    if rest.startswith("["):
        segs = [(i, rest[1:])]
        if "]" not in rest:
            for j, s in cont:
                segs.append((j, _strip_yaml_comment(s)))
                if "]" in s:
                    break
        for j, seg in segs:
            out.extend((e, j) for e in _split_tool_entries(seg.split("]", 1)[0]))
        return out
    if rest and not _BLOCK_SCALAR_RE.match(rest):
        return [(e, i) for e in _split_tool_entries(rest)]
    for j, s in cont:
        t = _strip_yaml_comment(s).strip()
        if not t:
            continue
        m = re.match(r"-(?:\s+|$)(.*)$", t)
        if m:
            out.extend((e, j) for e in _split_tool_entries(m.group(1)))
        elif rest:
            out.extend((e, j) for e in _split_tool_entries(t))
    return out


# Front-matter fields only sub-agent definitions use (skills and docs pages
# share name/description, so those two alone prove nothing).
_AGENT_ONLY_KEYS = (
    "tools", "model", "color", "permissionMode", "mcpServers",
) + _AGENT_DENY_KEYS
_DOC_DIRS = (
    "docs", "doc", "documentation", "website", "site", "wiki", "blog", "pages",
)


def _is_agent_definition(ctx, fields):
    """True for a Claude Code sub-agent file, not a skill or a docs page.

    Location decides first: anything under .claude/agents/, or a direct child
    of a plugin's agents/ folder that is not inside a docs tree.  Deeper or
    docs-tree files under some agents/ folder count only when their front
    matter carries an agent-only field such as tools or model.
    """
    path = ctx.get("path") or "<text>"
    if path == "<text>":
        return False
    parts = [p.lower() for p in re.split(r"[\\/]+", path) if p]
    name = parts[-1] if parts else ""
    if not name.endswith(".md") or name in ("readme.md", "skill.md"):
        return False
    dirs = parts[:-1]
    if "agents" not in dirs:
        return False
    if "name" not in fields or "description" not in fields:
        return False
    for k in range(1, len(dirs)):
        if dirs[k] == "agents" and dirs[k - 1] == ".claude":
            return True
    if dirs[-1] == "agents" and not any(d in _DOC_DIRS for d in dirs):
        return True
    return any(k in fields for k in _AGENT_ONLY_KEYS)


def _pg013_markdown(ctx, lines, hits):
    fields = _frontmatter_fields(lines)
    if not fields:
        return
    if _is_agent_definition(ctx, fields):
        agent = _unquote(_strip_yaml_comment(fields["name"][1])) or "?"
        if "tools" in fields:
            for entry, j in _fm_entries(fields["tools"]):
                if _WILDCARD_TOOL_RE.match(entry):
                    _add_hit(
                        hits, lines, j + 1,
                        "Sub-agent '%s' lists wildcard tool entry '%s' in 'tools' "
                        "(grants every matching tool)" % (agent, entry),
                    )
            return
        if any(k in fields for k in _AGENT_DENY_KEYS):
            return
        near = [
            k for k in fields
            if k != "tools" and re.sub(r"[-_]", "", k.lower()) in ("tools", "allowedtools")
        ]
        note = ""
        if near:
            note = " ('%s' is not a field subagents recognize)" % near[0]
        _add_hit(
            hits, lines, fields["name"][0] + 1,
            "Sub-agent '%s' omits 'tools', so it inherits every tool available "
            "to subagents, MCP tools included%s" % (agent, note),
        )
        return
    for key in _ALLOWED_TOOLS_KEYS:
        if key not in fields:
            continue
        for entry, j in _fm_entries(fields[key]):
            if _WILDCARD_TOOL_RE.match(entry):
                _add_hit(
                    hits, lines, j + 1,
                    "Skill/command front matter pre-approves wildcard tool entry "
                    "'%s' in '%s' (runs without a permission prompt)" % (entry, key),
                )


def _is_extension_package(data):
    name = data.get("name")
    if isinstance(name, str):
        low = name.lower()
        if low.startswith("@modelcontextprotocol/") or _MCP_TOKEN_RE.search(low):
            return True
    keywords = data.get("keywords")
    if isinstance(keywords, list):
        for kw in keywords:
            if isinstance(kw, str) and (
                kw.lower() in _EXTENSION_KEYWORDS or _MCP_TOKEN_RE.search(kw.lower())
            ):
                return True
    for dep_key in ("dependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(dep_key)
        if isinstance(deps, dict) and any(d in deps for d in _MCP_SDK_DEPS):
            return True
    return False


def _pg013_package(text, starts, data, lines, hits):
    scripts = data.get("scripts")
    if not isinstance(scripts, _JDict) or not _is_extension_package(data):
        return
    pkg = data.get("name") if isinstance(data.get("name"), str) else "?"
    for key in _NPM_INSTALL_SCRIPTS:
        value = scripts.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        lineno = _offset_line(starts, _key_offset(text, scripts, key))
        _add_hit(
            hits, lines, lineno,
            "Install-time npm script '%s' in MCP/agent extension package '%s' "
            "runs automatically on every install" % (key, pkg),
        )


def _pg013_plugin(text, starts, data, lines, hits, base):
    # hooks.json wraps the event map in "hooks"; plugin.json may also give a
    # list mixing file paths and inline event maps.
    hooks = data.get("hooks")
    event_maps = []
    if isinstance(hooks, dict):
        event_maps.append(hooks)
    elif isinstance(hooks, list) and base == "plugin.json":
        event_maps.extend(h for h in hooks if isinstance(h, dict))
    for event_map in event_maps:
        for event, when in _AUTO_HOOK_EVENTS:
            groups = event_map.get(event)
            if not isinstance(groups, list):
                continue
            for group in groups:
                inner = group.get("hooks") if isinstance(group, dict) else None
                if not isinstance(inner, list):
                    continue
                for hook in inner:
                    if not isinstance(hook, _JDict) or hook.get("type") != "command":
                        continue
                    cmd = hook.get("command")
                    if not isinstance(cmd, str) or not cmd.strip():
                        continue
                    lineno = _offset_line(starts, _key_offset(text, hook, "command"))
                    _add_hit(
                        hits, lines, lineno,
                        "Plugin hook on '%s' runs a command automatically %s: %s"
                        % (event, when, _short(cmd)),
                    )
    commands = data.get("commands") if base == "plugin.json" else None
    if isinstance(commands, dict):
        for cname, spec in commands.items():
            allowed = spec.get("allowedTools") if isinstance(spec, dict) else None
            if not isinstance(allowed, _JList):
                continue
            offsets = None
            for entry in allowed:
                if isinstance(entry, str) and _WILDCARD_TOOL_RE.match(entry.strip()):
                    if offsets is None:
                        offsets = _ItemOffsets(text, allowed)
                    lineno = _offset_line(starts, offsets.offset(entry))
                    _add_hit(
                        hits, lines, lineno,
                        "Plugin command '%s' pre-approves wildcard tool entry '%s' "
                        "in allowedTools (runs without a permission prompt)"
                        % (cname, entry.strip()),
                    )


def _analyze_permission_inheritance(ctx):
    lines = _ctx_lines(ctx)
    hits = {}
    ext = _file_ext(ctx)
    if ext in (".md", ""):
        _pg013_markdown(ctx, lines, hits)
    base = _basename(ctx)
    if base in ("package.json", "hooks.json", "plugin.json"):
        text = _json_text(ctx)
        if text is None:
            return hits
        try:
            data = _json_positions(text)
        except (ValueError, RecursionError):
            return hits
        if not isinstance(data, _JDict):
            return hits
        starts = _line_starts(text)
        if base == "package.json":
            _pg013_package(text, starts, data, lines, hits)
        else:
            _pg013_plugin(text, starts, data, lines, hits, base)
    return hits


# ---------------------------------------------------------------------------
# PG014: over-broad tool input schema
# ---------------------------------------------------------------------------

_SCHEMA_KEYS = ("inputSchema", "input_schema", "parameters")
_PATH_TOKENS = {
    "path", "paths", "filepath", "filepaths", "filename", "filenames",
    "pathname", "dir", "dirs", "dirname", "directory", "directories",
    "folder", "folders", "cwd",
}
_PATH_LAST = {"file", "files"}
_COMMAND_TOKENS = {
    "command", "commands", "cmd", "cmds", "cmdline", "commandline", "shell",
}
_COMMAND_LAST = {"script"}
_URL_TOKENS = {"url", "urls", "uri", "uris", "endpoint", "endpoints", "webhook", "href"}
_SQL_TOKENS = {"sql"}
_SQL_LAST = {"query", "statement"}
_SQL_TOOL_TOKENS = {
    "sql", "sqlite", "postgres", "postgresql", "mysql", "mssql", "db", "database",
}
_CODE_TOKENS = {"expression", "expr", "eval"}
_CODE_LANG = {
    "source", "python", "py", "js", "javascript", "ts", "typescript",
    "program", "script", "lua", "ruby",
}
_TRIVIAL_PATTERNS = {
    "", ".*", ".+", "(.*)", "(.+)", "[\\s\\S]*", "[\\s\\S]+",
    "[\\S\\s]*", "[\\S\\s]+", "(?s).*", "(?s).+",
}


_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
# "HTMLParser" -> "HTML_Parser": "_" before the last capital of a run of 2+
# capitals that is followed by a lowercase letter.  Same result as
# re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s) without its quadratic
# backtracking on long all-capital names.
_ACRONYM_END_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_NAME_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def _name_tokens(name):
    s = _CAMEL_RE.sub(r"\1_\2", name)
    s = _ACRONYM_END_RE.sub("_", s)
    return [t for t in _NAME_SPLIT_RE.split(s.lower()) if t]


def _sink_category(param, tool_tokens):
    tokens = _name_tokens(param)
    if not tokens:
        return None
    tset = set(tokens)
    last = tokens[-1]
    if tset & _PATH_TOKENS or last in _PATH_LAST:
        return "path"
    if tset & _COMMAND_TOKENS or last in _COMMAND_LAST:
        return "command"
    if tset & _URL_TOKENS:
        return "url"
    if tset & _SQL_TOKENS or (last in _SQL_LAST and tool_tokens & _SQL_TOOL_TOKENS):
        return "sql"
    if (
        tset & _CODE_TOKENS
        or tokens == ["code"]
        or (last == "code" and len(tokens) > 1 and tokens[-2] in _CODE_LANG)
    ):
        return "code"
    return None


def _schema_types(schema):
    t = schema.get("type")
    if isinstance(t, str):
        return {t.lower()}
    if isinstance(t, list):
        return {x.lower() for x in t if isinstance(x, str)}
    return set()


def _is_constrained(schema):
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return True
    if "const" in schema:
        return True
    max_len = schema.get("maxLength")
    if isinstance(max_len, (int, float)) and not isinstance(max_len, bool):
        return True
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        core = pattern
        if core.startswith("^"):
            core = core[1:]
        if core.endswith("$") and not core.endswith("\\$"):
            core = core[:-1]
        if core not in _TRIVIAL_PATTERNS:
            return True
    for key in ("anyOf", "oneOf"):
        alts = schema.get(key)
        if isinstance(alts, list) and alts and all(
            isinstance(a, dict) and _is_constrained(a) for a in alts
        ):
            return True
    parts = schema.get("allOf")
    if isinstance(parts, list) and any(
        isinstance(a, dict) and _is_constrained(a) for a in parts
    ):
        return True
    return False


def _loose_optional(schema):
    """Label suffix ("" or "[]") for a loose Optional/Union string schema.

    Pydantic and FastMCP emit Optional[str] as {"anyOf": [{"type": "string"},
    {"type": "null"}]} with no top-level "type" (oneOf likewise).  The
    schema counts when every branch is null, a string or an array of
    strings, and some string branch is unconstrained; enum/const/maxLength/
    pattern may sit on the outer schema or on that branch.  Returns None
    when the schema is not of that shape or is constrained.
    """
    if _is_constrained(schema):
        return None
    for key in ("anyOf", "oneOf"):
        alts = schema.get(key)
        if not isinstance(alts, list) or not alts:
            continue
        suffix = None
        shaped = True
        branches = 0
        for alt in alts:
            if not isinstance(alt, dict) or "$ref" in alt:
                shaped = False
                break
            types = _schema_types(alt)
            if types == {"null"}:
                continue
            if "string" in types and types <= {"string", "null"}:
                target, mark = alt, ""
            elif "array" in types and types <= {"array", "null"} and isinstance(
                alt.get("items"), dict
            ) and "string" in _schema_types(alt["items"]):
                target, mark = alt["items"], "[]"
            else:
                shaped = False
                break
            branches += 1
            if suffix is None and not _is_constrained(target):
                suffix = mark
        if shaped and branches and suffix is not None:
            return suffix
    return None


def _tool_schemas(node, out):
    """Collect (tool_name, schema) for every tool definition in a JSON tree."""
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str):
            for key in _SCHEMA_KEYS:
                schema = node.get(key)
                if not isinstance(schema, _JDict) or not isinstance(
                    schema.get("properties"), _JDict
                ):
                    continue
                if key == "parameters" and "object" not in _schema_types(schema):
                    continue
                out.append((name, schema))
                break
        for value in node.values():
            _tool_schemas(value, out)
    elif isinstance(node, list):
        for value in node:
            _tool_schemas(value, out)


def _broad_params(schema, tool_tokens, prefix, depth, out):
    """Collect (label, category, properties_node, key, child) for loose sinks."""
    props = schema.get("properties")
    if not isinstance(props, _JDict) or depth > 5:
        return
    for pname, pschema in props.items():
        if not isinstance(pschema, _JDict):
            continue
        label = prefix + pname
        types = _schema_types(pschema)
        target = None
        if "string" in types:
            target = pschema
        elif "array" in types and isinstance(pschema.get("items"), dict):
            items = pschema["items"]
            if "string" in _schema_types(items):
                target = items
                label += "[]"
        category = _sink_category(pname, tool_tokens)
        if (
            category
            and target is not None
            and "$ref" not in pschema
            and not _is_constrained(target)
        ):
            out.append((label, category, props, pname, pschema))
        elif category and target is None and "type" not in pschema and "$ref" not in pschema:
            suffix = _loose_optional(pschema)
            if suffix is not None:
                out.append((label + suffix, category, props, pname, pschema))
        if "object" in types:
            _broad_params(pschema, tool_tokens, prefix + pname + ".", depth + 1, out)


def _analyze_broad_schema(ctx):
    if _file_ext(ctx) not in (".json", ".mcp", ""):
        return {}
    text = _json_text(ctx)
    if text is None or not any(
        '"%s"' % k in text for k in _SCHEMA_KEYS
    ):
        return {}
    try:
        data = _json_positions(text)
    except (ValueError, RecursionError):
        return {}
    tools = []
    _tool_schemas(data, tools)
    if not tools:
        return {}
    lines = _ctx_lines(ctx)
    starts = _line_starts(text)
    hits = {}
    for tool, schema in tools:
        loose = []
        _broad_params(schema, set(_name_tokens(tool)), "", 0, loose)
        if not loose:
            continue
        extra = ""
        if schema.get("additionalProperties") is not False:
            extra = "; the schema also accepts undeclared properties (set additionalProperties: false)"
        for label, category, props, key, child in loose:
            offset = -1
            for needle in _key_needles(key):
                offset = text.rfind(needle, props.start, child.start)
                if offset >= 0:
                    break
            lineno = _offset_line(starts, offset if offset >= 0 else props.start)
            _add_hit(
                hits, lines, lineno,
                "Over-broad tool schema: '%s' parameter '%s' (%s) is a free-form "
                "string (no enum, const, maxLength or non-trivial pattern)%s"
                % (tool, label, category, extra),
            )
    return hits


# ---------------------------------------------------------------------------
# PG021: checksum fetched from the same origin as the artifact
# ---------------------------------------------------------------------------

_DOWNLOAD_CMD_RE = re.compile(
    r"(?<![\w.-])(curl|wget|aria2c|invoke-webrequest|iwr|invoke-restmethod|irm|"
    r"start-bitstransfer)(?:\.exe)?(?![\w-])",
    re.IGNORECASE,
)
_DOCKER_ADD_RE = re.compile(r"^\s*ADD\s", re.IGNORECASE)
_SEGMENT_END_RE = re.compile(r"&&|\|\||\||;")
_CURL_UPLOAD_RE = re.compile(
    r"(?:^|\s)(?:-T|--upload-file|-F|--form|-d|--data(?:-[a-z]+)?)(?=[\s=]|$)|"
    r"(?:^|\s)(?:-X|--request)[\s=]*[\"']?(?:PUT|POST|PATCH)\b",
)
_WGET_UPLOAD_RE = re.compile(
    r"--(?:post|body)-(?:file|data)\b|--method[\s=]+[\"']?(?:PUT|POST|PATCH)\b",
    re.IGNORECASE,
)
_PS_UPLOAD_RE = re.compile(
    r"-Method\s+[\"']?(?:Put|Post|Patch)\b|-InFile\b|-TransferType\s+Upload\b",
    re.IGNORECASE,
)
_URL_TOKEN_RE = re.compile(
    r"""(https?://[^\s"'`<>|;()\\]+)"""
    r"""|\$\{\{env\.([A-Za-z_]\w*)\}\}([^\s"'`<>|;()\\]*)"""
    r"""|\$(?:env:)?\{?([A-Za-z_]\w*)\}?([^\s"'`<>|;()\\]*)""",
    re.IGNORECASE,
)
_URL_ASSIGN_RE = re.compile(
    r"""(?:^|[\s;(])(?:export\s+|(?:ARG|ENV|arg|env)\s+)?\$?(?:env:)?"""
    r"""([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*|\s*:\s+)["']?(https?://[^\s"'`#]+)"""
)
_DOCKER_ENV_SPACE_RE = re.compile(
    r"""^\s*ENV\s+([A-Za-z_]\w*)\s+["']?(https?://[^\s"'`#]+)""", re.IGNORECASE
)
_GH_EXPR_RE = re.compile(r"\$\{\{([^}\n]{0,200}?)\}\}")
_PROSE_KEY_RE = re.compile(
    r"""^\s*(?:-\s+)?["']?(?:name|description|title|summary)["']?\s*:""",
    re.IGNORECASE,
)
_CHECKSUM_FILE_RES = (
    re.compile(r"\.(?:sha(?:1|224|256|384|512)|md5|b2)(?:sum)?(?:\.txt)?$"),
    re.compile(r"^(?:.*[-_.])?(?:sha(?:1|224|256|384|512)|md5|b2)sums?(?:\.txt)?$"),
    re.compile(r"^(?:.*[-_.])?checksums?(?:\.txt|\.sha256)?$"),
)
# Signatures and certificates travel with checksums; they are not artifacts.
_SIGNATURE_FILE_RE = re.compile(
    r"\.(?:sig|asc|minisig|pem|crt|cert|sigstore|bundle|intoto\.jsonl)$", re.IGNORECASE
)
# Signature checks that waive PG021 for the whole file.  "-V" may be merged
# with other short flags (minisign -Vm file).  gpg --decrypt is not listed:
# it prints a bad or missing signature as a warning and still exits 0 for
# encrypted-only input, so it does not gate the download on a signature.
_SIGNATURE_VERIFY_RE = re.compile(
    r"\bgpg2?\b[^\n|;&]{0,200}?\s--verify\b|\bgpgv2?\b|\bcosign\s+verify(?:-blob)?\b|"
    r"\b(?:minisign|signify)\b[^\n|;&]{0,200}?\s-[A-Za-z]*V[A-Za-z]*\b|"
    r"\bopenssl\s+dgst\b[^\n|;&]{0,200}?\s-verify\b|\bsigstore\s+verify\b|"
    r"\bgh\s+attestation\s+verify\b|\bslsa-verifier\b"
)


def _is_dockerfile(ctx):
    base = _basename(ctx)
    return base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile")


# Code hosts where the owner/repo path, not the host, is the trust boundary.
_MULTI_TENANT_HOSTS = (
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org",
    "raw.githubusercontent.com",
)


_URL_PARTS_RE = re.compile(r"https?://([^/?#]+)([^?#]*)", re.IGNORECASE)
_URL_QUERY_RE = re.compile(r"[?#]")


def _url_origin(url):
    """'host' (or 'host/owner/repo' on shared code hosts) of an http(s) URL."""
    m = _URL_PARTS_RE.match(url)
    if not m:
        return None
    host = m.group(1).rsplit("@", 1)[-1].lower()
    if host in _MULTI_TENANT_HOSTS:
        parts = [p for p in m.group(2).split("/") if p][:2]
        if len(parts) == 2:
            return "/".join([host] + parts)
    return host


def _url_basename(url):
    path = _URL_QUERY_RE.split(url, maxsplit=1)[0].rstrip("/")
    return path.rsplit("/", 1)[-1].strip("\"',")


def _is_checksum_file(name):
    low = name.lower()
    # Each pattern contains one of these literals.
    if "sha" not in low and "md5" not in low and "b2" not in low and "checksum" not in low:
        return False
    return any(rx.search(low) for rx in _CHECKSUM_FILE_RES)


def _pg021_logical_lines(clean):
    """Yield [(index, text)] pieces joined by trailing '\\' or '`' continuations.

    `clean` holds the lines already passed through _strip_yaml_comment
    (which is idempotent, so this matches stripping each raw line here).
    """
    pieces = []
    for i, s in enumerate(clean):
        if _PROSE_KEY_RE.match(s):
            s = ""
        if "${{" in s:
            s = _GH_EXPR_RE.sub(lambda m: "${{" + re.sub(r"\s+", "", m.group(1)) + "}}", s)
        stripped = s.rstrip()
        if stripped.endswith("\\") or stripped.endswith(" `"):
            pieces.append((i, stripped[:-1]))
            continue
        pieces.append((i, s))
        yield pieces
        pieces = []
    if pieces:
        yield pieces


def _is_upload(command, segment):
    if "-" not in segment:  # every upload pattern starts with a "-" option
        return False
    name = command.lower()
    if name == "curl":
        return bool(_CURL_UPLOAD_RE.search(segment))
    if name == "wget":
        return bool(_WGET_UPLOAD_RE.search(segment))
    if name == "aria2c":
        return False
    return bool(_PS_UPLOAD_RE.search(segment))


def _download_urls(pieces, dockerfile, assigned):
    """[(url, index)] for every URL fetched on one logical line."""
    if len(pieces) == 1:
        logical = pieces[0][1]
        offsets = None
    else:
        texts = [t for _, t in pieces]
        offsets = []
        pos = 0
        for t in texts:
            offsets.append(pos)
            pos += len(t) + 1
        logical = " ".join(texts)
    # Every _URL_TOKEN_RE alternative needs "://" or "$".
    if "://" not in logical and "$" not in logical:
        return []
    cmds = list(_DOWNLOAD_CMD_RE.finditer(logical))
    add = dockerfile and _DOCKER_ADD_RE.match(logical)
    if not cmds and not add:
        return []
    segments = []
    for k, m in enumerate(cmds):
        limit = cmds[k + 1].start() if k + 1 < len(cmds) else len(logical)
        end = _SEGMENT_END_RE.search(logical, m.end(), limit)
        seg_end = end.start() if end else limit
        segment = logical[m.end():seg_end]
        if not _is_upload(m.group(1), segment):
            segments.append((m.end(), seg_end))
    if add:
        segments.append((0, len(logical)))
    out = []
    for start, end in segments:
        for t in _URL_TOKEN_RE.finditer(logical, start, end):
            if t.group(1):
                url = t.group(1)
            else:
                var = t.group(2) or t.group(4)
                rest = t.group(3) if t.group(2) else t.group(5)
                if var not in assigned:
                    continue
                url = assigned[var] + (rest or "")
            if offsets is None:
                out.append((url, pieces[0][0]))
            else:
                piece = bisect.bisect_right(offsets, t.start()) - 1
                out.append((url, pieces[piece][0]))
    return out


def _pg021_artifact_index(artifacts, hosts):
    """{host: (names, trie)} for the artifact downloads on the given hosts.

    names keeps download order.  trie maps lowercase names split on "." to
    the position of the first artifact with that name: for a checksum name N,
    N.lower().startswith(A.lower() + ".") holds exactly when A's dot segments
    are a proper prefix of N's, so one walk over N finds every candidate.
    """
    index = {}
    for host, name, _ in artifacts:
        if host not in hosts:
            continue
        entry = index.get(host)
        if entry is None:
            entry = index[host] = ([], {})
        names, trie = entry
        node = trie
        for seg in name.lower().split("."):
            node = node.setdefault(seg, {})
        node.setdefault(None, len(names))
        names.append(name)
    return index


def _pg021_pick_artifact(entry, checksum_name):
    """First same-host artifact whose name + "." prefixes the checksum name
    (case-insensitively), else the first same-host artifact."""
    names, trie = entry
    segs = checksum_name.lower().split(".")
    best = None
    node = trie
    for seg in segs[:-1]:
        node = node.get(seg)
        if node is None:
            break
        pos = node.get(None)
        if pos is not None and (best is None or pos < best):
            best = pos
    return names[best if best is not None else 0]


def _analyze_same_origin_checksum(ctx):
    dockerfile = _is_dockerfile(ctx)
    if not (_is_yaml_like(ctx) or dockerfile):
        return {}
    text = ctx.get("text", "")
    low = text.lower()
    if not ("http://" in low or "https://" in low):
        return {}
    lines = _ctx_lines(ctx)
    # _strip_yaml_comment only changes lines that contain "#".
    clean = [_strip_yaml_comment(s) if "#" in s else s for s in lines]
    # One search over the lines joined by "|": no alternative can match
    # across it (it is neither \s nor in [^\n|;&], and \b sees it as a line
    # edge), so this equals searching line by line.
    if _SIGNATURE_VERIFY_RE.search("|".join(clean)):
        return {}
    assigned = {}
    for s in clean:
        if "://" not in s:  # both patterns need a literal http(s)://
            continue
        for m in _URL_ASSIGN_RE.finditer(s):
            assigned.setdefault(m.group(1), m.group(2))
        if dockerfile:
            m = _DOCKER_ENV_SPACE_RE.match(s)
            if m:
                assigned.setdefault(m.group(1), m.group(2))
    checksums = []
    artifacts = []
    for pieces in _pg021_logical_lines(clean):
        for url, idx in _download_urls(pieces, dockerfile, assigned):
            host = _url_origin(url)
            name = _url_basename(url)
            if host and name:
                if _is_checksum_file(name):
                    checksums.append((host, name, idx))
                elif not _SIGNATURE_FILE_RE.search(name):
                    artifacts.append((host, name, idx))
    if not checksums:
        return {}
    hits = {}
    by_host = _pg021_artifact_index(artifacts, set(c[0] for c in checksums))
    for host, name, idx in checksums:
        entry = by_host.get(host)
        if entry is None:
            continue
        artifact = _pg021_pick_artifact(entry, name)
        _add_hit(
            hits, lines, idx + 1,
            "Same-origin checksum: '%s' is downloaded from %s, the same origin as "
            "the artifact '%s'; whoever can replace the artifact can replace the "
            "checksum (pin the expected hash in the repo or verify a signature)"
            % (name, host, artifact),
        )
    return hits


_detect_unpinned_launch = _file_level("_pg008", _analyze_unpinned_launch)
_detect_metadata_poisoning = _file_level("_pg009", _analyze_metadata_poisoning)
_detect_untrusted_trigger = _file_level("_pg010", _analyze_untrusted_trigger)
_detect_expression_injection = _file_level("_pg011", _analyze_expression_injection)
_detect_permission_inheritance = _file_level("_pg013", _analyze_permission_inheritance)
_detect_broad_schema = _file_level("_pg014", _analyze_broad_schema)
_detect_same_origin_checksum = _file_level("_pg021", _analyze_same_origin_checksum)


# ---------------------------------------------------------------------------
# Shared helpers (PG012-PG020)
# ---------------------------------------------------------------------------
#
# Same conventions as PG008-PG011: one whole-file analyzer per rule, cached in
# ctx via _file_level, findings recorded with _add_hit.

_CONFIG_EXTS = _PG008_EXTS
_CONFIG_TXT_EXTS = _PG008_EXTS + (".txt",)
_NO_JSON = object()


def _cached_hits(ctx, key, analyzer):
    """Read another rule's _file_level cache, computing it if needed."""
    cache = ctx.get(key)
    if cache is None:
        try:
            cache = analyzer(ctx)
        except Exception:
            cache = {}
        ctx[key] = cache
    return cache


def _json_data(ctx):
    """Parsed JSON for .json/.mcp/<text> input (PG008's condition), else None."""
    data = ctx.get("_json", _NO_JSON)
    if data is _NO_JSON:
        data = None
        text = ctx.get("text", "").lstrip("﻿")
        if _file_ext(ctx) in (".json", ".mcp", "") and text.lstrip()[:1] in ("{", "["):
            try:
                data = json.loads(text)
            except ValueError:
                data = None
        ctx["_json"] = data
    return data


def _is_comment_line(line):
    return line.lstrip().startswith(("#", "//"))


def _code_text(line, ctx):
    """The line without a trailing ' # comment' (JSON lines are kept as is)."""
    if _file_ext(ctx) in (".json", ".mcp"):
        return line
    return _strip_yaml_comment(line)


def _skip_config_line(line):
    return _is_comment_line(line) or bool(_DESCRIPTIVE_LINE_RE.match(line))


def _host_of(value):
    """Host part of a URL or host[:port] value, lower-cased."""
    v = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", value.strip().strip("\"'"))
    v = re.split(r"[/?#]", v, maxsplit=1)[0].rsplit("@", 1)[-1]
    if v.startswith("["):
        return v[1:v.find("]")].lower() if "]" in v else v[1:].lower()
    return v.split(":", 1)[0].lower()


def _is_local_host(host):
    host = host.strip("[]").lower()
    return (
        host in ("localhost", "::1", "0.0.0.0")
        or host.endswith(".localhost")
        or bool(re.match(r"^127(?:\.\d{1,3}){3}$", host))
    )


def _first_value(lines, i, pos):
    """(value, lineno) of the option value after lines[i][pos:].

    Falls back to the first token of the next non-blank line (JSON arrays,
    YAML block lists, backslash continuations). Returns ("", None) if the
    next thing is another option or nothing.
    """
    m = _OPTION_VALUE_RE.match(lines[i], pos)
    if m and m.group(1):
        value, lineno = m.group(1), i + 1
    else:
        value, lineno = "", None
        for j in range(i + 1, min(i + 4, len(lines))):
            toks = _heuristic_tokens(lines[j][:2000])
            if toks and toks[0] == "-":
                toks = toks[1:]
            if toks:
                value, lineno = toks[0], j + 1
                break
    if not value or value.startswith("-") or value == "\\":
        return "", None
    return value, lineno


_OPTION_VALUE_RE = re.compile(r"""["']?\s*[=:,]?\s*[\[(]?\s*["']?([^\s"',\[\]{}()]*)""")


def _command_argvs(ctx):
    """[(argv, argv_lines)] for every command/args pair, merged like PG008.

    JSON files reuse _json_commands/_command_argv and locate each token with
    _find_line; other files reuse PG008's inline-launch and command-key +
    args heuristics (any command name, not only launchers).
    """
    cached = ctx.get("_argvs")
    if cached is None:
        try:
            cached = _analyze_command_argvs(ctx)
        except Exception:
            cached = []
        ctx["_argvs"] = cached
    return cached


def _analyze_command_argvs(ctx):
    lines = _ctx_lines(ctx)
    out = []
    data = _json_data(ctx)
    if data is not None:
        argvs = []
        _json_commands(data, argvs)
        cmd_lines = [i for i, l in enumerate(lines, 1) if _JSON_CMD_KEY_RE.search(l)]
        for k, argv in enumerate(argvs):
            base = cmd_lines[k] if k < len(cmd_lines) else 1
            cur = base - 1
            where = []
            for tok in argv:
                ln = _find_line(lines, tok, cur)
                if ln is None:
                    ln = base
                else:
                    cur = ln - 1
                where.append(ln)
            out.append((argv, where))
        return out
    for i, line in enumerate(lines):
        lineno = i + 1
        if not _DESCRIPTIVE_LINE_RE.match(line):
            start = _inline_launch_start(line)
            if start is not None:
                tokens = _heuristic_tokens(line[start:])
                out.append((tokens, [lineno] * len(tokens)))
        m = _CMD_ONLY_RE.search(line)
        if not m:
            continue
        value = next(g for g in m.groups() if g is not None)
        found = _find_args(lines, i, m.end())
        if not found:
            continue
        argv = [(tok, lineno) for tok in _split_arg(value)]
        for item, item_line in _collect_args(lines, found[0], found[1]):
            argv.extend((tok, item_line) for tok in _split_arg(item))
        out.append(([t for t, _ in argv], [l for _, l in argv]))
    return out


def _cli_options(argv, start, value_flags):
    """_parse_cli's walk, yielding (flag, value, flag_index, value_index)."""
    i = start
    while i < len(argv):
        tok = argv[i]
        if tok in _SHELL_SEPARATORS or tok == "--":
            return
        if tok.startswith("-") and len(tok) > 1:
            name, eq, value = tok.partition("=")
            if eq:
                yield name, value, i, i
            elif name in value_flags and i + 1 < len(argv):
                yield name, argv[i + 1], i, i + 1
                i += 1
            else:
                yield name, None, i, None
            i += 1
            continue
        return


def _logical_lines(lines, skip, want):
    """Yield [(token, lineno)] per command line, joining trailing-backslash lines.

    Only command lines with a physical line matching `want` are tokenized.
    """
    group = []
    for i, raw in enumerate(lines):
        if skip(raw):
            if group:
                yield _group_tokens(group, want)
                group = []
            continue
        s = raw.rstrip()
        cont = s.endswith("\\")
        group.append((s[:-1] if cont else s, i + 1))
        if not cont:
            yield _group_tokens(group, want)
            group = []
    if group:
        yield _group_tokens(group, want)


def _group_tokens(group, want):
    if not any(want.search(s) for s, _ in group):
        return []
    return [(tok, ln) for s, ln in group for tok in _heuristic_tokens(s)]


def _is_separator_token(tok):
    return tok in _SHELL_SEPARATORS or tok[:1] in ("|", ";", "&")


def _cmd_name(tok):
    """_launcher_name for a command token; "" for URLs."""
    return "" if "://" in tok else _launcher_name(tok)


# ---------------------------------------------------------------------------
# PG012: blanket / standing tool approval
# ---------------------------------------------------------------------------

_APPROVAL_LIST_KEY_RE = re.compile(
    r"""(?:^|[\s{,])["']?(allow|allowedTools|allowed_tools|alwaysAllow|always_allow|"""
    r"""autoApprove|auto_approve)["']?\s*[:=]\s*""",
    re.IGNORECASE,
)
_ALLOWED_TOOLS_FLAG_RE = re.compile(r"(?<![\w-])(--allowed[-_]?tools)(?![\w-])", re.IGNORECASE)
_TOKEN_RE = re.compile(r"""[^\s"'`,\[\]{}]+""")  # same split as _heuristic_tokens
_TOOL_STAR_RE = re.compile(r"^([A-Za-z_][\w.-]*)\(\s*\*{1,2}\s*\)$")
_READ_ONLY_TOOLS = ("read", "glob", "grep", "ls", "websearch")
_BYPASS_RES = (
    (
        re.compile(
            r"""(?:mode["']?\s*[:=]\s*["']?|--permission-mode["']?[\s,=]+["']?)"""
            r"""bypass[_-]?permissions(?![\w-])""",
            re.IGNORECASE,
        ),
        "permission mode 'bypassPermissions' skips every confirmation prompt",
    ),
    (
        re.compile(
            r"""(?:approval[_-]?mode["']?\s*[:=]\s*["']?|--approval-mode["']?[\s,=]+["']?)"""
            r"""yolo(?![\w-])""",
            re.IGNORECASE,
        ),
        "approval mode 'yolo' skips every confirmation prompt",
    ),
    (
        re.compile(r"(?<![\w-])--dangerously-bypass-approvals-and-sandbox(?![\w-])", re.IGNORECASE),
        "'--dangerously-bypass-approvals-and-sandbox' skips every confirmation "
        "prompt and the sandbox",
    ),
    (
        re.compile(
            r"""(?:^|[\s{,])["']?enableAllProjectMcpServers["']?\s*[:=]\s*["']?true\b""",
            re.IGNORECASE,
        ),
        "'enableAllProjectMcpServers: true' auto-approves every MCP server a "
        "project .mcp.json declares",
    ),
)
_TRUST_TRUE_RE = re.compile(r"""(?:^|[\s{,])["']?trust["']?\s*[:=]\s*["']?true\b""", re.IGNORECASE)


def _wildcard_scope(item):
    """(clean_item, scope) when an allow-list entry approves a whole tool, else None."""
    s = item.strip().strip("\"'`").strip()
    if s in ("*", "**"):
        return s, "every tool"
    m = _TOOL_STAR_RE.match(s)
    if m:
        if m.group(1).lower() in _READ_ONLY_TOOLS:
            return None
        return s, "every %s call" % m.group(1)
    if s in ("Bash", "PowerShell"):
        return s, "every %s call" % s
    if s.lower().startswith("mcp__") and s.endswith("*"):
        return s, "every matching MCP tool"
    return None


def _approval_message(item, where, scope):
    return "Blanket approval: '%s' in '%s' allows %s without confirmation" % (
        item, where, scope,
    )


_TOML_HEADER_RE = re.compile(r"""^\s*\[\[?\s*([^\[\]#]+?)\s*\]\]?\s*(?:#.*)?$""")
_BRACE_TOKEN_RE = re.compile(r"""[\\"{}]""")
# JSON / JSONC / JSON5 lexing for _json_permission_allows(): strings, comments,
# bare (JSON5) keys and the structural characters.
_JSONC_STEP_RE = re.compile(r"""["']|//|/\*|[{}\[\]:]|[A-Za-z_$][\w$-]*""")
_DQ_BODY_RE = re.compile(r'''(?:[^"\\\n\r]|\\.)*''')
_SQ_BODY_RE = re.compile(r"""(?:[^'\\\n\r]|\\.)*""")
_EOL_RE = re.compile(r"[\n\r]")
# The line breaks str.splitlines() uses: _ctx_lines() numbering.
_SPLITLINES_BREAK_RE = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")
_LEAD_JSONC_NOISE_RE = re.compile(r"""(?:\s+|//[^\n\r]*|#[^\n\r]*|/\*.*?(?:\*/|\Z))*""", re.DOTALL)


def _json_permission_allows(text):
    """{(line_index, column)} of each "allow" key nested inside a "permissions" value.

    Walks the object nesting of the whole text (so a string holding U+2028 or
    a form feed, which str.splitlines() breaks, stays one string), skipping
    // and /* */ comments; '...' strings and bare keys are read as JSON5 does.
    For JSON that parsed this is the parse tree's nesting. Line/column follow
    str.splitlines(), like _ctx_lines().
    """
    keys = []
    stack = []  # (opening char, inside a "permissions" value?)
    last_key = None
    pending = None
    n = len(text)
    pos = 0
    while True:
        t = _JSONC_STEP_RE.search(text, pos)
        if not t:
            break
        tok = t.group(0)
        pos = t.end()
        if tok in ("\"", "'"):
            body = (_DQ_BODY_RE if tok == '"' else _SQ_BODY_RE).match(text, pos)
            end = body.end()
            if end < n and text[end] == tok:
                pending = (text[pos:end], pos)
                pos = end + 1
            else:
                pending = None  # unterminated: stop at the line break
                pos = end
            continue
        if tok == "//":
            e = _EOL_RE.search(text, pos)
            pos = e.start() if e else n
            continue
        if tok == "/*":
            e = text.find("*/", pos)
            pos = e + 2 if e >= 0 else n
            continue
        if tok[0] not in "{}[]:":
            pending = (tok, t.start())  # bare word: a JSON5 key, or a value
            continue
        # In JSON a key only comes right after '{' or ',' inside an object, so
        # not checking the container type below changes nothing for JSON; it
        # keeps broken text (a stray ']' or '}', an unclosed array) readable.
        if tok == ":":
            if pending is not None:
                last_key = pending[0]
                if last_key.lower() == "allow" and stack and stack[-1][1]:
                    keys.append(pending[1])
        elif tok in "{[":
            under = (bool(stack) and stack[-1][1]) or (last_key or "").lower() == "permissions"
            stack.append((tok, under))
            last_key = None
        elif stack:
            stack.pop()
            last_key = None
        pending = None
    if not keys:
        return set()
    starts = [0] + [b.end() for b in _SPLITLINES_BREAK_RE.finditer(text)]
    out = set()
    for off in keys:
        i = bisect.bisect_right(starts, off) - 1
        out.add((i, off - starts[i]))
    return out


def _looks_like_json(text):
    """Does the text (after a BOM, blanks and comments) open a JSON object/array?

    A first line like '[permissions]' is a TOML table header, not an array.
    """
    s = text.lstrip("\ufeff")
    p = _LEAD_JSONC_NOISE_RE.match(s).end()
    if s[p:p + 1] == "{":
        return True
    if s[p:p + 1] != "[":
        return False
    e = _EOL_RE.search(s, p)
    return not _TOML_HEADER_RE.match(s[p:e.start() if e else len(s)])


def _yaml_under_permissions(lines):
    """Per line: is a less-indented line above it (an ancestor) a `permissions:` key?"""
    under = [False] * len(lines)
    stack = []  # (indent, is a permissions key)
    count = 0
    for j, line in enumerate(lines):
        t = line.strip()
        if not t or t.startswith(("#", "//")):
            continue
        d = _indent(line)
        while stack and stack[-1][0] >= d:
            count -= stack.pop()[1]
        under[j] = count > 0
        m = _YAML_KEY_RE.match(line)
        is_perm = bool(m) and m.group(3).lower() == "permissions"
        stack.append((d, is_perm))
        count += is_perm
    return under


def _toml_under_permissions(lines):
    """Per line: is it inside a TOML table whose dotted name has a `permissions` part?"""
    under = []
    cur = False
    for line in lines:
        m = _TOML_HEADER_RE.match(line)
        if m:
            cur = any(
                part.strip().strip("\"'").lower() == "permissions"
                for part in m.group(1).split(".")
            )
        under.append(cur)
    return under


def _brace_key(line, b):
    """Lower-cased key written just before the '{' at line[b] ('a' in 'a: {', '"a" = {')."""
    k = b
    while k > 0 and line[k - 1] in " \t":
        k -= 1
    if k == 0 or line[k - 1] not in ":=":
        return ""
    k -= 1
    while k > 0 and line[k - 1] in " \t":
        k -= 1
    if k > 0 and line[k - 1] in "\"'":
        k -= 1
    end = k
    while k > 0 and (line[k - 1].isalnum() or line[k - 1] in "_-"):
        k -= 1
    return line[k:end].lower()


class _AllowScope(object):
    """Decides whether an `allow` list key sits under a `permissions` key.

    JSON, and .json/.mcp/<text> input that does not parse but still opens
    with '{' or '[' (JSONC comments, trailing commas, JSON5): by the object
    nesting. Anything else: an enclosing `permissions: {` / `permissions = {`
    earlier on the same line, or a `permissions:` ancestor by indentation
    (YAML), or a `[...permissions...]` table header (TOML), whatever the
    extension says (TOML text in a .yml file still counts).
    """

    def __init__(self, ctx, lines):
        self.lines = lines
        text = ctx.get("text", "")
        if _json_data(ctx) is not None or (
            _file_ext(ctx) in (".json", ".mcp", "") and _looks_like_json(text)
        ):
            self.json = _json_permission_allows(text)
        else:
            self.json = None
        self.yaml = None
        self.toml = None
        self.row = None

    def ok(self, i, line, m):
        col = m.start(1)
        if self.json is not None:
            return (i, col) in self.json
        if self.row is None or self.row[0] != i:
            self.row = [i, 0, [], False]  # line, scan position, '{' stack, inside "..."
        row = self.row
        k, stack, quoted = row[1], row[2], row[3]
        while True:
            t = _BRACE_TOKEN_RE.search(line, k, col)
            if not t:
                break
            c = t.group(0)
            k = t.end()
            if quoted:
                if c == "\\":
                    k += 1  # escaped character inside a "..." string
                elif c == '"':
                    quoted = False
            elif c == '"':
                quoted = True
            elif c == "{":
                # each entry: is this brace, or one around it, a permissions value?
                stack.append(
                    (bool(stack) and stack[-1]) or _brace_key(line, t.start()) == "permissions"
                )
            elif c == "}" and stack:
                stack.pop()
        row[1], row[3] = max(k, col), quoted
        if stack and stack[-1]:
            return True
        if self.yaml is None:
            self.yaml = _yaml_under_permissions(self.lines)
        if self.yaml[i]:
            return True
        if self.toml is None:
            self.toml = _toml_under_permissions(self.lines)
        return self.toml[i]


class _ListCollector(object):
    """_collect_args(lines, j, pos) for many keys on one line, without redoing shared work.

    new_items(j, pos, key) yields the items _collect_args(lines, j, pos)
    would return, in order, except ones it already yielded for the same key
    text from the same starting state (their findings are already recorded):
    a long line of 'allow: [' keys with no closing ']' would otherwise read
    the rest of the line (and up to 51 more lines) once per key.
    """

    def __init__(self, lines):
        self.lines = lines
        self.close_memo = {}  # line -> {(position, quote): index of the closing ']' or -1}
        self.walked = {}      # (line, end of part, key) -> item search positions done
        self.scanners = {}    # (line, end of part) -> _ItemScanner
        self.below_done = set()  # (line, key, kind) whose following-line part was yielded

    def _close(self, j, s):
        """s + _find_unquoted(lines[j][s:], ']'), or -1."""
        memo = self.close_memo.setdefault(j, {})
        line = self.lines[j]
        n = len(line)
        k, quote = s, None
        trail = []
        res = -1
        while k < n:
            state = (k, quote)
            if state in memo:
                res = memo[state]
                break
            trail.append(state)
            c = line[k]
            if quote:
                if c == "\\":
                    k += 2
                    continue
                if c == quote:
                    quote = None
            elif c in "\"'":
                quote = c
            elif c == "]":
                res = k
                break
            k += 1
        for state in trail:
            memo[state] = res
        return res

    def new_items(self, j, pos, key):
        lines = self.lines
        line = lines[j]
        q = _SPACES_RE.match(line, pos).end()
        if q < len(line) and line[q] == "[":
            s = q + 1
            close = self._close(j, s)
            end = close if close >= 0 else len(line)
            done = self.walked.setdefault((j, end, key), set())
            scanner = self.scanners.get((j, end))
            if scanner is None:
                scanner = self.scanners[(j, end)] = _ItemScanner(line, end)
            e = s
            while e not in done:
                done.add(e)
                found = scanner.search(e)
                if found is None:
                    break
                yield found[1], j + 1
                e = found[0]
            if close >= 0 or (j, key, "[") in self.below_done:
                return
            self.below_done.add((j, key, "["))
            k = j
            while k + 1 < len(lines) and k - j <= 50:
                k += 1
                seg = lines[k]
                c = _find_unquoted(seg, "]")
                for item in _list_items(seg if c < 0 else seg[:c]):
                    yield item, k + 1
                if c >= 0:
                    break
        elif q == len(line) or line[q] == "#":
            if (j, key, "-") in self.below_done:
                return
            self.below_done.add((j, key, "-"))
            for item in _collect_args(lines, j, len(line)):
                yield item
        else:
            stripped = line[pos:].strip()
            for tok in _heuristic_tokens(_strip_yaml_comment(stripped)):
                yield tok, j + 1


def _analyze_blanket_approval(ctx):
    if _file_ext(ctx) not in _CONFIG_EXTS:
        return {}
    lines = _ctx_lines(ctx)
    low = ctx.get("full_lower", "")
    allow_scope = _AllowScope(ctx, lines) if "permissions" in low else None
    mcp_ok = "mcp" in low
    collector = _ListCollector(lines)
    hits = {}
    for i, raw in enumerate(lines):
        if _skip_config_line(raw):
            continue
        line = _code_text(raw, ctx)
        lineno = i + 1
        for rx, what in _BYPASS_RES:
            if rx.search(line):
                _add_hit(hits, lines, lineno, "Blanket approval: " + what)
        if mcp_ok and _TRUST_TRUE_RE.search(line):
            _add_hit(
                hits,
                lines,
                lineno,
                "Blanket approval: MCP server 'trust: true' skips confirmation "
                "for all of its tools",
            )
        for m in _APPROVAL_LIST_KEY_RE.finditer(line):
            key = m.group(1)
            if key.lower() == "allow" and not (allow_scope and allow_scope.ok(i, line, m)):
                continue
            # The key pattern ends in \s*, so m.end() is where line[m.end():].strip() starts.
            e = m.end()
            if e == len(line) or line[e] in "[#":
                items = collector.new_items(i, e, key)
            else:
                # Scalar value: only the value itself, never the rest of the line.
                items = [(t, lineno) for t in _heuristic_tokens(line[e:e + 200])[:1]]
            for item, item_line in items:
                found = _wildcard_scope(item)
                if found:
                    _add_hit(hits, lines, item_line, _approval_message(found[0], key, found[1]))
        flags = _FlagValues(line)
        for m in _ALLOWED_TOOLS_FLAG_RE.finditer(line):
            flag = m.group(1)
            scopes = flags.new_scopes(m.end(), flag)
            if scopes is None:  # nothing after the flag on this line
                value, vline = _first_value(lines, i, len(lines[i]))
                scopes = [(_wildcard_scope(value), vline)] if value else []
            else:
                scopes = [(found, lineno) for found in scopes]
            for found, vline in scopes:
                if found:
                    _add_hit(hits, lines, vline, _approval_message(found[0], flag, found[1]))
    return hits


class _FlagValues(object):
    """The --allowedTools value loop of one line, without rescanning the rest of the line per flag.

    For a flag ending at `end`, the original reads rest = line[end:] (one '='
    dropped) and takes its _TOKEN_RE tokens up to the first one starting with
    '-'. Those are the line's own tokens after the one holding `end`, plus
    the tail of that one; consecutive flags share the same run of tokens.
    """

    def __init__(self, line):
        self.line = line
        self.spans = None
        self.done = {}  # flag spelling -> token index its values were read up to

    def new_scopes(self, end, flag):
        """_wildcard_scope() of each value not yet read for this flag spelling, in
        order; None when rest has no token at all."""
        line = self.line
        if self.spans is None:
            self.spans = [(t.start(), t.end()) for t in _TOKEN_RE.finditer(line)]
            self.ends = [e for _, e in self.spans]
        a = end + 1 if line.startswith("=", end) else end
        k = bisect.bisect_right(self.ends, a)
        if k == len(self.spans):
            return None
        start, stop = self.spans[k]
        if line[max(start, a)] == "-":
            return []
        if start >= a:
            out = [_wildcard_scope(line[start:stop])]
        else:
            out = [_wildcard_scope_span(line, a, stop)]
        j = max(k + 1, self.done.get(flag, 0))
        while j < len(self.spans) and line[self.spans[j][0]] != "-":
            out.append(_wildcard_scope(line[self.spans[j][0]:self.spans[j][1]]))
            j += 1
        if j > k + 1:
            self.done[flag] = j
        return out


_TOOL_STAR_SPAN_RE = re.compile(r"([A-Za-z_][\w.-]*)\(\s*\*{1,2}\s*\)$")


def _wildcard_scope_span(line, a, b):
    """_wildcard_scope(line[a:b]) for a _TOKEN_RE token tail, copying it only on a hit.

    A token has no whitespace, quotes or backticks, so the strip()s in
    _wildcard_scope are no-ops and its tests reduce to the checks below.
    """
    n = b - a
    if n <= 10:
        return _wildcard_scope(line[a:b])
    last = line[b - 1]
    if last == ")":
        m = _TOOL_STAR_SPAN_RE.match(line, a, b)
        if m:
            if m.group(1).lower() in _READ_ONLY_TOOLS:
                return None
            return line[a:b], "every %s call" % m.group(1)
        return None
    if last == "*" and line[a:a + 5].lower() == "mcp__":
        return line[a:b], "every matching MCP tool"
    return None


# ---------------------------------------------------------------------------
# PG015: over-broad workflow token permissions
# ---------------------------------------------------------------------------

_PERMISSIONS_KEY_RE = re.compile(r"""^(\s*)(-\s+)?["']?permissions["']?\s*:(.*)$""")
_SCOPE_KV_RE = re.compile(r"""["']?([\w-]+)["']?\s*:\s*["']?([\w-]+)["']?""")


def _analyze_ci_permissions(ctx):
    if not _is_github_workflow(ctx):
        return {}
    lines = _ctx_lines(ctx)
    triggers = []
    for event in _workflow_triggers(lines):
        if event in _UNTRUSTED_TRIGGERS and event not in triggers:
            triggers.append(event)
    hits = {}
    for i, line in enumerate(lines):
        m = _PERMISSIONS_KEY_RE.match(line)
        if not m:
            continue
        lineno = i + 1
        rest = _strip_yaml_comment(m.group(3)).strip()
        if _unquote(rest).lower() == "write-all":
            _add_hit(
                hits,
                lines,
                lineno,
                "Workflow token granted 'permissions: write-all' (every scope "
                "writable; grant only the scopes each job needs)",
            )
            continue
        if not triggers:
            continue
        scopes = {}
        if rest.startswith("{"):
            body, j = rest, i
            while "}" not in body and j + 1 < len(lines) and j - i < 20:
                j += 1
                body += " " + _strip_yaml_comment(lines[j]).strip()
            for k, v in _SCOPE_KV_RE.findall(body.split("}", 1)[0].lstrip("{")):
                scopes[k.lower()] = v.lower()
        elif not rest:
            key_col = len(m.group(1)) + len(m.group(2) or "")
            for j in range(i + 1, _block_end(lines, i, key_col)):
                mm = _SCOPE_KV_RE.match(_strip_yaml_comment(lines[j]).strip())
                if mm:
                    scopes[mm.group(1).lower()] = mm.group(2).lower()
        if scopes.get("contents") == "write" and scopes.get("id-token") == "write":
            _add_hit(
                hits,
                lines,
                lineno,
                "Untrusted trigger (%s) gets 'contents: write' and 'id-token: write' "
                "in one permissions block (repo push plus OIDC cloud credentials)"
                % ", ".join(triggers),
            )
    return hits


# ---------------------------------------------------------------------------
# PG016: output exfiltration channel (markdown image / link URL)
# ---------------------------------------------------------------------------

_TEMPLATE_VAR_RE = re.compile(
    r"\{\{[^{}\n]{0,200}\}\}|\$\{[^{}\n]{0,200}\}|\{[A-Za-z_][\w.]{0,100}\}"
)
_URL_BODY = (
    r"""https?://(?:\{\{[^{}\n]{0,200}\}\}|\$\{[^{}\n]{0,200}\}|[^\s()"'<>\\])+"""
)
_MD_TARGET_RE = re.compile(r"\]\(\s*<?(" + _URL_BODY + ")", re.IGNORECASE)
_MD_REFDEF_RE = re.compile(
    r"^\s{0,3}\[[^\]\n]{1,300}\]:\s*<?(" + _URL_BODY + ")", re.IGNORECASE
)
_HTML_IMG_RE = re.compile(
    r"""<img\b[^>]{0,300}?\bsrc\s*=\s*\\?["']?(""" + _URL_BODY + ")", re.IGNORECASE
)


def _exfil_values(url, kind):
    """(host, [placeholders in the query string]) for an exfiltrating URL, else None.

    Single-brace {name} placeholders count for images only: in links they are
    usually API documentation (?filter={filter}), not prompt templates.
    """
    found = list(_TEMPLATE_VAR_RE.finditer(url))
    if not found:
        return None
    masked = list(url)
    for m in found:
        masked[m.start():m.end()] = "X" * (m.end() - m.start())
    masked = "".join(masked)
    start = masked.index("://") + 3
    end = len(masked)
    for ch in "/?#":
        k = masked.find(ch, start)
        if k >= 0:
            end = min(end, k)
    if any(m.start() < end for m in found):
        return None  # host itself is templated (relative/site URL)
    host = _host_of(url)
    if not host or _is_local_host(host):
        return None
    q = masked.find("?", end)
    if q < 0:
        return None
    frag = masked.find("#", q)
    stop = frag if frag >= 0 else len(masked)
    values = [
        m.group(0)
        for m in found
        if q < m.start() < stop and (kind == "image" or m.group(0)[:2] in ("{{", "${"))
    ]
    if not values:
        return None
    return host, values


def _analyze_exfil_channel(ctx):
    if _is_github_workflow(ctx) or _is_github_action(ctx):
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    for i, line in enumerate(lines):
        if "http" not in line.lower():
            continue
        targets = []
        for m in _MD_TARGET_RE.finditer(line):
            j = line.rfind("[", max(0, m.start() - 300), m.start())
            if j < 0:
                continue
            kind = "image" if j > 0 and line[j - 1] == "!" else "link"
            targets.append((kind, m.group(1)))
        m = _MD_REFDEF_RE.match(line)
        if m:
            targets.append(("link", m.group(1)))
        for m in _HTML_IMG_RE.finditer(line):
            targets.append(("image", m.group(1)))
        for kind, url in targets:
            found = _exfil_values(url, kind)
            if not found:
                continue
            host, values = found
            when = (
                "fetched automatically when rendered" if kind == "image" else "sent when clicked"
            )
            _add_hit(
                hits,
                lines,
                i + 1,
                "Output exfiltration channel: %s URL to '%s' carries template value %s "
                "in its query (%s)"
                % (kind, host, ", ".join("'%s'" % _short(v, 40) for v in values), when),
            )
    return hits


# ---------------------------------------------------------------------------
# PG017: unbounded agent loop / budget
# ---------------------------------------------------------------------------

_LOOP_LIMIT_KEYS = (
    "maxiterations",
    "maxturns",
    "maxround",
    "maxrounds",
    "recursionlimit",
    "maxconsecutiveautoreply",
    "maxtoolcalls",
    "maxbudget",
    "maxbudgetusd",
    "maxcost",
    "maxcostusd",
)
_LOOP_HINT_RE = re.compile(
    r"iteration|turn|round|recursion|auto_?reply|tool_?calls|budget|cost", re.IGNORECASE
)
_LOOP_KV_RE = re.compile(
    r"""(?:^|[\s{,\[(])["']?([A-Za-z_][\w.-]{0,80})["']?\s*[:=]\s*"""
    r"""("[^"\n]{0,40}"|'[^'\n]{0,40}'|[^\s,;}\])#"']{1,40})"""
)
_UNBOUNDED_WORDS = ("unlimited", "infinite", "infinity", "inf", "+inf", ".inf", "+.inf")
_NUMBER_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")


def _is_loop_key(key):
    norm = re.sub(r"[^a-z0-9]", "", key.rsplit(".", 1)[-1].lower())
    return any(norm.endswith(k) for k in _LOOP_LIMIT_KEYS)


def _unbounded_value(value):
    v = value.strip().strip("\"'").strip().lower()
    if v in _UNBOUNDED_WORDS:
        return True
    if _NUMBER_RE.match(v):
        return float(v) <= 0
    return False


def _unbounded_loop(key, value):
    """Is `key: value` an unbounded or non-positive loop/budget limit?

    AutoGen's max_consecutive_auto_reply=0 means "never auto-reply" (a stop,
    not a missing limit), so only that key's 0 is accepted; inf/-1 still count.
    """
    if not (_is_loop_key(key) and _unbounded_value(value)):
        return False
    norm = re.sub(r"[^a-z0-9]", "", key.rsplit(".", 1)[-1].lower())
    if norm.endswith("maxconsecutiveautoreply"):
        v = value.strip().strip("\"'").strip()
        return not (_NUMBER_RE.match(v) and float(v) == 0)
    return True


def _loop_message(key, value):
    return (
        "Agent loop/budget limit '%s' set to %s (unbounded or non-positive; "
        "set a finite positive cap)" % (key, value.strip())
    )


def _analyze_unbounded_loop(ctx):
    if _file_ext(ctx) not in _CONFIG_EXTS:
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    for i, raw in enumerate(lines):
        if not _LOOP_HINT_RE.search(raw) or _skip_config_line(raw):
            continue
        line = _code_text(raw, ctx)
        for m in _LOOP_KV_RE.finditer(line):
            key, value = m.group(1), m.group(2)
            if _unbounded_loop(key, value):
                _add_hit(hits, lines, i + 1, _loop_message(key, value))
        toks = _heuristic_tokens(line)
        for k, tok in enumerate(toks):
            if not tok.startswith("--"):
                continue
            name, eq, value = tok[2:].partition("=")
            if not eq:
                value = toks[k + 1] if k + 1 < len(toks) else ""
            if value and _unbounded_loop(name, value):
                _add_hit(hits, lines, i + 1, _loop_message("--" + name, value))
    return hits


# ---------------------------------------------------------------------------
# PG018: privileged MCP container / admin-scoped credential in args
# ---------------------------------------------------------------------------

_ADMIN_SCOPE_RE = re.compile(r"(?:^|_)(?:admin|root|superuser|service_?role|master|global)(?:_|$)")
_CRED_WORD_RE = re.compile(
    r"(?:^|_)(?:token|key|secret|password|passwd|pat|credentials?|apikey)(?:_|$)"
)
_SOCKET_SUFFIXES = ("docker.sock", "podman.sock")
# "_id" as its own word, or glued to the credential word ("tokenid"); not "android", "valid".
_CRED_ID_RE = re.compile(r"(?:^|_|token|key|secret)id$")


def _admin_cred_name(name):
    norm = name.lstrip("-").lower().replace("-", "_")
    if re.search(r"(?:^|_)(?:file|path|dir|env|var)$", norm):
        return False  # names a file / env var holding the credential, not the value
    if _CRED_ID_RE.search(norm):
        return False  # an identifier (--aws-kms-master-key-id, ROOT_KEY_ID, --root-tokenid), not a secret
    return bool(_ADMIN_SCOPE_RE.search(norm) and _CRED_WORD_RE.search(norm))


def _mount_source(flag, value):
    if flag == "--mount":
        for part in value.split(","):
            k, _, v = part.partition("=")
            if k.strip().lower() in ("source", "src"):
                return v.strip()
        return ""
    return value.split(":", 1)[0].strip()


def _pg006_root_on(ctx, lines, lineno):
    """True when PG006 already reports a filesystem root on this line."""
    if not 0 < lineno <= len(lines):
        return False
    # Once per line: a long line with many '-v /:/' would otherwise be rescanned per mount.
    cache = ctx.setdefault("_pg006_root", {})
    found = cache.get(lineno)
    if found is None:
        found = any(
            msg.startswith("Over-broad filesystem root")
            for msg, _ in (_detect_broad_mcp(lines[lineno - 1], ctx) or ())
        )
        cache[lineno] = found
    return found


def _docker_privilege_hits(argv, where, start, ctx, lines, hits):
    for name, value, fidx, vidx in _cli_options(argv, start, _DOCKER_VALUE_FLAGS):
        fline = where[fidx]
        vline = where[vidx] if vidx is not None else fline
        low = (value or "").strip().lower()
        if name == "--privileged" and low in ("", "true", "1"):
            _add_hit(
                hits, lines, fline,
                "Privileged MCP container: '--privileged' (full access to host "
                "devices and kernel)",
            )
        elif name in ("-v", "--volume", "--mount") and value:
            src = _mount_source(name, value)
            if src in ("/", "//", "/."):
                if not _pg006_root_on(ctx, lines, vline):
                    _add_hit(
                        hits, lines, vline,
                        "Privileged MCP container: host root mounted ('%s %s')"
                        % (name, value),
                    )
            elif src.lower().endswith(_SOCKET_SUFFIXES):
                _add_hit(
                    hits, lines, vline,
                    "Privileged MCP container: container engine socket mounted "
                    "('%s %s' gives root on the host)" % (name, value),
                )
        elif name in ("--network", "--net") and low == "host":
            _add_hit(
                hits, lines, fline,
                "Privileged MCP container: host network namespace ('%s host')" % name,
            )
        elif name == "--pid" and low == "host":
            _add_hit(
                hits, lines, fline,
                "Privileged MCP container: host PID namespace ('--pid host')",
            )
        elif name == "--cap-add" and value:
            for cap in value.split(","):
                c = cap.strip().upper()
                c = c[4:] if c.startswith("CAP_") else c
                if c in ("ALL", "SYS_ADMIN"):
                    _add_hit(
                        hits, lines, vline,
                        "Privileged MCP container: capability '%s' added (--cap-add)" % c,
                    )


# CI pipeline definitions: their docker commands are build steps, not MCP servers.
_CI_CONFIG_NAMES = (
    ".gitlab-ci.yml", ".gitlab-ci.yaml", "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml",
    "azure-pipelines.yml", "azure-pipelines.yaml", ".drone.yml", ".drone.yaml",
    ".travis.yml", ".travis.yaml",
)


def _is_ci_config(ctx):
    path = (ctx.get("path") or "").replace("\\", "/").lower()
    parts = path.split("/")
    name = parts[-1]
    if name in _CI_CONFIG_NAMES:
        return True
    if name in ("config.yml", "config.yaml") and len(parts) > 1 and parts[-2] == ".circleci":
        return True
    return name == "jenkinsfile" or name.startswith("jenkinsfile.") or name.endswith(".jenkinsfile")


def _analyze_container_privilege(ctx):
    if _file_ext(ctx) not in _CONFIG_EXTS:
        return {}
    if _is_github_workflow(ctx) or _is_github_action(ctx) or _is_ci_config(ctx):
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    for argv, where in _command_argvs(ctx):
        for i, tok in enumerate(argv):
            nxt = argv[i + 1].lower() if i + 1 < len(argv) else ""
            if _launcher_name(tok) == "docker" and nxt == "run":
                _docker_privilege_hits(argv, where, i + 2, ctx, lines, hits)
            if tok.startswith("-"):
                name, eq, value = tok.partition("=")
                if not eq and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                    value = argv[i + 1]
                if value and _admin_cred_name(name):
                    _add_hit(
                        hits, lines, where[i],
                        "Admin-scoped credential in MCP server args: '%s' (use a "
                        "least-privilege token)" % name,
                    )
            elif "=" in tok and not tok.startswith(("http:", "https:")):
                name, _, value = tok.partition("=")
                if value and re.match(r"^[A-Za-z_][\w-]*$", name) and _admin_cred_name(name):
                    _add_hit(
                        hits, lines, where[i],
                        "Admin-scoped credential in MCP server args: '%s' (use a "
                        "least-privilege token)" % name,
                    )
    return hits


# ---------------------------------------------------------------------------
# PG019: verification disabled
# ---------------------------------------------------------------------------

_VERIFY_OFF_RES = (
    (
        re.compile(r"(?<![\w-])--insecure(?![\w-])(?!=\s*(?:false|0)\b)"),
        "'--insecure' skips TLS certificate checks",
    ),
    (
        re.compile(
            r"""(?<![\w-])--insecure-skip-tls-verify(?:=(?:true|1))?(?![\w=-])|"""
            r"""(?:^|[\s{,])["']?insecure-skip-tls-verify["']?\s*:\s*["']?true\b""",
            re.IGNORECASE,
        ),
        "'insecure-skip-tls-verify' skips TLS certificate checks",
    ),
    (
        re.compile(r"(?<![\w-])--no-check-certificate(?![\w-])"),
        "'--no-check-certificate' skips TLS certificate checks",
    ),
    (
        re.compile(r"""strict[-_]?ssl["']?(?:\s*[:=]\s*|\s+)["']?false\b""", re.IGNORECASE),
        "npm 'strict-ssl' false skips registry TLS certificate checks",
    ),
    (
        re.compile(r"""NODE_TLS_REJECT_UNAUTHORIZED["']?\s*[:=]\s*["']?0(?![\w.])"""),
        "'NODE_TLS_REJECT_UNAUTHORIZED=0' turns off TLS certificate checks for all "
        "Node.js connections",
    ),
    (
        re.compile(
            r"""GIT_SSL_NO_VERIFY["']?\s*[:=]\s*["']?(?:1|true)\b|"""
            r"""http\.sslverify["']?(?:\s*[:=]\s*|\s+)["']?false\b""",
            re.IGNORECASE,
        ),
        "git 'sslVerify' off skips TLS certificate checks",
    ),
    (
        re.compile(r"(?<![\w-])--insecure-ignore-(?:tlog|sct)(?:=(?:true|1))?(?![\w=-])"),
        "cosign '--insecure-ignore-...' skips transparency-log/SCT checks",
    ),
)
# The line patterns above that a local-only curl / wget command may waive.
_LOCAL_WAIVED = {
    "--insecure": _VERIFY_OFF_RES[0],
    "--no-check-certificate": _VERIFY_OFF_RES[2],
}
_WGET_RE = re.compile(r"wget", re.IGNORECASE)
_TRUSTED_HOST_RE = re.compile(
    r"""(?<![\w-])(--trusted-host|--allow-insecure-host|PIP_TRUSTED_HOST|UV_INSECURE_HOST|"""
    r"""trusted[-_]host|allow[-_]insecure[-_]host)(?![\w-])""",
    re.IGNORECASE,
)
_CURL_VALUE_SHORT = frozenset("AbcCdDeEFHKmoPQrtTuUwxXyYz")
_SHORT_BUNDLE_RE = re.compile(r"^-[A-Za-z0-9]+$")
_ANY_REGEX_RE = re.compile(r"^\^?\.[*+]\$?$")
_CURL_OR_COSIGN_RE = re.compile(r"curl|cosign", re.IGNORECASE)
_COSIGN_VERBS = ("verify", "verify-blob", "verify-attestation", "verify-blob-attestation")


def _curl_k_tokens(tokens):
    """Yield (token, lineno) for curl short-option bundles that include -k."""
    skip = False
    for tok, ln in tokens:
        if skip:
            skip = False
            continue
        if not _SHORT_BUNDLE_RE.match(tok):
            continue
        body = tok[1:]
        for k, ch in enumerate(body):
            if ch == "k":
                yield tok, ln
                break
            if ch in _CURL_VALUE_SHORT:
                skip = k == len(body) - 1
                break


_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


# Options that take the next token as their value (so it is not a target).
_CURL_VALUE_LONG = frozenset((
    "--abstract-unix-socket", "--aws-sigv4", "--cacert", "--capath", "--cert", "--cert-type",
    "--ciphers", "--config", "--connect-timeout", "--connect-to", "--continue-at", "--cookie",
    "--cookie-jar", "--crlfile", "--data", "--data-ascii", "--data-binary", "--data-raw",
    "--data-urlencode", "--dns-servers", "--engine", "--form", "--form-string", "--ftp-port",
    "--header", "--interface", "--json", "--key", "--key-type", "--limit-rate", "--max-filesize",
    "--max-redirs", "--max-time", "--oauth2-bearer", "--output", "--output-dir", "--pass",
    "--pinnedpubkey", "--proxy", "--proxy-header", "--proxy-user", "--quote", "--range",
    "--referer", "--request", "--resolve", "--retry", "--retry-delay", "--retry-max-time",
    "--speed-limit", "--speed-time", "--tls-max", "--trace", "--trace-ascii", "--unix-socket",
    "--upload-file", "--url", "--user", "--user-agent", "--variable", "--write-out",
))
_WGET_VALUE_SHORT = frozenset("aABdeiIlDoOPQRtTUwX")
_WGET_VALUE_LONG = frozenset((
    "--accept", "--append-output", "--base", "--bind-address", "--body-data", "--body-file",
    "--ca-certificate", "--ca-directory", "--certificate", "--directory-prefix", "--domains",
    "--exclude-domains", "--execute", "--header", "--http-password", "--http-user",
    "--input-file", "--level", "--limit-rate", "--load-cookies", "--method", "--output-document",
    "--output-file", "--password", "--post-data", "--post-file", "--private-key",
    "--proxy-password", "--proxy-user", "--quota", "--referer", "--reject", "--save-cookies",
    "--timeout", "--tries", "--user", "--user-agent", "--wait",
))
_DUP_FD_RE = re.compile(r"^\d*[<>]&\d*-?$")  # 2>&1
_REDIRECT_RE = re.compile(r"^(?:\d*>>?|&>>?|\d*<)(.*)$")  # '> file', '>file', '2>>log'
# A bare host target: dotted name, [ipv6] or localhost, optional :port and path.
_HOST_TARGET_RE = re.compile(
    r"""^(?:\[[0-9A-Fa-f:.]*\]|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\.?|localhost)(?::\d+)?(?:[/?#]\S*)?$""",
    re.IGNORECASE,
)
_INSECURE_FLAGS = {"curl": "--insecure", "wget": "--no-check-certificate"}


def _curl_local_only(tokens, value_short=_CURL_VALUE_SHORT, value_long=_CURL_VALUE_LONG):
    """True when a curl (or wget) command only talks to this machine.

    Every scheme://host token (or --opt=scheme://host), option values
    included, must be local, and there must be at least one. Every other
    target (a word that is not an option or an option's value) must be a
    local bare host as well; a variable ('$HOST', '%HOST%', '{{host}}') or a
    remote bare host such as 'example.org/x' keeps the finding. Other words
    (JSON/YAML key text the tokenizer picked up) are ignored.
    """
    urls = []
    for tok, _ in tokens:
        if tok.startswith("-") and "=" in tok:
            tok = tok.split("=", 1)[1]
        if _URL_SCHEME_RE.match(tok):
            urls.append(tok)
    if not (urls and all(_is_local_host(_host_of(u)) for u in urls)):
        return False
    skip = False
    for tok, _ in tokens:
        if skip:
            skip = False
            continue
        if _DUP_FD_RE.match(tok):
            continue
        r = _REDIRECT_RE.match(tok)
        if r:
            skip = not r.group(1)  # '> file': the next token is the file
            continue
        if tok.startswith("--"):
            skip = "=" not in tok and tok in value_long
            continue
        if _SHORT_BUNDLE_RE.match(tok):
            body = tok[1:]
            for k, ch in enumerate(body):
                if ch in value_short:
                    skip = k == len(body) - 1
                    break
            continue
        if _URL_SCHEME_RE.match(tok):
            continue
        if "$" in tok or "%" in tok or "{{" in tok or "`" in tok:
            return False
        if _HOST_TARGET_RE.match(tok) and not _is_local_host(_host_of(tok)):
            return False
    return True


def _curl_message(tok):
    return "Verification disabled: curl '%s' accepts any TLS certificate" % tok


def _cosign_problem(verb, tokens):
    if any(t in ("--key", "--sk") or t.startswith("--key=") for t, _ in tokens):
        return None
    for k, (tok, _) in enumerate(tokens):
        name, eq, value = tok.partition("=")
        if name not in ("--certificate-identity", "--certificate-identity-regexp"):
            continue
        if not eq:
            value = tokens[k + 1][0] if k + 1 < len(tokens) else ""
        if name.endswith("-regexp") and _ANY_REGEX_RE.match(value):
            return (
                "Verification disabled: 'cosign %s' with --certificate-identity-regexp "
                "'%s' accepts any signer" % (verb, value)
            )
        return None
    return (
        "Verification disabled: 'cosign %s' without --certificate-identity accepts "
        "a signature from any signer" % verb
    )


def _split_semicolons(tokens):
    """tokens with a trailing ';' split off ('a;' -> 'a', ';'), plus a final '|' sentinel."""
    flushed = []
    for tok, ln in tokens:
        if tok.endswith(";") and len(tok) > 1:
            flushed.extend([(tok[:-1], ln), (";", ln)])
        else:
            flushed.append((tok, ln))
    flushed.append(("|", 0))
    return flushed


def _count_waived(tokens, flag, waived, local):
    """waived[(flag, lineno, local)] += 1 for each `flag` token of one command."""
    for tok, ln in tokens:
        if tok == flag:
            key = (flag, ln, local)
            waived[key] = waived.get(key, 0) + 1


def _wget_waivers(tokens, waived):
    """Count the --no-check-certificate tokens of wget commands, local-only or not."""
    cur = None
    for tok, ln in _split_semicolons(tokens):
        low = tok.lower()
        name = _cmd_name(tok) if ("curl" in low or "cosign" in low or "wget" in low) else ""
        if _is_separator_token(tok) or name in ("curl", "cosign", "wget"):
            if cur is not None:
                local = _curl_local_only(cur, _WGET_VALUE_SHORT, _WGET_VALUE_LONG)
                _count_waived(cur, "--no-check-certificate", waived, local)
            cur = [] if name == "wget" else None
            continue
        if cur is not None:
            cur.append((tok, ln))


def _drop_waived(hits, code, waived_sets):
    """Remove a line's '--insecure' / '--no-check-certificate' finding when every
    occurrence on the line belongs to a local-only curl / wget command.

    waived_sets: one {(flag, lineno, local_only): count} per tokenizing pass.
    A pass that saw the flag in a command that is not local-only keeps the
    finding. Passes can see the same token, so local-only counts are compared
    by their largest value, never their sum.
    """
    keys = set()
    for w in waived_sets:
        keys.update((flag, ln) for flag, ln, local in w if local)
    for flag, ln in keys:
        if any(w.get((flag, ln, False)) for w in waived_sets):
            continue
        count = max(w.get((flag, ln, True), 0) for w in waived_sets)
        rx, what = _LOCAL_WAIVED[flag]
        bucket = hits.get(ln)
        if not bucket or not 0 < ln <= len(code):
            continue
        message = "Verification disabled: " + what
        if count >= sum(1 for _ in rx.finditer(code[ln - 1])):
            bucket[:] = [(m, s) for m, s in bucket if m != message]
            if not bucket:
                del hits[ln]


def _check_command_tokens(tokens, hits, lines, waived=None):
    """One pass over a logical command line: curl -k and cosign verify.

    With `waived`, also counts the --insecure tokens of each curl command (see _drop_waived).
    """
    mode = None
    curl = []
    cosign = None
    for tok, ln in _split_semicolons(tokens):
        low = tok.lower()
        name = _cmd_name(tok) if ("curl" in low or "cosign" in low) else ""
        if _is_separator_token(tok) or name in ("curl", "cosign"):
            if mode == "curl":
                local = _curl_local_only(curl)
                if not local:
                    for t, l in _curl_k_tokens(curl):
                        _add_hit(hits, lines, l, _curl_message(t))
                if waived is not None:
                    _count_waived(curl, "--insecure", waived, local)
            elif mode == "cosign":
                problem = _cosign_problem(cosign[0], cosign[2])
                if problem:
                    _add_hit(hits, lines, cosign[1], problem)
            mode, curl, cosign = None, [], None
            if name == "curl":
                mode = "curl"
            elif name == "cosign":
                mode = "cosign_verb"
                cosign = [None, ln, []]
            continue
        if mode == "curl":
            curl.append((tok, ln))
        elif mode == "cosign_verb":
            if tok.lower() in _COSIGN_VERBS:
                mode = "cosign"
                cosign[0] = tok.lower()
            else:
                mode = None
        elif mode == "cosign":
            cosign[2].append((tok, ln))


def _analyze_verification_disabled(ctx):
    if _file_ext(ctx) not in _CONFIG_TXT_EXTS:
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    code = [_code_text(l, ctx) for l in lines]
    for i, raw in enumerate(lines):
        if _skip_config_line(raw):
            continue
        line = code[i]
        lineno = i + 1
        for rx, what in _VERIFY_OFF_RES:
            if rx.search(line):
                _add_hit(hits, lines, lineno, "Verification disabled: " + what)
        for m in _TRUSTED_HOST_RE.finditer(line):
            value, _ = _first_value(code, i, m.end())
            if value and _is_local_host(_host_of(value)):
                continue
            shown = "%s %s" % (m.group(1), value) if value else m.group(1)
            _add_hit(
                hits, lines, lineno,
                "Verification disabled: '%s' trusts a package host without TLS "
                "certificate checks" % shown,
            )
    waived_lines, waived_argvs = {}, {}
    for tokens in _logical_lines(code, _skip_config_line, _CURL_OR_COSIGN_RE):
        if tokens:
            _check_command_tokens(tokens, hits, lines, waived_lines)
    for tokens in _logical_lines(code, _skip_config_line, _WGET_RE):
        if tokens:
            _wget_waivers(tokens, waived_lines)
    if not (_is_github_workflow(ctx) or _is_github_action(ctx)):
        for argv, where in _command_argvs(ctx):
            pairs = list(zip(argv, where))
            for k, (tok, _) in enumerate(pairs):
                if _cmd_name(tok) == "curl":
                    _check_command_tokens(pairs[k:], hits, lines, waived_argvs)
                    break
            for k, (tok, _) in enumerate(pairs):
                if _cmd_name(tok) == "wget":
                    _wget_waivers(pairs[k:], waived_argvs)
                    break
    _drop_waived(hits, code, (waived_lines, waived_argvs))
    return hits


# ---------------------------------------------------------------------------
# PG020: risky dependency source
# ---------------------------------------------------------------------------

_INDEX_OPT_RE = re.compile(
    r"""(?<![\w./-])(--extra-index-url|--index-url|--default-index|--index|--find-links|"""
    r"""--registry|PIP_EXTRA_INDEX_URL|PIP_INDEX_URL|PIP_FIND_LINKS|UV_EXTRA_INDEX_URL|"""
    r"""UV_INDEX_URL|UV_DEFAULT_INDEX|UV_INDEX|NPM_CONFIG_REGISTRY|"""
    r"""extra[-_]index[-_]url|index[-_]url|find[-_]links|default[-_]index|"""
    r"""npmRegistryServer|registry[-_]url|registry)(?![\w-])""",
    re.IGNORECASE,
)
_PIP_SHORT_INDEX_RE = re.compile(
    r"""\b(?:pip3?|uv\s+pip)\s+(?:install|download|wheel)\b[^|;&\n]{0,500}?\s-i(?:\s+|=)"""
    r"""["']?(http://[^\s"']+)""",
    re.IGNORECASE,
)
# requirements*.txt: "-i URL" at the start of a line is pip's --index-url.
_REQ_SHORT_INDEX_RE = re.compile(r"""^\s*-i(?:\s+|=)["']?([^\s"']+)""")
_GIT_DEP_RE = re.compile(r"""(?<![\w])git\+(?!file:)[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>`,\]}]+""")
# _GIT_DEP_RE.finditer() is quadratic on runs like 'git+git+git+...' (the scheme
# part rescans the run from every 'git+'); _git_dep_spans() finds the same matches.
_GIT_PLUS_RE = re.compile(r"""(?<![\w])git\+(?!file:)(?=[A-Za-z])""")
_SCHEME_RUN_RE = re.compile(r"""[A-Za-z0-9+.-]*""")
_GIT_BODY_RE = re.compile(r"""://[^\s"'<>`,\]}]+""")
# package.json "repository"/"url" metadata is not a dependency. Reference
# definition, matched against line[:start] by _metadata_key_before().
_REPO_METADATA_KEY_RE = re.compile(
    r"""["']?(?:url|repository|repo|homepage|bugs)["']?\s*[:=]\s*["']?$""", re.IGNORECASE
)
_REPO_METADATA_WORD_RE = re.compile(r"""(?:url|repository|repo|homepage|bugs)$""", re.IGNORECASE)
# pyproject [project.urls] / [tool.poetry.urls] keys (Source, "Bug Tracker", ...): only
# inside those tables, where every value is a link; elsewhere 'source = "git+..."' is a dependency.
_URLS_TABLE_WORD_RE = re.compile(
    r"""(?:source|source[ _-]?code|download|documentation|docs|changelog|issues|tracker|funding)$""",
    re.IGNORECASE,
)
_INLINE_URLS_RE = re.compile(r"""^\s*["']?urls["']?\s*=\s*\{""")


def _git_dep_spans(line):
    """(start, end) of each _GIT_DEP_RE.finditer(line) match, in linear time."""
    run_from, run_end = -1, -1
    pos = 0
    while True:
        m = _GIT_PLUS_RE.search(line, pos)
        if not m:
            return
        p = m.end()
        # [A-Za-z][A-Za-z0-9+.-]* must be followed by '://': ':' is outside the
        # class, so only the end of the whole run can work. One run serves every
        # 'git+' inside it.
        if not run_from <= p < run_end:
            run_from, run_end = p, _SCHEME_RUN_RE.match(line, p).end()
        body = _GIT_BODY_RE.match(line, run_end)
        if body:
            yield m.start(), body.end()
            pos = body.end()
        else:
            pos = m.start() + 1


def _metadata_key_before(line, end, words_re):
    """Does line[:end] end in `KEY["']?\\s*[:=]\\s*["']?` (KEY from words_re)?

    Same answer as searching line[:end] with _REPO_METADATA_KEY_RE (built
    from those words), reading back from `end` instead of copying the prefix.
    """
    k = end
    if k > 0 and line[k - 1] in "\"'":
        k -= 1
    while k > 0 and line[k - 1].isspace():
        k -= 1
    if k == 0 or line[k - 1] not in ":=":
        return False
    k -= 1
    while k > 0 and line[k - 1].isspace():
        k -= 1
    if k > 0 and line[k - 1] in "\"'":
        k -= 1
    return bool(words_re.search(line, max(0, k - 16), k))


def _toml_urls_lines(lines):
    """Per line: inside a [project.urls] / [tool.poetry.urls] table (or a urls = {...} line of
    [project] / [tool.poetry])?"""
    out = []
    table = ()
    for line in lines:
        m = _TOML_HEADER_RE.match(line)
        if m:
            table = tuple(p.strip().strip("\"'").lower() for p in m.group(1).split("."))
            out.append(False)
            continue
        out.append(
            table in (("project", "urls"), ("tool", "poetry", "urls"))
            or (table in (("project",), ("tool", "poetry")) and bool(_INLINE_URLS_RE.match(line)))
        )
    return out


def _is_plain_http(url):
    return url.lower().startswith("http://") and not _is_local_host(_host_of(url))


def _index_message(opt, value):
    extra = re.sub(r"[^a-z]", "", opt.lower()) in (
        "extraindexurl", "pipextraindexurl", "uvextraindexurl",
    )
    url = value.split("=", 1)[1] if "=" in value and "://" in value.split("=", 1)[1] else value
    http = bool(url) and _is_plain_http(url)
    if extra and http:
        return (
            "Dependency source: '%s %s' adds a second package index over plain http "
            "(dependency confusion and tampering in transit)" % (opt, _short(url))
        )
    if extra:
        return (
            "Dependency source: '%s' adds a second package index next to the default "
            "(dependency confusion)" % opt
        )
    if http:
        return (
            "Dependency source: '%s %s' fetches packages over plain http (tampering "
            "in transit)" % (opt, _short(url))
        )
    return None


def _analyze_dependency_source(ctx):
    if _file_ext(ctx) not in _CONFIG_TXT_EXTS:
        return {}
    lines = _ctx_lines(ctx)
    pg008 = None
    urls_table = None
    hits = {}
    code = [_code_text(l, ctx) for l in lines]
    for i, raw in enumerate(lines):
        if _skip_config_line(raw):
            continue
        line = code[i]
        lineno = i + 1
        for m in _INDEX_OPT_RE.finditer(line):
            value, _ = _first_value(code, i, m.end())
            message = _index_message(m.group(1), value)
            if message:
                _add_hit(hits, lines, lineno, message)
        shorts = [m.group(1) for m in _PIP_SHORT_INDEX_RE.finditer(line)]
        if _file_ext(ctx) == ".txt":
            m = _REQ_SHORT_INDEX_RE.match(line)
            if m:
                shorts.append(m.group(1))
        for url in shorts:
            message = _index_message("-i", url)
            if message:
                _add_hit(hits, lines, lineno, message)
        for start, end in _git_dep_spans(line):
            spec = line[start:end].rstrip(").;")
            if _COMMIT_SHA_RE.search(spec) or _metadata_key_before(line, start, _REPO_METADATA_WORD_RE):
                continue
            if urls_table is None:
                urls_table = _toml_urls_lines(lines) if _file_ext(ctx) == ".toml" else [False] * len(lines)
            if urls_table[i] and _metadata_key_before(line, start, _URLS_TABLE_WORD_RE):
                continue
            if pg008 is None:
                pg008 = _cached_hits(ctx, "_pg008", _analyze_unpinned_launch)
            if any("git source without a commit SHA" in msg for msg, _ in pg008.get(lineno, ())):
                continue  # PG008 already reports this launch spec on this line
            _add_hit(
                hits, lines, lineno,
                "Dependency source: git dependency '%s' is not pinned to a 40-char "
                "commit SHA" % _short(spec, 80),
            )
    return hits


_detect_blanket_approval = _file_level("_pg012", _analyze_blanket_approval)
_detect_ci_permissions = _file_level("_pg015", _analyze_ci_permissions)
_detect_exfil_channel = _file_level("_pg016", _analyze_exfil_channel)
_detect_unbounded_loop = _file_level("_pg017", _analyze_unbounded_loop)
_detect_container_privilege = _file_level("_pg018", _analyze_container_privilege)
_detect_verification_disabled = _file_level("_pg019", _analyze_verification_disabled)
_detect_dependency_source = _file_level("_pg020", _analyze_dependency_source)


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES = [
    Rule(
        "PG001",
        "high",
        "Prompt-injection seed phrase in prompt text",
        _detect_injection,
    ),
    Rule(
        "PG002",
        "high",
        "Embedded role override (SYSTEM:/ASSISTANT:) inside untrusted content",
        _detect_system_override,
    ),
    Rule(
        "PG003",
        "medium",
        "Untrusted content interpolated without delimiters/guards",
        _detect_untrusted_placeholder,
    ),
    Rule(
        "PG004",
        "high",
        "Dangerous tool/function capability exposed (shell/exec/eval/file/http)",
        _detect_dangerous_tool,
    ),
    Rule(
        "PG005",
        "high",
        "Destructive action without human-in-the-loop",
        _detect_destructive,
    ),
    Rule(
        "PG006",
        "high",
        "Over-broad MCP/server permissions (root FS, env passthrough, unsafe flags)",
        _detect_broad_mcp,
    ),
    Rule(
        "PG007",
        "medium",
        "Secret committed in prompt/config",
        _detect_secret,
    ),
    Rule(
        "PG008",
        "medium",
        "Unpinned launch command (npx/uvx/pipx/docker without version or digest, remote script piped to a shell)",
        _detect_unpinned_launch,
    ),
    Rule(
        "PG009",
        "high",
        "Tool description / resource metadata poisoning (hidden instructions, invisible characters)",
        _detect_metadata_poisoning,
    ),
    Rule(
        "PG010",
        "high",
        "Untrusted workflow trigger with privileged checkout or AI agent holding write token/secrets",
        _detect_untrusted_trigger,
    ),
    Rule(
        "PG011",
        "high",
        "Attacker-controlled GitHub expression expanded in run/script/AI prompt",
        _detect_expression_injection,
    ),
    Rule(
        "PG012",
        "high",
        "Blanket tool approval (wildcard allow entries, bypassPermissions/yolo mode, trusted MCP servers)",
        _detect_blanket_approval,
    ),
    Rule(
        "PG013",
        "medium",
        "Sub-agent, skill or plugin inherits or pre-approves broad permissions (omitted or wildcard tools, auto-run install/session hooks)",
        _detect_permission_inheritance,
    ),
    Rule(
        "PG014",
        "medium",
        "Over-broad tool input schema (free-form path, command, URL, SQL or code string parameter)",
        _detect_broad_schema,
    ),
    Rule(
        "PG015",
        "medium",
        "Over-broad GitHub workflow token (write-all, or contents + id-token write on an untrusted trigger)",
        _detect_ci_permissions,
    ),
    Rule(
        "PG016",
        "medium",
        "Output exfiltration channel (image/link URL whose query carries a template placeholder)",
        _detect_exfil_channel,
    ),
    Rule(
        "PG017",
        "medium",
        "Unbounded agent loop or budget (max_iterations/max_turns/... set to 0, negative, unlimited or inf)",
        _detect_unbounded_loop,
    ),
    Rule(
        "PG018",
        "high",
        "Privileged MCP container (--privileged, host root/socket mount, host network/PID, SYS_ADMIN) or admin-scoped token in server args",
        _detect_container_privilege,
    ),
    Rule(
        "PG019",
        "medium",
        "Verification disabled (TLS checks off, trusted-host, strict-ssl=false, cosign verify without signer identity)",
        _detect_verification_disabled,
    ),
    Rule(
        "PG020",
        "medium",
        "Risky dependency source (--extra-index-url, plain-http index/registry, git+ dependency without commit SHA)",
        _detect_dependency_source,
    ),
    Rule(
        "PG021",
        "medium",
        "Checksum downloaded from the same origin as the artifact it verifies",
        _detect_same_origin_checksum,
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}
