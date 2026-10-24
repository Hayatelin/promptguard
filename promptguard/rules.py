"""Rule definitions for promptguard.

Each rule is a small, self-contained detector. A rule has a stable id, a
severity (high/medium/low), a human description, and a callable that yields
zero or more matches for a given physical line of text.

The detectors are deliberately conservative and pattern-based (a linter, not
a guardrail). To avoid flagging promptguard's own rule strings, the trigger
phrases below are assembled from fragments where they would otherwise be
literal, and rules are scoped to realistic config/prompt shapes.
"""

import json
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
    low = ctx.get("full_lower", "")
    if "mcp" in low or "filesystem" in low or "allowed" in low or "root" in low or "args" in low:
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


def _add_hit(hits, lines, lineno, message):
    """Record a finding for `lineno`, once per (line, message)."""
    bucket = hits.setdefault(lineno, [])
    if any(m == message for m, _ in bucket):
        return
    snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
    bucket.append((message, snippet))


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
    base = re.split(r"[\\/]", token)[-1].lower()
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

    Returns [(launcher, spec, problem, hint, token_index)].
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
    for k, argv in enumerate(argvs):
        for launcher, spec, problem, hint, _ in _launch_problems(argv):
            lineno = _find_line(lines, spec, cursors.get(spec, 0))
            if lineno:
                cursors[spec] = lineno
            else:
                lineno = cmd_lines[k] if k < len(cmd_lines) else 1
            _add_hit(hits, lines, lineno, _unpinned_message(launcher, spec, problem, hint))


# Heuristic (a): a launcher at the start of a command string on one line.
_INLINE_LAUNCH_RE = re.compile(
    r"""(?:^\s*(?:-\s+)?|["'`=:;&|(]\s*|\s(?:-c|/c|/k)\s+)"""
    r"""((?:[^\s"'`]*[\\/])?(?:npx|uvx)(?:\.cmd|\.exe)?"""
    r"""|uv\s+tool\s+run|pipx\s+run|docker\s+run)\s+\S""",
    re.IGNORECASE,
)
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
    items = []
    for m in _LIST_ITEM_RE.finditer(part):
        value = next(g for g in m.groups() if g is not None)
        items.append(value)
    return items


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
            m = _INLINE_LAUNCH_RE.search(line)
            if m:
                tokens = _heuristic_tokens(line[m.start(1):])
                for launcher, spec, problem, hint, _ in _launch_problems(tokens):
                    _add_hit(hits, lines, lineno, _unpinned_message(launcher, spec, problem, hint))
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
        for launcher, spec, problem, hint, idx in _launch_problems(tokens):
            _add_hit(hits, lines, argv[idx][1], _unpinned_message(launcher, spec, problem, hint))


def _analyze_unpinned_launch(ctx):
    if _file_ext(ctx) not in _PG008_EXTS:
        return {}
    if _is_github_workflow(ctx) or _is_github_action(ctx):
        return {}
    lines = _ctx_lines(ctx)
    hits = {}
    for i, line in enumerate(lines, 1):
        for rx in (_PIPE_TO_SHELL_RE, _PIPE_TO_IEX_RE):
            m = rx.search(line)
            if m:
                _add_hit(
                    hits,
                    lines,
                    i,
                    "Remote script piped straight into a shell (%s ... | %s)"
                    % (m.group(1).lower(), m.group(2).lower()),
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


_detect_unpinned_launch = _file_level("_pg008", _analyze_unpinned_launch)
_detect_metadata_poisoning = _file_level("_pg009", _analyze_metadata_poisoning)
_detect_untrusted_trigger = _file_level("_pg010", _analyze_untrusted_trigger)
_detect_expression_injection = _file_level("_pg011", _analyze_expression_injection)


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
]

RULES_BY_ID = {r.id: r for r in RULES}
