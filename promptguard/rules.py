"""Rule definitions for promptguard.

Each rule is a small, self-contained detector. A rule has a stable id, a
severity (high/medium/low), a human description, and a callable that yields
zero or more matches for a given physical line of text.

The detectors are deliberately conservative and pattern-based (a linter, not
a guardrail). To avoid flagging promptguard's own rule strings, the trigger
phrases below are assembled from fragments where they would otherwise be
literal, and rules are scoped to realistic config/prompt shapes.
"""

import re

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
]

RULES_BY_ID = {r.id: r for r in RULES}
