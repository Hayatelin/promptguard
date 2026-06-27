"""Command-line interface for promptguard."""

import argparse
import json
import os
import sys

from . import __version__
from .scanner import (
    scan_path,
    filter_by_severity,
    summarize,
)

SEVERITY_TAG = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="promptguard",
        description=(
            "Security pre-flight for AI agents: scan configs, system prompts, "
            "tool definitions, and MCP server configs for prompt-injection "
            "risks and over-privileged tool exposure."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit findings as structured JSON.",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Only report (and fail on) findings at or above this severity.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-finding output; print only the summary.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="promptguard %s" % __version__,
    )
    return parser


def _print_findings(findings, stream):
    for f in findings:
        tag = SEVERITY_TAG.get(f.severity, f.severity.upper())
        stream.write(
            "[%s] %s:%d  [%s] %s\n"
            % (tag, f.path, f.line, f.rule_id, f.message)
        )
        if f.snippet:
            snippet = f.snippet
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
            stream.write("        | %s\n" % snippet)


def _print_summary(total, high, medium, low, stream):
    if total == 0:
        stream.write("promptguard: OK - no issues found\n")
    else:
        stream.write(
            "promptguard: %d issue(s) - %d high, %d medium, %d low\n"
            % (total, high, medium, low)
        )


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    target = args.path
    if not os.path.exists(target):
        sys.stderr.write("promptguard: error: path not found: %s\n" % target)
        return 2

    findings = scan_path(target)
    findings = filter_by_severity(findings, args.min_severity)

    # Stable ordering: by path, then line, then rule id.
    findings.sort(key=lambda f: (f.path, f.line, f.rule_id))

    total, high, medium, low = summarize(findings)

    if args.as_json:
        payload = {
            "tool": "promptguard",
            "version": __version__,
            "path": target,
            "min_severity": args.min_severity,
            "summary": {
                "total": total,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "findings": [f.to_dict() for f in findings],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        if not args.quiet:
            _print_findings(findings, sys.stdout)
            if findings:
                sys.stdout.write("\n")
        _print_summary(total, high, medium, low, sys.stdout)

    # Non-zero exit when there is anything at/above threshold.
    return 1 if total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
