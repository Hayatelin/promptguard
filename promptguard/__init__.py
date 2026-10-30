"""promptguard - a security pre-flight for AI agents.

Scans agent configs, system prompts, tool/function definitions, and MCP
server configs for prompt-injection risks and over-privileged / unsafe
tool exposure. Zero dependencies, standard library only.
"""

from .scanner import Finding, scan_text, scan_file, scan_path
from .rules import RULES

__version__ = "1.1.0"

__all__ = [
    "Finding",
    "scan_text",
    "scan_file",
    "scan_path",
    "RULES",
    "__version__",
]
