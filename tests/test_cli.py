"""Tests for CLI behavior: exit codes, JSON output, examples, thresholds."""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from promptguard.cli import main

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(HERE, "examples")


def run_cli(argv):
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestExitCodes(unittest.TestCase):
    def test_insecure_example_nonzero(self):
        code, out, _ = run_cli([os.path.join(EXAMPLES, "insecure-agent.json")])
        self.assertEqual(code, 1)
        self.assertIn("issue(s)", out)

    def test_secure_example_zero(self):
        code, out, _ = run_cli([os.path.join(EXAMPLES, "secure-agent.json")])
        self.assertEqual(code, 0)
        self.assertIn("OK - no issues found", out)

    def test_missing_path_returns_2(self):
        code, _, err = run_cli(["/no/such/path/here.json"])
        self.assertEqual(code, 2)
        self.assertIn("not found", err)


class TestJSONOutput(unittest.TestCase):
    def test_json_structure(self):
        code, out, _ = run_cli(
            ["--json", os.path.join(EXAMPLES, "insecure-agent.json")]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "promptguard")
        self.assertIn("summary", payload)
        self.assertTrue(payload["summary"]["total"] > 0)
        self.assertTrue(len(payload["findings"]) > 0)
        first = payload["findings"][0]
        for key in ("path", "line", "rule", "severity", "message", "snippet"):
            self.assertIn(key, first)

    def test_json_clean(self):
        code, out, _ = run_cli(
            ["--json", os.path.join(EXAMPLES, "secure-agent.json")]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["total"], 0)


class TestSeverityThreshold(unittest.TestCase):
    def test_high_only_drops_medium(self):
        code, out, _ = run_cli(
            ["--min-severity", "high", os.path.join(EXAMPLES, "insecure-agent.json")]
        )
        self.assertEqual(code, 1)
        self.assertNotIn("PG003", out)
        self.assertNotIn("PG007", out)
        self.assertIn("PG004", out)

    def test_examples_dir_flags(self):
        code, out, _ = run_cli([EXAMPLES])
        self.assertEqual(code, 1)
        self.assertIn("high", out)


class TestQuiet(unittest.TestCase):
    def test_quiet_suppresses_findings_lines(self):
        code, out, _ = run_cli(
            ["--quiet", os.path.join(EXAMPLES, "insecure-agent.json")]
        )
        self.assertEqual(code, 1)
        self.assertNotIn("[HIGH]", out)
        self.assertIn("issue(s)", out)


class TestExamples(unittest.TestCase):
    def test_over_broad_mcp_flags_unpinned_launch(self):
        code, out, _ = run_cli([os.path.join(EXAMPLES, "over-broad-mcp.json")])
        self.assertEqual(code, 1)
        self.assertIn("over-broad-mcp.json:5  [PG008]", out)


class TestBatchOneRulesThroughCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with open(os.path.join(self.tmp, "settings.json"), "w") as fh:
            fh.write('{"permissions": {"allow": ["Bash(*)"]}}\n')
        with open(os.path.join(self.tmp, "requirements.txt"), "w") as fh:
            fh.write("--extra-index-url https://pkgs.example/simple\nrequests==2.31.0\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_directory_scan_reports_new_rules(self):
        code, out, _ = run_cli([self.tmp])
        self.assertEqual(code, 1)
        self.assertIn("settings.json:1  [PG012]", out)
        self.assertIn("requirements.txt:1  [PG020]", out)

    def test_min_severity_high_keeps_only_high_new_rules(self):
        code, out, _ = run_cli(["--min-severity", "high", self.tmp])
        self.assertEqual(code, 1)
        self.assertIn("[PG012]", out)
        self.assertNotIn("[PG020]", out)

if __name__ == "__main__":
    unittest.main()
