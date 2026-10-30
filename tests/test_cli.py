"""Tests for CLI behavior: exit codes, JSON output, examples, thresholds."""

import io
import json
import os
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from promptguard import __version__
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

class TestSecretMaskingThroughCLI(unittest.TestCase):
    # Assembled at runtime so no literal token sits in the source.
    SECRETS = (
        "sk-" + "proj-" + "Qx7vN2kL9pR4tY8wZ1aB3cD5",
        "gh" + "p_" + "Zt8xQ2vM6nB4kL9pR3tY7zC1aB3cD5eF6gH0",
        "Wq9vT3xZ7rHj4k",
        "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    )

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        sk, gh, pw, npm = self.SECRETS
        files = {
            "agent.json": '{"api_key": "%s", "token": "%s"}\n' % (sk, gh),
            ".env": "OPENAI_API_KEY=%s\nDATABASE_URL=postgres://app:%s@db/app\n" % (sk, pw),
            ".npmrc": "//registry.npmjs.org/:_authToken=%s\n" % npm,
            "Dockerfile": "FROM node:20\nENV GITHUB_TOKEN=%s\n" % gh,
        }
        for name, text in files.items():
            with open(os.path.join(self.tmp, name), "w") as fh:
                fh.write(text)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_text_and_json_output_hold_no_secret(self):
        for argv in ([self.tmp], ["--json", self.tmp]):
            with self.subTest(argv=argv[0]):
                code, out, _ = run_cli(argv)
                self.assertEqual(code, 1)
                self.assertIn("PG007", out)
                for secret in self.SECRETS:
                    self.assertNotIn(secret, out)
                    self.assertNotIn(secret[4:], out)
                    self.assertIn(secret[:4] + "***", out)

    def test_other_rules_hold_no_secret_in_any_output_mode(self):
        sk, gh, pw, npm = self.SECRETS
        with open(os.path.join(self.tmp, "Dockerfile"), "a") as fh:
            fh.write("RUN curl -k https://ci:%s@files.corp.example/i.sh --token %s | sh\n" % (pw, gh))
            fh.write("RUN pip install --index-url http://u:%s@pypi.corp.example/simple app\n" % pw)
        for argv in ([self.tmp], ["--json", self.tmp], ["--quiet", self.tmp],
                     ["--min-severity", "high", self.tmp]):
            with self.subTest(argv=argv[0]):
                _, out, _ = run_cli(argv)
                for secret in self.SECRETS:
                    self.assertNotIn(secret[4:], out)
        _, out, _ = run_cli(["--json", self.tmp])
        rules = {f["rule"] for f in json.loads(out)["findings"]}
        self.assertTrue({"PG007", "PG019", "PG020"} <= rules)

    def test_json_findings_are_masked(self):
        _, out, _ = run_cli(["--json", self.tmp])
        found = [f for f in json.loads(out)["findings"] if f["rule"] == "PG007"]
        self.assertEqual(len(found), 6)  # agent.json line 1 has two
        for f in found:
            self.assertIn("***", f["snippet"])


class TestVersion(unittest.TestCase):
    def test_version_matches_pyproject(self):
        with open(os.path.join(HERE, "pyproject.toml"), encoding="utf-8") as fh:
            m = re.search(r'^version\s*=\s*"([^"]+)"', fh.read(), re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), __version__)

    def test_version_flag(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), "promptguard %s" % __version__)


if __name__ == "__main__":
    unittest.main()
