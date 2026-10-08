"""Tests for check_secrets.py.

Run from the repository root:
    python -m unittest discover -s tools -p "test_*.py"

Sample credentials are assembled at runtime from fragments so that this file
contains no literal string the scanner (or GitHub push protection) would flag.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_secrets  # noqa: E402

SAFE_AUTHOR_EMAIL = "tester" + "@" + "users.noreply.github.com"
REAL_LOOKING_EMAIL = "someone" + "@" + "example" + ".com"


def rules_hit(text: str) -> set[str]:
    return {finding.rule for finding in check_secrets.scan_text("sample.txt", text)}


class ContentRuleTests(unittest.TestCase):
    def test_each_credential_shape_is_detected(self) -> None:
        samples: list[tuple[str, str]] = [
            ("private-key-block", "-----BEGIN RSA " + "PRIVATE KEY-----"),
            ("aws-access-key-id", "AKIA" + "ABCDEFGHIJKLMNOP"),
            ("github-token", "ghp_" + "a" * 36),
            ("slack-token", "xoxb-" + "1234567890-abcdefghij"),
            ("google-api-key", "AIza" + "B" * 35),
            ("stripe-live-key", "sk_" + "live_" + "c" * 24),
            ("sk-style-api-key", "sk-" + "d" * 32),
            ("json-web-token", "eyJ" + "e" * 12 + "." + "eyJ" + "f" * 12 + "." + "g" * 12),
            ("url-with-credentials", "postgres" + "://" + "admin:hunter22" + "@" + "db.internal/app"),
            ("authorization-header", "Authorization" + ": " + "Bearer " + "h" * 20),
            ("credential-assignment", "pass" + "word" + ' = "' + "hunter22" + '"'),
            ("env-style-credential", "DB_" + "PASSWORD" + "=" + "hunter22"),
            ("username-assignment", "user" + "name" + ': "' + "realperson" + '"'),
            ("password-input-with-value", '<input type="pass' + 'word" value="' + "hunter22" + '">'),
            ("local-user-path", "C:" + "\\Users\\" + "realperson" + "\\Documents"),
            ("email-address", REAL_LOOKING_EMAIL),
        ]
        for rule_name, sample in samples:
            with self.subTest(rule=rule_name):
                self.assertIn(rule_name, rules_hit(sample))

    def test_unix_home_path_is_detected(self) -> None:
        self.assertIn("local-user-path", rules_hit("/" + "home" + "/realperson/project"))

    def test_json_escaped_windows_path_is_detected(self) -> None:
        self.assertIn(
            "local-user-path", rules_hit("C:" + "\\\\Users\\\\" + "realperson" + "\\\\x")
        )

    def test_ordinary_page_markup_is_clean(self) -> None:
        clean_page = "\n".join(
            [
                "<!doctype html>",
                '<link rel="stylesheet" href="./style.css">',
                '<img src="./logo@2x.png" alt="logo">',
                '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>',
                '<input type="password" name="password" placeholder="Password">',
                "@media (max-width: 600px) { body { margin: 0; } }",
                "const token = readTokenFromSession();",
                "<p>No secrets or passwords belong on this page.</p>",
            ]
        )
        self.assertEqual(set(), rules_hit(clean_page))

    def test_finding_reports_the_value_and_line(self) -> None:
        text = "first line\n" + "api_" + "key" + ": '" + "abcd1234efgh" + "'\n"
        findings = check_secrets.scan_text("config.js", text)
        self.assertEqual(1, len(findings))
        self.assertEqual(2, findings[0].line_number)
        self.assertEqual("abcd1234efgh", findings[0].matched_text)


class RedactionTests(unittest.TestCase):
    def test_long_value_is_never_shown_in_full(self) -> None:
        long_value = "supersecretvalue123"
        shown = check_secrets.redact(long_value)
        self.assertNotIn(long_value, shown)
        self.assertNotIn(long_value[4:], shown)

    def test_short_value_is_fully_hidden(self) -> None:
        self.assertEqual("***", check_secrets.redact("abc123"))


class FileNameTests(unittest.TestCase):
    def test_forbidden_names_are_flagged(self) -> None:
        for name in (
            ".env",
            "site/.env.local",
            "keys/server.pem",
            "data/app.sqlite",
            "id_rsa",
            "tools/__pycache__/module.cpython-313.pyc",
        ):
            with self.subTest(name=name):
                self.assertEqual(1, len(check_secrets.scan_file_name(name)))

    def test_ordinary_names_are_not_flagged(self) -> None:
        for name in ("index.html", "site/app.js", "site/data.json", "README.md"):
            with self.subTest(name=name):
                self.assertEqual([], check_secrets.scan_file_name(name))


class RepositoryScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name) / "repo"
        self.root.mkdir()
        self.allowlist_path = Path(self._temporary_directory.name) / "allowlist.txt"
        self.git("init", "-q", "-b", "main")

    def git(self, *arguments: str, author_email: str = SAFE_AUTHOR_EMAIL) -> None:
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=tester",
                "-c",
                f"user.email={author_email}",
                *arguments,
            ],
            check=True,
            capture_output=True,
        )

    def write(self, relative_path: str, content: str | bytes) -> None:
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")

    def run_main(self, allowlist_lines: list[str] | None = None) -> int:
        self.allowlist_path.write_text("\n".join(allowlist_lines or []), encoding="utf-8")
        return check_secrets.main(
            ["--root", str(self.root), "--allowlist", str(self.allowlist_path)]
        )

    def test_clean_repository_passes(self) -> None:
        self.write("index.html", "<h1>hello</h1>\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "clean")
        self.assertEqual(check_secrets.EXIT_CLEAN, self.run_main())

    def test_untracked_file_with_credential_fails(self) -> None:
        self.write("site/config.js", "const " + "pass" + "word" + ' = "' + "hunter22" + '";\n')
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main())

    def test_gitignored_file_is_not_scanned(self) -> None:
        self.write(".gitignore", "private/\n")
        self.write("private/notes.txt", REAL_LOOKING_EMAIL + "\n")
        self.assertEqual(check_secrets.EXIT_CLEAN, self.run_main())

    def test_binary_file_without_credentials_passes(self) -> None:
        self.write("photo.bin", b"\x00\x01\xff\xfe\x89PNG" + bytes(range(256)))
        self.assertEqual(check_secrets.EXIT_CLEAN, self.run_main())

    def test_credential_inside_binary_file_fails(self) -> None:
        embedded = ("AKIA" + "ABCDEFGHIJKLMNOP").encode("ascii")
        self.write("module.bin", b"\x00\x01\xff" + embedded + b"\x00\xfe")
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main())

    def test_credential_inside_utf16_file_fails(self) -> None:
        line = "pass" + "word" + ' = "' + "hunter22" + '"'
        self.write("notes.txt", line.encode("utf-16"))
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main())

    def test_forbidden_file_type_fails_even_when_content_is_clean(self) -> None:
        self.write("store.sqlite", b"\x00\x01binary")
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main())

    def test_allowlist_suppresses_only_the_exact_string(self) -> None:
        self.write("contact.html", "<p>" + REAL_LOOKING_EMAIL + "</p>\n")
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main())
        self.assertEqual(check_secrets.EXIT_CLEAN, self.run_main([REAL_LOOKING_EMAIL]))
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main(["other" + REAL_LOOKING_EMAIL]))

    def test_commit_with_personal_email_fails(self) -> None:
        self.write("index.html", "<h1>hello</h1>\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "leaky identity", author_email=REAL_LOOKING_EMAIL)
        self.assertEqual(check_secrets.EXIT_FINDINGS, self.run_main())

    def test_directory_that_is_not_a_repository_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as plain_directory:
            self.assertEqual(
                check_secrets.EXIT_ERROR,
                check_secrets.main(["--root", plain_directory, "--allowlist", "missing.txt"]),
            )


if __name__ == "__main__":
    unittest.main()
