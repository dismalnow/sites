#!/usr/bin/env python3
"""Pre-publish credential scan for this repository.

Everything in this repository is public: the source on GitHub and the pages
served from it. This script fails if any file that could be committed, or any
commit already in the history, looks like it carries a credential or a
personal identifier.

Usage:
    python tools/check_secrets.py

Exit codes:
    0  clean
    1  findings (do not commit or push)
    2  the scan could not run
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_PATH = Path(__file__).resolve().parent / "secrets_allowlist.txt"

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

UTF16_BYTE_ORDER_MARKS: tuple[bytes, ...] = (b"\xff\xfe", b"\xfe\xff")


@dataclass(frozen=True)
class ContentRule:
    name: str
    pattern: re.Pattern[str]
    # Capture group holding the sensitive value. 0 means the whole match.
    value_group: int = 0


@dataclass(frozen=True)
class Finding:
    path: str
    line_number: int  # 0 when the finding is about the file or commit itself
    rule: str
    matched_text: str


CONTENT_RULES: tuple[ContentRule, ...] = (
    ContentRule(
        "private-key-block",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    ContentRule(
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    ContentRule(
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    ContentRule(
        "slack-token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ),
    ContentRule(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    ContentRule(
        "stripe-live-key",
        re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"),
    ),
    ContentRule(
        "sk-style-api-key",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
    ),
    ContentRule(
        "json-web-token",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
        ),
    ),
    ContentRule(
        "url-with-credentials",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@'\"]+:[^\s/@'\"]+@"),
    ),
    ContentRule(
        "authorization-header",
        re.compile(
            r"(?i)\bauthorization\b[\"']?\s*[:=]\s*[\"']?\s*"
            r"(?:bearer|basic)\s+([A-Za-z0-9._~+/=\-]{8,})"
        ),
        value_group=1,
    ),
    ContentRule(
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|token|api[_\-]?key|access[_\-]?key"
            r"|client[_\-]?secret|private[_\-]?key|auth[_\-]?key)\b"
            r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{4,})[\"']"
        ),
        value_group=1,
    ),
    ContentRule(
        "env-style-credential",
        re.compile(
            r"^\s*(?:export\s+)?[A-Z0-9_]*"
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]*"
            r"\s*=\s*[\"']?([^\s\"']{4,})"
        ),
        value_group=1,
    ),
    ContentRule(
        "username-assignment",
        re.compile(
            r"(?i)\b(?:user(?:[_\-]?name)?|login)\b"
            r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{2,})[\"']"
        ),
        value_group=1,
    ),
    ContentRule(
        "password-input-with-value",
        re.compile(
            r"(?i)<input\b[^>]*\btype\s*=\s*[\"']?password[\"']?[^>]*"
            r"\bvalue\s*=\s*[\"']([^\"']+)[\"']"
        ),
        value_group=1,
    ),
    ContentRule(
        "password-input-with-value",
        re.compile(
            r"(?i)<input\b[^>]*\bvalue\s*=\s*[\"']([^\"']+)[\"'][^>]*"
            r"\btype\s*=\s*[\"']?password[\"']?"
        ),
        value_group=1,
    ),
    ContentRule(
        "local-user-path",
        re.compile(r"(?i)\b[A-Z]:\\+Users\\+([^\\\s\"'<>|/]+)"),
    ),
    ContentRule(
        "local-user-path",
        re.compile(r"(?<![A-Za-z0-9._\-])/(?:home|Users)/([A-Za-z0-9._\-]+)"),
    ),
    ContentRule(
        "email-address",
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b"
        ),
    ),
)

# "logo@2x.png" has the shape of an email address. These endings mark it as an asset.
ASSET_EXTENSIONS: frozenset[str] = frozenset(
    {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "css", "js", "map"}
)

FORBIDDEN_FILE_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".htpasswd",
        ".git-credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials.json",
        "secrets.json",
        "token.json",
        "service-account.json",
    }
)

FORBIDDEN_FILE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".pem",
        ".key",
        ".pfx",
        ".p12",
        ".jks",
        ".keystore",
        ".kdbx",
        ".ppk",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".pst",
        ".ost",
        ".pyc",
        ".pyo",
    }
)

ALLOWED_COMMIT_EMAIL_SUFFIX = "@users.noreply.github.com"
# Committer address GitHub uses for commits made in its web interface. Written in
# two parts so this file does not contain an email address for the scan to flag.
ALLOWED_COMMIT_EMAILS: frozenset[str] = frozenset({"noreply" + "@github.com"})


class ScanError(Exception):
    """The scan could not be completed, so its result cannot be trusted."""


def load_allowlist(allowlist_path: Path) -> frozenset[str]:
    """Each non-blank, non-comment line is one exact string that may be published."""
    if not allowlist_path.exists():
        return frozenset()
    try:
        lines = allowlist_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ScanError(f"cannot read allowlist {allowlist_path}: {error}") from error
    return frozenset(
        line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
    )


def run_git(root: Path, arguments: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as error:
        raise ScanError("git is not installed or not on PATH") from error
    if completed.returncode != 0:
        raise ScanError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip() or 'no error text'}"
        )
    return completed.stdout


def list_candidate_files(root: Path) -> list[str]:
    """Every file git would let you commit: tracked plus untracked, minus ignored."""
    output = run_git(
        root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    )
    relative_paths = sorted({entry for entry in output.split("\0") if entry})
    return [path for path in relative_paths if (root / path).is_file()]


def scan_file_name(relative_path: str) -> list[Finding]:
    name = PurePosixPath(relative_path).name
    lowered = name.lower()
    suffix = PurePosixPath(lowered).suffix
    forbidden = (
        lowered in FORBIDDEN_FILE_NAMES
        or lowered.startswith(".env.")
        or suffix in FORBIDDEN_FILE_SUFFIXES
    )
    if not forbidden:
        return []
    return [Finding(relative_path, 0, "forbidden-file-type", relative_path)]


def scan_text(relative_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in CONTENT_RULES:
            for match in rule.pattern.finditer(line):
                value = match.group(rule.value_group)
                if rule.name == "email-address":
                    extension = value.rsplit(".", 1)[-1].lower()
                    if extension in ASSET_EXTENSIONS:
                        continue
                findings.append(Finding(relative_path, line_number, rule.name, value))
    return findings


def scan_file(root: Path, relative_path: str) -> list[Finding]:
    findings = scan_file_name(relative_path)
    try:
        raw = (root / relative_path).read_bytes()
    except OSError as error:
        raise ScanError(f"cannot read {relative_path}: {error}") from error
    findings.extend(scan_text(relative_path, decode_for_scan(raw)))
    return findings


def decode_for_scan(raw: bytes) -> str:
    """Turn any file into text without losing bytes a credential could hide in.

    Binary files are scanned too: compiled code, image metadata, and documents
    all carry readable strings. Non-ASCII bytes in a binary become U+FFFD, which
    is not a word character, so a credential sitting between two arbitrary bytes
    still has the word boundaries the rules look for.
    """
    if raw.startswith(UTF16_BYTE_ORDER_MARKS):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("ascii", errors="replace")


def scan_commit_identities(root: Path) -> tuple[list[Finding], int]:
    """Author and committer emails are public too. Only no-reply addresses pass."""
    has_commits = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", "HEAD"],
        check=False,
        capture_output=True,
    )
    if has_commits.returncode != 0:
        return [], 0
    output = run_git(root, ["log", "--format=%h%x00%ae%x00%ce", "HEAD"])
    findings: list[Finding] = []
    commit_count = 0
    for record in output.splitlines():
        if not record:
            continue
        commit_count += 1
        short_hash, author_email, committer_email = record.split("\0")
        for email in {author_email, committer_email}:
            allowed = (
                email.endswith(ALLOWED_COMMIT_EMAIL_SUFFIX) or email in ALLOWED_COMMIT_EMAILS
            )
            if not allowed:
                findings.append(
                    Finding(f"commit {short_hash}", 0, "commit-identity-email", email)
                )
    return findings, commit_count


def redact(text: str) -> str:
    """Enough to locate the hit, never enough to reuse it."""
    if len(text) < 8:
        return "***"
    return f"{text[:3]}***({len(text)} chars)"


def scan_repository(root: Path, allowlist: frozenset[str]) -> tuple[list[Finding], int, int]:
    relative_paths = list_candidate_files(root)
    findings: list[Finding] = []
    for relative_path in relative_paths:
        findings.extend(scan_file(root, relative_path))
    commit_findings, commit_count = scan_commit_identities(root)
    findings.extend(commit_findings)
    kept = [finding for finding in findings if finding.matched_text not in allowlist]
    return kept, len(relative_paths), commit_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if anything committable looks like a credential or personal identifier."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository to scan (default: the repository this script lives in)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=ALLOWLIST_PATH,
        help="file of exact strings that are approved for publication",
    )
    arguments = parser.parse_args(argv)

    try:
        allowlist = load_allowlist(arguments.allowlist)
        findings, file_count, commit_count = scan_repository(arguments.root, allowlist)
    except ScanError as error:
        print(f"ERROR  {error}", file=sys.stderr)
        print("The scan did not complete. Treat this as a failure.", file=sys.stderr)
        return EXIT_ERROR

    if not findings:
        print(
            f"OK  scanned {file_count} file(s) and {commit_count} commit(s): "
            "no credentials or personal identifiers found."
        )
        return EXIT_CLEAN

    for finding in findings:
        location = (
            f"{finding.path}:{finding.line_number}" if finding.line_number else finding.path
        )
        print(f"FAIL  {location}  {finding.rule}  {redact(finding.matched_text)}")
    affected = len({finding.path for finding in findings})
    print(
        f"\n{len(findings)} finding(s) in {affected} location(s). "
        "Do not commit or push until every one is removed."
    )
    return EXIT_FINDINGS


if __name__ == "__main__":
    sys.exit(main())
