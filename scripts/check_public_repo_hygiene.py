#!/usr/bin/env python3
"""Public-repository zero-secret and zero-internal-jargon hygiene gate.

Scans staged files, tracked files (`--all-tracked`), or commit diffs/messages
(`--git-range <rev_range>`) to prevent credentials, Terraform state/tfvars,
internal workstation proxy URLs, internal shortlinks, or non-public tenant
jargon from entering the public Git object graph.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import subprocess
import sys
from collections.abc import Sequence


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Allowed template suffixes for otherwise-forbidden file patterns.
_ALLOWED_ENV_NAMES = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
    }
)
_ALLOWED_TFVARS_SUFFIXES = (".tfvars.example", ".tfvars.sample", ".tfvars.template")

# Binary extensions skipped during line-level text scanning (path checks still run).
_BINARY_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".whl",
        ".pyc",
        ".woff",
        ".woff2",
    }
)


@dataclasses.dataclass(frozen=True)
class HygieneRule:
    """A single content-level hygiene rule with actionable remediation advice."""

    rule_id: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    scoped_prefixes: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Finding:
    """A single violation discovered in a file path, line, or commit message."""

    source: str
    line_num: int
    rule_id: str
    message: str
    remediation: str


# Assemble internal tokens via adjacent string concatenation so plain-text
# repository greps for banned terms never match this scanner file itself.
_INTERNAL_SANDBOX_TERM = "arg" + "olis"
_CORP_DOMAIN_ALTO = "alto" + r"strat\.com"
_CORP_DOMAIN_JOO = "joo" + r"nix\.net"
_CORP_DOMAIN_PLEX = "google" + r"plex\.com"
_CORP_DOMAIN_GOOG = r"corp\.goog(?:le\.com)?"
_CORP_DOMAIN_UPLINK = r"uplink\.goog"
_CORP_CHRONICLE_BACKSTORY = r"backstory\.chronicle\.security"
_INTERNAL_DEMO_PROJECT = "defense-" + r"enterprise-\d+"
_INTERNAL_DEMO_ORG = "198798" + "4870407"
_PEM_HEADER = "-----BEGIN " + r"(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"

CONTENT_RULES: tuple[HygieneRule, ...] = (
    HygieneRule(
        rule_id="SECRET_PRIVATE_KEY",
        pattern=re.compile(_PEM_HEADER),
        message="PEM private key header detected.",
        remediation=(
            "Remove private key material immediately and rotate the credential; "
            "store runtime secrets in GCP Auth Manager or Secret Manager."
        ),
    ),
    HygieneRule(
        rule_id="SECRET_GCP_SA_KEY",
        pattern=re.compile(r'"private_key_id"\s*:\s*"[0-9a-f]{20,}"'),
        message="Google Cloud service account JSON key material detected.",
        remediation=(
            "Never commit service account JSON keys; bind IAM roles to dynamic "
            "SPIFFE workload identities or use Auth Manager."
        ),
    ),
    HygieneRule(
        rule_id="SECRET_GOOGLE_API_KEY",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        message="Google API key literal (`AIza...`) detected.",
        remediation=(
            "Replace with an environment variable placeholder (`<YOUR_API_KEY>`) "
            "or inject via GCP Auth Manager."
        ),
    ),
    HygieneRule(
        rule_id="SECRET_GOOGLE_OAUTH_TOKEN",
        pattern=re.compile(r"\bya29\.[0-9A-Za-z_.-]{25,}\b"),
        message="Live Google OAuth 2.0 access token (`ya29....`) detected.",
        remediation="Revoke/expire the token and remove it from tracked files.",
    ),
    HygieneRule(
        rule_id="SECRET_GITHUB_TOKEN",
        pattern=re.compile(
            r"\b(?:ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{50,})\b"
        ),
        message="GitHub personal access or OAuth token detected.",
        remediation="Revoke the token in GitHub Settings and remove it from code.",
    ),
    HygieneRule(
        rule_id="SECRET_AWS_ACCESS_KEY",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        message="AWS access key ID (`AKIA...`) detected.",
        remediation="Remove the key and use workload identity federation instead.",
    ),
    HygieneRule(
        rule_id="SECRET_GOOGLE_OAUTH_CLIENT_SECRET",
        pattern=re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{20,}\b"),
        message="Google OAuth 2.0 client secret (`GOCSPX-...`) detected.",
        remediation=(
            "Rotate the OAuth client secret and store it in GCP Auth Manager "
            "or local untracked `.env`."
        ),
    ),
    HygieneRule(
        rule_id="INTERNAL_JARGON_SANDBOX",
        pattern=re.compile(rf"\b{_INTERNAL_SANDBOX_TERM}\b", re.IGNORECASE),
        message="Internal Google sandbox terminology detected.",
        remediation=(
            'Replace internal terminology with "test Google SecOps tenant" '
            'or "test tenant".'
        ),
    ),
    HygieneRule(
        rule_id="INTERNAL_CORP_DOMAIN",
        pattern=re.compile(
            rf"(?:{_CORP_DOMAIN_ALTO}|{_CORP_DOMAIN_JOO}|{_CORP_DOMAIN_PLEX}"
            rf"|{_CORP_DOMAIN_GOOG}|{_CORP_DOMAIN_UPLINK}|{_CORP_CHRONICLE_BACKSTORY})",
            re.IGNORECASE,
        ),
        message="Internal corporate, demo-org, or workstation proxy domain detected.",
        remediation=(
            "Scrub internal hostnames and proxy URLs; pin package indexes to "
            "`https://pypi.org/simple` and use `<YOUR_DOMAIN>` placeholders."
        ),
    ),
    HygieneRule(
        rule_id="INTERNAL_DEMO_IDENTIFIER",
        pattern=re.compile(
            rf"\b(?:{_INTERNAL_DEMO_PROJECT}|{_INTERNAL_DEMO_ORG})\b",
            re.IGNORECASE,
        ),
        message="Internal DemoHub project or organization ID detected.",
        remediation=(
            "Parameterize project and organization IDs via `variables.tf` or "
            "`.env.example` placeholders."
        ),
    ),
    HygieneRule(
        rule_id="INTERNAL_SHORTLINK",
        pattern=re.compile(
            r"(?:^|[\s(\[<\"'`])"
            r"(?:https?://)?(?:goto\.google\.com/|(?:go|b|cl)/)"
            r"[a-zA-Z0-9][a-zA-Z0-9_-]{2,}\b"
        ),
        message="Internal Google shortlink (`go/`, `b/`, `cl/`, or `goto.google.com`) detected.",
        remediation="Replace internal shortlinks with public documentation URLs.",
    ),
    HygieneRule(
        rule_id="TERRAFORM_HARDCODED_TENANT",
        pattern=re.compile(
            r"(?:secops-demo-env|dandye-0324-chronicle|workshops-2026\d*"
            r"|a13f6726-efed-452e-9008-8fe0d3cb0f75"
            r"|7e977ce4-f45d-43b2-aea0-52f8b66acd80"
            r"|ytvgh\.siemplify-soar\.com"
            r"|\b1002894625780\b|\b89865786164\b)",
            re.IGNORECASE,
        ),
        message="Hardcoded lab/demo tenant identifier inside infrastructure module.",
        remediation=(
            "Use `var.project_id`, `var.project_number`, `var.org_id`, or "
            "`var.chronicle_customer_id` in `terraform/` and `governance/`."
        ),
        scoped_prefixes=("terraform/", "governance/"),
    ),
)


def check_forbidden_path(rel_path: str) -> Finding | None:
    """Return a `Finding` if `rel_path` itself must never be tracked in Git."""
    norm = rel_path.replace("\\", "/").removeprefix("./")
    p = pathlib.PurePosixPath(norm)
    name = p.name
    lower_name = name.lower()

    if ".gcloud" in p.parts or ".terraform" in p.parts:
        return Finding(
            source=norm,
            line_num=0,
            rule_id="FORBIDDEN_PATH_STATE_DIR",
            message=f"Directory `{norm}` contains local credentials or provider state.",
            remediation="Unstage the path and verify `.gcloud/` and `.terraform/` are in `.gitignore`.",
        )

    if (name == ".env" or name.startswith(".env.")) and name not in _ALLOWED_ENV_NAMES:
        return Finding(
            source=norm,
            line_num=0,
            rule_id="FORBIDDEN_PATH_DOTENV",
            message=f"Environment file `{norm}` must never be committed.",
            remediation="Commit only `.env.example` with `<YOUR_...>` placeholders.",
        )

    if ".tfstate" in lower_name:
        return Finding(
            source=norm,
            line_num=0,
            rule_id="FORBIDDEN_PATH_TFSTATE",
            message=f"Terraform state file `{norm}` contains plaintext resource secrets.",
            remediation="Remove from Git index (`git rm --cached`) and use local ignored or GCS backend state.",
        )

    if lower_name.endswith((".tfvars", ".tfvars.json")) and not lower_name.endswith(
        _ALLOWED_TFVARS_SUFFIXES
    ):
        return Finding(
            source=norm,
            line_num=0,
            rule_id="FORBIDDEN_PATH_TFVARS",
            message=f"Populated Terraform variable file `{norm}` must not be committed.",
            remediation="Commit only `terraform.tfvars.example` with sanitized placeholders.",
        )

    if lower_name.endswith((".pem", ".key", ".p12", ".pfx")):
        return Finding(
            source=norm,
            line_num=0,
            rule_id="FORBIDDEN_PATH_KEYFILE",
            message=f"Private key or certificate archive `{norm}` must not be committed.",
            remediation="Unstage and delete local key material; use GCP Auth Manager.",
        )

    return None


def scan_text(
    text: str,
    *,
    source: str,
    rel_path: str = "",
) -> list[Finding]:
    """Scan `text` line-by-line against `CONTENT_RULES`."""
    findings: list[Finding] = []
    norm_path = rel_path.replace("\\", "/").removeprefix("./")

    for idx, line in enumerate(text.splitlines(), start=1):
        for rule in CONTENT_RULES:
            if rule.scoped_prefixes and not norm_path.startswith(rule.scoped_prefixes):
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        source=source,
                        line_num=idx,
                        rule_id=rule.rule_id,
                        message=rule.message,
                        remediation=rule.remediation,
                    )
                )
    return findings


def scan_file(
    path: pathlib.Path, *, repo_root: pathlib.Path = REPO_ROOT
) -> list[Finding]:
    """Scan a single file's path and UTF-8 content."""
    try:
        rel_path = path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        rel_path = path.as_posix()

    findings: list[Finding] = []
    path_finding = check_forbidden_path(rel_path)
    if path_finding is not None:
        findings.append(path_finding)
        return findings

    if not path.is_file() or path.suffix.lower() in _BINARY_SUFFIXES:
        return findings

    try:
        raw = path.read_bytes()
    except OSError:
        return findings

    if b"\x00" in raw[:4096]:
        return findings

    text = raw.decode("utf-8", errors="replace")
    findings.extend(scan_text(text, source=rel_path, rel_path=rel_path))
    return findings


def _git_tracked_files(repo_root: pathlib.Path) -> list[pathlib.Path]:
    res = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    entries = [
        e.decode("utf-8", errors="replace") for e in res.stdout.split(b"\x00") if e
    ]
    return [repo_root / rel for rel in entries]


def scan_git_range(
    rev_range: str, *, repo_root: pathlib.Path = REPO_ROOT
) -> list[Finding]:
    """Scan added lines and commit messages across `rev_range` (e.g. `origin/main..HEAD`)."""
    findings: list[Finding] = []

    log_res = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "log",
            "--format=%H%n%B%n---END_COMMIT---",
            rev_range,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    for block in log_res.stdout.split("---END_COMMIT---"):
        lines = block.strip().splitlines()
        if not lines:
            continue
        sha = lines[0][:12]
        msg = "\n".join(lines[1:])
        findings.extend(scan_text(msg, source=f"commit:{sha}"))

    diff_res = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "log",
            "-p",
            "--no-color",
            "--unified=0",
            rev_range,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    current_file = ""
    current_sha = "range"
    line_counter = 0
    for line in diff_res.stdout.splitlines():
        if line.startswith("commit ") and len(line) >= 19:
            current_sha = line.split()[1][:12]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
            path_finding = check_forbidden_path(current_file)
            if path_finding is not None:
                findings.append(
                    dataclasses.replace(
                        path_finding,
                        source=f"{current_sha}:{current_file}",
                    )
                )
        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            line_counter = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            added_line = line[1:]
            findings.extend(
                dataclasses.replace(f, line_num=line_counter)
                for f in scan_text(
                    added_line,
                    source=f"{current_sha}:{current_file}",
                    rel_path=current_file,
                )
            )
            line_counter += 1
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Public-repository secret and internal-jargon hygiene scanner."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Explicit file paths to scan (passed automatically by pre-commit).",
    )
    parser.add_argument(
        "--all-tracked",
        action="store_true",
        help="Scan all Git-tracked files in the repository.",
    )
    parser.add_argument(
        "--git-range",
        default="",
        help="Scan commit messages and added diff lines across a Git revision range.",
    )
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    if args.all_tracked:
        for fpath in _git_tracked_files(REPO_ROOT):
            findings.extend(scan_file(fpath, repo_root=REPO_ROOT))
    if args.git_range:
        findings.extend(scan_git_range(args.git_range, repo_root=REPO_ROOT))
    for raw_file in args.files:
        findings.extend(scan_file(pathlib.Path(raw_file), repo_root=REPO_ROOT))

    if not findings:
        return 0

    print(
        f"PUBLIC REPO HYGIENE GATE FAILED ({len(findings)} violation(s) found):",
        file=sys.stderr,
    )
    for item in findings:
        loc = f"{item.source}:{item.line_num}" if item.line_num else item.source
        print(
            f"  [{item.rule_id}] {loc}: {item.message}\n"
            f"    Fix: {item.remediation}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
