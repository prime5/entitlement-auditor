"""Redact real identifiers from recorded GCP API responses before they become fixtures.

Two commands:

    python -m auditor.redact redact raw/ fixtures/   # raw/ is gitignored, fixtures/ is committed
    python -m auditor.redact check fixtures/         # exit 1 if anything still looks real

Why deterministic: the same real value always maps to the same token (HMAC with a
local salt), so (a) the same service account appearing in getIamPolicy and in
keys.list still lines up after redaction, and (b) re-recording next month
produces a small, reviewable diff instead of all-new tokens.

Why `check` needs no secrets: it looks for *shapes* that only real data has
(a non-example email, a project number that isn't in the pseudo range), so it
runs in CI and in the pre-commit hook without knowing the real values. If the
real values are in the environment, it checks for those too.

Configuration (env vars only; nothing here is ever written to disk):
    AUDITOR_REDACTION_SALT    required for `redact`; any long random string you keep locally
    AUDITOR_PROJECT_IDS       comma-separated real project IDs
    AUDITOR_PROJECT_NUMBERS   comma-separated real project numbers
    AUDITOR_REDACT_EXTRA      comma-separated other literals (e.g. your display name)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Google-owned service-account domains: the local part and the project segment
# are redacted separately, but the domain itself is structural and must survive
# so the collector can classify the principal (user-managed vs Google-managed).
GOOGLE_SA_SUFFIX = ".gserviceaccount.com"
SAFE_EMAIL_DOMAIN = "example.com"
SAFE_DOMAIN_SUFFIX = ".test"
PSEUDO_NUMBER_PREFIX = "000"  # real GCP project numbers never start with 0

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_PRINCIPAL_RE = re.compile(r"domain:([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Places a project number shows up in IAM data.
PROJECT_NUMBER_SHAPES = [
    re.compile(r"projects/(\d{6,})"),
    re.compile(r"(?<![\w-])(\d{6,})-compute@"),
    re.compile(r"service-(\d{6,})@"),
    re.compile(r"(?<![\w-])(\d{6,})@cloudservices\."),
]


class RedactionError(Exception):
    pass


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


@dataclass(frozen=True)
class Redactor:
    salt: bytes
    project_ids: tuple[str, ...] = ()
    project_numbers: tuple[str, ...] = ()
    extra: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "Redactor":
        salt = os.environ.get("AUDITOR_REDACTION_SALT", "")
        if len(salt) < 16:
            # Fail closed: without a salt the tokens would be guessable
            # (HMAC of a known project ID), which defeats the redaction.
            raise RedactionError("AUDITOR_REDACTION_SALT must be set (16+ chars)")
        return cls(
            salt=salt.encode(),
            project_ids=tuple(_env_list("AUDITOR_PROJECT_IDS")),
            project_numbers=tuple(_env_list("AUDITOR_PROJECT_NUMBERS")),
            extra=tuple(_env_list("AUDITOR_REDACT_EXTRA")),
        )

    def _h(self, value: str, n: int = 6) -> str:
        return hmac.new(self.salt, value.encode(), hashlib.sha256).hexdigest()[:n]

    def pseudo_number(self, real: str) -> str:
        digits = int(self._h(real, 12), 16) % 10**9
        return f"{PSEUDO_NUMBER_PREFIX}{digits:09d}"

    def pseudo_project_id(self, real: str) -> str:
        return f"proj-{self._h(real)}"

    def redact_text(self, text: str) -> str:
        # Order matters: numbers and IDs first, so a service-account email has
        # its project segment rewritten before the email pass sees it.
        for num in self.project_numbers:
            text = re.sub(rf"(?<!\d){re.escape(num)}(?!\d)", self.pseudo_number(num), text)
        for pid in self.project_ids:
            text = re.sub(
                rf"(?<![a-z0-9-]){re.escape(pid)}(?![a-z0-9-])", self.pseudo_project_id(pid), text
            )
        for lit in self.extra:
            text = text.replace(lit, f"redacted-{self._h(lit)}")

        def email(m: re.Match[str]) -> str:
            addr = m.group(0)
            domain = addr.rsplit("@", 1)[1].lower()
            if domain.endswith(GOOGLE_SA_SUFFIX) or domain == SAFE_EMAIL_DOMAIN:
                return addr
            return f"user-{self._h(addr.lower())}@{SAFE_EMAIL_DOMAIN}"

        text = EMAIL_RE.sub(email, text)
        text = DOMAIN_PRINCIPAL_RE.sub(
            lambda m: f"domain:org-{self._h(m.group(1).lower())}{SAFE_DOMAIN_SUFFIX}", text
        )
        return text

    def redact_json_file(self, src: Path, dst: Path) -> None:
        out = self.redact_text(src.read_text())
        json.loads(out)  # string-level rewrite must still be valid JSON
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(out)


@dataclass(frozen=True)
class Leak:
    path: str
    line: int
    reason: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.reason}"


def find_leaks(text: str, path: str = "<text>", known: tuple[str, ...] = ()) -> list[Leak]:
    leaks: list[Leak] = []
    for i, line in enumerate(text.splitlines(), start=1):
        for m in EMAIL_RE.finditer(line):
            domain = m.group(0).rsplit("@", 1)[1].lower()
            if not (domain == SAFE_EMAIL_DOMAIN or domain.endswith(GOOGLE_SA_SUFFIX)):
                leaks.append(Leak(path, i, f"non-redacted email domain '{domain}'"))
        for shape in PROJECT_NUMBER_SHAPES:
            for m in shape.finditer(line):
                if not m.group(1).startswith(PSEUDO_NUMBER_PREFIX):
                    leaks.append(Leak(path, i, "project number outside pseudo range"))
        for m in DOMAIN_PRINCIPAL_RE.finditer(line):
            if not m.group(1).endswith(SAFE_DOMAIN_SUFFIX):
                leaks.append(Leak(path, i, "non-redacted domain: principal"))
        for value in known:
            if value and value in line:
                leaks.append(Leak(path, i, "known real identifier present"))
    return leaks


def check_dir(root: Path) -> list[Leak]:
    known = tuple(
        _env_list("AUDITOR_PROJECT_IDS")
        + _env_list("AUDITOR_PROJECT_NUMBERS")
        + _env_list("AUDITOR_REDACT_EXTRA")
    )
    leaks: list[Leak] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in {".json", ".yaml", ".yml", ".txt"}:
            leaks.extend(find_leaks(p.read_text(), str(p), known))
    return leaks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m auditor.redact")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("redact", help="redact raw JSON captures into fixtures")
    r.add_argument("src", type=Path)
    r.add_argument("dst", type=Path)
    c = sub.add_parser("check", help="fail if a directory still contains real identifiers")
    c.add_argument("root", type=Path)
    args = ap.parse_args(argv)

    if args.cmd == "redact":
        redactor = Redactor.from_env()
        files = sorted(args.src.rglob("*.json"))
        for f in files:
            redactor.redact_json_file(f, args.dst / f.relative_to(args.src))
        leaks = check_dir(args.dst)
        for leak in leaks:
            print(leak, file=sys.stderr)
        print(f"redacted {len(files)} file(s) into {args.dst}; {len(leaks)} leak(s)")
        return 1 if leaks else 0

    leaks = check_dir(args.root)
    for leak in leaks:
        print(leak, file=sys.stderr)
    return 1 if leaks else 0


if __name__ == "__main__":
    raise SystemExit(main())
