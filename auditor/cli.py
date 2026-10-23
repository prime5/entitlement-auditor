"""Command line.

    python -m auditor.cli record                 # live, read-only, as auditor-reader -> raw/
    python -m auditor.cli inventory raw/         # offline: print normalized grants + keys
    python -m auditor.cli inventory fixtures/    # same, on redacted recordings
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from auditor import gcp


def _load_dotenv(path: Path = Path(".env")) -> None:
    if path.exists():
        for line in path.read_text().splitlines():
            k, sep, v = line.partition("=")
            if sep and not line.lstrip().startswith("#"):
                os.environ.setdefault(k.strip(), v.strip())


def cmd_record(out: Path) -> int:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    project = os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT")
    if not project:
        raise SystemExit("GOOGLE_CLOUD_QUOTA_PROJECT not set (see docs/BOOTSTRAP.md §6)")

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    who = gcp.assert_reader_identity(creds)  # before any API call
    print(f"recording {project} as {who.split('@')[0]}@… -> {out}/")
    counts = gcp.record(AuthorizedSession(creds), project, out)
    print(f"done: {counts['bindings']} project bindings, {counts['service_accounts']} service accounts")
    return 0


def cmd_inventory(raw: Path) -> int:
    grants, keys = gcp.normalize(raw)
    print(f"{len(grants)} grants")
    for g in sorted(grants, key=lambda g: (g.resource.type, g.role, g.principal.id)):
        tag = " [google-managed]" if g.managed_by == "google" else ""
        cond = f" if:{g.condition.title}" if g.condition else ""
        print(f"  {g.resource.type:15} {g.role:45} {g.principal.type}:{g.principal.id}{cond}{tag}")
    print(f"{len(keys)} user-managed keys")
    for k in keys:
        print(f"  {k.principal.id} key {k.id[:8]}… created {k.created} expires {k.expires or 'never'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    ap = argparse.ArgumentParser(prog="python -m auditor.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    r.add_argument("--out", type=Path, default=Path("raw"))
    i = sub.add_parser("inventory")
    i.add_argument("dir", type=Path)
    args = ap.parse_args(argv)
    return cmd_record(args.out) if args.cmd == "record" else cmd_inventory(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
