"""GCP collector: record raw API responses (read-only), then normalize them offline.

Two halves, deliberately separate:

  record(session, project, out_dir)  -> talks to Google, writes raw/ JSON. Needs credentials.
  normalize(raw_dir)                 -> pure function over files. No network, fully testable.

Tests only ever exercise `normalize` on recorded fixtures, and `record` through a
fake session. So the suite runs offline and never needs a credential.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from auditor.model import (
    Condition,
    Credential,
    Evidence,
    Grant,
    Principal,
    Resource,
    UnknownPrincipal,
)

CRM = "https://cloudresourcemanager.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
EXPECTED_IDENTITY_PREFIX = "auditor-reader@"

# Google service agents: identities Google creates and operates on your behalf.
# Classified as managed_by="google" so P3 can suppress them as expected.
# NOTE: default service accounts (NNN-compute@developer..., PROJECT@appspot...)
# are NOT here: Google creates them, but your workloads run as them, so their
# grants are yours to audit (DESIGN.md worked example, row 2).
_SERVICE_AGENT = re.compile(
    r"^(service-\d+@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com"
    r"|\d+@cloudservices\.gserviceaccount\.com"
    r"|service-\d+@[a-z0-9-]+\.iam\.gserviceaccount\.com"
    r"|[a-z0-9-]+@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com)$"
)


# ---------------------------------------------------------------- identity guard


class WrongIdentity(RuntimeError):
    pass


def assert_reader_identity(credentials: Any) -> str:
    """Refuse to run unless ADC is impersonating auditor-reader.

    With plain `gcloud auth application-default login`, ADC is *you* (Owner).
    The collector would still work, which is the danger: an audit tool quietly
    running with write power. Impersonated ADC exposes the target SA's email as
    `service_account_email`; user credentials don't have that attribute at all.
    """
    email = getattr(credentials, "service_account_email", None) or getattr(
        credentials, "_target_principal", None
    )
    if not email or not str(email).startswith(EXPECTED_IDENTITY_PREFIX):
        raise WrongIdentity(
            f"collector must run as {EXPECTED_IDENTITY_PREFIX}…, got {email or 'a user credential'}. "
            "Run: gcloud auth application-default login --impersonate-service-account=$SA"
        )
    return str(email)


# ---------------------------------------------------------------- record (network)


class Session(Protocol):
    def get(self, url: str, **kw: Any) -> Any: ...
    def post(self, url: str, **kw: Any) -> Any: ...


def _json(resp: Any) -> dict:
    resp.raise_for_status()
    return resp.json()


def _write(out: Path, name: str, data: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / name).write_text(json.dumps(data, indent=2, sort_keys=True))


def _safe(email: str) -> str:
    return email.replace("@", "_at_")


def record(session: Session, project: str, out_dir: Path) -> dict[str, int]:
    """Read-only calls only. Every request here is a get/list/getIamPolicy."""
    out = out_dir / "gcp"
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # requestedPolicyVersion 3: without it, conditional bindings come back
    # degraded, which would hide exactly the grants that need the closest look.
    policy = _json(
        session.post(
            f"{CRM}/projects/{project}:getIamPolicy",
            json={"options": {"requestedPolicyVersion": 3}},
        )
    )
    _write(out, "project_iam_policy.json", {"observed_at": observed_at, "project": project, "policy": policy})

    accounts: list[dict] = []
    token = None
    while True:  # paginate: never assume one page
        params = {"pageSize": 100, **({"pageToken": token} if token else {})}
        page = _json(session.get(f"{IAM}/projects/{project}/serviceAccounts", params=params))
        accounts += page.get("accounts", [])
        token = page.get("nextPageToken")
        if not token:
            break
    _write(out, "service_accounts.json", {"observed_at": observed_at, "accounts": accounts})

    for sa in accounts:
        email = sa["email"]
        keys = _json(
            session.get(
                f"{IAM}/projects/{project}/serviceAccounts/{email}/keys",
                params={"keyTypes": "USER_MANAGED"},
            )
        )
        sa_policy = _json(
            session.post(
                f"{IAM}/projects/{project}/serviceAccounts/{email}:getIamPolicy",
                params={"options.requestedPolicyVersion": 3},
            )
        )
        _write(out / "sa", f"{_safe(email)}.json", {
            "observed_at": observed_at, "email": email, "keys": keys.get("keys", []), "policy": sa_policy,
        })

    return {"bindings": len(policy.get("bindings", [])), "service_accounts": len(accounts)}


# ---------------------------------------------------------------- normalize (pure)


def parse_member(member: str) -> tuple[Principal, str]:
    """'user:a@b.com' -> (Principal(user, a@b.com), managed_by)."""
    if member in ("allUsers", "allAuthenticatedUsers"):
        return Principal("public", member), "user"
    if member.startswith(("principal://", "principalSet://")):
        return Principal("federated", member), "user"
    if member.startswith("deleted:"):
        return Principal("deleted", member.removeprefix("deleted:")), "user"

    kind, sep, ident = member.partition(":")
    if not sep or not ident:
        raise UnknownPrincipal(member)
    if kind == "serviceAccount":
        return Principal("serviceAccount", ident), ("google" if _SERVICE_AGENT.match(ident) else "user")
    if kind in ("user", "group", "domain"):
        return Principal(kind, ident), "user"  # type: ignore[arg-type]
    raise UnknownPrincipal(member)


def _grants_from_policy(policy: dict, resource: Resource, api: str, observed_at: str) -> list[Grant]:
    evidence = Evidence(api=api, observed_at=observed_at, etag=policy.get("etag"))
    grants = []
    for binding in policy.get("bindings", []):
        cond = binding.get("condition")
        condition = Condition(cond.get("title", ""), cond["expression"]) if cond else None
        for member in binding.get("members", []):
            principal, managed_by = parse_member(member)
            grants.append(Grant("gcp", principal, resource, binding["role"], condition, "direct", managed_by, evidence))
    return grants


class IncompleteInventory(RuntimeError):
    pass


def _check_complete(policy: dict, produced: int, where: str) -> None:
    """Every (binding, member) pair must become exactly one grant (threat model T3)."""
    expected = sum(len(b.get("members", [])) for b in policy.get("bindings", []))
    if expected != produced:
        raise IncompleteInventory(f"{where}: {expected} binding members but {produced} grants")


def normalize(raw_dir: Path) -> tuple[list[Grant], list[Credential]]:
    root = raw_dir / "gcp"
    proj = json.loads((root / "project_iam_policy.json").read_text())
    project, policy = proj["project"], proj["policy"]

    project_res = Resource("project", f"//cloudresourcemanager.googleapis.com/projects/{project}")
    grants = _grants_from_policy(policy, project_res, "projects.getIamPolicy", proj["observed_at"])
    _check_complete(policy, len(grants), "project policy")

    credentials: list[Credential] = []
    for f in sorted((root / "sa").glob("*.json")) if (root / "sa").exists() else []:
        rec = json.loads(f.read_text())
        email = rec["email"]
        sa_res = Resource("serviceAccount", f"//iam.googleapis.com/projects/{project}/serviceAccounts/{email}")
        sa_grants = _grants_from_policy(rec["policy"], sa_res, "serviceAccounts.getIamPolicy", rec["observed_at"])
        _check_complete(rec["policy"], len(sa_grants), f"policy on {email}")
        grants += sa_grants

        owner = Principal("serviceAccount", email)
        for k in rec["keys"]:
            expires = k.get("validBeforeTime")
            credentials.append(Credential(
                principal=owner,
                kind="saKey",
                id=k["name"].rsplit("/", 1)[-1],
                created=k.get("validAfterTime"),
                # Google uses 9999-12-31 for "never expires"
                expires=None if (expires or "").startswith("9999") else expires,
                disabled=bool(k.get("disabled", False)),
            ))

    return grants, credentials
