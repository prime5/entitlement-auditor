"""Declared state: read grants out of `terraform show -json <planfile>`.

Why the plan JSON and not the .tf files: HCL has variables, for_each and
references (`google_service_account.reader.email`). The plan JSON has all of
that already resolved to concrete values, so this module never evaluates HCL.

Why `planned_values` and not `prior_state`: planned_values is what the
configuration says *should* exist after apply, which is the definition of
"declared". prior_state is what Terraform last saw, which is closer to "actual"
and would hide config changes not yet applied.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from auditor.gcp import parse_member
from auditor.model import Condition, Evidence, Grant, Resource


class UnsupportedDeclaration(ValueError):
    """An IAM resource type this loader doesn't model.

    Fail closed (threat model T3): silently skipping, say, a
    google_project_iam_policy would make declared state look smaller than it is,
    and everything it grants would be reported as undeclared drift (or worse,
    an authoritative policy's removals would go unnoticed).
    """


SUPPORTED = {
    "google_project_iam_member",
    "google_project_iam_binding",
    "google_service_account_iam_member",
    "google_service_account_iam_binding",
}


def _walk(module: dict) -> Iterator[dict]:
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk(child)


def _condition(values: dict) -> Condition | None:
    conds = values.get("condition") or []
    if not conds:
        return None
    c = conds[0]
    return Condition(c.get("title", ""), c["expression"])


def _require(values: dict, field: str, address: str) -> Any:
    if values.get(field) in (None, ""):
        # A value Terraform can't know until apply (e.g. the email of a service
        # account not yet created). We can't diff what we can't see.
        raise UnsupportedDeclaration(f"{address}: '{field}' is unknown until apply")
    return values[field]


def _resource(rtype: str, values: dict, address: str) -> Resource:
    if rtype.startswith("google_project_"):
        project = _require(values, "project", address)
        return Resource("project", f"//cloudresourcemanager.googleapis.com/projects/{project}")
    sa = _require(values, "service_account_id", address)
    if not sa.startswith("projects/") or "/serviceAccounts/" not in sa:
        raise UnsupportedDeclaration(f"{address}: use the SA's .name (projects/P/serviceAccounts/EMAIL), got {sa!r}")
    return Resource("serviceAccount", f"//iam.googleapis.com/{sa}")


def load_plan(plan_json: Path) -> list[Grant]:
    plan = json.loads(plan_json.read_text())
    evidence = Evidence(api="terraform show -json", observed_at=plan.get("timestamp", ""), etag=None)
    grants: list[Grant] = []

    for r in _walk(plan.get("planned_values", {}).get("root_module", {})):
        rtype, address, values = r["type"], r["address"], r.get("values", {})
        if "_iam_" not in rtype:
            continue  # not access: service accounts, APIs, buckets themselves
        if rtype not in SUPPORTED:
            raise UnsupportedDeclaration(f"{address}: IAM resource type {rtype} is not modeled")

        resource = _resource(rtype, values, address)
        role = _require(values, "role", address)
        members = [_require(values, "member", address)] if rtype.endswith("_member") else _require(values, "members", address)
        for member in members:
            principal, managed_by = parse_member(member)
            grants.append(Grant("gcp", principal, resource, role, _condition(values), "direct", managed_by, evidence))

    return grants
