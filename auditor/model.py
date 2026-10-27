"""Common data model: grants (who can do what where) and credentials (how a principal proves itself).

Everything is a frozen dataclass: once normalized, a grant is a value, not an
object you mutate. That makes grants hashable, so the P2 diff is set arithmetic.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

PrincipalType = Literal[
    "user",
    "serviceAccount",
    "group",
    "domain",
    "public",          # allUsers / allAuthenticatedUsers
    "federated",       # principal:// and principalSet:// (workload/workforce identity)
    "deleted",         # deleted:user:..., deleted:serviceAccount:...
]
ManagedBy = Literal["user", "google"]


class UnknownPrincipal(ValueError):
    """Raised for a member string we can't classify.

    Failing closed is deliberate (threat model T3): a principal type we've never
    seen is exactly the case where silently skipping it would hide access.
    """


@dataclass(frozen=True)
class Principal:
    type: PrincipalType
    id: str  # the member string without its type prefix, e.g. an email; kept as Google returned it

    # Email-shaped identities compare case-insensitively. Found on the first real
    # recording (10/22): IAM returns `user:First.Last@gmail.com` even though the
    # binding was created as `first.last@gmail.com`, and Terraform declares it
    # lowercase. Comparing raw strings would report the same Owner grant as both
    # "undeclared" and "missing". `id` keeps Google's spelling for display; only
    # the comparison key is normalized.
    _CASE_INSENSITIVE = frozenset({"user", "group", "serviceAccount", "domain", "deleted"})

    def key_id(self) -> str:
        return self.id.lower() if self.type in self._CASE_INSENSITIVE else self.id


@dataclass(frozen=True)
class Resource:
    type: Literal["project", "serviceAccount"]
    name: str  # Cloud Asset full resource name


@dataclass(frozen=True)
class Condition:
    title: str
    expression: str

    def digest(self) -> str:
        return hashlib.sha256(f"{self.title}\0{self.expression}".encode()).hexdigest()[:12]


@dataclass(frozen=True)
class Evidence:
    api: str
    observed_at: str  # ISO-8601 UTC
    etag: str | None


@dataclass(frozen=True)
class Grant:
    system: Literal["gcp"]
    principal: Principal
    resource: Resource
    role: str
    condition: Condition | None
    origin: str  # "direct" in P1; inherited/viaGroup arrive with orgs and groups
    managed_by: ManagedBy
    # Evidence and last_used describe *how we saw it*, not *what it is*, so they
    # are excluded from equality: the same grant observed twice is one grant.
    evidence: Evidence = field(compare=False)
    last_used: dict | None = field(default=None, compare=False)  # None = unknown, never "unused"

    def key(self) -> tuple[str, str, str, str, str, str]:
        """Identity of a grant for the declared-vs-actual diff (DESIGN.md §2)."""
        return (
            self.system,
            self.resource.name,
            self.principal.type,
            self.principal.key_id(),
            self.role,
            self.condition.digest() if self.condition else "",
        )


@dataclass(frozen=True)
class Credential:
    principal: Principal
    kind: Literal["saKey"]
    id: str
    created: str | None
    expires: str | None  # None = never expires
    disabled: bool
    last_auth: dict | None = field(default=None, compare=False)


def to_json(objs: list[Grant] | list[Credential]) -> str:
    from dataclasses import asdict

    return json.dumps([asdict(o) for o in objs], indent=2, sort_keys=True)
