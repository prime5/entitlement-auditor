"""Structural diff of declared vs actual grants.

Deliberately dumb: it says *what* differs, never *how bad* it is. Severity
(an unexpected Owner vs a Google service agent) is policy, and policy lives in
one place, Rego, from P3 on (DESIGN.md §2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from auditor.model import Grant

DriftKind = Literal["UNDECLARED", "MISSING", "CONDITION_CHANGED"]


@dataclass(frozen=True)
class Drift:
    kind: DriftKind
    declared: Grant | None
    actual: Grant | None

    @property
    def grant(self) -> Grant:
        return self.actual or self.declared  # type: ignore[return-value]


def _base(g: Grant) -> tuple:
    """Grant identity without the condition: used to pair up condition changes."""
    return g.key()[:-1]


def diff(declared: list[Grant], actual: list[Grant]) -> list[Drift]:
    decl = {g.key(): g for g in declared}
    act = {g.key(): g for g in actual}

    only_decl = [decl[k] for k in decl.keys() - act.keys()]
    only_act = [act[k] for k in act.keys() - decl.keys()]

    # Same principal, role and resource on both sides but different conditions
    # is one change, not one MISSING plus one UNDECLARED. Pair them only when
    # the pairing is unambiguous (exactly one on each side).
    by_base_decl: dict[tuple, list[Grant]] = {}
    by_base_act: dict[tuple, list[Grant]] = {}
    for g in only_decl:
        by_base_decl.setdefault(_base(g), []).append(g)
    for g in only_act:
        by_base_act.setdefault(_base(g), []).append(g)

    drifts: list[Drift] = []
    paired: set[int] = set()
    for base, ds in by_base_decl.items():
        acts = by_base_act.get(base, [])
        if len(ds) == 1 and len(acts) == 1:
            drifts.append(Drift("CONDITION_CHANGED", ds[0], acts[0]))
            paired |= {id(ds[0]), id(acts[0])}

    drifts += [Drift("MISSING", g, None) for g in only_decl if id(g) not in paired]
    drifts += [Drift("UNDECLARED", None, g) for g in only_act if id(g) not in paired]
    return sorted(drifts, key=lambda d: (d.kind, d.grant.key()))
