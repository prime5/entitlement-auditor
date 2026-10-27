"""Declared (Terraform plan JSON) vs actual (recorded IAM), all offline."""

import json
from pathlib import Path

import pytest

from auditor import gcp
from auditor.cli import main
from auditor.declared import UnsupportedDeclaration, load_plan
from auditor.diff import diff

DATA = Path(__file__).parent / "data"
ROOT = Path(__file__).resolve().parent.parent
P = "proj-a1b2c3"
READER = f"auditor-reader@{P}.iam.gserviceaccount.com"


@pytest.fixture
def drifts():
    actual, _ = gcp.normalize(DATA / "sample_raw")
    return diff(load_plan(DATA / "sample_plan.json"), actual)


def _kinds(drifts):
    return sorted((d.kind, d.grant.role, d.grant.principal.id.lower()) for d in drifts)


# ----------------------------------------------------------- loader

def test_loader_resolves_for_each_and_child_modules():
    grants = load_plan(DATA / "sample_plan.json")
    # 4 root IAM members + 3 inside module.reader_roles; the google_service_account itself is not a grant
    assert len(grants) == 7
    assert {g.role for g in grants if g.principal.id == READER} >= {
        "roles/iam.securityReviewer", "roles/policyanalyzer.activityAnalysisViewer",
        "roles/serviceusage.serviceUsageConsumer",
    }


def test_sa_level_grant_lands_on_the_sa_resource():
    tc = [g for g in load_plan(DATA / "sample_plan.json") if g.role == "roles/iam.serviceAccountTokenCreator"]
    assert tc[0].resource.name == f"//iam.googleapis.com/projects/{P}/serviceAccounts/{READER}"


def _plan_with(resource: dict, tmp_path: Path) -> Path:
    p = tmp_path / "plan.json"
    p.write_text(json.dumps({"planned_values": {"root_module": {"resources": [resource]}}}))
    return p


def test_binding_resources_expand_to_one_grant_per_member(tmp_path):
    plan = _plan_with({"address": "a", "type": "google_project_iam_binding", "values": {
        "project": P, "role": "roles/viewer", "members": ["user:a@example.com", "group:g@example.com"]}}, tmp_path)
    assert len(load_plan(plan)) == 2


@pytest.mark.parametrize("rtype", ["google_project_iam_policy", "google_storage_bucket_iam_member"])
def test_unmodeled_iam_type_fails_closed(rtype, tmp_path):
    plan = _plan_with({"address": "x", "type": rtype, "values": {}}, tmp_path)
    with pytest.raises(UnsupportedDeclaration):
        load_plan(plan)


def test_value_unknown_until_apply_fails_closed(tmp_path):
    # e.g. member = "serviceAccount:${google_service_account.new.email}" for an SA not yet created
    plan = _plan_with({"address": "x", "type": "google_project_iam_member",
                       "values": {"project": P, "role": "roles/viewer", "member": None}}, tmp_path)
    with pytest.raises(UnsupportedDeclaration, match="unknown until apply"):
        load_plan(plan)


def test_non_iam_resources_are_ignored(tmp_path):
    plan = _plan_with({"address": "s", "type": "google_project_service", "values": {"service": "iam.googleapis.com"}}, tmp_path)
    assert load_plan(plan) == []


# ----------------------------------------------------------- diff

def test_each_planted_drift_is_found(drifts):
    assert _kinds(drifts) == sorted([
        ("CONDITION_CHANGED", "roles/storage.objectViewer", "user-1a2b3c@example.com"),
        ("MISSING", "roles/logging.viewer", READER),
        ("UNDECLARED", "roles/editor", "000123456789-compute@developer.gserviceaccount.com"),
        ("UNDECLARED", "roles/editor", "000123456789@cloudservices.gserviceaccount.com"),
        ("UNDECLARED", "roles/pubsub.serviceAgent", "service-000123456789@gcp-sa-pubsub.iam.gserviceaccount.com"),
    ])


def test_owner_declared_with_different_case_is_not_drift(drifts):
    """Declared 'User-1A2B3C@…', IAM returns 'user-1a2b3c@…': same principal (P2.1 fix)."""
    assert not [d for d in drifts if d.grant.role == "roles/owner"]


def test_worked_example_default_sa_editor_is_undeclared(drifts):
    """DESIGN.md §2 row 2: the grant `terraform plan` can't see, because *_iam_member only tracks its own pairs."""
    d = [d for d in drifts if d.grant.role == "roles/editor" and d.grant.managed_by == "user"]
    assert len(d) == 1 and d[0].kind == "UNDECLARED" and d[0].declared is None


def test_condition_change_is_one_drift_not_two(drifts):
    viewer = [d for d in drifts if d.grant.role == "roles/storage.objectViewer"]
    assert len(viewer) == 1
    assert viewer[0].declared.condition.title == "until-2026-11-30"
    assert viewer[0].actual.condition.title == "until-2026-12-31"


def test_identical_sides_have_no_drift():
    actual, _ = gcp.normalize(DATA / "sample_raw")
    assert diff(actual, actual) == []


def test_cli_exit_code_signals_drift(capsys):
    assert main(["drift", str(DATA / "sample_raw"), str(DATA / "sample_plan.json")]) == 2
    assert "drift 3" in capsys.readouterr().out  # 2 google-managed listed but not counted


# ----------------------------------------------------------- the real project

REAL_PLAN = ROOT / "fixtures" / "terraform" / "plan.json"


@pytest.mark.skipif(not REAL_PLAN.exists(), reason="record fixtures/terraform/plan.json (infra/README.md)")
def test_real_project_matches_its_declaration():
    """Real recording vs real Terraform plan, both redacted with the same salt: no drift."""
    actual, _ = gcp.normalize(ROOT / "fixtures")
    assert diff(load_plan(REAL_PLAN), actual) == []
