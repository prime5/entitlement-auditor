"""Collector tests. All offline: normalize runs on a recorded sample, record runs on a fake session."""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditor import gcp
from auditor.model import Principal, UnknownPrincipal

SAMPLE = Path(__file__).parent / "data" / "sample_raw"
P = "proj-a1b2c3"
READER = f"auditor-reader@{P}.iam.gserviceaccount.com"
COMPUTE = "000123456789-compute@developer.gserviceaccount.com"


# ----------------------------------------------------------- member parsing

@pytest.mark.parametrize("member, ptype, managed", [
    ("user:user-1@example.com", "user", "user"),
    ("group:g@example.com", "group", "user"),
    ("domain:org-1.test", "domain", "user"),
    (f"serviceAccount:{READER}", "serviceAccount", "user"),
    # default SA: Google-created, but your workloads run as it -> yours to audit
    (f"serviceAccount:{COMPUTE}", "serviceAccount", "user"),
    ("serviceAccount:service-000123456789@gcp-sa-pubsub.iam.gserviceaccount.com", "serviceAccount", "google"),
    ("serviceAccount:000123456789@cloudservices.gserviceaccount.com", "serviceAccount", "google"),
    ("allUsers", "public", "user"),
    ("allAuthenticatedUsers", "public", "user"),
    ("principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*", "federated", "user"),
    ("deleted:serviceAccount:old@x.iam.gserviceaccount.com?uid=123", "deleted", "user"),
])
def test_parse_member(member, ptype, managed):
    principal, managed_by = gcp.parse_member(member)
    assert principal.type == ptype and managed_by == managed


@pytest.mark.parametrize("member", ["", "user:", "someNewType:x", "noColon"])
def test_unknown_member_fails_closed(member):
    with pytest.raises(UnknownPrincipal):
        gcp.parse_member(member)


# ----------------------------------------------------------- normalize

@pytest.fixture
def inventory():
    return gcp.normalize(SAMPLE)


def test_every_binding_member_becomes_one_grant(inventory):
    grants, _ = inventory
    # 7 project bindings with 8 members total, plus 1 grant on the reader SA's own policy
    assert len(grants) == 9


def test_reader_has_exactly_its_three_roles(inventory):
    grants, _ = inventory
    reader_roles = {g.role for g in grants if g.principal == Principal("serviceAccount", READER)}
    assert reader_roles == {
        "roles/iam.securityReviewer",
        "roles/policyanalyzer.activityAnalysisViewer",
        "roles/serviceusage.serviceUsageConsumer",
    }


def test_token_creator_is_on_the_sa_not_the_project(inventory):
    """The bootstrap invariant from BOOTSTRAP.md §3, now checkable from data."""
    grants, _ = inventory
    tc = [g for g in grants if g.role == "roles/iam.serviceAccountTokenCreator"]
    assert len(tc) == 1
    assert tc[0].resource.type == "serviceAccount" and tc[0].resource.name.endswith(READER)


def test_service_agents_marked_google_managed(inventory):
    grants, _ = inventory
    google = {g.principal.id for g in grants if g.managed_by == "google"}
    assert google == {
        "service-000123456789@gcp-sa-pubsub.iam.gserviceaccount.com",
        "000123456789@cloudservices.gserviceaccount.com",
    }


def test_condition_is_part_of_grant_identity(inventory):
    grants, _ = inventory
    cond = [g for g in grants if g.condition]
    assert len(cond) == 1 and cond[0].key()[-1] != ""


def test_equality_ignores_evidence(inventory):
    grants, _ = inventory
    g = grants[0]
    again = gcp.Grant(g.system, g.principal, g.resource, g.role, g.condition, g.origin, g.managed_by,
                      gcp.Evidence("other", "2030-01-01", None))
    assert again == g and len({g, again}) == 1


def test_keys_normalized_with_never_expiring_as_none(inventory):
    _, keys = inventory
    assert len(keys) == 1
    k = keys[0]
    assert k.principal.id == COMPUTE and k.id == "abcdef0123456789" and k.expires is None


def test_dropped_member_is_detected(tmp_path):
    """Simulates a normalizer bug: the completeness check must catch it, not pass silently."""
    shutil.copytree(SAMPLE, tmp_path / "raw")
    bad = gcp._grants_from_policy
    try:
        gcp._grants_from_policy = lambda *a: bad(*a)[1:]  # drop one grant
        with pytest.raises(gcp.IncompleteInventory):
            gcp.normalize(tmp_path / "raw")
    finally:
        gcp._grants_from_policy = bad


# ----------------------------------------------------------- identity guard

def test_refuses_user_credentials():
    with pytest.raises(gcp.WrongIdentity):
        gcp.assert_reader_identity(SimpleNamespace())  # user creds: no SA email at all


def test_refuses_other_service_account():
    with pytest.raises(gcp.WrongIdentity):
        gcp.assert_reader_identity(SimpleNamespace(service_account_email=f"admin@{P}.iam.gserviceaccount.com"))


def test_accepts_reader():
    assert gcp.assert_reader_identity(SimpleNamespace(service_account_email=READER)) == READER


# ----------------------------------------------------------- record (fake session)

class FakeSession:
    """Serves the sample files as if they were the Google APIs, and records every call."""

    def __init__(self):
        root = SAMPLE / "gcp"
        self.policy = json.loads((root / "project_iam_policy.json").read_text())["policy"]
        self.accounts = json.loads((root / "service_accounts.json").read_text())["accounts"]
        self.calls: list[tuple[str, str]] = []

    def _resp(self, data):
        return SimpleNamespace(json=lambda: data, raise_for_status=lambda: None)

    def get(self, url, **kw):
        self.calls.append(("GET", url))
        if url.endswith("/serviceAccounts"):
            # two pages, to prove pagination is followed
            if (kw.get("params") or {}).get("pageToken"):
                return self._resp({"accounts": self.accounts[1:]})
            return self._resp({"accounts": self.accounts[:1], "nextPageToken": "p2"})
        if url.endswith("/keys"):
            return self._resp({"keys": []})
        raise AssertionError(f"unexpected GET {url}")

    def post(self, url, **kw):
        self.calls.append(("POST", url))
        if url.endswith(":getIamPolicy"):
            return self._resp(self.policy if "cloudresourcemanager" in url else {"etag": "x"})
        raise AssertionError(f"unexpected POST {url}")


def test_record_is_read_only_and_paginates(tmp_path):
    s = FakeSession()
    counts = gcp.record(s, P, tmp_path)
    assert counts == {"bindings": 7, "service_accounts": 2}
    # Every POST must be a getIamPolicy; anything else would be a write.
    assert all(url.endswith(":getIamPolicy") for method, url in s.calls if method == "POST")
    assert len(list((tmp_path / "gcp" / "sa").glob("*.json"))) == 2


def test_record_then_normalize_round_trip(tmp_path):
    gcp.record(FakeSession(), P, tmp_path)
    grants, _ = gcp.normalize(tmp_path)
    assert len(grants) == 8  # project grants only; the fake returns empty SA policies


# ----------------------------------------------------------- comparison key

def _grant(member: str):
    principal, managed_by = gcp.parse_member(member)
    res = gcp.Resource("project", f"//cloudresourcemanager.googleapis.com/projects/{P}")
    return gcp.Grant("gcp", principal, res, "roles/owner", None, "direct", managed_by,
                     gcp.Evidence("test", "2026-10-26", None))


def test_email_case_does_not_change_grant_key():
    """Real case from 10/22: IAM returned the Owner email capitalized; Terraform declares it lowercase."""
    from_iam = _grant("user:First.Last@example.com")
    from_terraform = _grant("user:first.last@example.com")
    assert from_iam.key() == from_terraform.key()
    assert from_iam.principal.id == "First.Last@example.com"  # display keeps Google's spelling


def test_federated_identities_stay_case_sensitive():
    # principal:// subjects come from an external IdP; their case can be significant
    a = _grant("principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/Alice")
    b = _grant("principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/alice")
    assert a.key() != b.key()


def test_real_recording_normalizes():
    """The committed, redacted recording of the real project (P1.3) keeps parsing."""
    grants, keys = gcp.normalize(Path(__file__).resolve().parent.parent / "fixtures")
    assert len(grants) == 5 and keys == []
    assert {g.resource.type for g in grants} == {"project", "serviceAccount"}
