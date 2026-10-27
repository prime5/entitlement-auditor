"""Redaction must be complete, deterministic, structure-preserving and fail closed.

The sample below has the shape of a real projects.getIamPolicy response, with
made-up "real" values standing in for the ones you'd see on your project.
"""

import json
from pathlib import Path

import pytest

from auditor.redact import Redactor, RedactionError, check_dir, find_leaks, main

REAL_ID = "pram-auditor-7731"
REAL_NUM = "482915736201"
REAL_USER = "someone.real@gmail.com"

RAW_POLICY = {
    "bindings": [
        {"role": "roles/owner", "members": [f"user:{REAL_USER}"]},
        {
            "role": "roles/editor",
            "members": [f"serviceAccount:{REAL_NUM}-compute@developer.gserviceaccount.com"],
        },
        {
            "role": "roles/iam.securityReviewer",
            "members": [f"serviceAccount:auditor-reader@{REAL_ID}.iam.gserviceaccount.com"],
        },
        {
            "role": "roles/pubsub.serviceAgent",
            "members": [f"serviceAccount:service-{REAL_NUM}@gcp-sa-pubsub.iam.gserviceaccount.com"],
        },
        {"role": "roles/viewer", "members": ["domain:realcompany.org"]},
    ],
    "etag": "BwX1abc=",
    "resource": f"//cloudresourcemanager.googleapis.com/projects/{REAL_ID}",
    "parent": f"projects/{REAL_NUM}",
}


@pytest.fixture
def redactor() -> Redactor:
    return Redactor(
        salt=b"test-salt-not-a-secret-0123456789",
        project_ids=(REAL_ID,),
        project_numbers=(REAL_NUM,),
    )


def test_no_real_value_survives(redactor):
    out = redactor.redact_text(json.dumps(RAW_POLICY))
    for real in (REAL_ID, REAL_NUM, REAL_USER, "realcompany.org"):
        assert real not in out


def test_structure_survives(redactor):
    out = json.loads(redactor.redact_text(json.dumps(RAW_POLICY)))
    members = [m for b in out["bindings"] for m in b["members"]]
    # Principal type prefixes and Google SA domains are what the collector
    # classifies on, so they must come through untouched.
    assert members[0].startswith("user:user-") and members[0].endswith("@example.com")
    assert members[1].endswith("-compute@developer.gserviceaccount.com")
    assert members[2].startswith("serviceAccount:auditor-reader@proj-")
    assert "@gcp-sa-pubsub.iam.gserviceaccount.com" in members[3]
    assert members[4].startswith("domain:org-") and members[4].endswith(".test")
    assert out["etag"] == "BwX1abc="  # etags aren't identifying; keep them for P4 tests


def test_same_value_same_token_across_files(redactor):
    # The default compute SA appears in the policy and would appear in
    # serviceAccounts.list; both must redact to the same string.
    a = redactor.redact_text(f"{REAL_NUM}-compute@developer.gserviceaccount.com")
    b = redactor.redact_text(f'{{"email": "{REAL_NUM}-compute@developer.gserviceaccount.com"}}')
    assert a in b


def test_pseudo_number_is_recognisable_and_twelve_digits(redactor):
    n = redactor.pseudo_number(REAL_NUM)
    assert n.startswith("000") and len(n) == 12 and n.isdigit()


def test_number_inside_a_longer_number_is_not_rewritten(redactor):
    longer = f"9{REAL_NUM}9"
    assert redactor.redact_text(longer) == longer


def test_redacted_output_passes_check(redactor):
    out = redactor.redact_text(json.dumps(RAW_POLICY, indent=2))
    assert find_leaks(out) == []


def test_check_catches_raw_data_without_knowing_real_values():
    # No env, no known values: shape alone must flag every leak class.
    reasons = {leak.reason for leak in find_leaks(json.dumps(RAW_POLICY, indent=2))}
    assert "non-redacted email domain 'gmail.com'" in reasons
    assert "project number outside pseudo range" in reasons
    assert "non-redacted domain: principal" in reasons


def test_check_flags_known_values_from_env(tmp_path, monkeypatch):
    # A project ID never appears in a "shape" the structural check knows,
    # e.g. a bare label value. The env-driven check is what catches that.
    (tmp_path / "labels.json").write_text(json.dumps({"label": REAL_ID}))
    monkeypatch.setenv("AUDITOR_PROJECT_IDS", REAL_ID)
    assert [l.reason for l in check_dir(tmp_path)] == ["known real identifier present"]


def test_missing_salt_fails_closed(monkeypatch):
    monkeypatch.delenv("AUDITOR_REDACTION_SALT", raising=False)
    with pytest.raises(RedactionError):
        Redactor.from_env()


def test_cli_redacts_a_directory_end_to_end(tmp_path, monkeypatch):
    raw, fixtures = tmp_path / "raw", tmp_path / "fixtures"
    (raw / "gcp").mkdir(parents=True)
    (raw / "gcp" / "project_iam_policy.json").write_text(json.dumps(RAW_POLICY))
    monkeypatch.setenv("AUDITOR_REDACTION_SALT", "local-salt-0123456789abcdef")
    monkeypatch.setenv("AUDITOR_PROJECT_IDS", REAL_ID)
    monkeypatch.setenv("AUDITOR_PROJECT_NUMBERS", REAL_NUM)

    assert main(["redact", str(raw), str(fixtures)]) == 0
    assert main(["check", str(fixtures)]) == 0
    assert (fixtures / "gcp" / "project_iam_policy.json").exists()


def test_numeric_sa_ids_are_redacted_consistently(redactor):
    """Found 10/26: the reader's uniqueId/oauth2ClientId survived redaction in service_accounts.json."""
    real = "111794503432940811892"
    api = json.dumps({"uniqueId": real, "oauth2ClientId": real})
    tf = json.dumps({"unique_id": real})
    out_api, out_tf = redactor.redact_text(api), redactor.redact_text(tf)
    assert real not in out_api + out_tf
    pseudo = json.loads(out_api)["uniqueId"]
    assert pseudo.startswith("000") and len(pseudo) == len(real)
    assert json.loads(out_api)["oauth2ClientId"] == pseudo == json.loads(out_tf)["unique_id"]
    assert find_leaks(out_api) == [] and find_leaks(out_tf) == []


def test_check_flags_raw_numeric_sa_id():
    reasons = [l.reason for l in find_leaks('{"uniqueId": "111794503432940811892"}')]
    assert reasons == ["non-redacted numeric ID 'uniqueId'"]


def test_file_names_are_redacted_and_checked(tmp_path, monkeypatch):
    """Found on the first real recording (10/22): sa/<email>.json kept the real project ID in its name."""
    raw, fixtures = tmp_path / "raw", tmp_path / "fixtures"
    sa_file = raw / "gcp" / "sa" / f"auditor-reader_at_{REAL_ID}.iam.gserviceaccount.com.json"
    sa_file.parent.mkdir(parents=True)
    sa_file.write_text(json.dumps({"email": f"auditor-reader@{REAL_ID}.iam.gserviceaccount.com"}))
    monkeypatch.setenv("AUDITOR_REDACTION_SALT", "local-salt-0123456789abcdef")
    monkeypatch.setenv("AUDITOR_PROJECT_IDS", REAL_ID)

    # the check alone must flag a real ID in a file name...
    assert any("file name" in l.reason for l in check_dir(raw))
    # ...and redact must produce names that pass it
    assert main(["redact", str(raw), str(fixtures)]) == 0
    names = [p.name for p in fixtures.rglob("*.json")]
    assert len(names) == 1 and REAL_ID not in names[0] and names[0].startswith("auditor-reader_at_proj-")


@pytest.mark.parametrize("rel", ["fixtures", "tests/data"])
def test_committed_data_is_clean(rel):
    """Same check as the pre-commit hook, so CI enforces it even if the hook is skipped."""
    root = Path(__file__).resolve().parent.parent / rel
    assert [str(l) for l in check_dir(root)] == []
