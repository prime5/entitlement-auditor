# entitlement-auditor

Audits access on my own cloud accounts: compares **declared** access (Terraform)
with **actual** access (what the cloud APIs report), and reports the drift. It
runs read-only by default, and nothing changes on a real account without my
approval for that specific change. I'm its first user; it runs against a GCP
project that hosts the auditor itself.

Design, decisions and threat model: [`DESIGN.md`](DESIGN.md).

## What works today

| Piece | Where |
|---|---|
| Read-only identity: impersonated service account, no key files; the collector refuses to run as anything else | [`docs/BOOTSTRAP.md`](docs/BOOTSTRAP.md), `auditor/gcp.py` |
| Collector: project IAM, service accounts, key metadata, per-SA policies → common grant model, with a check that no binding member is dropped | `auditor/gcp.py`, `auditor/model.py` |
| Declared state: the real project's IAM in Terraform, adopted with `import` blocks | [`infra/`](infra/) |
| Drift diff: UNDECLARED / MISSING / CONDITION_CHANGED, read from `terraform show -json` | `auditor/declared.py`, `auditor/diff.py` |
| Redaction: real recordings become public test fixtures with no real identifiers (contents *and* file names), enforced by a pre-commit hook and a test | `auditor/redact.py` |

## Evidence from the real project

On 10/28/2026 I added `roles/viewer` to the auditor's service account by hand
with gcloud. **`terraform plan` reported "No changes"**, because
`google_project_iam_member` only tracks the pairs it declares. **The auditor
reported `UNDECLARED project roles/viewer`** and exited 2. Then I reverted the
change and both showed clean. Steps and results: [`docs/DRIFT-DEMO.md`](docs/DRIFT-DEMO.md).

Both states are committed as redacted fixtures, so anyone can reproduce them
without credentials:

```bash
python -m auditor.cli drift fixtures/ fixtures/terraform/plan.json        # drift 0
python -m auditor.cli drift fixtures/demo/ fixtures/terraform/plan.json   # drift 1: roles/viewer
python -m pytest -q
```

## Not built yet

Severity and privilege-escalation rules as policy-as-code (P3, OPA/Rego), the
human-approved remediation flow and audit log (P4), and the rest of the phase
plan in `DESIGN.md` §6.
