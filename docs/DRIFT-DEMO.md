# Drift demo: the grant `terraform plan` can't see

DESIGN.md's central claim, reproduced on the real project:

> `google_project_iam_member` only tracks its own (role, member) pair. A grant
> added outside Terraform is invisible to `terraform plan`. The auditor diffs
> the **whole** policy, so it catches it.

Every step is reversible, and step 5 reverses it. Run from the repo root.

## 1. Baseline: clean

```bash
.venv/bin/python -m auditor.cli record
(cd infra && terraform plan -out=plan.out && terraform show -json plan.out > ../raw/terraform/plan.json)
.venv/bin/python -m auditor.cli drift raw/ raw/terraform/plan.json; echo "exit=$?"
```
Expect: `drift 0`, `exit=0`.

## 2. Make an out-of-band change, as yourself

`gcloud` uses your own account here (not the impersonated ADC), so this is the
kind of console or CLI change that happens "just for a minute while debugging".

```bash
source .env   # for $AUDITOR_PROJECT_IDS
gcloud projects add-iam-policy-binding "$AUDITOR_PROJECT_IDS" \
  --member="serviceAccount:auditor-reader@${AUDITOR_PROJECT_IDS}.iam.gserviceaccount.com" \
  --role=roles/viewer --condition=None --quiet >/dev/null && echo "added roles/viewer"
```

`roles/viewer` is a **basic role**: it grants read on almost every service in
the project, far wider than the reader's three narrow roles.

## 3. Terraform doesn't see it

```bash
(cd infra && terraform plan)
```
Expect: **`No changes. Your infrastructure matches the configuration.`**

## 4. The auditor does

```bash
.venv/bin/python -m auditor.cli record
.venv/bin/python -m auditor.cli drift raw/ raw/terraform/plan.json; echo "exit=$?"
```
Expect: `drift 1`, a line `UNDECLARED  project  roles/viewer  serviceAccount:auditor-reader@…`, `exit=2`.

## 5. Revert, and confirm clean

```bash
gcloud projects remove-iam-policy-binding "$AUDITOR_PROJECT_IDS" \
  --member="serviceAccount:auditor-reader@${AUDITOR_PROJECT_IDS}.iam.gserviceaccount.com" \
  --role=roles/viewer --condition=None --quiet >/dev/null && echo "removed roles/viewer"
.venv/bin/python -m auditor.cli record
.venv/bin/python -m auditor.cli drift raw/ raw/terraform/plan.json; echo "exit=$?"
```
Expect: `drift 0`, `exit=0`.

In P4 the auditor itself proposes step 5, and you approve it.
