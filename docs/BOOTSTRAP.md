# Bootstrap: the GCP project and the read-only identity

You run every command here yourself, on your Mac. Nothing below is ever pasted
into a chat, a commit or a log. The commands produce no key files at all:
the auditor reads through **impersonation**, so your user credential asks Google
for a short-lived token for `auditor-reader`, and no long-lived secret exists.

The project is **dogfooded**: its real job is hosting the auditor itself (scan job,
audit-log anchor bucket, signing key, added in later phases). So it audits its own host.

## 0. Prerequisites

```bash
brew install --cask gcloud-cli      # older name: google-cloud-sdk
# open a new terminal tab, then:
gcloud --version
gcloud auth login                   # the Google account that will own the project
gcloud config list account
```

Keep §1–§6 in **one shell**: `$PROJECT_ID`, `$ME` and `$SA` are shell variables.
If the tab closes, re-export `PROJECT_ID` with the *same* value (it's in `.env`
after §6). Never re-run the `openssl` line, because it would generate a new ID.

## 1. Project (one-time)

```bash
export PROJECT_ID="entitlement-auditor-$(openssl rand -hex 2)"   # globally unique, 6-30 chars
export ME="$(gcloud config get-value account)"

gcloud projects create "$PROJECT_ID" --name="entitlement-auditor"
gcloud config set project "$PROJECT_ID"   # later commands can't hit another project by accident
gcloud services enable \
  iam.googleapis.com iamcredentials.googleapis.com \
  cloudresourcemanager.googleapis.com serviceusage.googleapis.com \
  policyanalyzer.googleapis.com policytroubleshooter.googleapis.com \
  --project "$PROJECT_ID"
```

- `iamcredentials` is the API that issues impersonated tokens.
- `policyanalyzer` serves "last used" data (Activity Analyzer). If enabling it
  fails with a billing error, skip it for now. The collector records
  `last_used = null` ("unknown"), which by design never produces a "stale" finding.
- The project is standalone, with no organization. That means the org policy
  that stops Google from automatically granting **Editor** to default service
  accounts doesn't apply here. Once Compute Engine is enabled (it needs a
  billing account), expect that grant to be the first real UNDECLARED finding.

## 2. The reader service account

```bash
gcloud iam service-accounts create auditor-reader \
  --display-name="entitlement-auditor (read-only)" \
  --description="Discovery only. No write roles. Impersonated, never keyed." \
  --project "$PROJECT_ID"
export SA="auditor-reader@${PROJECT_ID}.iam.gserviceaccount.com"

for role in roles/iam.securityReviewer \
            roles/policyanalyzer.activityAnalysisViewer \
            roles/serviceusage.serviceUsageConsumer; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA" --role="$role" --condition=None
done
```

| Role | Why |
|---|---|
| `iam.securityReviewer` | read IAM policies, list service accounts and their key metadata. No write permissions. |
| `policyanalyzer.activityAnalysisViewer` | read last-authentication / last-used data |
| `serviceusage.serviceUsageConsumer` | lets API calls bill quota to this project |

## 3. Let *only you* impersonate it, on this one service account

```bash
gcloud iam service-accounts add-iam-policy-binding "$SA" \
  --member="user:$ME" --role=roles/iam.serviceAccountTokenCreator \
  --project "$PROJECT_ID"
```

The binding goes on the **service account**, not the project. Token Creator at
project level would let you mint tokens for *every* SA in the project. That is
exactly the escalation path P3's Rego rules will flag, so the bootstrap must
not create it. (Owner does not include `getAccessToken`, so this binding is
needed even though you're Owner.)

## 4. Verify: read works, write is refused

**Wait 3–7 minutes after §3.** New IAM bindings take time to apply. Until they
do, both commands fail with `Permission 'iam.serviceAccounts.getAccessToken'`.
That means "not applied yet", not "read-only works". Don't remove and re-add the
binding while waiting: each change restarts the wait, and IAM displays your email
with its account capitalization, which is the same principal (learned 10/22).

Smallest check first:

```bash
gcloud auth print-access-token --impersonate-service-account="$SA" >/dev/null && echo "impersonation OK"
```

If it still fails after 10 minutes, ask Google why:

```bash
gcloud policy-intelligence troubleshoot-policy iam \
  "//iam.googleapis.com/projects/$PROJECT_ID/serviceAccounts/$SA" \
  --principal-email="$ME" --permission=iam.serviceAccounts.getAccessToken
```

Then the real test:

```bash
# should print an etag
gcloud projects get-iam-policy "$PROJECT_ID" \
  --impersonate-service-account="$SA" --format="value(etag)"

# should FAIL, and the denied permission must be the WRITE, not getAccessToken
gcloud iam service-accounts create should-not-exist \
  --impersonate-service-account="$SA" --project "$PROJECT_ID" 2>&1 | grep -o "Permission '[^']*'"
# expected: Permission 'iam.serviceAccounts.create'
```

## 5. Application Default Credentials for the Python collector

```bash
gcloud auth application-default login --impersonate-service-account="$SA"
```

## 6. Local env file (gitignored)

```bash
cat > .env <<EOF
GOOGLE_CLOUD_QUOTA_PROJECT=$PROJECT_ID
AUDITOR_PROJECT_IDS=$PROJECT_ID
AUDITOR_PROJECT_NUMBERS=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
AUDITOR_REDACT_EXTRA=$ME
AUDITOR_REDACTION_SALT=$(openssl rand -hex 24)
EOF
git check-ignore .env && echo "ignored: good"
```

The salt never leaves this file. If you lose it, re-recorded fixtures just get
new tokens. Nothing breaks.

## 7. Hooks

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pre-commit install
.venv/bin/pre-commit run --all-files
```

## 8. First recording (P1.2)

```bash
.venv/bin/python -m auditor.cli record               # refuses to run unless ADC is auditor-reader
.venv/bin/python -m auditor.cli inventory raw/       # look at it locally; raw/ is gitignored
set -a; source .env; set +a
.venv/bin/python -m auditor.redact redact raw/ fixtures/
.venv/bin/python -m auditor.cli inventory fixtures/  # same counts, no real identifiers
git add fixtures/ && git commit -m "P1.2: first recorded inventory (redacted)"
```

Read the `fixtures/` diff before committing. The pre-commit hook re-checks it.

## Undo (if you ever want the project gone)

```bash
gcloud projects delete "$PROJECT_ID"   # 30-day recovery window
```
