# entitlement-auditor — Phase 0 design

Status: **draft for review**. No code yet. Values in examples marked
`ILLUSTRATIVE` are real GCP *shapes* with placeholder values; P1 replaces them
with a redacted recording of the real project.

---

## 1. Problem and user

**Problem.** Access on my own accounts accumulates out of band: a role widened
while debugging, a default service account Google granted Editor to, a key I
created once and forgot. Nothing tells me when *actual* access stops matching
what I *meant* to grant. `terraform plan` does not either (see Decision 2).

**What the tool does.** For one system at a time:

1. Reads **actual** grants with read-only credentials.
2. Reads **declared** grants from Terraform.
3. Diffs them, classifies each difference with policy-as-code, and explains it.
4. Proposes the least-privilege fix, with evidence.
5. Changes nothing until I approve that specific change. Every proposal,
   decision and outcome is recorded in an append-only audit log.

**User.** One: me, as owner/operator of my GCP project and GitHub account.
Success means I run it weekly against accounts I depend on and act on what it
finds. Multi-user and multi-tenant concerns enter only in P5, as *approver*
groups (me plus my own break-glass identity), not as imagined customers.

**Out of scope (stated so nobody infers otherwise):** GCP deny policies and
principal access boundaries, org/folder inheritance (unless Q1 says the project
sits in an org), resource-level IAM below the project (buckets, topics) until
after P2, and Google consumer third-party app grants (see Decision 1).

---

## 2. Common data model

Two entities. Grants are *who can do what where*; credentials are *how a
principal proves it is itself*. Keeping them separate matters: a service
account key is not a permission, but a stale key on a privileged service
account is one of the highest-value findings.

### Grant

| Field | Type | Notes |
|---|---|---|
| `system` | `gcp` \| `github` | |
| `principal` | `{type, id}` | type ∈ `user`, `serviceAccount`, `group`, `domain`, `googleManaged`, `githubUser`, `githubApp`, `deployKey` |
| `resource` | `{type, name}` | GCP uses Cloud Asset full resource names, e.g. `//cloudresourcemanager.googleapis.com/projects/PROJECT_ID` |
| `role` | string | As granted (`roles/pubsub.editor`). Expanded to permissions lazily from role definitions in P3 (needed for custom roles and escalation analysis). |
| `condition` | `{title, expression}` \| null | IAM Conditions are part of identity: same role with a different condition is a different grant. |
| `origin` | `direct` \| `inherited(from)` \| `viaGroup(group)` | |
| `managed_by` | `user` \| `google` | Google service agents are classified, not reported as drift. |
| `evidence` | `{api, observed_at, etag}` | Where the fact came from. `etag` enables safe writes later. |
| `last_used` | `{at, source, window}` \| **null** | **null means unknown, never "unused".** A missing signal must not produce a "stale" finding. |

**Diff key:** `(system, resource.name, principal.type, principal.id, role, hash(condition))`.

### Credential

| Field | Notes |
|---|---|
| `principal` | owning principal |
| `kind` | `saKey` (user-managed only), `deployKey` |
| `id`, `created`, `expires` | |
| `last_auth` | from Policy Analyzer Activity Analyzer when available; null = unknown |

### Drift record (output of the diff, input to policy)

`{kind: UNDECLARED | MISSING | CONDITION_CHANGED, declared: Grant|null, actual: Grant|null}`.
The diff is structural only. Severity is *not* assigned here; that is policy's
job (P3), so there is exactly one place rules live.

### Worked example — ILLUSTRATIVE, on the shape of my GCP project

**Declared** (`infra/iam.tf`):

```hcl
resource "google_project_iam_member" "operator_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "user:${var.operator_email}"
}

resource "google_service_account" "ingest" {
  account_id = "aiops-ingest"
}

resource "google_project_iam_member" "ingest_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.ingest.email}"
}
```

**Actual** (`projects.getIamPolicy`, trimmed):

```json
{
  "bindings": [
    {"role": "roles/owner",             "members": ["user:OPERATOR"]},
    {"role": "roles/editor",            "members": ["serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com"]},
    {"role": "roles/pubsub.subscriber", "members": ["serviceAccount:aiops-ingest@PROJECT_ID.iam.gserviceaccount.com"]},
    {"role": "roles/pubsub.editor",     "members": ["serviceAccount:aiops-ingest@PROJECT_ID.iam.gserviceaccount.com"]},
    {"role": "roles/pubsub.serviceAgent","members": ["serviceAccount:service-PROJECT_NUMBER@gcp-sa-pubsub.iam.gserviceaccount.com"]}
  ],
  "etag": "BwX..."
}
```

Plus `iam.serviceAccounts.keys.list` on `aiops-ingest`: one `USER_MANAGED` key,
created 2026-08-15, last authentication unknown or old.

**Result:**

| # | Principal | Role | Diff | P3 severity (proposed) | Why |
|---|---|---|---|---|---|
| 1 | operator | owner | — | — | declared and present |
| 2 | default compute SA | **editor** | UNDECLARED | **high** | Basic role on an identity any VM in the project runs as. Google grants this automatically on many projects. |
| 3 | aiops-ingest | pubsub.subscriber | — | — | declared and present |
| 4 | aiops-ingest | **pubsub.editor** | UNDECLARED | **high** | Wider than declared: can create/delete topics, not just consume. Classic "widened while debugging". |
| 5 | pubsub service agent | pubsub.serviceAgent | UNDECLARED, `managed_by=google` | info | Google-managed; expected. Suppressed from drift, listed for completeness. |
| 6 | aiops-ingest key | (credential) | not declarable by policy | medium → high if row 4 stands | Long-lived key on an over-granted SA. |

**The punchline:** `terraform plan` on this project reports **"No changes."**
Rows 2, 4 and 6 are invisible to it. That is Decision 2.

---

## 3. Architecture

```
 infra/*.tf ─► terraform plan -out ─► terraform show -json ─► declared loader ─┐
                                                                                ├─► diff (pure Python) ─► drift[]
 GCP APIs ─► collector ─► normalize ─────────────────────────────► actual[] ──┘          │
  (impersonated read-only SA,                                                              ▼
   short-lived token, no keys)                                       OPA / Rego: severity, escalation paths,
   getIamPolicy · serviceAccounts.list · keys.list                    exceptions (with expiry) ─► findings[]
   SA-level getIamPolicy · Activity Analyzer                                                   │
                                                                                               ▼
                                                          proposer (deterministic) ─► proposal{finding, change, evidence, hash}
                                                                                               │
                                                     approve/reject, one at a time  ◄──────────┤  CLI in P4; OIDC-authenticated API in P5
                                                                                               ▼
                                                     apply = emit Terraform change ─► I run terraform apply ─► rescan verifies
 every step ─► audit log: append-only JSONL, hash-chained, head anchored outside the machine  (Go service in P6)
```

**Proposed layout**

```
entitlement-auditor/
  DESIGN.md
  auditor/            Python package: model, collectors/, declared/, diff, proposer, audit, cli
  policy/             *.rego and *_test.rego
  infra/              Terraform for my project (state gitignored, never committed)
  fixtures/           recorded API responses, redacted before commit
  tests/
  audit-svc/          Go (P6)
```

### Reuse from aiops-triage-agent (read before proposing — findings)

| File there | What it does | Plan here |
|---|---|---|
| `app/enforcement.py` `require_permission(action)` | FastAPI dependency: authenticate bearer, check policy, 403 on deny | **Reuse nearly as-is** for the approval API (P5), with the token now coming from Keycloak instead of self-minting. |
| `app/policy.py` `PolicyStore` | identity → action set from YAML; re-checks live policy each request | **Reuse the principle** (policy as data, live re-check). Superseded by OPA in P3. Note it is action-level only, no resource scoping — the auditor needs resource-level from day one. |
| `app/audit.py` | JSON record per decision → stdout + in-memory deque(500) | **Keep the record shape**, replace storage. A deque that resets on restart is not an audit log. Add event types (proposal / decision / outcome), hash chain, file sink. |
| `app/tokens.py` | HS256 JWT, 5-min TTL | **Do not copy.** `SECRET_KEY` falls back to a hardcoded string (`dev-secret-change-me-…`) when the env var is unset, so a misconfigured deploy silently signs with a public secret. Fail closed instead. In this repo, P4 needs no tokens at all (local CLI), and P5 uses OIDC. |
| `tests/test_policy.py` | TestClient + `caplog` on a non-propagating logger | **Reuse the pattern** for audit assertions. |

I'm copying code, not importing across repos. aiops-triage-agent stays untouched.

---

## 4. Decisions

### D1. Which system first → **GCP project IAM**

| Option | Declared-vs-actual possible? | Notes |
|---|---|---|
| **GCP IAM** | Yes, fully | Terraform provider covers bindings and SAs; read APIs are complete; last-used data exists (Activity Analyzer). Richest escalation semantics (`actAs`, token creator, key admin). |
| GitHub | Partly | Collaborators and deploy keys: yes (API + `integrations/github` provider). Installed apps: listable, not well declarable. **Token scopes: no** — the API cannot list a personal account's classic or fine-grained PATs; you only see the scopes of the token making the call. |
| Google account third-party grants | **No** | No API for consumer accounts. The Admin SDK token listing is Workspace-admin only. Drop it. |

**Recommendation:** GCP for P1–P4. GitHub as a second collector after P4, which
also proves the data model is genuinely system-agnostic (the real test of
"common model"). P1 slice: project-level IAM policy, service accounts,
user-managed keys, and SA-level IAM policies (the last one is where
impersonation escalation lives).

### D2. Declared state and how drift is computed → **Terraform, but the auditor computes its own diff**

The brief says drift = `terraform plan` vs reality. That is only true for
**authoritative** IAM resources:

| Terraform resource | Detects out-of-band additions? | Risk |
|---|---|---|
| `google_project_iam_member` | **No.** Tracks only its own (role, member) pair. | none to adopt |
| `google_project_iam_binding` | Yes, for that role only | Authoritative per role: apply removes other members of that role |
| `google_project_iam_policy` | Yes, whole project | Fully authoritative: a wrong apply can lock you out of the project, including removing Google service agents |

So: write declared state with non-authoritative `iam_member` (safe to apply),
read it via `terraform show -json` on a plan (resolved values, not raw HCL —
parsing HCL breaks on variables and modules), and let the auditor diff against
the full actual policy itself. That is precisely the gap the tool exists to
close, and it's a sentence that survives a drill-down.

**Terraform vs YAML:** Terraform, because declared state should be the thing
that actually provisions — a YAML file becomes a second source of truth that
drifts from Terraform. YAML keeps one narrow job: an **exceptions file**
(accepted risk, owner, reason, expiry date) fed to Rego as data, e.g. "default
compute SA editor accepted until 2026-12-31 because X". Expired exceptions
re-raise the finding.

No Terraform exists for the project yet (assumption, see Q1). Bootstrapping
uses `import {}` blocks for the grants I mean to keep; everything else is
drift by definition on day one, which is the honest starting point.

### D3. OPA/Rego vs OpenFGA → **OPA for P3**

| | OPA / Rego | OpenFGA |
|---|---|---|
| Model | Evaluate rules over a JSON document | Zanzibar-style relationship store; answers "does X have relation R to Y" |
| Fits | "Given this snapshot, which grants are dangerous and why" — exactly the audit question | Runtime authorization checks over relationships |
| Testing | `opa test` with table-driven `*_test.rego` | Model tests via CLI |
| Escalation paths | Natural: walk `actAs` / token-creator edges in the snapshot | Possible but you'd load the whole snapshot as tuples first |

**Recommendation:** OPA. The audit problem is "rules over a snapshot", which is
OPA's native shape. OpenFGA would be justified only for P5 approver
authorization if tenant/group relationships got deep — they won't for one
operator, so the approval API also moves from `roles.yaml` to OPA, giving one
policy engine and one test discipline. Python calls the pinned `opa` binary
(`opa eval`); Go in P6 can embed OPA as a library if needed.

### Not a top-3 decision but stated: remediation apply path → see Q3

My recommendation is that the tool **never holds write credentials**. An
approved proposal becomes a Terraform change (add an `iam_member` to codify, or
import-then-remove to revoke); I run `terraform apply`; the next scan verifies
and the audit log records the outcome. Slower, but blast radius of a
compromised or buggy tool stays read-only.

---

## 5. Threat model (short form)

| # | What goes wrong | Impact | What stops it |
|---|---|---|---|
| T1 | Read credential leaks | Attacker gets a full map of my access — reconnaissance | No SA keys at all: impersonate a dedicated reader SA via ADC (short-lived tokens). Reader holds `roles/iam.securityReviewer` (+ Activity Analyzer viewer), nothing else. Secrets only in env; `.gitignore` + gitleaks pre-commit; log redaction. |
| T2 | Inventory/fixtures published | Same as T1, via my public repo | Fixtures redacted by a deterministic script (project id/number, emails → tokens) before commit; a test fails if raw identifiers appear in `fixtures/`. |
| T3 | **False negative** (tool misses an owner grant) | Worse than a false positive: false confidence | Completeness check: normalized grant count must equal raw `bindings × members`. Unknown principal type or role → **critical**, fail closed. Adversarial Rego tests (P3). |
| T4 | Bad remediation locks me out | Lose control of the project | Invariant enforced in policy: never propose removing the last owner or the operator's own grants. Dry-run default. Tool has no write creds (D-apply). Writes, if ever direct, use `etag` so a stale view can't clobber. |
| T5 | Approval replay / approving something else | Unapproved change | Approval binds to `sha256(proposal)` and the `etag` observed at proposal time; any change to either invalidates it. One approval = one change. |
| T6 | Prompt injection (if an LLM writes proposals) | Attacker-controlled text (SA descriptions, repo names, collaborator bios) steers the fix | Proposals are computed deterministically from the finding. An LLM, if used at all, writes only the explanation, and its output is never executed (Q4). |
| T7 | Audit log tampered | Can't prove what was approved | Append-only JSONL, each record carries `prev_hash`; `verify` recomputes the chain. A local chain is tamper-*evident* only if the head is anchored elsewhere — periodically write the head hash to a GCS bucket with a retention policy (pennies) or a signed git commit. |
| T8 | Terraform state leaks secrets | Keys in plaintext state | Never create SA keys via Terraform. State local and gitignored (or GCS backend with restricted IAM). |
| T9 | Supply chain | Malicious provider/binary | Commit `.terraform.lock.hcl`; pin OPA and k6 by version + checksum. |

---

## 6. Phase plan

Each phase ends in one commit (or a short series) with a clear message.
Session estimates assume 30–45 min sessions.

### P1 — Read-only inventory of GCP (≈3 sessions)
- **Done when:** `.gitignore`, gitleaks hook and redaction script land *first*;
  reader SA exists and is impersonated (you run the commands); collector pulls
  project IAM, SAs, user-managed keys, SA-level IAM; normalized to the model;
  completeness check passes; pytest runs offline on recorded, redacted
  fixtures; verify whether Activity Analyzer data is available on this project
  and record the answer.
- **Honest claim after:** "I wrote a read-only collector that inventories IAM
  bindings, service accounts and keys on my GCP project using impersonated
  short-lived credentials — no key files — normalized into a common grant
  model and tested against recorded fixtures."

### P2 — Declared state + structural diff (≈3 sessions)
- **Done when:** `infra/` describes the grants I intend, bootstrapped with
  `import {}` blocks; declared loader reads `terraform show -json`; diff emits
  UNDECLARED / MISSING / CONDITION_CHANGED; a fixture reproduces the worked
  example, including the case `terraform plan` reports as "No changes".
- **Honest claim:** "It diffs my real project against Terraform-declared state
  and catches out-of-band grants that `terraform plan` can't see, because
  non-authoritative IAM resources only track their own members."

### P3 — Policy as code (≈3–4 sessions)
- **Done when:** severity taxonomy in Rego (unexpected basic role, over-broad
  vs declared, stale grant only with a non-null `last_used`, old/unused key,
  managed-agent suppression, exceptions with expiry); escalation rules for
  `iam.serviceAccountUser` / `serviceAccountTokenCreator` / `serviceAccountKeyAdmin`
  on a privileged SA, `projectIamAdmin` (can grant itself owner), custom roles
  containing `iam.roles.update` or `setIamPolicy`, and `domain:`/group
  principals; `opa test` suite with adversarial cases; no rules left in Python.
- **Honest claim:** "Findings and privilege-escalation paths are expressed in
  Rego with an `opa test` suite of N cases, including multi-hop impersonation."

### P4 — Proposals, approval, audit log (≈3–4 sessions)
- **Done when:** proposer turns each finding into a least-privilege change
  with evidence; CLI shows one proposal at a time, approve/reject with reason;
  approval bound to proposal hash + etag; approved change written as a
  Terraform diff, never applied by the tool; hash-chained audit log with
  `verify`; rescan marks outcome (fixed / still present). Applied to at least
  one real finding on my project.
- **Honest claim:** "I fixed real drift on my own project through it: every
  change is a proposal I approved individually, applied as Terraform, verified
  by rescan, with a tamper-evident audit trail."

### P5 — OIDC + SCIM 2.0 (≈4–5 sessions)
- **Done when:** Keycloak (container) is the OIDC provider for the approval API
  (authorization code + PKCE); `require_permission` from aiops-triage-agent now
  checks Keycloak-issued tokens against OPA; the auditor exposes a **SCIM 2.0
  service-provider** endpoint (`/Users`, `/Groups`, PATCH, filtering, per-tenant
  bearer) that an IdP provisions into; approver groups arrive over SCIM and gate
  who may approve which system. Neither Keycloak nor Ory Kratos ships a SCIM
  server, so the SCIM side is mine to build and test against a real client —
  see Q5.
- **Honest claim:** "Approvers authenticate through Keycloak OIDC, and approver
  groups are provisioned into the auditor over SCIM 2.0 from [IdP]."
- **Risk, stated once:** this is the phase most likely to drift into
  simulation, since I'm the only user. It stays real only if the groups gate
  something I actually do.

### P6 — Go audit service, k6, OTel, SLO (≈4–5 sessions)
- **Recommendation:** rewrite the **audit-log service** in Go, not the
  discovery worker. It's request-serving (so k6 measures something real), it
  must be durable and ordered under bursts (a scan emits hundreds of events),
  and it reuses the OTel Go SDK work from flowgate. The discovery worker is a
  batch job; k6 has nothing to drive.
- **Done when:** Go service appends + verifies the chain; Python core emits to
  it; OTel traces span scan → finding → proposal → audit append; k6 run
  measured; SLOs set from those numbers (e.g. append p99, zero lost/reordered
  events, verified post-run by chain check).
- **Honest claim:** "The audit trail runs as a Go service; I load-tested it
  with k6, set SLOs from measured numbers, and traced a finding end to end."

---

## 7. Open questions

1. **Scope:** which GCP project ID(s)? Is the project standalone or under an
   organization (changes inheritance and org-policy coverage)? I'm assuming no
   Terraform exists for it yet — correct?
2. **Credentials:** OK to create a dedicated `auditor-reader` SA
   (`roles/iam.securityReviewer` + Activity Analyzer viewer) that you
   impersonate via `gcloud auth application-default login
   --impersonate-service-account`? I'll write the exact commands; you run them.
3. **Apply path:** tool emits a Terraform change you apply (my recommendation),
   or the tool applies via the API with a separate write identity after
   approval?
4. **LLM in the loop:** deterministic proposals with no LLM, or an LLM that
   only writes the explanation text? (It never decides the change either way.)
5. **SCIM client for P5:** Keycloak with a community SCIM extension, or an Okta
   free developer/integrator org provisioning into the auditor — closer to your
   PANW Cloud Identity Engine work?
