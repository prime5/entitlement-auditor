# P7: RFC 8693 token exchange, detailed design

Status: **design, for review** (P7.1). Builds on DESIGN.md D4 and threat model T10–T13.
No code yet. Each later step (P7.2–P7.4) is one commit.

## 1. The problem, in one paragraph

The weekly scan, and later an agent drafting fixes, must act **on my behalf**
without holding my credentials and without standing credentials of their own.
RFC 8693 gives that a standard shape. The agent presents **my** token (the
*subject*) plus proof of **its own** identity (the *actor*). The auditor's token
endpoint returns a new token that is narrower, short-lived, and records both
identities: `sub` = me, `act.sub` = the agent. Every API call made with it is
attributable to both of us, and policy can treat "me" and "an agent acting for me"
differently. The rule that matters: **an agent can never approve a change.**

## 2. Build vs buy (stated up front because an interviewer will ask)

Keycloak supports standard token exchange (since v26.2). In production I'd use
it, or my IdP's equivalent. I'm building it here for two reasons:
1. The learning goal: to write token validation, signing, JWKS and delegation
   semantics myself, not configure them.
2. The rules that matter (narrowing only, no chaining, agents never approve)
   live in **my** code and tests, where I can show them.

The scope is deliberately small (§9), so it stays defensible rather than
becoming a half-built authorization server.

## 3. Flow

```
 agent (scan worker)                 auditor STS                         Google
 ───────────────────                 ───────────                         ──────
 holds: its private key              holds: STS private key (ES256),
        my Google ID token                  agent registry, operator config
        (handed to it by me)
         │
         │ 1. sign actor assertion (JWT, ES256, 60 s, aud = STS token URL, jti)
         │ 2. POST /oauth/token  (form-encoded)
         │      grant_type=urn:ietf:params:oauth:grant-type:token-exchange
         │      subject_token=<my Google ID token>
         │      subject_token_type=urn:ietf:params:oauth:token-type:id_token
         │      actor_token=<assertion>
         │      actor_token_type=urn:ietf:params:oauth:token-type:jwt
         │      scope=findings:read
         │      audience=entitlement-auditor-api
         ├──────────────────────────────────►│
         │                                   │ 3. validate subject token ───────► JWKS (cached)
         │                                   │ 4. validate actor assertion against registry key
         │                                   │ 5. apply the six rules (§6)
         │                                   │ 6. sign delegated token, write audit event
         │◄──────────────────────────────────┤
         │   { access_token, issued_token_type, token_type, expires_in, scope }
         │
         │ 7. GET /findings  Authorization: Bearer <delegated token>
         └──────────────────────────────────► auditor API: verify (own JWKS), check policy
```

## 4. Validating the subject token: my Google ID token (P7.2)

I get it with `gcloud auth print-identity-token` as myself. Checks, all required,
in this order (cheapest and most decisive first):

| # | Check | Why |
|---|---|---|
| 1 | Header `alg` is `RS256`, and in an allowlist chosen by the **verifier**, never taken from the token | Algorithm confusion: `alg: none`, or an HS256 token "signed" with the public key |
| 2 | `kid` found in Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`, cached per its `Cache-Control`; refetched once on an unknown `kid`) | Key rotation without accepting unknown keys |
| 3 | Signature valid | Authenticity |
| 4 | `iss` ∈ {`https://accounts.google.com`, `accounts.google.com`} | Google issues both forms |
| 5 | `aud` ∈ configured allowlist | See the honest caveat below |
| 6 | `exp` in the future, `iat` not in the future, 60 s leeway each | Clock skew between machines |
| 7 | `email_verified` is true and `email` (lowercased) == the configured operator | The token proves *which* Google account; config decides whether it's *mine* |

**Honest caveat, decision D-P7a.** A user ID token from gcloud carries
`aud` = gcloud's own OAuth client ID, not `entitlement-auditor-api`. gcloud only
lets you set `--audiences` when impersonating a service account. So the auditor
must accept a token **that was not issued for it**. That's a known confused-deputy
risk: any other service that receives my gcloud ID token could replay it here.

| Option | Pro | Con |
|---|---|---|
| A. Accept gcloud's client ID as `aud`, with checks 7 and §6 rule 2 | Works today, no infra | The confused-deputy risk above |
| B. Register my own OAuth client and log in through it | Proper audience | An OAuth consent screen and a client secret to manage, for one user |
| C. Wait for Keycloak (P8) | Correct by construction | Blocks P7 on P8 |

**Recommendation: A now, C later.** The issuer is pluggable (a table of issuer →
JWKS URL + allowed audiences), so adding Keycloak in P8 is configuration, not
code. The README states the caveat, so the claim survives a drill-down.

## 5. Validating the actor: the agent's own proof (P7.3)

The agent signs a short JWT with **its own** key (the `private_key_jwt` pattern,
RFC 7523):

```json
{ "iss": "agent:scan-worker", "sub": "agent:scan-worker",
  "aud": "https://<auditor>/oauth/token",
  "iat": 1761940000, "exp": 1761940060, "jti": "<uuid>" }
```

The STS looks up `agent:scan-worker` in the **agent registry**
(`config/agents.yaml`, committed; it holds only public keys):

```yaml
agents:
  agent:scan-worker:
    public_key_pem: |            # ES256 public key; its private key never leaves the worker
      -----BEGIN PUBLIC KEY----- ...
    may_act_for: [operator]      # who it may represent (plays RFC 8693 §4.4 may_act's role)
    scope_ceiling: [findings:read, scans:run, proposals:create]
```

Checks: signature against the registered key; `iss == sub ==` a registered agent;
`aud` == this token endpoint exactly; `exp - iat` ≤ 60 s; `jti` not seen before,
kept in a TTL cache for 2 minutes (replay protection, T12).

Why a key and not a shared secret: the registry can be public, and a leaked
registry gives an attacker nothing.

## 6. The six rules (all deny by default, each with its own tests)

| # | Rule | Implementation |
|---|---|---|
| 1 | **Narrowing only** | `granted = requested ∩ operator_scopes ∩ agent.scope_ceiling`. Empty → `invalid_scope`, never an empty token. No `scope` param → the agent's ceiling, still intersected. |
| 2 | **Who may act for whom** | `operator ∈ agent.may_act_for`, else `unauthorized_client` |
| 3 | **Lifetime** | `exp = min(now + 300 s, subject.exp)`: never outlives the authority it came from |
| 4 | **No chaining** | A subject token with an `act` claim → `invalid_grant`. Blocks laundering one delegation into another. |
| 5 | **Signing** | ES256, private key from `AUDITOR_STS_KEY_PATH` (gitignored file), `kid` = RFC 7638 thumbprint; public keys at `/.well-known/jwks.json`. No HS256, no fallback secret (the aiops-triage-agent bug, not repeated). |
| 6 | **Audit** | One event per exchange, granted or refused: `sub`, `act`, scope requested vs granted, `jti`, `parent` (sha256 of the subject token: Google ID tokens can't be relied on to carry a `jti`), outcome, and the error code. **Never the tokens themselves.** |

`operator_scopes` = every scope the API defines, including `proposals:approve`.
The operator holds all of them, which is exactly why rule 1 must intersect with
the agent ceiling and why `proposals:approve` is in **no** agent's ceiling.

## 7. The issued token

Header: `{"alg": "ES256", "typ": "at+jwt", "kid": "<thumbprint>"}`. `typ` per
RFC 9068, so this token can't be confused with an ID token.

```json
{
  "iss": "https://<auditor>",
  "aud": "entitlement-auditor-api",
  "sub": "user:<operator email>",
  "act": { "sub": "agent:scan-worker" },
  "scope": "findings:read",
  "client_id": "agent:scan-worker",
  "iat": 1761940000,
  "exp": 1761940300,
  "jti": "<uuid>",
  "parent": "<sha256 of subject token, first 16 hex>"
}
```

Response (RFC 8693 §2.2.1):

```json
{ "access_token": "<jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer", "expires_in": 300, "scope": "findings:read" }
```

Errors follow RFC 6749 §5.2 (HTTP 400, JSON `{"error": …}`): `invalid_request`,
`invalid_grant` (bad or expired subject token, chaining), `invalid_client`
(bad actor assertion), `unauthorized_client` (not allowed to act for this
subject), `invalid_scope`, and `invalid_target` (unknown `audience`, from
RFC 8693 §2.2.2). Error descriptions never echo token contents.

## 8. Using it: the API side (P7.4)

A small FastAPI app, reusing the `require_permission` *shape* from aiops-triage-agent:

- `GET /findings`: the latest drift report. Needs `findings:read`.
- `POST /proposals/{id}/approve`: a stub in P7, real in P4. Needs `proposals:approve`
  **and no `act` claim.** A delegated token is refused even if a bug ever put
  `proposals:approve` into its scope. Two independent locks; a test for each.

Verification on the API side: own JWKS, `typ == at+jwt`, `iss`, `aud`, `exp`,
then scope. The decision is logged with both `sub` and `act.sub`.

## 9. Out of scope (said so they can't be inferred)

Refresh tokens, other grant types (client credentials, authorization code),
token introspection and revocation endpoints, nested `act` (chaining is refused,
not supported), multiple audiences, DPoP or mTLS-bound tokens. Each is a sentence
in the README's "not built" list, not a gap someone has to discover.

## 10. Libraries

**PyJWT + cryptography.** PyJWT does ES256 and RS256, and ships `PyJWKClient` for
Google's JWKS. It's the most common choice, so interview-familiar. Considered:
**joserfc/Authlib**, which is more complete (JWE, full OAuth server) but brings
far more surface than one endpoint needs. FastAPI for the endpoint and API;
`httpx` only in tests.

## 11. Test plan (offline: no network, no real tokens)

- Tests generate their own RSA "Google" key and ES256 agent and STS keys, mint
  ID tokens with them, and point the validator at a fixture JWKS.
- One test per row of §4 (including `alg: none`, an HS256 token signed with the
  public key, wrong `iss`, wrong `aud`, expired, `email_verified=false`, another
  email).
- One test per rule in §6, including: a requested scope the agent's ceiling lacks;
  `proposals:approve` requested by an agent; a subject token expiring in 90 s
  giving `expires_in ≤ 90`; a subject carrying `act`; a replayed actor `jti`; an
  actor assertion valid for 10 minutes.
- API tests: a delegated token reads findings; a delegated token is refused on
  approve even with the scope forced in; a direct token approves.
- Live (P7.4, on my Mac): a real `gcloud auth print-identity-token` exchanged by
  the scan worker, used to read real findings; results recorded the same way as
  DRIFT-DEMO.md.

## 12. Steps

| Step | Deliverable | Honest claim after it |
|---|---|---|
| P7.1 | This document | none: design only |
| P7.2 ✅ | `auditor/sts/subject.py`: pluggable issuer validator, Google configured; §4 tests; `cli subject-token` for a live check | "I validate Google ID tokens myself: JWKS with rotation, pinned algorithms, issuer, audience and expiry checks, tested against algorithm-confusion attacks." |
| P7.3 | `/oauth/token`, actor assertions, agent registry, six rules, ES256 signing, JWKS endpoint; §5–§7 tests | "I implemented an RFC 8693 token exchange: narrowing only, capped lifetime, no chaining, audited." |
| P7.4 | `/findings` + approve stub, two-lock approval rule, live run with my real Google token | "Agents read my findings through delegated tokens carrying `sub` and `act`; policy makes it impossible for a delegated token to approve a change." |

## 13. Decisions (answered 10/31)

1. **D-P7a: accepted.** The subject token's audience is gcloud's client ID for
   now; the confused-deputy caveat stays documented; Keycloak (P8) replaces it.
2. **Runs locally for P7.** Deployment is a separate step, **P7.5**, only if it
   stays free: Cloud Run's free tier should cover this usage, but it needs a
   billing account on the project. So: budget alert first (alerts notify, they
   don't cap), `max-instances=1`, a dedicated runtime service account. Enabling
   Cloud Run will make Google create the default compute SA with Editor: the
   auditor should report it as UNDECLARED.
