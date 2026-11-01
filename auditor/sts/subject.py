"""Validate the *subject token*: an OIDC ID token from an issuer we trust (P7.2).

The checks, in the order they run (docs/P7-TOKEN-EXCHANGE.md §4):

  1. algorithm is in the VERIFIER's allowlist for that issuer (never the token's choice)
  2. `kid` names a key in the issuer's JWKS (refetched once if unknown, for rotation)
  3. signature verifies with that key
  4. `iss` is exactly one of the issuer's identifiers
  5. `aud` is in the configured allowlist
  6. `exp` in the future and `iat` not in the future, with leeway for clock skew
  7. `email_verified` is true and `email` is the configured operator

Any failure raises SubjectTokenError. Its `reason` is for the audit log; callers
return the generic RFC 6749 error `invalid_grant` to the client. Neither one ever
contains the token.

Issuers are configuration, not code: adding Keycloak in P8 is one more IssuerConfig.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

import jwt
from jwt import PyJWK


class SubjectTokenError(Exception):
    """The subject token is not acceptable. `reason` is a short machine-readable code."""

    error = "invalid_grant"  # the RFC 6749 §5.2 code a client sees

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class IssuerConfig:
    name: str
    issuer_ids: frozenset[str]  # Google uses two spellings of the same issuer
    jwks_uri: str
    audiences: frozenset[str]
    algorithms: tuple[str, ...]


# Google's OIDC issuer. `aud` for a *user* ID token from `gcloud auth
# print-identity-token` is gcloud's own OAuth client ID, not ours: this is the
# confused-deputy caveat accepted as decision D-P7a. Verify the value against your
# own token (`python -m auditor.cli subject-token` prints its aud) and override
# with AUDITOR_SUBJECT_AUDIENCES if it differs.
GCLOUD_CLIENT_ID = "32555940559.apps.googleusercontent.com"
GOOGLE = IssuerConfig(
    name="google",
    issuer_ids=frozenset({"https://accounts.google.com", "accounts.google.com"}),
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    audiences=frozenset({GCLOUD_CLIENT_ID}),
    algorithms=("RS256",),
)


@dataclass(frozen=True)
class Subject:
    """What a validated subject token tells us. Never holds the token itself."""

    issuer: str
    email: str  # lowercased
    subject_id: str  # the issuer's stable `sub`
    expires_at: int
    token_ref: str  # sha256 prefix, for audit linkage (`parent` in the issued token)


# ---------------------------------------------------------------- keys


Fetcher = Callable[[str], Mapping[str, Any]]  # jwks_uri -> parsed JWKS document


@dataclass
class JwksCache:
    """Per-issuer key cache with rotation handling.

    Unknown `kid` -> refetch once (the issuer may have rotated). Refetches are
    rate-limited, so a flood of tokens with random `kid`s can't turn us into a
    request amplifier against the issuer.
    """

    fetch: Fetcher
    ttl_seconds: int = 3600
    min_refetch_interval: int = 60
    now: Callable[[], float] = time.time
    _keys: dict[str, dict[str, PyJWK]] = field(default_factory=dict)
    _fetched_at: dict[str, float] = field(default_factory=dict)

    def _load(self, uri: str) -> None:
        doc = self.fetch(uri)
        keys: dict[str, PyJWK] = {}
        for jwk in doc.get("keys", []):
            if "kid" in jwk and jwk.get("use", "sig") == "sig":
                keys[jwk["kid"]] = PyJWK.from_dict(jwk)
        self._keys[uri] = keys
        self._fetched_at[uri] = self.now()

    def key(self, uri: str, kid: str) -> PyJWK:
        age = self.now() - self._fetched_at.get(uri, float("-inf"))
        if age > self.ttl_seconds:
            self._load(uri)
        elif kid not in self._keys.get(uri, {}) and age > self.min_refetch_interval:
            self._load(uri)
        try:
            return self._keys[uri][kid]
        except KeyError:
            raise SubjectTokenError("unknown_kid") from None


def http_fetcher(uri: str) -> Mapping[str, Any]:
    """Production fetcher. Kept out of the validator so tests never touch the network."""
    import requests

    resp = requests.get(uri, timeout=5)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------- validator


@dataclass
class SubjectValidator:
    issuers: tuple[IssuerConfig, ...]
    operator_email: str
    keys: JwksCache
    leeway_seconds: int = 60
    now: Callable[[], float] = time.time

    def _issuer_for(self, unverified_iss: Any) -> IssuerConfig:
        for cfg in self.issuers:
            if unverified_iss in cfg.issuer_ids:
                return cfg
        raise SubjectTokenError("untrusted_issuer")

    def validate(self, token: str) -> Subject:
        try:
            header = jwt.get_unverified_header(token)
            # Reading `iss` unverified only selects WHICH issuer's rules apply.
            # Nothing is trusted until the signature check below, which also
            # re-checks `iss` against that issuer's configuration.
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise SubjectTokenError("malformed") from None

        cfg = self._issuer_for(unverified.get("iss"))

        # 1. Algorithm, chosen by us. Rejects `none`, and HS256 tokens "signed"
        #    with the issuer's public key (algorithm confusion).
        if header.get("alg") not in cfg.algorithms:
            raise SubjectTokenError("algorithm_not_allowed")

        # 2. Key, by kid, from this issuer's JWKS only.
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise SubjectTokenError("missing_kid")
        key = self.keys.key(cfg.jwks_uri, kid)

        # 3-6. Signature, iss, aud, exp and iat, in one verified decode.
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=list(cfg.algorithms),
                audience=list(cfg.audiences),
                issuer=list(cfg.issuer_ids),
                leeway=self.leeway_seconds,
                options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            )
        except jwt.InvalidSignatureError:
            raise SubjectTokenError("bad_signature") from None
        except jwt.InvalidIssuerError:
            raise SubjectTokenError("wrong_issuer") from None
        except jwt.InvalidAudienceError:
            raise SubjectTokenError("wrong_audience") from None
        except jwt.ExpiredSignatureError:
            raise SubjectTokenError("expired") from None
        except jwt.ImmatureSignatureError:
            raise SubjectTokenError("not_yet_valid") from None
        except jwt.MissingRequiredClaimError as e:
            raise SubjectTokenError(f"missing_claim:{e.claim}") from None
        except jwt.PyJWTError:
            raise SubjectTokenError("invalid") from None

        # 6, explicitly. PyJWT also rejects a future iat; stating the rule here
        # means it holds even if a library upgrade changes that default.
        if claims["iat"] > self.now() + self.leeway_seconds:
            raise SubjectTokenError("not_yet_valid")

        # 7. Identity: the token proves WHICH account; config decides if it's mine.
        if claims.get("email_verified") not in (True, "true"):
            raise SubjectTokenError("email_not_verified")
        email = str(claims.get("email", "")).lower()
        if not email or email != self.operator_email.lower():
            raise SubjectTokenError("not_operator")

        return Subject(
            issuer=cfg.name,
            email=email,
            subject_id=str(claims["sub"]),
            expires_at=int(claims["exp"]),
            token_ref=hashlib.sha256(token.encode()).hexdigest()[:16],
        )


def describe_unverified(token: str) -> dict[str, Any]:
    """For the CLI's diagnostics only: header and non-identifying claims, no signature check."""
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    keep = ("iss", "aud", "azp", "exp", "iat", "email_verified")
    return {"header": {k: header.get(k) for k in ("alg", "kid", "typ")},
            "claims": {k: claims.get(k) for k in keep if k in claims}}


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)
