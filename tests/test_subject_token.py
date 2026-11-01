"""Subject-token validation (docs/P7-TOKEN-EXCHANGE.md §4). Offline: the tests act
as their own "Google", with an RSA key they generate and a JWKS they serve."""

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import RSAAlgorithm

from auditor.sts.subject import (
    GOOGLE,
    JwksCache,
    SubjectTokenError,
    SubjectValidator,
)

OPERATOR = "operator@example.com"
AUD = next(iter(GOOGLE.audiences))
NOW = 1_762_000_000


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid):
    d = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    d.update(kid=kid, use="sig", alg="RS256")
    return d


class FakeGoogle:
    """Signs ID tokens and serves its JWKS; counts fetches so tests can see refetch behaviour."""

    def __init__(self):
        self.signing = {"k1": _rsa()}
        self.published = ["k1"]
        self.fetches = 0

    def fetch(self, uri):
        assert uri == GOOGLE.jwks_uri
        self.fetches += 1
        return {"keys": [_jwk(self.signing[k], k) for k in self.published]}

    def token(self, kid="k1", alg="RS256", key=None, **overrides):
        claims = {
            "iss": "https://accounts.google.com", "aud": AUD, "sub": "1234567890",
            "email": OPERATOR, "email_verified": True,
            "iat": NOW - 10, "exp": NOW + 3600,
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or self.signing[kid], algorithm=alg, headers={"kid": kid})


@pytest.fixture
def google():
    return FakeGoogle()


@pytest.fixture
def clock():
    return {"t": NOW}


@pytest.fixture
def validator(google, clock):
    now = lambda: clock["t"]
    return SubjectValidator(
        issuers=(GOOGLE,), operator_email=OPERATOR,
        keys=JwksCache(fetch=google.fetch, now=now), now=now,
    )


def reason(validator, token):
    with pytest.raises(SubjectTokenError) as e:
        validator.validate(token)
    return e.value.reason


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture(autouse=True)
def frozen_pyjwt_clock(monkeypatch, clock):
    # PyJWT reads the wall clock for exp/iat; pin it to the test clock.
    import jwt.api_jwt as api

    class _DT:
        @staticmethod
        def now(tz=None):
            from datetime import datetime, timezone
            return datetime.fromtimestamp(clock["t"], tz=timezone.utc)

    monkeypatch.setattr(api, "datetime", _DT, raising=False)
    monkeypatch.setattr(time, "time", lambda: clock["t"])


# ----------------------------------------------------------- the happy path

def test_valid_token_yields_subject_without_the_token(validator, google):
    tok = google.token()
    s = validator.validate(tok)
    assert s.email == OPERATOR and s.issuer == "google" and s.subject_id == "1234567890"
    assert s.expires_at == NOW + 3600
    assert s.token_ref == hashlib.sha256(tok.encode()).hexdigest()[:16]
    assert tok not in repr(s)


@pytest.mark.parametrize("iss", ["https://accounts.google.com", "accounts.google.com"])
def test_both_google_issuer_spellings_accepted(validator, google, iss):
    assert validator.validate(google.token(iss=iss)).email == OPERATOR


# ----------------------------------------------------------- check 1: algorithm

def test_alg_none_rejected(validator):
    header = _b64(json.dumps({"alg": "none", "kid": "k1"}).encode())
    body = _b64(json.dumps({"iss": "https://accounts.google.com", "aud": AUD, "sub": "x",
                            "email": OPERATOR, "email_verified": True,
                            "iat": NOW, "exp": NOW + 60}).encode())
    assert reason(validator, f"{header}.{body}.") == "algorithm_not_allowed"


def test_hs256_signed_with_the_public_key_rejected(validator, google):
    """Classic algorithm confusion: an attacker uses the public key as an HMAC secret."""
    public_pem = google.signing["k1"].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = _b64(json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"iss": "https://accounts.google.com", "aud": AUD, "sub": "x",
                            "email": OPERATOR, "email_verified": True,
                            "iat": NOW, "exp": NOW + 60}).encode())
    sig = _b64(hmac.new(public_pem, f"{header}.{body}".encode(), hashlib.sha256).digest())
    assert reason(validator, f"{header}.{body}.{sig}") == "algorithm_not_allowed"


def test_other_asymmetric_alg_rejected(validator, google):
    tok = google.token(alg="ES256", key=ec.generate_private_key(ec.SECP256R1()))
    assert reason(validator, tok) == "algorithm_not_allowed"


# ----------------------------------------------------------- check 2: kid and rotation

def test_missing_kid_rejected(validator, google):
    tok = jwt.encode({"iss": "https://accounts.google.com"}, google.signing["k1"], algorithm="RS256")
    assert reason(validator, tok) == "missing_kid"


def test_rotated_key_found_by_refetch(validator, google, clock):
    validator.validate(google.token())             # first fetch: k1 only
    google.signing["k2"] = _rsa()
    google.published.append("k2")                  # Google rotates in k2
    clock["t"] += 120                              # past the refetch rate limit
    assert validator.validate(google.token(kid="k2", iat=clock["t"] - 5)).email == OPERATOR
    assert google.fetches == 2


def test_unknown_kid_refetch_is_rate_limited(validator, google):
    validator.validate(google.token())
    google.signing["kX"] = _rsa()                  # signed with a key Google never published
    for _ in range(5):
        assert reason(validator, google.token(kid="kX")) == "unknown_kid"
    assert google.fetches == 1                     # no amplification against the issuer


# ----------------------------------------------------------- check 3: signature

def test_signature_from_a_different_key_rejected(validator, google):
    tok = google.token(key=_rsa())                 # right kid, wrong private key
    assert reason(validator, tok) == "bad_signature"


def test_tampered_payload_rejected(validator, google):
    h, _, s = google.token().split(".")
    forged = _b64(json.dumps({"iss": "https://accounts.google.com", "aud": AUD, "sub": "x",
                              "email": OPERATOR, "email_verified": True,
                              "iat": NOW, "exp": NOW + 999999}).encode())
    assert reason(validator, f"{h}.{forged}.{s}") == "bad_signature"


# ----------------------------------------------------------- check 4: issuer

def test_untrusted_issuer_rejected_before_any_key_fetch(validator, google):
    assert reason(validator, google.token(iss="https://evil.example")) == "untrusted_issuer"
    assert google.fetches == 0


# ----------------------------------------------------------- check 5: audience

def test_token_for_another_audience_rejected(validator, google):
    assert reason(validator, google.token(aud="some-other-client.apps.googleusercontent.com")) == "wrong_audience"


# ----------------------------------------------------------- check 6: time

def test_expired_rejected(validator, google):
    assert reason(validator, google.token(iat=NOW - 7200, exp=NOW - 120)) == "expired"


def test_expired_within_leeway_accepted(validator, google):
    assert validator.validate(google.token(iat=NOW - 3600, exp=NOW - 30)).email == OPERATOR


def test_issued_in_the_future_rejected(validator, google):
    assert reason(validator, google.token(iat=NOW + 600, exp=NOW + 4200)) == "not_yet_valid"


@pytest.mark.parametrize("claim", ["exp", "iat", "sub"])
def test_missing_required_claim_rejected(validator, google, claim):
    assert reason(validator, google.token(**{claim: None})) == f"missing_claim:{claim}"


# ----------------------------------------------------------- check 7: identity

def test_unverified_email_rejected(validator, google):
    assert reason(validator, google.token(email_verified=False)) == "email_not_verified"


def test_someone_elses_valid_google_token_rejected(validator, google):
    """A genuine, correctly signed Google token is still not enough: it must be MINE."""
    assert reason(validator, google.token(email="someone.else@example.com")) == "not_operator"


def test_operator_email_matches_case_insensitively(validator, google):
    assert validator.validate(google.token(email="Operator@Example.com")).email == OPERATOR


# ----------------------------------------------------------- hygiene

def test_errors_never_contain_the_token(validator, google):
    tok = google.token(email="someone.else@example.com")
    with pytest.raises(SubjectTokenError) as e:
        validator.validate(tok)
    assert tok not in str(e.value) and e.value.error == "invalid_grant"


def test_garbage_is_malformed(validator):
    assert reason(validator, "not.a.jwt") == "malformed"
