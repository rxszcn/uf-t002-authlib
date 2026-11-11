"""Tests for the Relying Party side of OIDC Back-Channel Logout 1.0.

These cover the logout token validation rules of §2.6 and the error codes
of §4.4. The OP side (token creation, sender, registration) is tested in
``test_backchannel.py``.
"""

import time
import uuid

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from authlib.oidc.backchannel import InvalidLogoutTokenError
from authlib.oidc.backchannel import InvalidLogoutTokenSignatureError
from authlib.oidc.backchannel import LogoutTokenClaims
from authlib.oidc.backchannel import validate_logout_token
from tests.util import read_file_path

ISSUER = "https://provider.test"
CLIENT_ID = "client-1"


@pytest.fixture
def private_jwks():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture
def public_jwks():
    return KeySet.import_key_set(read_file_path("jwks_public.json"))


@pytest.fixture
def other_private_jwks():
    return KeySet.import_key_set(read_file_path("jwks_single_private.json"))


def encode_token(header, payload, key):
    if header.get("alg") == "none":
        return jwt.encode(header, payload, None, algorithms=["none"])
    return jwt.encode(header, payload, key)


@pytest.fixture
def make_logout_token(private_jwks):
    def _make(claims_overrides=None, header_overrides=None, key=None):
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 120,
            "jti": str(uuid.uuid4()),
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
            "sub": "user-1",
            "sid": "session-1",
        }
        if claims_overrides:
            payload.update(claims_overrides)
        header = {"alg": "RS256", "typ": "logout+jwt"}
        if header_overrides:
            header.update(header_overrides)
        return encode_token(header, payload, key or private_jwks)

    return _make


def decode_claims(token, public_jwks):
    return dict(jwt.decode(token, public_jwks).claims)


def validate(token, public_jwks, **kwargs):
    options = dict(client_id=CLIENT_ID, issuer=ISSUER)
    options.update(kwargs)
    return validate_logout_token(token, public_jwks, **options)


# --- Happy path -----------------------------------------------------------


def test_valid_token_with_sub_and_sid(make_logout_token, public_jwks):
    claims = validate(make_logout_token(), public_jwks)
    assert isinstance(claims, LogoutTokenClaims)
    assert claims["sub"] == "user-1"
    assert claims["sid"] == "session-1"
    assert claims["iss"] == ISSUER
    assert claims["events"] == {BACKCHANNEL_LOGOUT_EVENT: {}}


def test_sid_only_token(make_logout_token, public_jwks, private_jwks):
    claims = decode_claims(make_logout_token(), public_jwks)
    del claims["sub"]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_jwks)
    result = validate(token, public_jwks)
    assert "sub" not in result
    assert result["sid"] == "session-1"


def test_sub_only_token(make_logout_token, public_jwks, private_jwks):
    claims = decode_claims(make_logout_token(), public_jwks)
    del claims["sid"]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_jwks)
    result = validate(token, public_jwks)
    assert "sid" not in result
    assert result["sub"] == "user-1"


def test_audience_list_contains_client_id(make_logout_token, public_jwks):
    token = make_logout_token({"aud": [CLIENT_ID, "other-client"]})
    claims = validate(token, public_jwks)
    assert CLIENT_ID in claims["aud"]


def test_jwks_dict_accepted(make_logout_token):
    token = make_logout_token()
    claims = validate_logout_token(
        token,
        read_file_path("jwks_public.json"),
        client_id=CLIENT_ID,
        issuer=ISSUER,
    )
    assert claims["sub"] == "user-1"


def test_typ_jwt_accepted(make_logout_token, public_jwks):
    token = make_logout_token(header_overrides={"typ": "jwt"})
    validate(token, public_jwks)


def test_typ_application_jwt_accepted(make_logout_token, public_jwks):
    token = make_logout_token(header_overrides={"typ": "application/jwt"})
    validate(token, public_jwks)


def test_missing_exp_accepted(make_logout_token, public_jwks, private_jwks):
    """exp is RECOMMENDED, not REQUIRED, for logout tokens."""
    claims = decode_claims(make_logout_token(), public_jwks)
    del claims["exp"]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_jwks)
    result = validate(token, public_jwks)
    assert "exp" not in result


def test_issuer_not_checked_when_none(make_logout_token, public_jwks):
    token = make_logout_token({"iss": "https://other-issuer.test"})
    claims = validate_logout_token(token, public_jwks, client_id=CLIENT_ID)
    assert claims["iss"] == "https://other-issuer.test"


# --- Signature and parsing failures (HTTP 401) ---------------------------


def test_malformed_token_is_401(public_jwks):
    with pytest.raises(InvalidLogoutTokenSignatureError) as exc:
        validate("not-a-jwt", public_jwks)
    assert exc.value.status_code == 401
    assert exc.value.error == "invalid_token"


def test_empty_token_is_400(public_jwks):
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate("", public_jwks)
    assert exc.value.status_code == 400


def test_foreign_signature_is_401(make_logout_token, public_jwks, other_private_jwks):
    token = make_logout_token(key=other_private_jwks)
    with pytest.raises(InvalidLogoutTokenSignatureError) as exc:
        validate(token, public_jwks)
    assert exc.value.status_code == 401


@pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
def test_none_algorithm_is_401(make_logout_token, public_jwks):
    token = make_logout_token(header_overrides={"alg": "none"})
    with pytest.raises(InvalidLogoutTokenSignatureError) as exc:
        validate(token, public_jwks)
    assert exc.value.status_code == 401


def test_unknown_kid_is_401(make_logout_token, public_jwks, private_jwks):
    # Sign with a real key, then claim a kid the RP JWKS does not have.
    claims = decode_claims(make_logout_token(), public_jwks)
    token = jwt.encode(
        {"alg": "RS256", "typ": "logout+jwt", "kid": "unknown-key-id"},
        claims,
        private_jwks.keys[0],
    )
    with pytest.raises(InvalidLogoutTokenSignatureError):
        validate(token, public_jwks)


# --- Claim failures (HTTP 400) --------------------------------------------


@pytest.mark.parametrize(
    "claim",
    ["iss", "aud", "iat", "jti", "events"],
)
def test_missing_required_claim(make_logout_token, public_jwks, private_jwks, claim):
    claims = decode_claims(make_logout_token(), public_jwks)
    del claims[claim]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_jwks)
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert exc.value.status_code == 400
    assert claim in exc.value.description


def test_issuer_mismatch_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"iss": "https://evil.test"})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert exc.value.status_code == 400
    assert "iss" in exc.value.description


def test_audience_mismatch_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"aud": "someone-else"})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert exc.value.status_code == 400
    assert "aud" in exc.value.description


def test_audience_list_without_client_id_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"aud": ["a", "b"]})
    with pytest.raises(InvalidLogoutTokenError):
        validate(token, public_jwks)


def test_missing_events_member_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"events": {"https://other.example/event": {}}})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert "events" in exc.value.description


def test_events_not_object_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"events": "not-an-object"})
    with pytest.raises(InvalidLogoutTokenError):
        validate(token, public_jwks)


def test_non_empty_event_value_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"events": {BACKCHANNEL_LOGOUT_EVENT: {"not": "empty"}}})
    with pytest.raises(InvalidLogoutTokenError):
        validate(token, public_jwks)


def test_nonce_claim_rejected(make_logout_token, public_jwks):
    token = make_logout_token({"nonce": "nonce-value"})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert "nonce" in exc.value.description


def test_neither_sub_nor_sid_is_400(make_logout_token, public_jwks):
    token = make_logout_token({"sub": None, "sid": None})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert "sub" in exc.value.description or "sid" in exc.value.description


def test_null_sub_with_sid_present(make_logout_token, public_jwks, private_jwks):
    """A null sub must not silently pass as 'no sub' when sid exists."""
    claims = decode_claims(make_logout_token(), public_jwks)
    claims["sub"] = None
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_jwks)
    with pytest.raises(InvalidLogoutTokenError):
        validate(token, public_jwks)


def test_expired_token_is_400(make_logout_token, public_jwks):
    now = int(time.time())
    token = make_logout_token({"iat": now - 1000, "exp": now - 10})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks, leeway=0)
    assert exc.value.status_code == 400


def test_expired_token_within_leeway_accepted(make_logout_token, public_jwks):
    now = int(time.time())
    token = make_logout_token({"iat": now - 100, "exp": now - 30})
    validate(token, public_jwks, leeway=60)


def test_wrong_typ_is_400(make_logout_token, public_jwks):
    token = make_logout_token(header_overrides={"typ": "at+jwt"})
    with pytest.raises(InvalidLogoutTokenError) as exc:
        validate(token, public_jwks)
    assert "typ" in exc.value.description


def test_unsupported_algorithm_rejected(make_logout_token, public_jwks):
    with pytest.raises(InvalidLogoutTokenSignatureError):
        validate(make_logout_token(), public_jwks, algorithms=["ES256"])


def test_none_removed_from_algorithms(make_logout_token, public_jwks):
    with pytest.raises(InvalidLogoutTokenSignatureError):
        validate(make_logout_token(), public_jwks, algorithms=["none"])


def test_error_body_is_oauth2_json():
    error = InvalidLogoutTokenError(description="boom")
    status, body, headers = error()
    assert status == 400
    assert body["error"] == "invalid_request"
    assert body["error_description"] == "boom"
    assert headers[0][0] == "Content-Type"
