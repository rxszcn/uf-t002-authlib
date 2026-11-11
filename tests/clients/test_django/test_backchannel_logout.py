"""Tests for the Django OIDC Back-Channel Logout endpoint (RP side)."""

import json
import time
import uuid
from unittest import mock

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from authlib.integrations.django_client import OAuth
from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from tests.clients.util import mock_send_value
from tests.util import read_file_path

ISSUER = "https://provider.test"
CLIENT_ID = "dev"


@pytest.fixture
def private_key():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture
def jwks():
    return read_file_path("jwks_public.json")


def make_client():
    oauth = OAuth()
    return oauth.register(
        "dev",
        client_id=CLIENT_ID,
        client_secret="secret",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )


def make_logout_token(private_key, claims_overrides=None):
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
    return jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, payload, private_key)


def patch_metadata(jwks):
    metadata = {
        "issuer": ISSUER,
        "jwks_uri": "https://provider.test/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }

    def fake_send(request, **kwargs):
        if request.url.endswith("/jwks.json"):
            return mock_send_value(jwks)
        return mock_send_value(metadata)

    return mock.patch("requests.sessions.Session.send", side_effect=fake_send)


def test_backchannel_logout_clears_session(factory, private_key, jwks):
    client = make_client()
    cleared = []
    request = factory.post(
        "/backchannel-logout", data={"logout_token": make_logout_token(private_key)}
    )

    with patch_metadata(jwks):
        response = client.handle_backchannel_logout(
            request, lambda claims: cleared.append(dict(claims))
        )

    assert response.status_code == 200
    assert json.loads(response.content) == {}
    assert len(cleared) == 1
    assert cleared[0]["sub"] == "user-1"
    assert cleared[0]["sid"] == "session-1"


def test_sid_only_clears_one_session(factory, private_key, jwks):
    client = make_client()
    claims = dict(
        jwt.decode(make_logout_token(private_key), KeySet.import_key_set(jwks)).claims
    )
    del claims["sub"]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_key)

    cleared = []
    request = factory.post("/backchannel-logout", data={"logout_token": token})
    with patch_metadata(jwks):
        response = client.handle_backchannel_logout(
            request, lambda claims: cleared.append(dict(claims))
        )

    assert response.status_code == 200
    assert "sub" not in cleared[0]
    assert cleared[0]["sid"] == "session-1"


def test_missing_logout_token_is_400(factory):
    client = make_client()
    request = factory.post("/backchannel-logout", data={})
    response = client.handle_backchannel_logout(request, lambda claims: None)
    assert response.status_code == 400
    assert json.loads(response.content)["error"] == "invalid_request"


def test_bad_signature_is_401(factory, jwks):
    client = make_client()
    request = factory.post("/backchannel-logout", data={"logout_token": "a.b.c"})
    with patch_metadata(jwks):
        response = client.handle_backchannel_logout(request, lambda claims: None)
    assert response.status_code == 401
    assert json.loads(response.content)["error"] == "invalid_token"


def test_invalid_claim_is_400(factory, private_key, jwks):
    client = make_client()
    token = make_logout_token(private_key, {"aud": "someone-else"})
    request = factory.post("/backchannel-logout", data={"logout_token": token})
    with patch_metadata(jwks):
        response = client.handle_backchannel_logout(request, lambda claims: None)
    assert response.status_code == 400
    assert json.loads(response.content)["error"] == "invalid_request"


def test_callback_exception_propagates(factory, private_key, jwks):
    client = make_client()

    def failing(claims):
        raise RuntimeError("session store down")

    request = factory.post(
        "/backchannel-logout", data={"logout_token": make_logout_token(private_key)}
    )
    with patch_metadata(jwks):
        with pytest.raises(RuntimeError, match="session store down"):
            client.handle_backchannel_logout(request, failing)
