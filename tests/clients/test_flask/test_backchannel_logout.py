"""Tests for the Flask OIDC Back-Channel Logout endpoint (RP side)."""

import time
import uuid
from unittest import mock

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.jwk import KeySet

from authlib.integrations.flask_client import OAuth
from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from tests.clients.util import mock_send_value
from tests.util import read_file_path

ISSUER = "https://provider.test"
CLIENT_ID = "dev"


@pytest.fixture
def jwks():
    return read_file_path("jwks_public.json")


@pytest.fixture
def private_key():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture
def app(jwks):
    app = Flask(__name__)
    app.secret_key = "!"
    # View exceptions reach the test instead of being converted to 500.
    app.config["PROPAGATE_EXCEPTIONS"] = True
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id=CLIENT_ID,
        client_secret="secret",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": ISSUER,
        "jwks_uri": "https://provider.test/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }

    cleared = []

    def clear_sessions(claims):
        cleared.append(dict(claims))

    @app.route("/backchannel-logout", methods=["POST"])
    def backchannel_logout():
        return client.handle_backchannel_logout(clear_sessions)

    app.cleared = cleared
    app.metadata = metadata
    app.jwks = jwks
    app.oauth_client = client
    return app


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


def patch_metadata(app):
    def fake_send(request, **kwargs):
        url = request.url
        if url.endswith("/.well-known/openid-configuration"):
            return mock_send_value(app.metadata)
        if url.endswith("/jwks.json"):
            return mock_send_value(app.jwks)
        raise AssertionError(f"unexpected request to {url}")

    return mock.patch("requests.sessions.Session.send", side_effect=fake_send)


def test_backchannel_logout_clears_session(app, private_key):
    """A valid logout token triggers the cleanup callback and returns 200."""
    token = make_logout_token(private_key)
    with patch_metadata(app):
        rv = app.test_client().post("/backchannel-logout", data={"logout_token": token})

    assert rv.status_code == 200
    assert rv.json == {}
    assert len(app.cleared) == 1
    assert app.cleared[0]["sub"] == "user-1"
    assert app.cleared[0]["sid"] == "session-1"


def test_backchannel_logout_sid_only(app, private_key, jwks):
    """A sid-only token lets the RP clear one session, not the whole account."""
    claims = dict(
        jwt.decode(make_logout_token(private_key), KeySet.import_key_set(jwks)).claims
    )
    del claims["sub"]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_key)

    with patch_metadata(app):
        rv = app.test_client().post("/backchannel-logout", data={"logout_token": token})

    assert rv.status_code == 200
    assert app.cleared[0].get("sid") == "session-1"
    assert "sub" not in app.cleared[0]


def test_missing_logout_token_is_400(app):
    rv = app.test_client().post("/backchannel-logout", data={})
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert app.cleared == []


def test_bad_signature_is_401(app):
    with patch_metadata(app):
        rv = app.test_client().post(
            "/backchannel-logout", data={"logout_token": "a.b.c"}
        )
    assert rv.status_code == 401
    assert rv.json["error"] == "invalid_token"
    assert app.cleared == []


def test_invalid_claim_is_400(app, private_key):
    token = make_logout_token(private_key, {"aud": "someone-else"})
    with patch_metadata(app):
        rv = app.test_client().post("/backchannel-logout", data={"logout_token": token})
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert app.cleared == []


def test_callback_exception_propagates(app, private_key):
    def failing_callback(claims):
        raise RuntimeError("session store down")

    @app.route("/backchannel-logout-failing", methods=["POST"])
    def failing():
        return app.oauth_client.handle_backchannel_logout(failing_callback)

    token = make_logout_token(private_key)
    with patch_metadata(app):
        with pytest.raises(RuntimeError, match="session store down"):
            app.test_client().post(
                "/backchannel-logout-failing", data={"logout_token": token}
            )
    assert app.cleared == []


def test_metadata_and_jwks_cached_after_first_call(app, private_key):
    """The second request reuses the cached metadata and JWKS."""
    token = make_logout_token(private_key)
    with mock.patch("requests.sessions.Session.send") as send:
        send.side_effect = [
            mock_send_value(app.metadata),
            mock_send_value(app.jwks),
        ]
        rv1 = app.test_client().post(
            "/backchannel-logout", data={"logout_token": token}
        )
        rv2 = app.test_client().post(
            "/backchannel-logout", data={"logout_token": token}
        )

    assert rv1.status_code == 200
    assert rv2.status_code == 200
    assert send.call_count == 2
