"""Tests for the Starlette OIDC Back-Channel Logout endpoint (RP side)."""

import json
import time
import uuid
from urllib.parse import urlencode

import httpx2
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet
from starlette.requests import Request

from authlib.integrations.starlette_client import OAuth
from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from tests.clients.asgi_helper import AsyncPathMapDispatch
from tests.util import read_file_path

ISSUER = "https://provider.test"
CLIENT_ID = "dev"


@pytest.fixture
def private_key():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture
def jwks():
    return read_file_path("jwks_public.json")


def make_client(jwks):
    metadata = {
        "issuer": ISSUER,
        "jwks_uri": "https://provider.test/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    transport = httpx2.ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {"body": metadata},
                "/jwks.json": {"body": jwks},
            }
        )
    )
    oauth = OAuth()
    return oauth.register(
        "dev",
        client_id=CLIENT_ID,
        client_secret="secret",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={"transport": transport},
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


def post_request(form):
    body = urlencode(form).encode()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/backchannel-logout",
        "query_string": b"",
        "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        "session": {},
    }

    async def receive():
        return {"type": "http.request", "body": body}

    return Request(scope, receive=receive)


@pytest.mark.asyncio
async def test_backchannel_logout_clears_session(private_key, jwks):
    client = make_client(jwks)
    cleared = []
    request = post_request({"logout_token": make_logout_token(private_key)})

    response = await client.handle_backchannel_logout(
        request, lambda claims: cleared.append(dict(claims))
    )

    assert response.status_code == 200
    assert json.loads(response.body) == {}
    assert len(cleared) == 1
    assert cleared[0]["sub"] == "user-1"
    assert cleared[0]["sid"] == "session-1"


@pytest.mark.asyncio
async def test_async_callback_supported(private_key, jwks):
    client = make_client(jwks)
    cleared = []

    async def clear_sessions(claims):
        cleared.append(dict(claims))

    request = post_request({"logout_token": make_logout_token(private_key)})
    response = await client.handle_backchannel_logout(request, clear_sessions)

    assert response.status_code == 200
    assert cleared[0]["sid"] == "session-1"


@pytest.mark.asyncio
async def test_sid_only_clears_one_session(private_key, jwks):
    client = make_client(jwks)
    claims = dict(
        jwt.decode(make_logout_token(private_key), KeySet.import_key_set(jwks)).claims
    )
    del claims["sub"]
    token = jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, private_key)

    cleared = []
    request = post_request({"logout_token": token})
    response = await client.handle_backchannel_logout(
        request, lambda claims: cleared.append(dict(claims))
    )

    assert response.status_code == 200
    assert "sub" not in cleared[0]
    assert cleared[0]["sid"] == "session-1"


@pytest.mark.asyncio
async def test_missing_logout_token_is_400(jwks):
    client = make_client(jwks)
    response = await client.handle_backchannel_logout(
        post_request({}), lambda claims: None
    )
    assert response.status_code == 400
    assert json.loads(response.body)["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_bad_signature_is_401(jwks):
    client = make_client(jwks)
    response = await client.handle_backchannel_logout(
        post_request({"logout_token": "a.b.c"}), lambda claims: None
    )
    assert response.status_code == 401
    assert json.loads(response.body)["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_invalid_claim_is_400(private_key, jwks):
    client = make_client(jwks)
    token = make_logout_token(private_key, {"aud": "someone-else"})
    response = await client.handle_backchannel_logout(
        post_request({"logout_token": token}), lambda claims: None
    )
    assert response.status_code == 400
    assert json.loads(response.body)["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_callback_exception_propagates(private_key, jwks):
    client = make_client(jwks)

    def failing(claims):
        raise RuntimeError("session store down")

    request = post_request({"logout_token": make_logout_token(private_key)})
    with pytest.raises(RuntimeError, match="session store down"):
        await client.handle_backchannel_logout(request, failing)
