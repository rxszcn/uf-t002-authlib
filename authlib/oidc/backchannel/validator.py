"""Logout token validation for OIDC Back-Channel Logout 1.0, RP side.

https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
"""

from __future__ import annotations

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.errors import MissingClaimError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib.oauth2.claims import JWTClaims

from .errors import InvalidLogoutTokenError
from .errors import InvalidLogoutTokenSignatureError
from .logout_token import BACKCHANNEL_LOGOUT_EVENT

__all__ = ["LogoutTokenClaims", "validate_logout_token"]


class LogoutTokenClaims(JWTClaims):
    """Claims of a back-channel logout token, validated per §2.6.

    The application usually does not use this class directly:
    :func:`validate_logout_token` and the ``parse_logout_token`` method of
    the OAuth client apps build and validate it. It is exported for
    applications that want to customize a validation rule.
    """

    ESSENTIAL_CLAIMS = ["iss", "aud", "iat", "jti", "events"]

    def validate(self, now=None, leeway=0):
        # A present-but-null claim is invalid, while the base class silently
        # removes null values before the type checks. Reject it explicitly so
        # the error stays an invalid_request instead of a missing claim.
        for claim in ("iss", "aud", "iat", "jti", "events", "sub", "sid", "exp"):
            if claim in self and self[claim] is None:
                raise InvalidLogoutTokenError(
                    description=f"The '{claim}' claim must not be null."
                )

        for claim in self.ESSENTIAL_CLAIMS:
            if claim not in self:
                raise InvalidLogoutTokenError(
                    description=f"The logout token is missing the '{claim}' claim."
                )

        # backchannel §2.6: "Verify that the Logout Token [...] does not
        # contain a nonce Claim."
        if "nonce" in self:
            raise InvalidLogoutTokenError(
                description="The logout token must not contain a nonce."
            )

        options = dict(self.options)
        # exp is optional on a logout token. The registry still validates it
        # when present, with the configured leeway; only the essentiality is
        # turned off so a missing exp does not fail.
        options.setdefault("exp", {"essential": False})
        try:
            # The generic registry checks the iss/aud/exp/iat/nbf types and
            # values, including the iss option configured by the validator.
            self.registry_cls(now, leeway, **options).validate(self)
        except (JoseError, MissingClaimError) as exc:
            raise InvalidLogoutTokenError(description=exc.description) from exc

        self.validate_issuer()
        self.validate_audience()
        self.validate_events()
        self.validate_subject_and_session()

    def validate_issuer(self):
        # backchannel §2.6: "Verify that the Issuer Identifier (iss claim)
        # matches the OP's issuer." The registry already enforces the value
        # option; this covers the case where no issuer was configured.
        issuer = self.options.get("iss", {}).get("value")
        if issuer is not None and self.get("iss") != issuer:
            raise InvalidLogoutTokenError(
                description="The 'iss' claim does not match the issuer."
            )

    def validate_audience(self):
        # backchannel §2.6: "Verify that the Audience (aud claim) contains
        # the client_id of the Relying Party."
        client_id = self.params.get("client_id")
        if not client_id:
            return

        aud = self.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if client_id not in audiences:
            raise InvalidLogoutTokenError(
                description="The 'aud' claim does not contain the client_id of this RP."
            )

    def validate_events(self):
        # backchannel §2.6: "Verify that the events claim [...] contains the
        # member name http://schemas.openid.net/event/backchannel-logout, and
        # that its value is an empty JSON object."
        events = self.get("events")
        if not isinstance(events, dict):
            raise InvalidLogoutTokenError(
                description="The 'events' claim must be a JSON object."
            )

        event = events.get(BACKCHANNEL_LOGOUT_EVENT)
        if event is None:
            raise InvalidLogoutTokenError(
                description=(
                    "The 'events' claim does not contain the backchannel-logout event."
                )
            )
        if event != {}:
            raise InvalidLogoutTokenError(
                description=(
                    "The value of the backchannel-logout event must be an empty object."
                )
            )

    def validate_subject_and_session(self):
        # backchannel §2.6 jti replay detection needs the application token
        # store and is handled by the framework apps, not the claims class.
        # backchannel §2.4: "A Logout Token MUST contain either a sub or a
        # sid Claim, and MAY contain both."
        sub = self.get("sub")
        sid = self.get("sid")
        if sub is None and sid is None:
            raise InvalidLogoutTokenError(
                description="The logout token must contain a 'sub' or a 'sid' claim."
            )
        if sub is not None and not isinstance(sub, str):
            raise InvalidLogoutTokenError(
                description="The 'sub' claim must be a string."
            )
        if sid is not None and not isinstance(sid, str):
            raise InvalidLogoutTokenError(
                description="The 'sid' claim must be a string."
            )


def _get_algorithms(key_set: KeySet, algorithms: list[str] | None) -> list[str]:
    """Return the algorithms accepted to verify a logout token.

    ``none`` is never accepted, even when the caller or the key set allows
    it, per backchannel §2.6.
    """
    if algorithms is None:
        algorithms = [alg.name for alg in JWSRegistry.filter_algorithms(key_set)]
    algorithms = [alg for alg in algorithms if alg != "none"]
    if not algorithms:
        raise InvalidLogoutTokenSignatureError(
            description="No algorithm can verify the logout token."
        )
    return algorithms


def validate_logout_token(
    logout_token: str,
    key_set: KeySet | dict,
    client_id: str,
    issuer: str | None = None,
    algorithms: list[str] | None = None,
    leeway: int = 120,
    claims_cls: type[LogoutTokenClaims] = LogoutTokenClaims,
) -> LogoutTokenClaims:
    """Decode and validate a back-channel logout token.

    The signature is verified against ``key_set`` first. All the checks of
    back-channel logout §2.6 are then performed on the claims.

    :param logout_token: The signed JWT received in the ``logout_token``
        form parameter.
    :param key_set: The public JWKS of the OP, as a joserfc
        :class:`~joserfc.jwk.KeySet` or a JWKS dict.
    :param client_id: The ``client_id`` of this RP, checked against the
        ``aud`` claim.
    :param issuer: The expected OP issuer, checked against the ``iss`` claim.
        When ``None``, the issuer is not checked beyond its presence.
    :param algorithms: Accepted signing algorithms. Defaults to the algorithms
        supported by the key set. ``none`` is always rejected.
    :param leeway: Clock drift tolerance, in seconds, for the time claims.
    :param claims_cls: The claims class to use. It must subclass
        :class:`LogoutTokenClaims`.
    :returns: The validated :class:`LogoutTokenClaims`.
    :raises InvalidLogoutTokenSignatureError: If the JWT cannot be decoded or
        its signature cannot be verified (HTTP 401).
    :raises InvalidLogoutTokenError: If a claim is invalid (HTTP 400).
    """
    if not logout_token or not isinstance(logout_token, str):
        raise InvalidLogoutTokenError(
            description="The 'logout_token' parameter is required."
        )

    if isinstance(key_set, dict):
        key_set = KeySet.import_key_set(key_set)

    alg_values = _get_algorithms(key_set, algorithms)

    try:
        token = jwt.decode(
            logout_token,
            key=key_set,
            registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
        )
    except JoseError as exc:
        # backchannel §2.6: an invalid signature or an unparsable token is
        # an authentication failure, answered with 401.
        raise InvalidLogoutTokenSignatureError(description=exc.description) from exc

    # backchannel §2.6: "an alg with the value none MUST NOT be used".
    # joserfc rejects the none alg when no matching key is found, but check
    # the header explicitly in case the key set contains an oct key.
    if token.header.get("alg") == "none":
        raise InvalidLogoutTokenSignatureError(
            description="Logout tokens must not use the 'none' algorithm."
        )

    # backchannel §2.6: "It is RECOMMENDED that Logout Tokens be explicitly
    # typed" with typ=logout+jwt. A token typed as another kind of JWT is not
    # a logout token.
    typ = token.header.get("typ")
    if typ is not None and typ.lower() not in (
        "logout+jwt",
        "jwt",
        "application/jwt",
    ):
        raise InvalidLogoutTokenError(
            description=f"The logout token has an unexpected 'typ' header: {typ}."
        )

    options = {}
    if issuer is not None:
        options["iss"] = {"value": issuer}

    claims = claims_cls(
        token.claims,
        token.header,
        options,
        {"client_id": client_id},
    )
    claims.validate(leeway=leeway)
    return claims
