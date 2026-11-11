"""Errors for OIDC Back-Channel Logout 1.0, on the Relying Party side.

https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
"""

from authlib.common.errors import AuthlibHTTPError

__all__ = [
    "BackchannelLogoutError",
    "InvalidLogoutTokenError",
    "InvalidLogoutTokenSignatureError",
    "LogoutTokenRateLimitedError",
    "BackchannelLogoutUnsupportedError",
]


class BackchannelLogoutError(AuthlibHTTPError):
    """Base class for the errors returned by a back-channel logout endpoint.

    The error body is the standard OAuth 2.0 JSON object with an ``error``
    and an optional ``error_description``.
    """

    error = "invalid_request"


class InvalidLogoutTokenError(BackchannelLogoutError):
    """The logout token is missing, malformed, or fails a claim check.

    The RP MUST respond with an HTTP 400 Bad Request, per back-channel
    logout §4.4.
    """

    error = "invalid_request"
    status_code = 400


class InvalidLogoutTokenSignatureError(BackchannelLogoutError):
    """The logout token signature cannot be verified.

    The RP MUST respond with an HTTP 401 Unauthorized, per back-channel
    logout §4.4: "If the Logout Token [...] is not valid, then the RP MUST
    respond with an HTTP 401 Unauthorized error."
    """

    error = "invalid_token"
    status_code = 401


class LogoutTokenRateLimitedError(BackchannelLogoutError):
    """Too many logout tokens were sent to the RP.

    The RP SHOULD respond with an HTTP 429 Too Many Requests, per
    back-channel logout §4.4.
    """

    error = "too_many_requests"
    status_code = 429


class BackchannelLogoutUnsupportedError(BackchannelLogoutError):
    """The RP does not support back-channel logout.

    The RP MUST respond with an HTTP 501 Not Implemented, per back-channel
    logout §4.4.
    """

    error = "backchannel_logout_not_supported"
    status_code = 501
