"""authlib.oidc.backchannel.
~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenID Connect Back-Channel Logout 1.0 Implementation.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

from .discovery import OpenIDProviderMetadata
from .errors import BackchannelLogoutError
from .errors import BackchannelLogoutUnsupportedError
from .errors import InvalidLogoutTokenError
from .errors import InvalidLogoutTokenSignatureError
from .errors import LogoutTokenRateLimitedError
from .logout_token import BACKCHANNEL_LOGOUT_EVENT
from .logout_token import create_logout_token
from .registration import ClientMetadataClaims
from .sender import BackchannelLogoutSender
from .validator import LogoutTokenClaims
from .validator import validate_logout_token

__all__ = [
    "BACKCHANNEL_LOGOUT_EVENT",
    "BackchannelLogoutError",
    "BackchannelLogoutSender",
    "BackchannelLogoutUnsupportedError",
    "ClientMetadataClaims",
    "InvalidLogoutTokenError",
    "InvalidLogoutTokenSignatureError",
    "LogoutTokenClaims",
    "LogoutTokenRateLimitedError",
    "OpenIDProviderMetadata",
    "create_logout_token",
    "validate_logout_token",
]
