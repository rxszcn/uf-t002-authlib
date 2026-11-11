"""Helpers shared by the framework back-channel logout endpoints."""

from __future__ import annotations

from authlib.oidc.backchannel.errors import InvalidLogoutTokenError


def get_logout_token_from_form(form) -> str:
    """Extract the ``logout_token`` parameter from a form-encoded request.

    :param form: A mapping of the request form data, as returned by the
        framework (Flask ``request.form``, Django ``request.POST``, the
        Starlette form dict).
    :raises InvalidLogoutTokenError: If the parameter is missing or empty.
    """
    logout_token = form.get("logout_token")
    if not logout_token:
        # backchannel §2.3: the request body must contain a logout_token
        # parameter. A missing parameter is an invalid_request (§4.4).
        raise InvalidLogoutTokenError(
            description="The 'logout_token' parameter is required."
        )
    return logout_token
