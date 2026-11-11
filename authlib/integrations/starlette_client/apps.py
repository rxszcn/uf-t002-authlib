import inspect

from starlette.datastructures import URL
from starlette.responses import JSONResponse
from starlette.responses import RedirectResponse

from ..base_client import BaseApp
from ..base_client import OAuthError
from ..base_client.async_app import AsyncOAuth1Mixin
from ..base_client.async_app import AsyncOAuth2Mixin
from ..base_client.async_openid import AsyncOpenIDMixin
from ..base_client.backchannel import get_logout_token_from_form
from ..httpx_client import AsyncOAuth1Client
from ..httpx_client import AsyncOAuth2Client


class StarletteAppMixin:
    async def save_authorize_data(self, request, **kwargs):
        state = kwargs.pop("state", None)
        if state:
            await self.framework.set_state_data(request.session, state, kwargs)
        else:
            raise RuntimeError("Missing state value")

    async def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Starlette view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        # Handle Starlette >= 0.26.0 where redirect_uri may now be a URL and not a string
        if redirect_uri and isinstance(redirect_uri, URL):
            redirect_uri = str(redirect_uri)
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        await self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv["url"], status_code=302)


class StarletteOAuth1App(StarletteAppMixin, AsyncOAuth1Mixin, BaseApp):
    client_cls = AsyncOAuth1Client

    async def authorize_access_token(self, request, **kwargs):
        params = dict(request.query_params)
        state = params.get("oauth_token")
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = await self.framework.get_state_data(request.session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params["request_token"] = data["request_token"]
        params.update(kwargs)
        await self.framework.clear_state_data(request.session, state)
        return await self.fetch_access_token(**params)


class StarletteOAuth2App(
    StarletteAppMixin, AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp
):
    client_cls = AsyncOAuth2Client

    async def logout_redirect(
        self, request, post_logout_redirect_uri=None, id_token_hint=None, **kwargs
    ):
        """Create a HTTP Redirect for End Session Endpoint (RP-Initiated Logout).

        :param request: HTTP request instance from Starlette view.
        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param kwargs: Extra parameters (state, client_id, logout_hint, ui_locales).
        :return: A HTTP redirect response.
        """
        if post_logout_redirect_uri and isinstance(post_logout_redirect_uri, URL):
            post_logout_redirect_uri = str(post_logout_redirect_uri)
        result = await self.create_logout_url(
            post_logout_redirect_uri=post_logout_redirect_uri,
            id_token_hint=id_token_hint,
            **kwargs,
        )
        if result.get("state"):
            await self.framework.set_state_data(
                request.session,
                result["state"],
                {
                    "post_logout_redirect_uri": post_logout_redirect_uri,
                },
            )
        return RedirectResponse(result["url"], status_code=302)

    async def validate_logout_response(self, request):
        """Validate the state parameter from the logout callback.

        :param request: HTTP request instance from Starlette view.
        :return: The state data dict.
        :raises OAuthError: If state is missing or invalid.
        """
        state = request.query_params.get("state")
        if not state:
            raise OAuthError(description='Missing "state" parameter')

        state_data = await self.framework.get_state_data(request.session, state)
        if not state_data:
            raise OAuthError(description='Invalid "state" parameter')

        await self.framework.clear_state_data(request.session, state)
        return state_data

    async def handle_backchannel_logout(self, request, on_logout):
        """Handle an OIDC Back-Channel Logout request.

        Register a Starlette route on the ``backchannel_logout_uri`` you gave
        to the OpenID Provider, and call this method from it::

            async def backchannel_logout(request):
                def clear_sessions(claims):
                    if claims.get("sid"):
                        clear_session_by_sid(claims["sid"])
                    else:
                        clear_user_sessions(claims["sub"])

                return await oauth.sso.handle_backchannel_logout(
                    request, clear_sessions
                )


            app.add_route("/backchannel-logout", backchannel_logout, methods=["POST"])

        The logout token is verified with the OP JWKS, and all the checks of
        the Back-Channel Logout specification are performed. ``on_logout`` is
        then called with the validated claims. It may be a regular function or
        an async function. It receives a mapping with a ``sub`` and/or a
        ``sid``:

        - with a ``sid``, terminate the local session that carries this
          session ID;
        - without a ``sid``, terminate every local session of the user
          identified by ``sub`` — this is the same account on all devices.

        :param request: HTTP request instance from the Starlette view.
        :param on_logout: A callable or async callable taking the validated
            logout token claims. It performs the actual session cleanup.
        :return: A Starlette ``JSONResponse``. ``200`` with an empty JSON
            object on success, or the error response required by the
            specification (``400``, ``401``, ``429`` or ``501``).
        """
        from authlib.oidc.backchannel.errors import BackchannelLogoutError

        try:
            async with request.form() as form:
                logout_token = get_logout_token_from_form(form)

            claims = await self.parse_logout_token(logout_token)
            result = on_logout(claims)
            if inspect.isawaitable(result):
                await result
        except BackchannelLogoutError as error:
            status, body, _headers = error()
            return JSONResponse(body, status_code=status)

        return JSONResponse({}, status_code=200)

    async def authorize_access_token(self, request, **kwargs):
        if request.scope.get("method", "GET") == "GET":
            data = request.query_params
        else:
            async with request.form() as form:
                data = dict(form)

        error = data.get("error")
        if error:
            description = data.get("error_description")
            uri = data.get("error_uri")
            raise OAuthError(error=error, description=description, uri=uri)

        params = {"code": data.get("code"), "state": data.get("state")}

        state_data = await self.framework.get_state_data(
            request.session, params.get("state")
        )
        await self.framework.clear_state_data(request.session, params.get("state"))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
        leeway = kwargs.pop("leeway", 120)
        token = await self.fetch_access_token(**params, **kwargs)

        if "id_token" in token and "nonce" in state_data:
            userinfo = await self.parse_id_token(
                token,
                nonce=state_data["nonce"],
                claims_options=claims_options,
                claims_cls=claims_cls,
                leeway=leeway,
            )
            token["userinfo"] = userinfo
        return token
