from flask import g
from flask import jsonify
from flask import redirect
from flask import request
from flask import session

from ..base_client import BaseApp
from ..base_client import OAuth1Mixin
from ..base_client import OAuth2Mixin
from ..base_client import OAuthError
from ..base_client import OpenIDMixin
from ..base_client.backchannel import get_logout_token_from_form
from ..requests_client import OAuth1Session
from ..requests_client import OAuth2Session


class FlaskAppMixin:
    @property
    def token(self):
        attr = f"_oauth_token_{self.name}"
        token = g.get(attr)
        if token:
            return token
        if self._fetch_token:
            token = self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        attr = f"_oauth_token_{self.name}"
        setattr(g, attr, token)

    def _get_requested_token(self, *args, **kwargs):
        return self.token

    def save_authorize_data(self, **kwargs):
        state = kwargs.pop("state", None)
        if state:
            self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError("Missing state value")

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(redirect_uri=redirect_uri, **rv)
        return redirect(rv["url"])


class FlaskOAuth1App(FlaskAppMixin, OAuth1Mixin, BaseApp):
    client_cls = OAuth1Session

    def authorize_access_token(self, **kwargs):
        """Fetch access token in one step.

        :return: A token dict.
        """
        params = request.args.to_dict(flat=True)
        state = params.get("oauth_token")
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = self.framework.get_state_data(session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params["request_token"] = data["request_token"]
        params.update(kwargs)
        self.framework.clear_state_data(session, state)
        token = self.fetch_access_token(**params)
        self.token = token
        return token


class FlaskOAuth2App(FlaskAppMixin, OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Session

    def logout_redirect(
        self, post_logout_redirect_uri=None, id_token_hint=None, **kwargs
    ):
        """Create a HTTP Redirect for End Session Endpoint (RP-Initiated Logout).

        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param kwargs: Extra parameters (state, client_id, logout_hint, ui_locales).
        :return: A HTTP redirect response.
        """
        result = self.create_logout_url(
            post_logout_redirect_uri=post_logout_redirect_uri,
            id_token_hint=id_token_hint,
            **kwargs,
        )
        if result.get("state"):
            self.framework.set_state_data(
                session,
                result["state"],
                {
                    "post_logout_redirect_uri": post_logout_redirect_uri,
                },
            )
        return redirect(result["url"])

    def validate_logout_response(self):
        """Validate the state parameter from the logout callback.

        :return: The state data dict.
        :raises OAuthError: If state is missing or invalid.
        """
        state = request.args.get("state")
        if not state:
            raise OAuthError(description='Missing "state" parameter')

        state_data = self.framework.get_state_data(session, state)
        if not state_data:
            raise OAuthError(description='Invalid "state" parameter')

        self.framework.clear_state_data(session, state)
        return state_data

    def handle_backchannel_logout(self, on_logout):
        """Handle an OIDC Back-Channel Logout request.

        Register a Flask view on the ``backchannel_logout_uri`` you gave to
        the OpenID Provider, and call this method from it::

            @app.route("/backchannel-logout", methods=["POST"])
            def backchannel_logout():
                def clear_sessions(claims):
                    if claims.get("sid"):
                        clear_session_by_sid(claims["sid"])
                    else:
                        clear_user_sessions(claims["sub"])

                return oauth.sso.handle_backchannel_logout(clear_sessions)

        The logout token is verified with the OP JWKS, and all the checks of
        the Back-Channel Logout specification are performed. ``on_logout`` is
        then called with the validated claims. It receives a mapping with a
        ``sub`` and/or a ``sid``:

        - with a ``sid``, terminate the local session that carries this
          session ID;
        - without a ``sid``, terminate every local session of the user
          identified by ``sub`` — this is the same account on all devices.

        :param on_logout: A callable taking the validated logout token
            claims. It performs the actual session cleanup. Exceptions it
            raises propagate to the Flask error handling.
        :return: A Flask response. ``200`` with an empty JSON object on
            success, or the error response required by the specification
            (``400``, ``401``, ``429`` or ``501``).
        """
        from authlib.oidc.backchannel.errors import BackchannelLogoutError

        try:
            logout_token = get_logout_token_from_form(request.form)
            claims = self.parse_logout_token(logout_token)
            on_logout(claims)
        except BackchannelLogoutError as error:
            status, body, _headers = error()
            return jsonify(body), status

        # backchannel §2.3: "the RP SHOULD return an HTTP 200 status code
        # with an empty JSON object or no content in the HTTP response
        # message body".
        return jsonify({}), 200

    def authorize_access_token(self, **kwargs):
        """Fetch access token in one step.

        :return: A token dict.
        """
        data = request.args if request.method == "GET" else request.form
        error = data.get("error")
        if error:
            description = data.get("error_description")
            uri = data.get("error_uri")
            raise OAuthError(error=error, description=description, uri=uri)

        params = {"code": data.get("code"), "state": data.get("state")}

        state_data = self.framework.get_state_data(session, params.get("state"))
        self.framework.clear_state_data(session, params.get("state"))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
        leeway = kwargs.pop("leeway", 120)
        token = self.fetch_access_token(**params, **kwargs)
        self.token = token

        if "id_token" in token and "nonce" in state_data:
            userinfo = self.parse_id_token(
                token,
                nonce=state_data["nonce"],
                claims_options=claims_options,
                claims_cls=claims_cls,
                leeway=leeway,
            )
            token["userinfo"] = userinfo
        return token
