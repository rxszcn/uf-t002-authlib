Added
~~~~~

- Add the Relying Party side of `OpenID Connect Back-Channel Logout 1.0
  <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_:
  ``validate_logout_token`` verifies a logout token per §2.6, and the Flask,
  Django and Starlette OAuth 2.0 apps gain ``handle_backchannel_logout`` to
  clear the matching sessions, including all the sessions of a user on every
  device. The error responses follow the status codes of §4.4.
  See :ref:`specs/backchannel` for details.
