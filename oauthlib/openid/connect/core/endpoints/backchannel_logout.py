"""
oauthlib.openid.connect.core.endpoints.backchannel_logout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module implements the Relying Party (client) side receiver of
OpenID Connect Back-Channel Logout 1.0 logout tokens.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""
import enum
import json
import logging
import time

from oauthlib.common import Request

log = logging.getLogger(__name__)

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class LogoutTokenStatus(enum.Enum):
    """Outcome of processing a back-channel logout token."""

    #: Token validated and the revocation callback was invoked.
    ACCEPTED = "accepted"
    #: Token is valid but its ``jti`` was seen before; no side effects.
    ALREADY_PROCESSED = "already_processed"
    #: Token failed validation; no side effects, ``jti`` not consumed.
    INVALID = "invalid"


class LogoutTokenResult:
    """Result of :meth:`BackchannelLogoutEndpoint.verify_logout_token`.

    Distinguishes a genuinely new logout notification from one that was
    already processed and from an invalid notification.
    """

    def __init__(self, status, claims=None, error=None):
        self.status = status
        self.claims = claims
        self.error = error

    @property
    def accepted(self):
        return self.status is LogoutTokenStatus.ACCEPTED

    @property
    def already_processed(self):
        return self.status is LogoutTokenStatus.ALREADY_PROCESSED

    @property
    def valid(self):
        return self.status is not LogoutTokenStatus.INVALID

    def __repr__(self):
        return "LogoutTokenResult(status={!r}, error={!r})".format(
            self.status, self.error)


class InMemoryJtiCache:
    """Default replay cache mapping ``jti`` values to their expiry.

    Entries are purged lazily once the logout token carrying them would
    have expired, so the cache does not grow without bounds.
    """

    def __init__(self):
        self._entries = {}

    def _purge(self, now=None):
        now = time.time() if now is None else now
        expired = [jti for jti, exp in self._entries.items()
                   if exp is not None and exp <= now]
        for jti in expired:
            del self._entries[jti]

    def __contains__(self, jti):
        self._purge()
        return jti in self._entries

    def add(self, jti, expires_at=None):
        self._purge()
        self._entries[jti] = expires_at


class BackchannelLogoutEndpoint:
    """Receives and validates back-channel logout tokens from an IdP.

    The identity provider configuration (issuer, audience and signature
    verification key) is supplied by the caller, as is the
    ``revoke_session`` callback used to terminate local sessions.

    :param issuer: Expected ``iss`` value of the identity provider.
    :param audience: Expected ``aud`` value (client_id or list thereof).
    :param key: Signature verification key. A PEM/bytes/str key, a PyJWT
        key object, or a dict mapping ``kid`` header values to keys.
    :param algorithms: Allowed JWS algorithms (default ``("RS256",)``).
    :param revoke_session: Callback invoked as
        ``revoke_session(sub=..., sid=...)`` exactly once per valid,
        previously unseen logout token. Either ``sub`` or ``sid`` (or
        both) may be ``None`` depending on the token's claims.
    :param leeway: Clock skew leeway in seconds for time-based claims.
    :param jti_cache: Replay cache for ``jti`` values. Any object
        supporting ``jti in cache`` and ``cache.add(jti, expires_at)``.
        Defaults to an in-memory cache.
    """

    def __init__(self, issuer, audience, key, algorithms=None,
                 revoke_session=None, leeway=0, jti_cache=None):
        self.issuer = issuer
        self.audience = audience
        self.key = key
        self.algorithms = list(algorithms) if algorithms else ["RS256"]
        self.revoke_session = revoke_session
        self.leeway = leeway
        self.jti_cache = jti_cache if jti_cache is not None else InMemoryJtiCache()

    def _resolve_key(self, logout_token):
        import jwt  # noqa: PLC0415

        if isinstance(self.key, dict):
            header = jwt.get_unverified_header(logout_token)
            kid = header.get("kid")
            if kid not in self.key:
                raise ValueError("unknown kid: %r" % (kid,))
            return self.key[kid]
        return self.key

    def verify_logout_token(self, logout_token):
        """Validate a logout token and trigger session revocation.

        Returns a :class:`LogoutTokenResult`. Validation covers the
        signature, issuer, audience, time-based claims (``exp``, ``iat``,
        ``nbf``), the presence of ``jti``, the required back-channel
        logout event, and the structural rules of the specification
        (no ``nonce``; at least one of ``sub``/``sid``). The ``jti`` of
        a token is only recorded once every check has passed, so a
        failed delivery never blocks a later legitimate token.
        """
        import jwt  # noqa: PLC0415

        try:
            claims = jwt.decode(
                logout_token,
                self._resolve_key(logout_token),
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "jti"]},
            )
        except Exception as exc:
            log.debug("Logout token failed JWT validation: %r", exc)
            return LogoutTokenResult(LogoutTokenStatus.INVALID, error=str(exc))

        error = self._validate_claims(claims)
        if error is not None:
            log.debug("Logout token failed claim validation: %s", error)
            return LogoutTokenResult(LogoutTokenStatus.INVALID,
                                     claims=claims, error=error)

        jti = claims["jti"]
        if jti in self.jti_cache:
            log.debug("Logout token jti %r already processed.", jti)
            return LogoutTokenResult(LogoutTokenStatus.ALREADY_PROCESSED,
                                     claims=claims)

        self.jti_cache.add(jti, claims.get("exp"))
        if self.revoke_session is not None:
            self.revoke_session(sub=claims.get("sub"), sid=claims.get("sid"))
        log.debug("Logout token jti %r accepted; session revocation triggered.",
                  jti)
        return LogoutTokenResult(LogoutTokenStatus.ACCEPTED, claims=claims)

    def _validate_claims(self, claims):
        events = claims.get("events")
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            return "missing back-channel logout event"
        if "nonce" in claims:
            return "logout tokens must not contain a nonce"
        if claims.get("sub") is None and claims.get("sid") is None:
            return "logout token contains neither sub nor sid"
        return None

    def create_logout_response(self, uri, http_method="POST", body=None,
                               headers=None):
        """HTTP entry point for the IdP's back-channel logout request.

        Parses the ``logout_token`` form parameter and returns the
        ``(headers, body, status_code)`` triple used throughout
        oauthlib. Invalid notifications are answered with ``400`` and an
        ``invalid_request`` error; both newly accepted and already
        processed notifications are answered with ``200`` (logout
        delivery is idempotent at the HTTP layer).
        """
        request = Request(uri, http_method, body, headers)
        logout_token = None
        for param, value in request.decoded_body or []:
            if param == "logout_token":
                logout_token = value

        response_headers = {"Content-Type": "application/json"}
        if logout_token is None:
            log.debug("Back-channel logout request missing logout_token.")
            error = {"error": "invalid_request",
                     "error_description": "missing logout_token parameter"}
            return response_headers, json.dumps(error), 400

        result = self.verify_logout_token(logout_token)
        if result.status is LogoutTokenStatus.INVALID:
            error = {"error": "invalid_request",
                     "error_description": "invalid logout token"}
            return response_headers, json.dumps(error), 400
        return response_headers, "", 200
