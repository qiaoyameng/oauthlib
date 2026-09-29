"""
oauthlib.openid.connect.core.endpoints.backchannel_logout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An implementation of the Relying Party (client) side of the
`OpenID Connect Back-Channel Logout 1.0`_ specification.

The endpoint receives Logout Tokens pushed by an OpenID Provider,
validates them and hands the targeted session (``sid``) or subject
(``sub``) over to a caller supplied session revocation callback.

.. _`OpenID Connect Back-Channel Logout 1.0`:
    https://openid.net/specs/openid-connect-backchannel-1_0.html
"""
import json
import logging
import time
from enum import Enum

import jwt

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.endpoints.base import (
    BaseEndpoint, catch_errors_and_unavailability,
)

log = logging.getLogger(__name__)

BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'


class LogoutTokenStatus(Enum):
    """Outcome of handling a single Logout Token."""

    #: The token was valid and the revocation callback was invoked.
    PROCESSED = 'processed'
    #: The token was valid but its ``jti`` was seen before; no side effects.
    ALREADY_PROCESSED = 'already_processed'
    #: The token failed validation; no side effects.
    INVALID = 'invalid'


class InMemoryJTIStore:
    """Default in-memory store of already processed ``jti`` values.

    Entries are kept until the ``exp`` of their Logout Token has passed,
    after which a replayed token would be rejected as expired anyway.
    """

    def __init__(self):
        self._jtis = {}

    def __contains__(self, jti):
        self._purge()
        return jti in self._jtis

    def add(self, jti, expires_at):
        self._purge()
        self._jtis[jti] = expires_at

    def _purge(self):
        now = time.time()
        expired = [jti for jti, exp in self._jtis.items() if exp <= now]
        for jti in expired:
            del self._jtis[jti]


class BackChannelLogoutEndpoint(BaseEndpoint):
    """Back-Channel Logout endpoint for Relying Parties.

    :param issuer: Expected ``iss`` value of the OpenID Provider.
    :param audience: Expected ``aud`` value, usually the client_id of this
        Relying Party. A list of accepted values may be supplied.
    :param keys: Key material used to verify the Logout Token signature.
        Either a single key, a dict mapping ``kid`` to keys, or a callable
        receiving the unverified JWT header and returning a key.
    :param session_revoker: Callable invoked as
        ``session_revoker(sid=..., sub=...)`` for every valid, not yet
        processed Logout Token. At least one of the arguments is not None.
    :param algorithms: Allowed JWS algorithms, defaults to ``['RS256']``.
    :param leeway: Leeway in seconds when validating ``exp`` and ``iat``.
    :param jti_store: Store used to make Logout Token processing idempotent.
        Must support ``jti in store`` and ``store.add(jti, exp)``. Defaults
        to an :class:`InMemoryJTIStore`.
    """

    valid_request_methods = ('POST',)

    def __init__(self, issuer, audience, keys, session_revoker,
                 algorithms=None, leeway=0, jti_store=None):
        BaseEndpoint.__init__(self)
        self.issuer = issuer
        self.audience = audience
        self.keys = keys
        self.session_revoker = session_revoker
        self.algorithms = algorithms or ['RS256']
        self.leeway = leeway
        self.jti_store = jti_store if jti_store is not None else InMemoryJTIStore()

    def handle_logout_token(self, logout_token):
        """Validate a Logout Token and revoke the targeted session.

        Returns a :class:`LogoutTokenStatus` distinguishing invalid
        notifications from ones that were already processed. The revocation
        callback is invoked at most once per ``jti``; a token that fails
        validation never claims its ``jti``.
        """
        claims = self.validate_logout_token(logout_token)
        if claims is None:
            return LogoutTokenStatus.INVALID

        jti = claims['jti']
        if jti in self.jti_store:
            log.info('Logout Token with jti %r already processed.', jti)
            return LogoutTokenStatus.ALREADY_PROCESSED

        self.session_revoker(sid=claims.get('sid'), sub=claims.get('sub'))
        self.jti_store.add(jti, claims['exp'])
        log.debug('Logout Token with jti %r processed.', jti)
        return LogoutTokenStatus.PROCESSED

    def validate_logout_token(self, logout_token):
        """Validate a Logout Token, returning its claims or None.

        Verification follows section 2.4 of the specification: signature,
        ``iss``, ``aud``, ``exp``, ``iat``, ``jti`` and the back-channel
        logout event are all required, and the token MUST NOT contain a
        ``nonce`` and MUST contain a ``sid`` and/or a ``sub`` claim.
        """
        try:
            header = jwt.get_unverified_header(logout_token)
        except jwt.exceptions.PyJWTError as exc:
            log.warning('Logout Token header could not be decoded: %r.', exc)
            return None

        if header.get('alg') not in self.algorithms:
            log.warning('Logout Token uses disallowed alg %r.', header.get('alg'))
            return None

        key = self._resolve_key(header)
        if key is None:
            log.warning('No verification key found for Logout Token.')
            return None

        try:
            claims = jwt.decode(
                logout_token,
                key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={'require': ['iss', 'aud', 'exp', 'iat', 'jti', 'events']},
            )
        except jwt.exceptions.PyJWTError as exc:
            log.warning('Logout Token failed verification: %r.', exc)
            return None

        if 'nonce' in claims:
            log.warning('Logout Token MUST NOT contain a nonce claim.')
            return None

        events = claims.get('events')
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            log.warning('Logout Token is missing the backchannel logout event.')
            return None

        if not claims.get('sid') and not claims.get('sub'):
            log.warning('Logout Token contains neither a sid nor a sub claim.')
            return None

        return claims

    @catch_errors_and_unavailability
    def create_logout_response(self, uri, http_method='POST', body=None, headers=None):
        """Handle an HTTP back-channel logout request.

        Returns ``(headers, body, status_code)``. Valid Logout Tokens,
        including duplicates of already processed ones, yield ``200 OK``;
        invalid ones yield ``400 Bad Request`` with an ``invalid_request``
        error as described in section 2.8 of the specification.
        """
        resp_headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        self._raise_on_bad_method(request)

        logout_token = None
        if request.decoded_body:
            logout_token = dict(request.decoded_body).get('logout_token')

        if not logout_token:
            log.warning('Missing logout_token parameter in %r.', request)
            body = json.dumps({
                'error': 'invalid_request',
                'error_description': 'Missing logout_token parameter.',
            })
            return resp_headers, body, 400

        status = self.handle_logout_token(logout_token)
        if status is LogoutTokenStatus.INVALID:
            body = json.dumps({
                'error': 'invalid_request',
                'error_description': 'The Logout Token is invalid.',
            })
            return resp_headers, body, 400

        return resp_headers, '', 200

    def _resolve_key(self, header):
        """Resolve the verification key for the given JWT header."""
        keys = self.keys
        if callable(keys):
            return keys(header)
        if isinstance(keys, dict):
            kid = header.get('kid')
            if kid is not None:
                return keys.get(kid)
            if len(keys) == 1:
                return next(iter(keys.values()))
            return None
        return keys
