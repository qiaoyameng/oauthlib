"""
oauthlib.oauth2.rfc6749.token_family
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional refresh token family protocol with reuse detection.

When refresh tokens are rotated, a *family* is the chain of refresh tokens
descending from one initial login. If a refresh token that was already
consumed (rotated) is presented again, the token is considered stolen and
the whole family is revoked. Families are independent: revoking one family
never affects other families, e.g. other sessions of the same user.

The storage contract is defined by :class:`RefreshTokenFamilyStore`. Its
central operation, :meth:`RefreshTokenFamilyStore.consume_and_register`,
must be **atomic**: it confirms the old token is still the live one,
consumes it and registers its successor as a single indivisible step.
Implementations must not emulate this with a non-atomic "check, then save"
sequence. :class:`InMemoryRefreshTokenStore` is a thread-safe reference
implementation.
"""
import logging
import threading
import uuid

log = logging.getLogger(__name__)


class RefreshTokenFamilyStore:
    """Storage protocol for refresh token families.

    Implementations of this protocol may be passed to
    ``RefreshTokenGrant(refresh_token_store=...)`` to enable refresh token
    rotation with reuse detection. When a store is configured, the grant
    delegates persistence of the refreshed token to
    :meth:`consume_and_register` instead of calling
    ``request_validator.save_token``, so implementations must persist the
    successor token (including its access token, if any) as part of the
    atomic operation.

    Note that ``request_validator.validate_refresh_token`` is still invoked
    by the grant as an advisory pre-check (client binding, scopes). The
    authoritative, race-free decision is made by
    :meth:`consume_and_register`.
    """

    def register_family_root(self, refresh_token, client_id=None, user=None,
                             scopes=None, token=None):
        """Start a new family for a freshly issued refresh token.

        This is called outside the refresh flow, when the first refresh
        token of a login is issued (e.g. from the authorization code
        grant's persistence logic).

        :param refresh_token: The newly issued refresh token string.
        :param client_id: The client the token was issued to, if any.
        :param user: The resource owner the token was issued to, if any.
        :param scopes: The scopes granted to the token, if any.
        :param token: The full token dict, if the issuer persists it here.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def consume_and_register(self, refresh_token, token, request):
        """Atomically consume ``refresh_token`` and register its successor.

        This method MUST be atomic. In one indivisible step it must:

        1. confirm ``refresh_token`` is still the live token of its family,
        2. mark ``refresh_token`` consumed, and
        3. register ``token['refresh_token']`` as the family's new live
           token and persist ``token``.

        :param refresh_token: The refresh token presented by the client.
        :param token: The new token dict, containing a ``refresh_token``
                      entry that becomes the family's live token.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :returns: True if the rotation was registered. False if
                  ``refresh_token`` is unknown, was already consumed, or
                  belongs to a revoked family. When the token was already
                  consumed (reuse detected), the implementation MUST revoke
                  the entire family - and only that family - before
                  returning False.
        :rtype: True or False

        A False return means the client receives an ``invalid_grant``
        error and no new token. If persistence fails, implementations must
        raise instead of returning, so the grant can refuse to hand out an
        unregistered token.

        Method is used by:
            - Refresh Token Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def is_live(self, refresh_token):
        """Check whether ``refresh_token`` is the live token of its family.

        :param refresh_token: The refresh token string.
        :rtype: True or False
        """
        raise NotImplementedError('Subclasses must implement this method.')


class InMemoryRefreshTokenStore(RefreshTokenFamilyStore):
    """Thread-safe in-memory reference implementation.

    All state transitions are serialized through a single lock, making
    :meth:`consume_and_register` atomic: at most one of any number of
    concurrent refresh attempts for the same token can succeed.

    Suitable for tests, demos and single-process deployments. Data is lost
    on restart.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # family_id -> {'client_id', 'user', 'scopes', 'tokens', 'live', 'revoked'}
        self._families = {}
        # refresh token -> family_id
        self._index = {}

    def register_family_root(self, refresh_token, client_id=None, user=None,
                             scopes=None, token=None):
        with self._lock:
            if refresh_token in self._index:
                raise ValueError('Refresh token is already registered.')
            family_id = uuid.uuid4().hex
            self._families[family_id] = {
                'client_id': client_id,
                'user': user,
                'scopes': list(scopes) if scopes else [],
                'tokens': {refresh_token: token},
                'live': refresh_token,
                'revoked': False,
            }
            self._index[refresh_token] = family_id
            return family_id

    def consume_and_register(self, refresh_token, token, request):
        successor = token['refresh_token']
        client_id = getattr(request, 'client_id', None)
        with self._lock:
            family_id = self._index.get(refresh_token)
            if family_id is None:
                log.debug('Unknown refresh token presented for rotation.')
                return False
            family = self._families[family_id]
            if (client_id is not None and family['client_id'] is not None
                    and client_id != family['client_id']):
                log.debug('Refresh token presented by wrong client, %r.',
                          client_id)
                return False
            if family['revoked'] or family['live'] != refresh_token:
                # Reuse of an already consumed (or revoked) token: the token
                # is considered stolen, revoke the whole family. Only this
                # family is touched; other logins are unaffected.
                log.warning('Refresh token reuse detected, revoking '
                            'family %s.', family_id)
                self._revoke_family(family_id)
                return False
            if successor in self._index:
                raise ValueError('Successor refresh token already registered.')
            family['tokens'][successor] = token
            family['live'] = successor
            self._index[successor] = family_id
            return True

    def is_live(self, refresh_token):
        with self._lock:
            family_id = self._index.get(refresh_token)
            if family_id is None:
                return False
            family = self._families[family_id]
            return not family['revoked'] and family['live'] == refresh_token

    def _revoke_family(self, family_id):
        """Revoke a family. Caller must hold the lock."""
        family = self._families[family_id]
        family['revoked'] = True
        family['live'] = None
