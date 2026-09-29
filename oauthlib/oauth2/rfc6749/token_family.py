"""
oauthlib.oauth2.rfc6749.token_family
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional refresh token *family* protocol (rotation with replay detection).

When refresh tokens are rotated, every token belongs to a *family* rooted at
one login session. If a refresh token that was already consumed is presented
again, both the legitimate client and an attacker may hold copies of the
token chain, so the only safe response is to revoke the whole family. Other
families of the same user (other logins, other devices) are independent and
MUST NOT be affected.

This module provides a thread-safe in-memory reference implementation of the
storage side of the protocol. The critical property is that confirming the
old token, consuming it and registering its successor happens as *one*
atomic operation under a single lock -- not as a "read then write" sequence,
which would lose races between concurrent refresh requests.
"""
import logging
import threading
import uuid
from types import SimpleNamespace

from .request_validator import RequestValidator

log = logging.getLogger(__name__)


class InMemoryTokenFamilyValidator(RequestValidator):
    """Thread-safe in-memory reference implementation of token families.

    Suitable for tests, demos and as documentation of the protocol contract.
    Production deployments should re-implement :meth:`consume_refresh_token`
    against their real storage, preserving the same atomicity guarantees
    (e.g. a single conditional ``UPDATE`` or a serializable transaction).
    """

    def __init__(self):
        # One lock guards every mutation below; consume_refresh_token never
        # performs a check outside of it.
        self._lock = threading.RLock()
        self._clients = {}         # client_id -> client object
        self._families = {}        # family_id -> {'revoked': bool}
        self._refresh_tokens = {}  # token -> record
        self._access_tokens = {}   # token -> record

    # ------------------------------------------------------------------
    # Client registry (demo helper)
    # ------------------------------------------------------------------

    def register_client(self, client_id):
        """Register a public client and return it."""
        with self._lock:
            client = self._clients.get(client_id)
            if client is None:
                client = SimpleNamespace(client_id=client_id)
                self._clients[client_id] = client
            return client

    # ------------------------------------------------------------------
    # Refresh token family protocol
    # ------------------------------------------------------------------

    def consume_refresh_token(self, refresh_token, new_refresh_token, client,
                              request, *args, **kwargs):
        """Atomically consume ``refresh_token`` and register its successor.

        Returns True on success, False if the token was unknown or already
        consumed (in which case the whole family is revoked). The entire
        check-consume-register sequence happens under one lock acquisition.
        """
        client_id = getattr(client, 'client_id', None) or request.client_id
        with self._lock:
            record = self._refresh_tokens.get(refresh_token)
            if record is None:
                log.debug('Unknown refresh token presented for rotation.')
                return False
            if record['client_id'] != client_id:
                # Client binding mismatch: reject, but do not punish the
                # legitimate family for a foreign client's mistake.
                log.debug('Refresh token presented by wrong client.')
                return False
            family = self._families[record['family_id']]
            if record['consumed'] or family['revoked']:
                # Replay of a spent token: revoke the entire family. Only
                # this family is touched; other logins of the same user are
                # stored in independent families and remain valid.
                family['revoked'] = True
                log.debug('Refresh token replay detected, revoked family %s.',
                          record['family_id'])
                return False
            record['consumed'] = True
            self._refresh_tokens[new_refresh_token] = {
                'family_id': record['family_id'],
                'client_id': record['client_id'],
                'user': record['user'],
                'scopes': list(record['scopes']),
                'consumed': False,
            }
            return True

    # ------------------------------------------------------------------
    # Standard RequestValidator interface
    # ------------------------------------------------------------------

    def client_authentication_required(self, request, *args, **kwargs):
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        with self._lock:
            client = self._clients.get(client_id)
            if client is None:
                return False
            request.client = client
            return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        with self._lock:
            return client_id in self._clients

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        return grant_type == 'refresh_token'

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Validate a refresh token presented to the token endpoint.

        Note: presenting a *spent* token is a replay event. Consistent with
        :meth:`consume_refresh_token`, this revokes the whole family. Do not
        call this method to merely probe token state; use
        :meth:`is_refresh_token_usable` for read-only introspection.
        """
        client_id = getattr(client, 'client_id', None)
        with self._lock:
            record = self._refresh_tokens.get(refresh_token)
            if record is None:
                return False
            family = self._families[record['family_id']]
            if record['consumed'] or family['revoked']:
                family['revoked'] = True
                log.debug('Refresh token replay detected, revoked family %s.',
                          record['family_id'])
                return False
            if client_id is not None and record['client_id'] != client_id:
                return False
            request.user = record['user']
            return True

    def is_refresh_token_usable(self, refresh_token):
        """Read-only check whether a refresh token is currently usable.

        Introspection helper for tests and monitoring; unlike
        :meth:`validate_refresh_token` it has no side effects and does not
        simulate presenting the token to the token endpoint.
        """
        with self._lock:
            record = self._refresh_tokens.get(refresh_token)
            return (record is not None
                    and not record['consumed']
                    and not self._families[record['family_id']]['revoked'])

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        with self._lock:
            record = self._refresh_tokens.get(refresh_token)
            return list(record['scopes']) if record else []

    def save_bearer_token(self, token, request, *args, **kwargs):
        with self._lock:
            refresh_token = token.get('refresh_token')
            family_id = None
            if refresh_token is not None:
                record = self._refresh_tokens.get(refresh_token)
                if record is None:
                    # Fresh login: a refresh token we have never seen starts
                    # a new, independent token family. Rotated successors
                    # were already registered by consume_refresh_token and
                    # keep their existing family.
                    family_id = uuid.uuid4().hex
                    self._families[family_id] = {'revoked': False}
                    self._refresh_tokens[refresh_token] = {
                        'family_id': family_id,
                        'client_id': request.client_id,
                        'user': getattr(request, 'user', None),
                        'scopes': list(request.scopes or []),
                        'consumed': False,
                    }
                else:
                    family_id = record['family_id']
            self._access_tokens[token['access_token']] = {
                'family_id': family_id,
                'client_id': request.client_id,
                'user': getattr(request, 'user', None),
                'scopes': list(request.scopes or []),
            }

    def validate_bearer_token(self, token, scopes, request):
        with self._lock:
            record = self._access_tokens.get(token)
            if record is None:
                return False
            if (record['family_id'] is not None
                    and self._families[record['family_id']]['revoked']):
                return False
            if scopes and not set(scopes).issubset(record['scopes']):
                return False
            request.user = record['user']
            request.scopes = list(record['scopes'])
            return True

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke a single token. Does not revoke the token's family."""
        with self._lock:
            self._access_tokens.pop(token, None)
            self._refresh_tokens.pop(token, None)
