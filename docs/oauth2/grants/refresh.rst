Refresh Token Grant
------------------------

.. autoclass:: oauthlib.oauth2.RefreshTokenGrant
    :members:
    :inherited-members:

Refresh token families (reuse detection)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Rotation alone cannot detect a stolen refresh token being replayed. Passing
a ``refresh_token_store`` to the grant enables an optional token family
protocol: the store atomically confirms the presented refresh token is
still the live one, consumes it and registers its successor. If a consumed
token is presented again, the whole family - and only that family, never
other logins of the same user - is revoked and the client receives
``invalid_grant``. If the store fails to persist, the client receives
``temporarily_unavailable`` and is never handed an unregistered token.

.. code-block:: python

    store = InMemoryRefreshTokenStore()
    grant = RefreshTokenGrant(request_validator=validator,
                              refresh_token_store=store)

.. autoclass:: oauthlib.oauth2.RefreshTokenFamilyStore
    :members:

.. autoclass:: oauthlib.oauth2.InMemoryRefreshTokenStore
    :members:
