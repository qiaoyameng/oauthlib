====================================
Back-Channel Logout endpoint (RP)
====================================

Receiving endpoint for `OpenID Connect Back-Channel Logout 1.0`_ Logout
Tokens, to be deployed by Relying Parties. It validates the Logout Token
(signature, issuer, audience, expiration, ``jti`` and the back-channel
logout event) and invokes a caller supplied callback with the targeted
``sid`` and/or ``sub`` so the local session can be revoked. Processing is
idempotent: a redelivered token does not trigger the callback twice.

.. _`OpenID Connect Back-Channel Logout 1.0`: https://openid.net/specs/openid-connect-backchannel-1_0.html

.. autoclass:: oauthlib.openid.connect.core.endpoints.backchannel_logout.BackChannelLogoutEndpoint
    :members:

.. autoclass:: oauthlib.openid.connect.core.endpoints.backchannel_logout.LogoutTokenStatus
    :members:
