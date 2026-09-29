Aggregated and distributed claims
==================================

A UserInfo response may reference claims that live outside the profile
itself using the ``_claim_names`` and ``_claim_sources`` members:

* **Aggregated claims** are delivered as an inline signed JWT in a
  source descriptor's ``JWT`` member.
* **Distributed claims** are retrieved from an ``endpoint`` using a
  caller provided fetch callable.

``resolve_claims`` expands the graph into a flat claim mapping. Only the
claims explicitly attributed to a source in ``_claim_names`` are taken
from it, so a source can neither override ``sub`` nor smuggle in
unrequested attributes. Missing sources, duplicate claim ownership and
cyclic mappings are reported as dedicated errors, and access credentials
never appear in error text.

.. autofunction:: oauthlib.openid.connect.core.claims.resolve_claims

.. autoclass:: oauthlib.openid.connect.core.claims.ClaimResolutionResult
    :members:

Strict mode (``strict=True``) raises the first error. The default
explicit partial-result mode returns the claims that resolved
successfully together with the collected errors::

    from oauthlib.openid.connect.core.claims import resolve_claims

    def verify(descriptor):
        return jwt.decode(descriptor['JWT'], key, algorithms=['ES256'])

    def fetch(descriptor):
        response = requests.get(
            descriptor['endpoint'],
            headers={'Authorization': f"Bearer {descriptor['access_token']}"})
        response.raise_for_status()
        return response.json()

    result = resolve_claims(
        userinfo,
        fetch_distributed_claims=fetch,
        verify_aggregated_claims=verify)

    if result.ok:
        profile = result.claims
    else:
        # result.claims holds everything that could still be resolved.
        ...
