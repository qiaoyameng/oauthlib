"""
Tests for Aggregated and Distributed Claims resolution
(OpenID Connect Core 1.0, section 5.6.2).

Two fake claim sources are used throughout:

* ``src_agg`` -- an aggregated source whose claims travel inside a
  signed JWT (HS256) embedded in ``_claim_sources``.
* ``src_dist`` -- a distributed source served by a fake fetcher
  callable standing in for an HTTP claim endpoint.
"""
import jwt

from oauthlib.openid.connect.core.claims import (
    REDACTED, ClaimResolutionError, resolve_claims,
)

from tests.unittest import TestCase


AGG_KEY = 'agg-signing-key-with-at-least-32-bytes!!'
DIST_ENDPOINT = 'https://claims.example.org/userinfo'
DIST_TOKEN = 'dist-access-token-SECRET'
BAD_ENDPOINT = 'https://claims.example.org/broken'
BAD_TOKEN = 'broken-access-token-SECRET'


def make_jwt(payload):
    return jwt.encode(payload, AGG_KEY, algorithm='HS256')


def verify_jwt(token):
    return jwt.decode(token, AGG_KEY, algorithms=['HS256'])


def fake_fetcher(endpoint, access_token):
    """Fake distributed claims endpoint; fails for BAD_ENDPOINT."""
    if endpoint == DIST_ENDPOINT:
        assert access_token == DIST_TOKEN
        return {
            'address': {'street': 'Main St 1', 'city': 'Springfield'},
            'phone_number': '+1-555-0100',
            # not mapped anywhere; must never leak into the result
            'internal_score': 9001,
            # sources must not be able to override sub
            'sub': 'attacker-controlled-sub',
        }
    # simulate an upstream error that leaks the credential into its message
    raise RuntimeError('upstream 401 for token %s' % access_token)


def make_claims(**overrides):
    claims = {
        'sub': 'user-123',
        'name': 'Jane Doe',
        '_claim_names': {
            'email': 'src_agg',
            'email_verified': 'src_agg',
            'address': 'src_dist',
            'phone_number': 'src_dist',
        },
        '_claim_sources': {
            'src_agg': {'JWT': make_jwt({
                'email': 'jane@example.org',
                'email_verified': True,
                # not mapped; must be dropped
                'is_admin': True,
            })},
            'src_dist': {
                'endpoint': DIST_ENDPOINT,
                'access_token': DIST_TOKEN,
            },
        },
    }
    claims.update(overrides)
    return claims


class AggregatedDistributedClaimsTest(TestCase):

    def test_resolves_aggregated_and_distributed_claims(self):
        resolved, diagnostics = resolve_claims(
            make_claims(), fetcher=fake_fetcher, jwt_decoder=verify_jwt)
        self.assertEqual(diagnostics, [])
        self.assertEqual(resolved, {
            'sub': 'user-123',
            'name': 'Jane Doe',
            'email': 'jane@example.org',
            'email_verified': True,
            'address': {'street': 'Main St 1', 'city': 'Springfield'},
            'phone_number': '+1-555-0100',
        })

    def test_sources_cannot_inject_unrequested_attributes(self):
        resolved, _ = resolve_claims(
            make_claims(), fetcher=fake_fetcher, jwt_decoder=verify_jwt)
        self.assertNotIn('is_admin', resolved)
        self.assertNotIn('internal_score', resolved)
        self.assertNotIn('_claim_names', resolved)
        self.assertNotIn('_claim_sources', resolved)

    def test_sources_cannot_override_sub(self):
        resolved, _ = resolve_claims(
            make_claims(), fetcher=fake_fetcher, jwt_decoder=verify_jwt)
        self.assertEqual(resolved['sub'], 'user-123')

    def test_sub_cannot_be_delegated_to_a_source(self):
        claims = make_claims()
        claims['_claim_names']['sub'] = 'src_agg'
        resolved, diagnostics = resolve_claims(
            claims, fetcher=fake_fetcher, jwt_decoder=verify_jwt,
            strict=False)
        self.assertEqual(resolved['sub'], 'user-123')
        self.assertIn('protected_claim', [d.code for d in diagnostics])

    def test_missing_source_produces_diagnostic(self):
        claims = make_claims()
        claims['_claim_names']['nickname'] = 'src_missing'
        resolved, diagnostics = resolve_claims(
            claims, fetcher=fake_fetcher, jwt_decoder=verify_jwt,
            strict=False)
        self.assertNotIn('nickname', resolved)
        missing = [d for d in diagnostics if d.code == 'missing_source']
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].source, 'src_missing')

    def test_duplicate_ownership_produces_diagnostic(self):
        # src_dist volunteers 'email' although it is mapped to src_agg
        def greedy_fetcher(endpoint, access_token):
            payload = fake_fetcher(endpoint, access_token)
            payload['email'] = 'spoofed@example.org'
            return payload

        resolved, diagnostics = resolve_claims(
            make_claims(), fetcher=greedy_fetcher, jwt_decoder=verify_jwt,
            strict=False)
        # the authoritative source still wins
        self.assertEqual(resolved['email'], 'jane@example.org')
        self.assertIn('duplicate_claim', [d.code for d in diagnostics])

    def test_circular_mapping_produces_diagnostic(self):
        # the aggregated JWT itself maps a claim back to its own source
        claims = make_claims()
        claims['_claim_names']['nickname'] = 'src_agg'
        claims['_claim_sources']['src_agg'] = {'JWT': make_jwt({
            'email': 'jane@example.org',
            'email_verified': True,
            '_claim_names': {'nickname': 'src_agg'},
            '_claim_sources': {'src_agg': {'JWT': make_jwt({'nickname': 'jd'})}},
        })}
        resolved, diagnostics = resolve_claims(
            claims, fetcher=fake_fetcher, jwt_decoder=verify_jwt,
            strict=False)
        self.assertNotIn('nickname', resolved)
        self.assertIn('circular_mapping', [d.code for d in diagnostics])

    def test_strict_mode_raises_when_one_source_fails(self):
        claims = make_claims()
        claims['_claim_sources']['src_dist'] = {
            'endpoint': BAD_ENDPOINT,
            'access_token': BAD_TOKEN,
        }
        with self.assertRaises(ClaimResolutionError) as ctx:
            resolve_claims(claims, fetcher=fake_fetcher,
                           jwt_decoder=verify_jwt)
        self.assertIn('fetch_failed',
                      [d.code for d in ctx.exception.diagnostics])

    def test_partial_mode_returns_available_claims(self):
        claims = make_claims()
        claims['_claim_sources']['src_dist'] = {
            'endpoint': BAD_ENDPOINT,
            'access_token': BAD_TOKEN,
        }
        resolved, diagnostics = resolve_claims(
            claims, fetcher=fake_fetcher, jwt_decoder=verify_jwt,
            strict=False)
        # aggregated claims from the healthy source are still resolved
        self.assertEqual(resolved['email'], 'jane@example.org')
        self.assertEqual(resolved['sub'], 'user-123')
        # claims owned by the failed source are absent
        self.assertNotIn('address', resolved)
        self.assertNotIn('phone_number', resolved)
        self.assertIn('fetch_failed', [d.code for d in diagnostics])

    def test_access_credentials_never_appear_in_error_text(self):
        claims = make_claims()
        claims['_claim_sources']['src_dist'] = {
            'endpoint': BAD_ENDPOINT,
            'access_token': BAD_TOKEN,
        }
        with self.assertRaises(ClaimResolutionError) as ctx:
            resolve_claims(claims, fetcher=fake_fetcher,
                           jwt_decoder=verify_jwt)
        error_text = str(ctx.exception)
        self.assertNotIn(BAD_TOKEN, error_text)
        self.assertIn(REDACTED, error_text)
        for diagnostic in ctx.exception.diagnostics:
            self.assertNotIn(BAD_TOKEN, diagnostic.message)
            self.assertNotIn(BAD_TOKEN, repr(diagnostic))

    def test_invalid_aggregated_jwt_produces_diagnostic(self):
        claims = make_claims()
        claims['_claim_sources']['src_agg'] = {
            'JWT': make_jwt({'email': 'jane@example.org'}) + 'tampered',
        }
        resolved, diagnostics = resolve_claims(
            claims, fetcher=fake_fetcher, jwt_decoder=verify_jwt,
            strict=False)
        self.assertNotIn('email', resolved)
        self.assertIn('jwt_decode_failed', [d.code for d in diagnostics])

    def test_distributed_source_requires_fetcher(self):
        claims = make_claims()
        del claims['_claim_sources']['src_dist']
        claims['_claim_sources']['src_dist2'] = {'endpoint': DIST_ENDPOINT}
        claims['_claim_names']['address'] = 'src_dist2'
        claims['_claim_names'].pop('phone_number')
        resolved, diagnostics = resolve_claims(
            claims, jwt_decoder=verify_jwt, strict=False)
        self.assertNotIn('address', resolved)
        self.assertIn('fetcher_missing', [d.code for d in diagnostics])

    def test_claims_without_external_references_pass_through(self):
        resolved, diagnostics = resolve_claims(
            {'sub': 'user-123', 'name': 'Jane Doe'})
        self.assertEqual(diagnostics, [])
        self.assertEqual(resolved, {'sub': 'user-123', 'name': 'Jane Doe'})
