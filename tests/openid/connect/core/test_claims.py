import time

import jwt

from oauthlib.openid.connect.core.claims import (
    CLAIM_NAMES_MEMBER,
    CLAIM_SOURCES_MEMBER,
    ClaimNotProvidedError,
    ClaimResolutionError,
    CyclicClaimMappingError,
    DuplicateClaimOwnershipError,
    InvalidClaimSourceError,
    MissingClaimSourceError,
    ProtectedClaimError,
    resolve_claims,
)

from tests.unittest import TestCase

SECRET = 'aggregator-signing-secret'
ISSUER = 'https://aggregator.example'

# Access credentials used by the fake sources. They must never surface in an
# error message.
DISTRIBUTED_TOKEN = 'supersecret-access-token-123'
AGGREGATED_TOKEN_SECRET = SECRET


def sign_aggregated(claims):
    return jwt.encode(
        dict(claims, iss=ISSUER, iat=int(time.time()), exp=int(time.time()) + 60),
        SECRET, algorithm='HS256')


def verify_aggregated(descriptor):
    """Fake aggregated claims verifier for a trusted inline signed JWT."""
    return jwt.decode(
        descriptor['JWT'], SECRET, algorithms=['HS256'], issuer=ISSUER,
        options={'require': ['iss', 'exp', 'iat']})


def make_fetcher(endpoints):
    """Build a fake distributed claims retriever keyed by endpoint URL."""

    def fetch(descriptor):
        endpoint = descriptor['endpoint']
        if endpoint not in endpoints:
            raise RuntimeError(f'GET {endpoint}?access_token={DISTRIBUTED_TOKEN}')
        return endpoints[endpoint]

    return fetch


AGGREGATED_ENDPOINT = 'src_aggregated'
DISTRIBUTED_ENDPOINT_NAME = 'src_distributed'
PROFILE_URL = 'https://profiles.example/me'
PAYMENT_URL = 'https://payments.example/wallet'


class ResolveClaimsTestCase(TestCase):

    def profile_with_two_sources(self, payment_payload=None,
                                 payment_fails=False):
        aggregated_jwt = sign_aggregated({
            'shipping_address': {'country': 'US', 'postal_code': '94043'},
            # Smuggled, unrequested attribute and a sub override attempt must
            # both be discarded by the resolver.
            'payment_info': {'card': '4242'},
            'sub': 'attacker-controlled-sub',
        })
        endpoints = {}
        if not payment_fails:
            endpoints[PAYMENT_URL] = payment_payload if payment_payload is not None else {
                'payment_info': {'account': 'acct_123'},
                'extra_not_requested': 'nope',
                'sub': 'attacker-controlled-sub',
            }
        userinfo = {
            'sub': 'user-1',
            'name': 'Alice Example',
            CLAIM_NAMES_MEMBER: {
                'shipping_address': AGGREGATED_ENDPOINT,
                'payment_info': DISTRIBUTED_ENDPOINT_NAME,
            },
            CLAIM_SOURCES_MEMBER: {
                AGGREGATED_ENDPOINT: {'JWT': aggregated_jwt},
                DISTRIBUTED_ENDPOINT_NAME: {
                    'endpoint': PAYMENT_URL,
                    'access_token': DISTRIBUTED_TOKEN,
                },
            },
        }
        return userinfo

    def test_two_fake_sources_happy_path(self):
        userinfo = self.profile_with_two_sources()
        result = resolve_claims(
            userinfo,
            fetch_distributed_claims=make_fetcher({
                PAYMENT_URL: {
                    'payment_info': {'account': 'acct_123'},
                    'extra_not_requested': 'nope',
                    'sub': 'attacker-controlled-sub',
                },
            }),
            verify_aggregated_claims=verify_aggregated,
        )

        self.assertTrue(result.ok, [str(e) for e in result.errors])
        self.assertEqual(result.claims['sub'], 'user-1')
        self.assertEqual(result.claims['name'], 'Alice Example')
        self.assertEqual(
            result.claims['shipping_address'],
            {'country': 'US', 'postal_code': '94043'})
        self.assertEqual(
            result.claims['payment_info'], {'account': 'acct_123'})
        self.assertNotIn('extra_not_requested', result.claims)
        self.assertNotIn(CLAIM_NAMES_MEMBER, result.claims)
        self.assertNotIn(CLAIM_SOURCES_MEMBER, result.claims)
        # Input mapping is not mutated.
        self.assertIn(CLAIM_NAMES_MEMBER, userinfo)

    def test_one_source_failing_strict_mode_raises(self):
        """Strict mode: a single failing source aborts the whole resolution."""
        userinfo = self.profile_with_two_sources(payment_fails=True)
        with self.assertRaises(InvalidClaimSourceError) as ctx:
            resolve_claims(
                userinfo,
                fetch_distributed_claims=make_fetcher({}),
                verify_aggregated_claims=verify_aggregated,
                strict=True,
            )
        message = str(ctx.exception)
        self.assertNotIn(DISTRIBUTED_TOKEN, message)
        self.assertNotIn(AGGREGATED_TOKEN_SECRET, message)
        # The endpoint host/path may be reported, query credentials may not.
        self.assertIn('payments.example', message)
        self.assertNotIn('access_token', message)

    def test_one_source_failing_partial_mode_returns_other_source(self):
        """Explicit partial result mode keeps claims from the healthy source."""
        userinfo = self.profile_with_two_sources(payment_fails=True)
        result = resolve_claims(
            userinfo,
            fetch_distributed_claims=make_fetcher({}),
            verify_aggregated_claims=verify_aggregated,
            strict=False,
        )

        self.assertFalse(result.ok)
        self.assertEqual(len(result.errors), 1)
        # The distributed claim is missing, the aggregated claim is present.
        self.assertNotIn('payment_info', result.claims)
        self.assertEqual(
            result.claims['shipping_address'],
            {'country': 'US', 'postal_code': '94043'})
        self.assertEqual(result.claims['sub'], 'user-1')
        message = str(result.errors[0])
        self.assertNotIn(DISTRIBUTED_TOKEN, message)

    def test_strict_mode_keyword_must_be_explicit_for_partial(self):
        # Default (strict=False) behaves like explicit partial results.
        userinfo = self.profile_with_two_sources(payment_fails=True)
        default_result = resolve_claims(
            userinfo,
            fetch_distributed_claims=make_fetcher({}),
            verify_aggregated_claims=verify_aggregated,
        )
        explicit_result = resolve_claims(
            userinfo,
            fetch_distributed_claims=make_fetcher({}),
            verify_aggregated_claims=verify_aggregated,
            strict=False,
        )
        self.assertEqual(default_result.ok, explicit_result.ok)
        self.assertEqual(default_result.claims, explicit_result.claims)


class ClaimDiagnosticsTestCase(TestCase):

    def resolve(self, userinfo, **kwargs):
        kwargs.setdefault('fetch_distributed_claims', make_fetcher({
            PROFILE_URL: {'nickname': 'ali'},
        }))
        kwargs.setdefault('verify_aggregated_claims', verify_aggregated)
        return resolve_claims(userinfo, **kwargs)

    def test_missing_claim_source_is_diagnosed(self):
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'ghost'},
            CLAIM_SOURCES_MEMBER: {},
        }
        result = self.resolve(userinfo)
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], MissingClaimSourceError)
        self.assertEqual(result.errors[0].claim, 'nickname')
        self.assertEqual(result.errors[0].source, 'ghost')
        with self.assertRaises(MissingClaimSourceError):
            self.resolve(userinfo, strict=True)

    def test_claim_attributed_to_source_and_present_locally_is_duplicate(self):
        userinfo = {
            'sub': 'u',
            'nickname': 'local-ali',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {
                'src1': {'endpoint': PROFILE_URL},
            },
        }
        result = self.resolve(userinfo)
        duplicates = [e for e in result.errors
                      if isinstance(e, DuplicateClaimOwnershipError)]
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0].claim, 'nickname')
        self.assertEqual(duplicates[0].source, 'userinfo')
        # Local value wins; the source cannot overwrite it.
        self.assertEqual(result.claims['nickname'], 'local-ali')

    def test_two_sources_claiming_same_field_is_duplicate(self):
        # Both sources answer the same field: the source that resolves second
        # must be diagnosed as a duplicate owner instead of overwriting.
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {
                'src1': {'JWT': sign_aggregated({
                    'nickname': 'first',
                    CLAIM_NAMES_MEMBER: {'nickname': 'src2'},
                    CLAIM_SOURCES_MEMBER: {'src2': {'endpoint': PROFILE_URL}},
                })},
            },
        }
        result = self.resolve(userinfo)
        duplicates = [e for e in result.errors
                      if isinstance(e, DuplicateClaimOwnershipError)]
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0].claim, 'nickname')
        self.assertEqual(duplicates[0].source, 'src1')
        self.assertEqual(result.claims['nickname'], 'first')

    def test_nested_graph_drops_unrequested_attributes(self):
        # Even when a source carries its own claim graph, plain attributes
        # that the parent did not request are still discarded.
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {
                'src1': {'JWT': sign_aggregated({
                    'nickname': 'ali',
                    'smuggled': {'role': 'admin'},
                    CLAIM_NAMES_MEMBER: {},
                    CLAIM_SOURCES_MEMBER: {},
                })},
            },
        }
        result = self.resolve(userinfo)
        self.assertTrue(result.ok, [str(e) for e in result.errors])
        self.assertEqual(result.claims['nickname'], 'ali')
        self.assertNotIn('smuggled', result.claims)

    def test_self_referential_source_is_cyclic(self):
        # The endpoint returns a payload referencing the same source name and
        # descriptor object again, forming a cycle through the endpoint.
        descriptors = {'loop': {'endpoint': PROFILE_URL}}
        nested = {
            CLAIM_NAMES_MEMBER: {'nickname': 'loop'},
            CLAIM_SOURCES_MEMBER: descriptors,
        }
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'loop'},
            CLAIM_SOURCES_MEMBER: descriptors,
        }
        result = self.resolve(
            userinfo,
            fetch_distributed_claims=make_fetcher({PROFILE_URL: nested}))
        cycles = [e for e in result.errors
                  if isinstance(e, CyclicClaimMappingError)]
        self.assertTrue(cycles)
        with self.assertRaises(CyclicClaimMappingError):
            self.resolve(
                userinfo,
                fetch_distributed_claims=make_fetcher({PROFILE_URL: nested}),
                strict=True)

    def test_sub_can_never_be_overridden_by_source(self):
        userinfo = {
            'sub': 'user-1',
            CLAIM_NAMES_MEMBER: {'sub': 'src1'},
            CLAIM_SOURCES_MEMBER: {'src1': {'endpoint': PROFILE_URL}},
        }
        result = self.resolve(userinfo)
        protected = [e for e in result.errors if isinstance(e, ProtectedClaimError)]
        self.assertEqual(len(protected), 1)
        self.assertEqual(result.claims['sub'], 'user-1')

    def test_sub_inside_aggregated_payload_is_ignored(self):
        userinfo = {
            'sub': 'user-1',
            CLAIM_NAMES_MEMBER: {'sub': 'jwtsrc'},
            CLAIM_SOURCES_MEMBER: {'jwtsrc': {'JWT': sign_aggregated({
                'sub': 'forged', 'nickname': 'ali'})}},
        }
        # Even when another claim is requested alongside, forged sub drops.
        userinfo[CLAIM_NAMES_MEMBER] = {'nickname': 'jwtsrc'}
        result = self.resolve(userinfo)
        self.assertEqual(result.claims['sub'], 'user-1')
        self.assertNotIn('forged', result.claims.values())

    def test_unrequested_attributes_are_dropped(self):
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {'src1': {
                'JWT': sign_aggregated({
                    'nickname': 'ali', 'admin': True,
                    'groups': ['everyone', 'staff']})}},
        }
        result = self.resolve(userinfo)
        self.assertTrue(result.ok, [str(e) for e in result.errors])
        self.assertEqual(result.claims['nickname'], 'ali')
        self.assertNotIn('admin', result.claims)
        self.assertNotIn('groups', result.claims)

    def test_aggregated_source_requires_verifier(self):
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'jwtsrc'},
            CLAIM_SOURCES_MEMBER: {'jwtsrc': {'JWT': 'header.body.sig'}},
        }
        result = resolve_claims(userinfo)
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], InvalidClaimSourceError)
        self.assertNotIn('header.body.sig', str(result.errors[0]))

    def test_distributed_source_requires_fetcher(self):
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {'src1': {'endpoint': PROFILE_URL}},
        }
        result = resolve_claims(userinfo)
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], InvalidClaimSourceError)

    def test_invalid_signature_is_diagnosed_without_token_leak(self):
        bad_token = jwt.encode({'nickname': 'ali'}, 'wrong-secret',
                               algorithm='HS256')
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'jwtsrc'},
            CLAIM_SOURCES_MEMBER: {'jwtsrc': {'JWT': bad_token}},
        }
        result = self.resolve(userinfo)
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], InvalidClaimSourceError)
        self.assertNotIn(bad_token, str(result.errors[0]))

    def test_descriptor_must_choose_jwt_or_endpoint(self):
        for descriptor in ({}, {'JWT': 'a.b.c', 'endpoint': PROFILE_URL}):
            userinfo = {
                'sub': 'u',
                CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
                CLAIM_SOURCES_MEMBER: {'src1': descriptor},
            }
            result = self.resolve(userinfo)
            self.assertFalse(result.ok)
            self.assertIsInstance(result.errors[0], InvalidClaimSourceError)

    def test_non_object_payload_is_invalid(self):
        result = self.resolve({
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {'src1': {'endpoint': PROFILE_URL}},
        }, fetch_distributed_claims=lambda descriptor: ['not', 'an', 'object'])
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], InvalidClaimSourceError)

    def test_non_object_userinfo_is_invalid(self):
        result = resolve_claims(['not', 'an', 'object'])
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], InvalidClaimSourceError)

    def test_claim_not_provided_by_source(self):
        result = self.resolve({
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'src1'},
            CLAIM_SOURCES_MEMBER: {'src1': {'endpoint': PROFILE_URL}},
        }, fetch_distributed_claims=make_fetcher({PROFILE_URL: {'name': 'Bob'}}))
        self.assertFalse(result.ok)
        self.assertIsInstance(result.errors[0], ClaimNotProvidedError)

    def test_nested_aggregated_graph_resolves(self):
        inner_jwt = sign_aggregated({'nickname': 'deep-ali'})
        outer_jwt = sign_aggregated({
            CLAIM_NAMES_MEMBER: {'nickname': 'inner'},
            CLAIM_SOURCES_MEMBER: {'inner': {'JWT': inner_jwt}},
        })
        userinfo = {
            'sub': 'u',
            CLAIM_NAMES_MEMBER: {'nickname': 'outer'},
            CLAIM_SOURCES_MEMBER: {'outer': {'JWT': outer_jwt}},
        }
        result = self.resolve(userinfo)
        self.assertTrue(result.ok, [str(e) for e in result.errors])
        self.assertEqual(result.claims['nickname'], 'deep-ali')

    def test_error_hierarchy_and_result_ok(self):
        self.assertTrue(issubclass(MissingClaimSourceError, ClaimResolutionError))
        result = self.resolve({'sub': 'u'})
        self.assertTrue(result.ok)
        self.assertEqual(result.claims, {'sub': 'u'})
