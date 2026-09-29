# -*- coding: utf-8 -*-
"""Tests for the optional refresh token family protocol."""
import json
import threading

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.token_family import InMemoryTokenFamilyValidator
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase


def make_request(refresh_token, client_id='client-1'):
    request = Request('http://a.b/path')
    request.grant_type = 'refresh_token'
    request.refresh_token = refresh_token
    request.client_id = client_id
    request.scope = None
    return request


def seed_login(validator, refresh_token, user='user-1',
               scopes=('read', 'write'), client_id='client-1'):
    """Simulate a fresh login issuing ``refresh_token`` (new family)."""
    request = Request('http://a.b/path')
    request.client_id = client_id
    request.user = user
    request.scopes = list(scopes)
    validator.save_bearer_token({
        'access_token': 'at-for-' + refresh_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
    }, request)


class TokenFamilyTestCase(TestCase):

    def setUp(self):
        self.validator = InMemoryTokenFamilyValidator()
        self.validator.register_client('client-1')
        self.grant = RefreshTokenGrant(request_validator=self.validator)
        self.bearer = BearerToken(self.validator)

    def refresh(self, refresh_token):
        return self.grant.create_token_response(
            make_request(refresh_token), self.bearer)

    def refresh_token_valid(self, refresh_token):
        # Read-only probe: validate_refresh_token would count as presenting
        # the token to the token endpoint (a replay event for spent tokens).
        return self.validator.is_refresh_token_usable(refresh_token)


class SequentialRotationTest(TokenFamilyTestCase):

    def test_exactly_one_usable_successor(self):
        seed_login(self.validator, 'rt0')

        _headers, body, status = self.refresh('rt0')
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertNotEqual(token['refresh_token'], 'rt0')

        # The old token is spent, exactly one successor is usable.
        self.assertFalse(self.refresh_token_valid('rt0'))
        self.assertTrue(self.refresh_token_valid(token['refresh_token']))

        # The successor itself rotates: still exactly one usable token.
        _headers, body2, status2 = self.refresh(token['refresh_token'])
        self.assertEqual(status2, 200)
        token2 = json.loads(body2)
        self.assertFalse(self.refresh_token_valid(token['refresh_token']))
        self.assertTrue(self.refresh_token_valid(token2['refresh_token']))


class ReplayDetectionTest(TokenFamilyTestCase):

    def test_replay_revokes_whole_family(self):
        seed_login(self.validator, 'rt0')
        _headers, body, status = self.refresh('rt0')
        self.assertEqual(status, 200)
        successor = json.loads(body)['refresh_token']
        access_token = json.loads(body)['access_token']

        # Replay of the spent token is rejected...
        _headers, body, status = self.refresh('rt0')
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_grant')

        # ...and revokes the entire family, including the successor that
        # was legitimately issued and its access tokens.
        self.assertFalse(self.refresh_token_valid(successor))
        _headers, body, status = self.refresh(successor)
        self.assertEqual(status, 400)
        self.assertFalse(self.validator.validate_bearer_token(
            access_token, ['read'], make_request(successor)))

    def test_replay_does_not_touch_other_logins_of_same_user(self):
        # Two independent logins (e.g. two devices) for the same user.
        seed_login(self.validator, 'rt-phone', user='user-1')
        seed_login(self.validator, 'rt-laptop', user='user-1')

        _headers, body, status = self.refresh('rt-phone')
        self.assertEqual(status, 200)
        phone_successor = json.loads(body)['refresh_token']

        # Replay on the phone's family revokes only that family.
        _headers, _body, status = self.refresh('rt-phone')
        self.assertEqual(status, 400)
        self.assertFalse(self.refresh_token_valid(phone_successor))

        # The laptop login of the same user is unaffected.
        self.assertTrue(self.refresh_token_valid('rt-laptop'))
        _headers, body, status = self.refresh('rt-laptop')
        self.assertEqual(status, 200)
        self.assertIn('refresh_token', json.loads(body))


class ConcurrentRotationTest(TokenFamilyTestCase):

    def test_concurrent_refresh_at_most_one_winner(self):
        for _ in range(25):
            validator = InMemoryTokenFamilyValidator()
            validator.register_client('client-1')
            seed_login(validator, 'rt0')
            grant = RefreshTokenGrant(request_validator=validator)
            bearer = BearerToken(validator)
            barrier = threading.Barrier(2)
            results = []

            def worker():
                try:
                    barrier.wait(timeout=10)
                    results.append(grant.create_token_response(
                        make_request('rt0'), bearer))
                except Exception as exc:  # fail the assertions below instead
                    results.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

            self.assertEqual(len(results), 2)
            for result in results:
                self.assertNotIsInstance(
                    result, Exception, 'worker raised %r' % (result,))
            statuses = sorted(result[2] for result in results)
            self.assertEqual(statuses, [200, 400],
                             'exactly one request may win the rotation race')

            winner = next(r for r in results if r[2] == 200)
            loser = next(r for r in results if r[2] == 400)
            winner_token = json.loads(winner[1])
            self.assertIn('refresh_token', winner_token)
            self.assertEqual(json.loads(loser[1])['error'], 'invalid_grant')

            # The spent token stays spent: a later replay is rejected and
            # no further successor can be minted from it.
            _headers, body, status = grant.create_token_response(
                make_request('rt0'), bearer)
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body)['error'], 'invalid_grant')


class StorageFailureTest(TokenFamilyTestCase):

    def test_storage_failure_never_returns_unregistered_token(self):
        validator = self.validator
        validator.storage_down = True

        original_consume = validator.consume_refresh_token

        def flaky_consume(*args, **kwargs):
            if validator.storage_down:
                raise RuntimeError('storage is down')
            return original_consume(*args, **kwargs)

        validator.consume_refresh_token = flaky_consume
        seed_login(validator, 'rt0')

        _headers, body, status = self.refresh('rt0')
        self.assertEqual(status, 500)
        error = json.loads(body)
        self.assertEqual(error['error'], 'server_error')
        self.assertNotIn('access_token', error)
        self.assertNotIn('refresh_token', error)

        # The failed attempt neither consumed the old token nor registered
        # a successor: the client can simply retry once storage recovers.
        self.assertTrue(self.refresh_token_valid('rt0'))
        validator.storage_down = False
        _headers, body, status = self.refresh('rt0')
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertTrue(self.refresh_token_valid(token['refresh_token']))
        self.assertFalse(self.refresh_token_valid('rt0'))


class LegacyValidator(RequestValidator):
    """Pre-protocol validator: no consume_refresh_token override."""

    def __init__(self):
        self.refresh_tokens = {'rt0': ['read']}
        self.saved = []

    def client_authentication_required(self, request, *args, **kwargs):
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        request.client = type('Client', (), {'client_id': client_id})()
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        return grant_type == 'refresh_token'

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        return refresh_token in self.refresh_tokens

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        return self.refresh_tokens.get(refresh_token, [])

    def save_bearer_token(self, token, request, *args, **kwargs):
        self.saved.append(token)


class LegacyCompatibilityTest(TestCase):

    def test_protocol_disabled_by_default(self):
        validator = RequestValidator()
        self.assertIsNone(validator.consume_refresh_token(
            'old', 'new', None, Request('http://a.b/path')))

    def test_legacy_validator_keeps_working(self):
        validator = LegacyValidator()
        grant = RefreshTokenGrant(request_validator=validator)
        bearer = BearerToken(validator)

        _headers, body, status = grant.create_token_response(
            make_request('rt0'), bearer)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertEqual(len(validator.saved), 1)

        # Legacy semantics are unchanged: the old token was not consumed.
        self.assertTrue(validator.validate_refresh_token(
            'rt0', None, make_request('rt0')))
