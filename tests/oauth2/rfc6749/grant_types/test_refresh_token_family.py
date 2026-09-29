# -*- coding: utf-8 -*-
import json
import threading
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.token_family import (
    InMemoryRefreshTokenStore, RefreshTokenFamilyStore,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase


def make_request(refresh_token, client_id='abcdef'):
    mock_client = mock.MagicMock()
    mock_client.user.return_value = 'mocked user'
    mock_client.client_id = client_id
    request = Request('http://a.b/path')
    request.grant_type = 'refresh_token'
    request.refresh_token = refresh_token
    request.client_id = client_id
    request.client = mock_client
    request.scope = 'foo'
    return request


def make_grant(store=None, **kwargs):
    mock_validator = mock.MagicMock()
    mock_validator.get_original_scopes.return_value = ['foo', 'bar']
    grant = RefreshTokenGrant(
        request_validator=mock_validator, refresh_token_store=store, **kwargs)
    return grant, mock_validator


def make_store(**root_kwargs):
    store = InMemoryRefreshTokenStore()
    store.register_family_root('rt0', client_id='abcdef',
                               user='mocked user', scopes=['foo'])
    return store


class RefreshTokenFamilyStoreTest(TestCase):

    def test_base_store_is_abstract(self):
        store = RefreshTokenFamilyStore()
        self.assertRaises(NotImplementedError,
                          store.register_family_root, 'rt0')
        self.assertRaises(NotImplementedError,
                          store.consume_and_register, 'rt0', {}, None)
        self.assertRaises(NotImplementedError, store.is_live, 'rt0')

    def test_consume_and_register_rotates_live_token(self):
        store = make_store()
        request = make_request('rt0')
        token = {'refresh_token': 'rt1', 'access_token': 'at1'}
        self.assertTrue(store.consume_and_register('rt0', token, request))
        self.assertFalse(store.is_live('rt0'))
        self.assertTrue(store.is_live('rt1'))

    def test_reuse_revokes_family(self):
        store = make_store()
        request = make_request('rt0')
        token = {'refresh_token': 'rt1'}
        self.assertTrue(store.consume_and_register('rt0', token, request))
        # Second use of the consumed token revokes the whole family.
        self.assertFalse(store.consume_and_register('rt0', token, request))
        self.assertFalse(store.is_live('rt0'))
        self.assertFalse(store.is_live('rt1'))

    def test_unknown_token_is_rejected_without_revoking(self):
        store = make_store()
        request = make_request('nope')
        self.assertFalse(store.consume_and_register(
            'nope', {'refresh_token': 'rt1'}, request))
        self.assertTrue(store.is_live('rt0'))

    def test_revocation_does_not_touch_other_logins_of_same_user(self):
        store = make_store()
        store.register_family_root('rtB', client_id='abcdef',
                                   user='mocked user', scopes=['foo'])
        request = make_request('rt0')
        token = {'refresh_token': 'rt1'}
        self.assertTrue(store.consume_and_register('rt0', token, request))
        self.assertFalse(store.consume_and_register('rt0', token, request))
        # The other session of the same user is unaffected.
        self.assertTrue(store.is_live('rtB'))

    def test_wrong_client_is_rejected_without_revoking(self):
        store = make_store()
        request = make_request('rt0', client_id='other-client')
        self.assertFalse(store.consume_and_register(
            'rt0', {'refresh_token': 'rt1'}, request))
        self.assertTrue(store.is_live('rt0'))

    def test_duplicate_root_raises(self):
        store = make_store()
        self.assertRaises(ValueError, store.register_family_root, 'rt0')


class RefreshTokenFamilyGrantTest(TestCase):

    def setUp(self):
        self.bearer = BearerToken(mock.MagicMock())

    def test_refresh_registers_successor_before_returning_it(self):
        store = make_store()
        grant, mock_validator = make_grant(store)
        headers, body, status = grant.create_token_response(
            make_request('rt0'), self.bearer)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertNotEqual(token['refresh_token'], 'rt0')
        self.assertTrue(store.is_live(token['refresh_token']))
        self.assertFalse(store.is_live('rt0'))
        # The store owns persistence; save_token must not be used.
        self.assertEqual(mock_validator.save_token.call_count, 0)

    def test_reused_refresh_token_gets_invalid_grant_and_revokes(self):
        store = make_store()
        grant, _ = make_grant(store)
        _, body, status = grant.create_token_response(
            make_request('rt0'), self.bearer)
        self.assertEqual(status, 200)
        successor = json.loads(body)['refresh_token']

        _, body, status = grant.create_token_response(
            make_request('rt0'), self.bearer)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_grant')
        self.assertNotIn('access_token', json.loads(body))
        # Reuse revoked the family, including the issued successor.
        self.assertFalse(store.is_live(successor))

    def test_revocation_leaves_other_logins_of_same_user_alone(self):
        store = make_store()
        store.register_family_root('rtB', client_id='abcdef',
                                   user='mocked user', scopes=['foo'])
        grant, _ = make_grant(store)
        grant.create_token_response(make_request('rt0'), self.bearer)
        # Replay the consumed token: family of rt0 is revoked ...
        _, _, status = grant.create_token_response(
            make_request('rt0'), self.bearer)
        self.assertEqual(status, 400)
        # ... but the second login of the same user still works.
        _, body, status = grant.create_token_response(
            make_request('rtB'), self.bearer)
        self.assertEqual(status, 200)
        self.assertTrue(store.is_live(json.loads(body)['refresh_token']))

    def test_unknown_refresh_token_gets_invalid_grant(self):
        store = make_store()
        grant, _ = make_grant(store)
        _, body, status = grant.create_token_response(
            make_request('unknown'), self.bearer)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_grant')

    def test_storage_failure_never_returns_unregistered_token(self):
        class FailingStore(InMemoryRefreshTokenStore):
            def consume_and_register(self, refresh_token, token, request):
                raise RuntimeError('database is down')

        store = FailingStore()
        store.register_family_root('rt0', client_id='abcdef')
        grant, _ = make_grant(store)
        _, body, status = grant.create_token_response(
            make_request('rt0'), self.bearer)
        self.assertEqual(status, 503)
        payload = json.loads(body)
        self.assertEqual(payload['error'], 'temporarily_unavailable')
        self.assertNotIn('access_token', payload)
        self.assertNotIn('refresh_token', payload)
        # The old token was not consumed, the client may retry.
        self.assertTrue(store.is_live('rt0'))

    def test_oauth2_error_from_store_is_passed_through(self):
        class PickyStore(InMemoryRefreshTokenStore):
            def consume_and_register(self, refresh_token, token, request):
                raise errors.InvalidClientError(request=request)

        store = PickyStore()
        store.register_family_root('rt0', client_id='abcdef')
        grant, _ = make_grant(store)
        _, body, status = grant.create_token_response(
            make_request('rt0'), self.bearer)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'invalid_client')

    def test_store_requires_refresh_token_rotation(self):
        self.assertRaises(
            ValueError, make_grant,
            InMemoryRefreshTokenStore(), issue_new_refresh_tokens=False)

    def test_concurrent_refresh_allows_at_most_one_usable_successor(self):
        for _ in range(50):
            store = make_store()
            grant, _ = make_grant(store)
            results = []
            barrier = threading.Barrier(2)

            def refresh():
                barrier.wait()
                results.append(grant.create_token_response(
                    make_request('rt0'), self.bearer))

            threads = [threading.Thread(target=refresh) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            statuses = sorted(status for _, _, status in results)
            self.assertEqual(statuses, [200, 400])
            loser = next(json.loads(body)
                         for _, body, status in results if status == 400)
            self.assertEqual(loser['error'], 'invalid_grant')
            self.assertNotIn('access_token', loser)
            winner = next(json.loads(body)
                          for _, body, status in results if status == 200)
            self.assertIn('access_token', winner)
            # The loser's reuse of the consumed token revoked the family,
            # so no token of the family remains usable afterwards.
            self.assertFalse(store.is_live('rt0'))
            self.assertFalse(store.is_live(winner['refresh_token']))


class RefreshTokenGrantCompatibilityTest(TestCase):
    """Validators that do not opt into the family store are unaffected."""

    def test_legacy_save_token_path_is_unchanged(self):
        grant, mock_validator = make_grant(store=None)
        self.assertIsNone(grant.refresh_token_store)
        bearer = BearerToken(mock_validator)
        _, body, status = grant.create_token_response(
            make_request('rt0'), bearer)
        self.assertEqual(status, 200)
        self.assertIn('access_token', json.loads(body))
        self.assertEqual(mock_validator.save_token.call_count, 1)
