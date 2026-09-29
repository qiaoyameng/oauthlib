# -*- coding: utf-8 -*-
import json
import time
from unittest import mock
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from oauthlib.openid import BackChannelLogoutEndpoint, LogoutTokenStatus
from oauthlib.openid.connect.core.endpoints.backchannel_logout import (
    BACKCHANNEL_LOGOUT_EVENT,
)

from tests.unittest import TestCase


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class InMemorySessionStore:
    """Minimal in-memory session store used as revocation callback target."""

    def __init__(self):
        self.sessions = {
            'sid-john': {'sub': 'john'},
            'sid-jane': {'sub': 'jane'},
        }
        self.revoked = []

    def revoke(self, sid=None, sub=None):
        for session_id, session in list(self.sessions.items()):
            matches_sid = sid is not None and session_id == sid
            matches_sub = sub is not None and session.get('sub') == sub
            if matches_sid or matches_sub:
                del self.sessions[session_id]
                self.revoked.append({'sid': sid, 'sub': sub})


class BackChannelLogoutEndpointTest(TestCase):
    issuer = 'https://op.example.com'
    client_id = 'rp-client'

    @classmethod
    def setUpClass(cls):
        cls.private_key = generate_key()
        cls.other_key = generate_key()

    def setUp(self):
        self.sessions = InMemorySessionStore()
        self.endpoint = BackChannelLogoutEndpoint(
            issuer=self.issuer,
            audience=self.client_id,
            keys=self.private_key.public_key(),
            session_revoker=self.sessions.revoke,
        )

    def make_token(self, key=None, algorithm='RS256', headers=None, **claims):
        payload = {
            'iss': self.issuer,
            'aud': self.client_id,
            'iat': int(time.time()),
            'exp': int(time.time()) + 600,
            'jti': 'jti-1',
            'events': {BACKCHANNEL_LOGOUT_EVENT: {}},
            'sid': 'sid-john',
        }
        for name, value in claims.items():
            if value is None:
                payload.pop(name, None)
            else:
                payload[name] = value
        return jwt.encode(payload, key or self.private_key,
                          algorithm=algorithm, headers=headers)

    def test_valid_token_with_sid(self):
        status = self.endpoint.handle_logout_token(self.make_token())
        self.assertEqual(status, LogoutTokenStatus.PROCESSED)
        self.assertEqual(self.sessions.revoked, [{'sid': 'sid-john', 'sub': None}])
        self.assertNotIn('sid-john', self.sessions.sessions)

    def test_valid_token_with_sub_only(self):
        token = self.make_token(sid=None, sub='jane')
        status = self.endpoint.handle_logout_token(token)
        self.assertEqual(status, LogoutTokenStatus.PROCESSED)
        self.assertEqual(self.sessions.revoked, [{'sid': None, 'sub': 'jane'}])
        self.assertNotIn('sid-jane', self.sessions.sessions)

    def test_valid_token_with_sid_and_sub(self):
        token = self.make_token(sub='john')
        status = self.endpoint.handle_logout_token(token)
        self.assertEqual(status, LogoutTokenStatus.PROCESSED)
        self.assertEqual(self.sessions.revoked,
                         [{'sid': 'sid-john', 'sub': 'john'}])

    def test_duplicate_delivery_has_no_side_effects(self):
        token = self.make_token()
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.PROCESSED)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.ALREADY_PROCESSED)
        self.assertEqual(len(self.sessions.revoked), 1)

    def test_failed_validation_does_not_consume_jti(self):
        invalid = self.make_token(sid=None)
        self.assertEqual(self.endpoint.handle_logout_token(invalid),
                         LogoutTokenStatus.INVALID)
        valid = self.make_token()
        self.assertEqual(self.endpoint.handle_logout_token(valid),
                         LogoutTokenStatus.PROCESSED)
        self.assertEqual(len(self.sessions.revoked), 1)

    def test_token_with_nonce_rejected(self):
        token = self.make_token(nonce='n-0S6_WzA2Mj')
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)
        self.assertEqual(self.sessions.revoked, [])

    def test_token_without_sid_and_sub_rejected(self):
        token = self.make_token(sid=None)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)
        self.assertEqual(self.sessions.revoked, [])

    def test_wrong_signature_rejected(self):
        token = self.make_token(key=self.other_key)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_wrong_issuer_rejected(self):
        token = self.make_token(iss='https://evil.example.com')
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_wrong_audience_rejected(self):
        token = self.make_token(aud='someone-else')
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_expired_token_rejected(self):
        token = self.make_token(iat=int(time.time()) - 1200,
                                exp=int(time.time()) - 600)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_missing_jti_rejected(self):
        token = self.make_token(jti=None)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_missing_iat_rejected(self):
        token = self.make_token(iat=None)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_missing_events_rejected(self):
        token = self.make_token(events=None)
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_wrong_event_rejected(self):
        token = self.make_token(events={'http://example.com/other-event': {}})
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_malformed_token_rejected(self):
        self.assertEqual(self.endpoint.handle_logout_token('not-a-jwt'),
                         LogoutTokenStatus.INVALID)

    def test_disallowed_algorithm_rejected(self):
        token = jwt.encode({'foo': 'bar'}, None, algorithm='none')
        self.assertEqual(self.endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_kid_key_mapping(self):
        endpoint = BackChannelLogoutEndpoint(
            issuer=self.issuer,
            audience=self.client_id,
            keys={'good': self.private_key.public_key()},
            session_revoker=self.sessions.revoke,
        )
        token = self.make_token(headers={'kid': 'good'})
        self.assertEqual(endpoint.handle_logout_token(token),
                         LogoutTokenStatus.PROCESSED)
        token = self.make_token(jti='jti-2', headers={'kid': 'unknown'})
        self.assertEqual(endpoint.handle_logout_token(token),
                         LogoutTokenStatus.INVALID)

    def test_callable_key_resolver(self):
        resolver = mock.Mock(return_value=self.private_key.public_key())
        endpoint = BackChannelLogoutEndpoint(
            issuer=self.issuer,
            audience=self.client_id,
            keys=resolver,
            session_revoker=self.sessions.revoke,
        )
        token = self.make_token()
        self.assertEqual(endpoint.handle_logout_token(token),
                         LogoutTokenStatus.PROCESSED)
        resolver.assert_called_once()

    def test_create_logout_response_success(self):
        body = urlencode({'logout_token': self.make_token()})
        headers, body, status = self.endpoint.create_logout_response(
            'https://rp.example.com/backchannel_logout', body=body)
        self.assertEqual(status, 200)
        self.assertEqual(body, '')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(len(self.sessions.revoked), 1)

    def test_create_logout_response_duplicate_still_ok(self):
        body = urlencode({'logout_token': self.make_token()})
        self.endpoint.create_logout_response('https://rp.example.com/bc',
                                             body=body)
        _, _, status = self.endpoint.create_logout_response(
            'https://rp.example.com/bc', body=body)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.sessions.revoked), 1)

    def test_create_logout_response_invalid_token(self):
        body = urlencode({'logout_token': self.make_token(nonce='abc')})
        headers, body, status = self.endpoint.create_logout_response(
            'https://rp.example.com/bc', body=body)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_request')
        self.assertEqual(self.sessions.revoked, [])

    def test_create_logout_response_missing_token(self):
        _, body, status = self.endpoint.create_logout_response(
            'https://rp.example.com/bc', body=urlencode({}))
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_request')
