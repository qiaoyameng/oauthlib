# -*- coding: utf-8 -*-
import re
from unittest import mock

import jwt

from oauthlib.common import Request
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.jwt_response import (
    ExpiredSignedResponseError, InvalidAudienceError, InvalidSignatureError,
    JWTResponseConfig, validate_signed_response,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase


SECRET = 'response-signing-secret'
ISSUER = 'https://as.example.com'


def decode_unverified(response_jwt):
    return jwt.decode(response_jwt, options={'verify_signature': False})


class JWTResponseModeServerTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.client = 'batman'
        self.request.client_id = 'abcdef'
        self.request.response_type = 'code'
        self.request.grant_type = 'authorization_code'
        self.request.redirect_uri = 'https://a.b/cb'
        self.request.state = 'xyz'
        self.request.response_mode = 'query.jwt'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.is_pkce_required.return_value = False
        self.mock_validator.get_code_challenge.return_value = None
        self.mock_validator.is_origin_allowed.return_value = False

        self.config = JWTResponseConfig(
            signing_key=SECRET, algorithm='HS256',
            issuer=ISSUER, expires_in=600)
        self.auth = AuthorizationCodeGrant(
            request_validator=self.mock_validator,
            jwt_response_config=self.config)
        self.bearer = BearerToken(self.mock_validator)

    def extract_response_jwt(self, headers):
        query = dict(Request(headers['Location']).uri_query_params)
        self.assertIn('response', query)
        self.assertNotIn('code', query)
        self.assertNotIn('state', query)
        return query['response']

    def test_query_jwt_success(self):
        h, _b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        claims = decode_unverified(self.extract_response_jwt(h))
        self.assertIn('code', claims)
        self.assertEqual(claims['state'], 'xyz')
        self.assertEqual(claims['iss'], ISSUER)
        self.assertEqual(claims['aud'], 'abcdef')
        self.assertLessEqual(claims['exp'] - claims['iat'], 600)

    def test_form_post_jwt_success(self):
        self.request.response_mode = 'form_post.jwt'
        h, b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 200)
        self.assertNotIn('Location', h)
        self.assertIn('<form method="post" action="https://a.b/cb">', b)
        match = re.search(r'name="response" value="([^"]+)"', b)
        self.assertIsNotNone(match)
        claims = decode_unverified(match.group(1))
        self.assertIn('code', claims)
        self.assertEqual(claims['state'], 'xyz')
        self.assertEqual(claims['aud'], 'abcdef')

    def test_jwt_error_response_uses_same_wrapping(self):
        self.mock_validator.validate_scopes.return_value = False
        h, _b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        claims = decode_unverified(self.extract_response_jwt(h))
        self.assertEqual(claims['error'], 'invalid_scope')
        self.assertEqual(claims['state'], 'xyz')
        self.assertEqual(claims['aud'], 'abcdef')
        self.assertNotIn('code', claims)

    def test_unvalidated_redirect_uri_still_fatal(self):
        self.mock_validator.validate_redirect_uri.return_value = False
        self.request.redirect_uri = 'https://evil.example/cb'
        self.assertRaises(errors.MismatchingRedirectURIError,
                          self.auth.create_authorization_response,
                          self.request, self.bearer)

    def test_signing_failure_does_not_fall_back_to_plaintext(self):
        self.config.create_response = mock.Mock(side_effect=ValueError('boom'))
        self.assertRaises(errors.ServerError,
                          self.auth.create_authorization_response,
                          self.request, self.bearer)

    def test_jwt_mode_without_config_falls_back_to_default_mode(self):
        self.auth.jwt_response_config = None
        h, _b, _s = self.auth.create_authorization_response(self.request, self.bearer)
        grant = dict(Request(h['Location']).uri_query_params)
        self.assertIn('code', grant)
        self.assertNotIn('response', grant)


class JWTResponseModeClientTest(TestCase):

    def setUp(self):
        self.config = JWTResponseConfig(
            signing_key=SECRET, algorithm='HS256',
            issuer=ISSUER, expires_in=600)
        self.client = WebApplicationClient('abcdef', state='xyz')

    def create_response(self, client_id='abcdef', **params):
        return self.config.create_response(client_id, params)

    def test_valid_response_roundtrip(self):
        response_jwt = self.create_response(code='somecode', state='xyz')
        params = self.client.parse_signed_authorization_response(
            response_jwt, SECRET, issuer=ISSUER)
        self.assertEqual(params['code'], 'somecode')
        self.assertEqual(params['state'], 'xyz')
        self.assertEqual(self.client.code, 'somecode')

    def test_wrong_audience_rejected(self):
        response_jwt = self.create_response(client_id='someone-else',
                                            code='somecode', state='xyz')
        self.assertRaises(InvalidAudienceError,
                          self.client.parse_signed_authorization_response,
                          response_jwt, SECRET)

    def test_expired_response_rejected(self):
        config = JWTResponseConfig(signing_key=SECRET, issuer=ISSUER,
                                   expires_in=-10)
        response_jwt = config.create_response('abcdef',
                                              {'code': 'somecode', 'state': 'xyz'})
        self.assertRaises(ExpiredSignedResponseError,
                          self.client.parse_signed_authorization_response,
                          response_jwt, SECRET)

    def test_state_mismatch_rejected(self):
        response_jwt = self.create_response(code='somecode', state='other')
        self.assertRaises(errors.MismatchingStateError,
                          self.client.parse_signed_authorization_response,
                          response_jwt, SECRET)

    def test_replaced_code_rejected(self):
        response_jwt = self.create_response(code='somecode', state='xyz')
        claims = decode_unverified(response_jwt)
        claims['code'] = 'attacker-code'
        tampered = jwt.encode(claims, 'attacker-key', algorithm='HS256')
        self.assertRaises(InvalidSignatureError,
                          self.client.parse_signed_authorization_response,
                          tampered, SECRET)

    def test_error_response_raised(self):
        response_jwt = self.create_response(error='access_denied', state='xyz')
        self.assertRaises(errors.AccessDeniedError,
                          self.client.parse_signed_authorization_response,
                          response_jwt, SECRET)

    def test_validate_signed_response_function(self):
        response_jwt = self.create_response(code='somecode', state='xyz')
        params = validate_signed_response(
            response_jwt, SECRET, issuer=ISSUER, audience='abcdef',
            state='xyz')
        self.assertEqual(params['code'], 'somecode')
        self.assertNotIn('iss', params)
        self.assertNotIn('aud', params)
        self.assertNotIn('exp', params)
