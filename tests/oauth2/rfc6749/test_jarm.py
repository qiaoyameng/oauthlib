# -*- coding: utf-8 -*-
import re
import urllib.parse as urlparse
from unittest import mock

import jwt

from oauthlib.common import Request, urlencode
from oauthlib.oauth2.rfc6749 import errors, jarm
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase

SECRET = 'jarm-signing-secret'
ISSUER = 'https://as.example.com'
CLIENT_ID = 'abcdef'
REDIRECT_URI = 'https://a.b/cb'


def decode_unverified(token):
    return jwt.decode(token, options={'verify_signature': False})


class JARMServerTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.client = 'batman'
        self.request.client_id = CLIENT_ID
        self.request.response_type = 'code'
        self.request.grant_type = 'authorization_code'
        self.request.redirect_uri = REDIRECT_URI
        self.request.state = 'xyz'
        self.request.response_mode = 'query.jwt'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.is_pkce_required.return_value = False
        self.auth = AuthorizationCodeGrant(
            request_validator=self.mock_validator,
            jwt_response_signing_key=SECRET,
            jwt_response_issuer=ISSUER,
            jwt_response_lifetime=600)
        self.bearer = BearerToken(self.mock_validator)

    def extract_response_param(self, headers):
        query = urlparse.urlparse(headers['Location']).query
        params = dict(urlparse.parse_qsl(query))
        self.assertIn('response', params)
        return params

    def test_query_jwt_success(self):
        h, _b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        params = self.extract_response_param(h)
        # No plaintext parameters may leak into the redirect URI.
        self.assertNotIn('code', params)
        self.assertNotIn('state', params)

        claims = jarm.validate_jarm_response(
            params['response'], SECRET, algorithms=['HS256'],
            issuer=ISSUER, audience=CLIENT_ID, state='xyz')
        self.assertIn('code', claims)
        self.assertEqual(claims['state'], 'xyz')
        self.assertEqual(claims['iss'], ISSUER)
        self.assertEqual(claims['aud'], CLIENT_ID)
        self.assertGreater(claims['exp'], claims['iat'])

    def test_jwt_alias_for_query_jwt(self):
        self.request.response_mode = 'jwt'
        h, _b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        params = self.extract_response_param(h)
        claims = jarm.validate_jarm_response(
            params['response'], SECRET, algorithms=['HS256'],
            issuer=ISSUER, audience=CLIENT_ID)
        self.assertIn('code', claims)

    def test_form_post_jwt_success(self):
        self.request.response_mode = 'form_post.jwt'
        h, body, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 200)
        self.assertEqual(h['Content-Type'], 'text/html;charset=UTF-8')
        self.assertIn('action="{}"'.format(REDIRECT_URI), body)
        self.assertIn('name="response"', body)

        token = re.search(r'name="response" value="([^"]+)"', body).group(1)
        claims = jarm.validate_jarm_response(
            token, SECRET, algorithms=['HS256'],
            issuer=ISSUER, audience=CLIENT_ID, state='xyz')
        self.assertIn('code', claims)

    def test_error_response_wrapped_in_jwt(self):
        self.mock_validator.validate_response_type.return_value = False
        h, _b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        params = self.extract_response_param(h)
        self.assertNotIn('error', params)

        claims = jarm.validate_jarm_response(
            params['response'], SECRET, algorithms=['HS256'],
            issuer=ISSUER, audience=CLIENT_ID)
        self.assertEqual(claims['error'], 'unauthorized_client')
        self.assertEqual(claims['state'], 'xyz')
        self.assertEqual(claims['aud'], CLIENT_ID)

    def test_error_response_wrapped_in_jwt_form_post(self):
        self.request.response_mode = 'form_post.jwt'
        self.mock_validator.validate_response_type.return_value = False
        h, body, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 200)
        token = re.search(r'name="response" value="([^"]+)"', body).group(1)
        claims = jarm.validate_jarm_response(
            token, SECRET, algorithms=['HS256'],
            issuer=ISSUER, audience=CLIENT_ID)
        self.assertEqual(claims['error'], 'unauthorized_client')

    def test_invalid_client_id_not_redirected(self):
        self.mock_validator.validate_client_id.return_value = False
        self.assertRaises(errors.InvalidClientIdError,
                          self.auth.create_authorization_response,
                          self.request, self.bearer)

    def test_invalid_redirect_uri_not_redirected(self):
        self.mock_validator.validate_redirect_uri.return_value = False
        self.assertRaises(errors.MismatchingRedirectURIError,
                          self.auth.create_authorization_response,
                          self.request, self.bearer)

    def test_missing_signing_key_raises_server_error(self):
        self.auth.jwt_response_signing_key = None
        self.assertRaises(errors.ServerError,
                          self.auth.create_authorization_response,
                          self.request, self.bearer)

    def test_signing_failure_never_falls_back_to_plaintext(self):
        # RS256 with a non-RSA key makes jwt.encode fail.
        self.auth.jwt_response_algorithm = 'RS256'
        try:
            self.auth.create_authorization_response(self.request, self.bearer)
        except errors.ServerError:
            pass
        else:
            self.fail('Expected ServerError, no plaintext response allowed')

    def test_error_signing_failure_raises(self):
        self.auth.jwt_response_algorithm = 'RS256'
        self.mock_validator.validate_response_type.return_value = False
        self.assertRaises(errors.ServerError,
                          self.auth.create_authorization_response,
                          self.request, self.bearer)

    def test_plaintext_modes_unaffected(self):
        self.request.response_mode = 'query'
        h, _b, s = self.auth.create_authorization_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        params = dict(urlparse.parse_qsl(urlparse.urlparse(h['Location']).query))
        self.assertIn('code', params)
        self.assertNotIn('response', params)


class JARMClientTest(TestCase):

    def setUp(self):
        self.client = WebApplicationClient(CLIENT_ID)

    def make_response_uri(self, params=None, **overrides):
        params = params if params is not None else {'code': 'somecode', 'state': 'xyz'}
        token = jarm.generate_jarm_response(
            params, SECRET, algorithm='HS256', issuer=ISSUER,
            audience=overrides.pop('audience', CLIENT_ID),
            expires_in=overrides.pop('expires_in', 600))
        return '{}?response={}'.format(REDIRECT_URI, token)

    def test_parse_valid_response(self):
        uri = self.make_response_uri()
        claims = self.client.parse_jarm_response(
            uri=uri, key=SECRET, algorithms=['HS256'],
            issuer=ISSUER, state='xyz')
        self.assertEqual(claims['code'], 'somecode')
        self.assertEqual(self.client.code, 'somecode')

    def test_parse_form_post_body(self):
        token = jarm.generate_jarm_response(
            {'code': 'somecode', 'state': 'xyz'}, SECRET,
            algorithm='HS256', issuer=ISSUER, audience=CLIENT_ID)
        body = urlencode([('response', token)])
        claims = self.client.parse_jarm_response(
            body=body, key=SECRET, algorithms=['HS256'],
            issuer=ISSUER, state='xyz')
        self.assertEqual(claims['code'], 'somecode')

    def test_wrong_audience_rejected(self):
        uri = self.make_response_uri(audience='someone-else')
        self.assertRaises(jwt.InvalidAudienceError,
                          self.client.parse_jarm_response,
                          uri=uri, key=SECRET, algorithms=['HS256'],
                          issuer=ISSUER, state='xyz')

    def test_expired_response_rejected(self):
        uri = self.make_response_uri(expires_in=-10)
        self.assertRaises(jwt.ExpiredSignatureError,
                          self.client.parse_jarm_response,
                          uri=uri, key=SECRET, algorithms=['HS256'],
                          issuer=ISSUER, state='xyz')

    def test_state_mismatch_rejected(self):
        uri = self.make_response_uri()
        self.assertRaises(errors.MismatchingStateError,
                          self.client.parse_jarm_response,
                          uri=uri, key=SECRET, algorithms=['HS256'],
                          issuer=ISSUER, state='other')

    def test_replaced_code_rejected(self):
        # Attacker swaps the code claim and re-signs with another key.
        uri = self.make_response_uri()
        token = dict(urlparse.parse_qsl(urlparse.urlparse(uri).query))['response']
        tampered = decode_unverified(token)
        tampered['code'] = 'attacker-code'
        forged = jwt.encode(tampered, 'attacker-key', algorithm='HS256')
        forged_uri = '{}?response={}'.format(REDIRECT_URI, forged)
        self.assertRaises(jwt.InvalidSignatureError,
                          self.client.parse_jarm_response,
                          uri=forged_uri, key=SECRET, algorithms=['HS256'],
                          issuer=ISSUER, state='xyz')

    def test_replaced_code_without_resigning_rejected(self):
        # Attacker edits the payload but keeps the original signature.
        uri = self.make_response_uri()
        token = dict(urlparse.parse_qsl(urlparse.urlparse(uri).query))['response']
        header, _payload, signature = token.split('.')
        tampered = decode_unverified(token)
        tampered['code'] = 'attacker-code'
        import base64
        import json
        payload = base64.urlsafe_b64encode(
            json.dumps(tampered).encode()).decode().rstrip('=')
        forged = '{}.{}.{}'.format(header, payload, signature)
        forged_uri = '{}?response={}'.format(REDIRECT_URI, forged)
        self.assertRaises(jwt.InvalidSignatureError,
                          self.client.parse_jarm_response,
                          uri=forged_uri, key=SECRET, algorithms=['HS256'],
                          issuer=ISSUER, state='xyz')

    def test_error_claims_raise_oauth2_error(self):
        uri = self.make_response_uri(
            params={'error': 'access_denied', 'state': 'xyz'})
        self.assertRaises(errors.AccessDeniedError,
                          self.client.parse_jarm_response,
                          uri=uri, key=SECRET, algorithms=['HS256'],
                          issuer=ISSUER, state='xyz')

    def test_missing_response_parameter(self):
        self.assertRaises(errors.MissingCodeError,
                          self.client.parse_jarm_response,
                          uri='{}?code=plaintext'.format(REDIRECT_URI),
                          key=SECRET, algorithms=['HS256'])
