"""Tests for RFC 9396 Rich Authorization Requests (authorization_details)."""
import json
from urllib.parse import parse_qs, quote, urlparse

from oauthlib.common import Request
from oauthlib.oauth2 import (
    AuthorizationDetailsRegistry, AuthorizationDetailsValidator,
    InvalidAuthorizationDetailsError, RequestValidator, WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc9396 import parse_authorization_details

from tests.unittest import TestCase


class PaymentDetailsValidator(AuthorizationDetailsValidator):
    """Example server side policy for a "payment" authorization detail."""

    def validate(self, detail, request):
        creditor = detail.get('creditor')
        amount = detail.get('amount')
        if not isinstance(creditor, str) or not creditor:
            raise InvalidAuthorizationDetailsError(
                description='payment details require a creditor', request=request)
        if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount <= 0:
            raise InvalidAuthorizationDetailsError(
                description='payment details require a positive amount', request=request)
        return {'type': 'payment', 'creditor': creditor, 'amount': amount}

    def is_within(self, requested, granted, request):
        return (requested.get('creditor') == granted.get('creditor')
                and requested.get('amount', 0) <= granted.get('amount', 0))


class ParseAuthorizationDetailsTest(TestCase):

    def test_valid_details(self):
        details = parse_authorization_details('[{"type": "payment", "amount": 42}]')
        self.assertEqual(details, [{'type': 'payment', 'amount': 42}])

    def test_rejects_invalid_json(self):
        self.assertRaises(InvalidAuthorizationDetailsError,
                          parse_authorization_details, '[{"type": ')
        self.assertRaises(InvalidAuthorizationDetailsError,
                          parse_authorization_details, None)

    def test_rejects_duplicate_members(self):
        self.assertRaises(InvalidAuthorizationDetailsError,
                          parse_authorization_details,
                          '[{"type": "payment", "type": "other"}]')
        self.assertRaises(InvalidAuthorizationDetailsError,
                          parse_authorization_details,
                          '[{"type": "payment", "amount": 1, "amount": 2}]')

    def test_rejects_invalid_top_level(self):
        for raw in ('{"type": "payment"}', '"payment"', '42', '[]', 'null',
                    '[42]', '[["payment"]]', '[{}]', '[{"type": ""}]',
                    '[{"type": 42}]'):
            self.assertRaises(InvalidAuthorizationDetailsError,
                              parse_authorization_details, raw)


class AuthorizationDetailsRegistryTest(TestCase):

    def setUp(self):
        self.registry = AuthorizationDetailsRegistry()
        self.registry.register('payment', PaymentDetailsValidator())
        self.request = Request('https://a.b/path')

    def test_register_requires_type_and_validator(self):
        self.assertRaises(ValueError, self.registry.register, '', PaymentDetailsValidator())
        self.assertRaises(ValueError, self.registry.register, 'x', object())

    def test_validate_details_unknown_type(self):
        self.assertRaises(InvalidAuthorizationDetailsError,
                          self.registry.validate_details,
                          '[{"type": "unknown"}]', self.request)

    def test_validate_details_returns_validated(self):
        details = self.registry.validate_details(
            '[{"type": "payment", "creditor": "bob", "amount": 30, "extra": 1}]',
            self.request)
        self.assertEqual(details,
                         [{'type': 'payment', 'creditor': 'bob', 'amount': 30}])

    def test_validate_details_type_policy(self):
        self.assertRaises(InvalidAuthorizationDetailsError,
                          self.registry.validate_details,
                          '[{"type": "payment", "amount": -1}]', self.request)

    def test_is_within_granted_default_is_equality(self):
        registry = AuthorizationDetailsRegistry()
        registry.register('thing', AuthorizationDetailsValidator())
        granted = [{'type': 'thing', 'a': 1}]
        self.assertTrue(registry.is_within_granted(
            [{'type': 'thing', 'a': 1}], granted, self.request))
        self.assertFalse(registry.is_within_granted(
            [{'type': 'thing', 'a': 2}], granted, self.request))

    def test_is_within_granted_uses_type_policy(self):
        granted = [{'type': 'payment', 'creditor': 'bob', 'amount': 30}]
        self.assertTrue(self.registry.is_within_granted(
            [{'type': 'payment', 'creditor': 'bob', 'amount': 10}],
            granted, self.request))
        self.assertFalse(self.registry.is_within_granted(
            [{'type': 'payment', 'creditor': 'bob', 'amount': 31}],
            granted, self.request))
        self.assertFalse(self.registry.is_within_granted(
            [{'type': 'payment', 'creditor': 'eve', 'amount': 10}],
            granted, self.request))
        self.assertFalse(self.registry.is_within_granted(
            [{'type': 'unknown'}], granted, self.request))
        self.assertFalse(self.registry.is_within_granted(
            [{'type': 'payment', 'creditor': 'bob', 'amount': 10}], None,
            self.request))


class Client:
    client_id = 'test-client'


class InMemoryValidator(RequestValidator):
    """In-memory validator persisting codes and tokens in dicts."""

    def __init__(self):
        self.client = Client()
        self.codes = {}
        self.tokens = {}

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return client_id == self.client.client_id

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return redirect_uri == 'https://client.example.com/cb'

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return 'https://client.example.com/cb'

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return set(scopes) <= {'profile', 'payment'}

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return []

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return response_type == 'code'

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes[code['code']] = {
            'client_id': client_id,
            'redirect_uri': request.redirect_uri,
            'scopes': request.scopes,
            'user': request.user,
            'authorization_details': request.authorization_details,
        }

    def client_authentication_required(self, request, *args, **kwargs):
        return True

    def authenticate_client(self, request, *args, **kwargs):
        if request.client_id == self.client.client_id and \
                request.client_secret == 's3cret':
            request.client = self.client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        saved = self.codes.get(code)
        if saved is None or saved['client_id'] != client_id:
            return False
        request.scopes = saved['scopes']
        request.user = saved['user']
        request.authorization_details = saved['authorization_details']
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        return self.codes[code]['redirect_uri'] == redirect_uri

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type == 'authorization_code'

    def save_bearer_token(self, token, request, *args, **kwargs):
        self.tokens[token['access_token']] = dict(token)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes.pop(code, None)


class AuthorizationDetailsFlowTest(TestCase):
    """Full authorization code flow with an in-memory validator."""

    def setUp(self):
        self.validator = InMemoryValidator()
        self.registry = AuthorizationDetailsRegistry()
        self.registry.register('payment', PaymentDetailsValidator())
        self.server = WebApplicationServer(
            self.validator,
            authorization_details_registry=self.registry)
        self.payment = [{'type': 'payment', 'creditor': 'bob', 'amount': 30}]

    def authorize(self, details=None, raw_details=None, scope='payment'):
        uri = ('https://as.example.com/authorize?response_type=code'
               '&client_id=test-client'
               '&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb')
        if scope is not None:
            uri += '&scope=' + quote(scope)
        if raw_details is not None:
            uri += '&authorization_details=' + quote(raw_details)
        elif details is not None:
            uri += '&authorization_details=' + quote(json.dumps(details))
        headers, body, status = self.server.create_authorization_response(
            uri, credentials={'user': 'alice'})
        return headers, body, status

    def authorize_code(self, **kwargs):
        headers, _body, status = self.authorize(**kwargs)
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertNotIn('error', query)
        return query['code'][0]

    def token(self, code, details=None, raw_details=None):
        body = ('grant_type=authorization_code&code=' + code
                + '&client_id=test-client&client_secret=s3cret'
                + '&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb')
        if raw_details is not None:
            body += '&authorization_details=' + quote(raw_details)
        elif details is not None:
            body += '&authorization_details=' + quote(json.dumps(details))
        return self.server.create_token_response(
            'https://as.example.com/token', body=body)

    def test_details_bound_to_code_and_carried_into_token(self):
        code = self.authorize_code(details=self.payment)
        saved = self.validator.codes[code]
        self.assertEqual(saved['authorization_details'], self.payment)

        # Token request omits authorization_details: the details bound to
        # the code are carried into the token.
        _headers, body, status = self.token(code)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token['authorization_details'], self.payment)
        saved_token = self.validator.tokens[token['access_token']]
        self.assertEqual(saved_token['authorization_details'], self.payment)

    def test_token_request_may_narrow_details(self):
        code = self.authorize_code(details=self.payment)
        narrower = [{'type': 'payment', 'creditor': 'bob', 'amount': 10}]
        _headers, body, status = self.token(code, details=narrower)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token['authorization_details'], narrower)

    def test_token_request_cannot_widen_amount(self):
        code = self.authorize_code(details=self.payment)
        wider = [{'type': 'payment', 'creditor': 'bob', 'amount': 31}]
        _headers, body, status = self.token(code, details=wider)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_authorization_details')

    def test_token_request_cannot_replace_creditor(self):
        code = self.authorize_code(details=self.payment)
        replaced = [{'type': 'payment', 'creditor': 'eve', 'amount': 10}]
        _headers, body, status = self.token(code, details=replaced)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_authorization_details')

    def test_token_request_cannot_add_details_when_code_has_none(self):
        code = self.authorize_code(details=None)
        _headers, body, status = self.token(code, details=self.payment)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_authorization_details')

    def test_token_request_rejects_unknown_type(self):
        code = self.authorize_code(details=self.payment)
        _headers, body, status = self.token(
            code, details=[{'type': 'unknown', 'x': 1}])
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_authorization_details')

    def test_token_request_rejects_duplicate_members(self):
        code = self.authorize_code(details=self.payment)
        raw = '[{"type": "payment", "type": "payment"}]'
        _headers, body, status = self.token(code, raw_details=raw)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_authorization_details')

    def test_authorization_request_rejects_unknown_type(self):
        headers, _body, status = self.authorize(details=[{'type': 'unknown'}])
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_authorization_details'])

    def test_authorization_request_rejects_duplicate_members(self):
        raw = '[{"type": "payment", "creditor": "bob", "creditor": "eve", "amount": 1}]'
        headers, _body, status = self.authorize(raw_details=raw)
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_authorization_details'])

    def test_authorization_request_rejects_invalid_top_level(self):
        headers, _body, status = self.authorize(
            raw_details='{"type": "payment"}')
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_authorization_details'])

    def test_authorization_request_rejected_by_type_policy(self):
        headers, _body, status = self.authorize(
            details=[{'type': 'payment', 'creditor': 'bob', 'amount': -5}])
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_authorization_details'])

    def test_scope_validation_stays_independent(self):
        headers, _body, status = self.authorize(
            details=self.payment, scope='payment admin')
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_scope'])

        code = self.authorize_code(details=self.payment, scope='profile')
        _headers, body, status = self.token(code)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token['scope'], 'profile')
        self.assertEqual(token['authorization_details'], self.payment)

    def test_flow_without_details_is_unaffected(self):
        code = self.authorize_code(details=None)
        _headers, body, status = self.token(code)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertNotIn('authorization_details', token)

    def test_details_ignored_without_registry(self):
        server = WebApplicationServer(self.validator)
        uri = ('https://as.example.com/authorize?response_type=code'
               '&client_id=test-client'
               '&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb'
               '&authorization_details=' + quote(json.dumps(self.payment)))
        headers, _body, status = server.create_authorization_response(
            uri, credentials={'user': 'alice'})
        self.assertEqual(status, 302)
        query = parse_qs(urlparse(headers['Location']).query)
        self.assertIn('code', query)

    def test_authorization_request_rejects_duplicate_parameter(self):
        details = quote(json.dumps(self.payment))
        uri = ('https://as.example.com/authorize?response_type=code'
               '&client_id=test-client'
               '&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb'
               '&authorization_details=' + details +
               '&authorization_details=' + details)
        self.assertRaises(errors.InvalidRequestFatalError,
                          self.server.create_authorization_response,
                          uri, credentials={'user': 'alice'})
