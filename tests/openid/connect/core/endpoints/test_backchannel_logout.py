# -*- coding: utf-8 -*-
import json
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauthlib.openid import BackchannelLogoutEndpoint
from oauthlib.openid.connect.core.endpoints.backchannel_logout import (
    BACKCHANNEL_LOGOUT_EVENT, LogoutTokenStatus,
)

from tests.unittest import TestCase

ISSUER = "https://idp.example.com"
AUDIENCE = "my-client-id"


def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


class InMemorySessionStore:
    """Minimal in-memory session store keyed by sid and sub."""

    def __init__(self):
        self.sessions = {}
        self.revocations = []

    def add(self, sid=None, sub=None):
        self.sessions[(sid, sub)] = True

    def revoke_session(self, sub=None, sid=None):
        self.revocations.append((sub, sid))
        self.sessions.pop((sid, sub), None)


class BackchannelLogoutEndpointTest(TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_key_pair()
        self.other_private_pem, _ = generate_key_pair()
        self.store = InMemorySessionStore()
        self.endpoint = BackchannelLogoutEndpoint(
            issuer=ISSUER,
            audience=AUDIENCE,
            key=self.public_pem,
            revoke_session=self.store.revoke_session,
        )

    def make_token(self, key=None, jti="jti-1", sub="user-1", sid="sid-1",
                   events=None, nonce=None, issuer=ISSUER, audience=AUDIENCE,
                   exp=None, iat=None, extra=None, omit=()):
        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": audience,
            "iat": now if iat is None else iat,
            "exp": now + 600 if exp is None else exp,
            "jti": jti,
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}} if events is None else events,
        }
        if sub is not None:
            claims["sub"] = sub
        if sid is not None:
            claims["sid"] = sid
        if nonce is not None:
            claims["nonce"] = nonce
        if extra:
            claims.update(extra)
        for claim in omit:
            claims.pop(claim, None)
        return jwt.encode(claims, key or self.private_pem, algorithm="RS256")

    def test_valid_token_with_sid_revokes_session(self):
        self.store.add(sid="sid-1", sub="user-1")
        result = self.endpoint.verify_logout_token(self.make_token())
        self.assertEqual(result.status, LogoutTokenStatus.ACCEPTED)
        self.assertTrue(result.accepted)
        self.assertEqual(self.store.revocations, [("user-1", "sid-1")])
        self.assertEqual(self.store.sessions, {})

    def test_valid_token_with_sub_only(self):
        result = self.endpoint.verify_logout_token(self.make_token(sid=None))
        self.assertEqual(result.status, LogoutTokenStatus.ACCEPTED)
        self.assertEqual(self.store.revocations, [("user-1", None)])

    def test_valid_token_with_sid_only(self):
        result = self.endpoint.verify_logout_token(self.make_token(sub=None))
        self.assertEqual(result.status, LogoutTokenStatus.ACCEPTED)
        self.assertEqual(self.store.revocations, [(None, "sid-1")])

    def test_replay_does_not_revoke_twice(self):
        token = self.make_token()
        first = self.endpoint.verify_logout_token(token)
        second = self.endpoint.verify_logout_token(token)
        self.assertEqual(first.status, LogoutTokenStatus.ACCEPTED)
        self.assertEqual(second.status, LogoutTokenStatus.ALREADY_PROCESSED)
        self.assertTrue(second.already_processed)
        self.assertEqual(len(self.store.revocations), 1)

    def test_failed_validation_does_not_consume_jti(self):
        bad = self.make_token(key=self.other_private_pem, jti="jti-9")
        good = self.make_token(jti="jti-9")
        bad_result = self.endpoint.verify_logout_token(bad)
        self.assertEqual(bad_result.status, LogoutTokenStatus.INVALID)
        good_result = self.endpoint.verify_logout_token(good)
        self.assertEqual(good_result.status, LogoutTokenStatus.ACCEPTED)
        self.assertEqual(len(self.store.revocations), 1)

    def test_nonce_is_rejected(self):
        result = self.endpoint.verify_logout_token(self.make_token(nonce="n-1"))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)
        self.assertFalse(result.valid)
        self.assertEqual(self.store.revocations, [])

    def test_missing_sub_and_sid_is_rejected(self):
        result = self.endpoint.verify_logout_token(
            self.make_token(sub=None, sid=None))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)
        self.assertEqual(self.store.revocations, [])

    def test_missing_logout_event_is_rejected(self):
        result = self.endpoint.verify_logout_token(self.make_token(events={}))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_wrong_event_is_rejected(self):
        events = {"http://schemas.example.com/event/other": {}}
        result = self.endpoint.verify_logout_token(self.make_token(events=events))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_wrong_issuer_is_rejected(self):
        result = self.endpoint.verify_logout_token(
            self.make_token(issuer="https://evil.example.com"))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_wrong_audience_is_rejected(self):
        result = self.endpoint.verify_logout_token(
            self.make_token(audience="someone-else"))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_expired_token_is_rejected(self):
        now = int(time.time())
        result = self.endpoint.verify_logout_token(
            self.make_token(iat=now - 1200, exp=now - 600))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_missing_jti_is_rejected(self):
        result = self.endpoint.verify_logout_token(self.make_token(omit=("jti",)))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_missing_iat_is_rejected(self):
        result = self.endpoint.verify_logout_token(self.make_token(omit=("iat",)))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_bad_signature_is_rejected(self):
        result = self.endpoint.verify_logout_token(
            self.make_token(key=self.other_private_pem))
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_garbage_token_is_rejected(self):
        result = self.endpoint.verify_logout_token("not-a-jwt")
        self.assertEqual(result.status, LogoutTokenStatus.INVALID)

    def test_kid_key_mapping(self):
        endpoint = BackchannelLogoutEndpoint(
            issuer=ISSUER, audience=AUDIENCE,
            key={"good-key": self.public_pem},
            revoke_session=self.store.revoke_session,
        )
        token = jwt.encode(
            json.loads(json.dumps({
                "iss": ISSUER, "aud": AUDIENCE,
                "iat": int(time.time()), "exp": int(time.time()) + 600,
                "jti": "jti-kid", "sub": "user-1",
                "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
            })),
            self.private_pem, algorithm="RS256",
            headers={"kid": "good-key"},
        )
        result = endpoint.verify_logout_token(token)
        self.assertEqual(result.status, LogoutTokenStatus.ACCEPTED)

    def test_http_response_success(self):
        body = "logout_token=" + self.make_token()
        headers, body_out, status = self.endpoint.create_logout_response(
            "https://rp.example.com/backchannel_logout", body=body)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.store.revocations), 1)

    def test_http_response_replay_is_still_200(self):
        token = self.make_token()
        self.endpoint.create_logout_response(
            "https://rp.example.com/backchannel_logout",
            body="logout_token=" + token)
        _, _, status = self.endpoint.create_logout_response(
            "https://rp.example.com/backchannel_logout",
            body="logout_token=" + token)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.store.revocations), 1)

    def test_http_response_invalid_token(self):
        headers, body_out, status = self.endpoint.create_logout_response(
            "https://rp.example.com/backchannel_logout",
            body="logout_token=not-a-jwt")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body_out)["error"], "invalid_request")

    def test_http_response_missing_token(self):
        headers, body_out, status = self.endpoint.create_logout_response(
            "https://rp.example.com/backchannel_logout", body="foo=bar")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body_out)["error"], "invalid_request")
