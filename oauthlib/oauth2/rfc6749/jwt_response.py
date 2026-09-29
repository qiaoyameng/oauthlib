"""
oauthlib.oauth2.rfc6749.jwt_response
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Signed (JWT) authorization responses, in the spirit of `JARM`_ (JWT Secured
Authorization Response Mode for OAuth 2.0).

When enabled on the provider side, authorization response parameters
(``code``, ``state``, ``error``, ...) are wrapped into a signed JWT instead
of being sent in clear through the user-agent, protecting them against
tampering during the redirection.

.. _`JARM`: https://openid.net/specs/oauth-v2-jarm.html
"""
import logging
import time

from . import errors

log = logging.getLogger(__name__)

JWT_RESPONSE_MODES = ('jwt', 'query.jwt', 'form_post.jwt')

DEFAULT_RESPONSE_JWT_EXPIRES_IN = 600


class InvalidSignedResponseError(errors.OAuth2Error):
    """The signed authorization response could not be validated."""
    error = 'invalid_request'
    description = 'The signed authorization response is invalid.'


class InvalidSignatureError(InvalidSignedResponseError):
    description = 'The signature of the authorization response is invalid.'


class InvalidAudienceError(InvalidSignedResponseError):
    description = 'The authorization response was not issued for this client.'


class InvalidIssuerError(InvalidSignedResponseError):
    description = 'The authorization response was issued by an unexpected issuer.'


class ExpiredSignedResponseError(InvalidSignedResponseError):
    description = 'The signed authorization response has expired.'


def _import_jwt():
    try:
        import jwt
    except ImportError:
        raise ImportError(
            'PyJWT is required to use signed (JWT) authorization responses. '
            'Install it with: pip install pyjwt'
        )
    return jwt


class JWTResponseConfig:
    """Server-side configuration for signed (JWT) authorization responses.

    :param signing_key: Key used to sign the response JWT.
    :param algorithm: Signature algorithm, defaults to ``HS256``.
    :param issuer: Value of the ``iss`` claim, identifying the
                   authorization server.
    :param expires_in: Lifetime of the response JWT in seconds,
                       defaults to 600.
    """

    def __init__(self, signing_key, algorithm='HS256', issuer=None,
                 expires_in=DEFAULT_RESPONSE_JWT_EXPIRES_IN):
        self.signing_key = signing_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.expires_in = expires_in

    def create_response(self, client_id, params):
        """Wrap authorization response parameters into a signed JWT.

        The ``aud`` claim is bound to the client the response is intended
        for, so a response cannot be replayed to another client.

        :param client_id: The client the response is intended for. Used as
                          the ``aud`` claim.
        :param params: Mapping of response parameters (e.g. ``code`` and
                       ``state``, or ``error`` and ``error_description``).
        :returns: The signed JWT as a string.
        """
        jwt = _import_jwt()
        now = int(time.time())
        claims = dict(params)
        claims['iss'] = self.issuer
        claims['aud'] = client_id
        claims['iat'] = now
        claims['exp'] = now + self.expires_in
        log.debug('Creating signed authorization response for client %s.',
                  client_id)
        return jwt.encode(claims, self.signing_key, algorithm=self.algorithm)


def validate_signed_response(response, key, algorithms=None, issuer=None,
                             audience=None, state=None):
    """Validate a signed (JWT) authorization response.

    Verifies the signature, the expiration time and, when provided, the
    issuer, the audience and the ``state`` parameter.

    :param response: The response JWT as received in the ``response``
                     parameter of the callback.
    :param key: Key used to verify the signature.
    :param algorithms: Allowed signature algorithms. Defaults to
                       ``['HS256']``.
    :param issuer: Expected ``iss`` claim, if any.
    :param audience: Expected ``aud`` claim, usually the client_id of the
                     client receiving the response.
    :param state: Expected ``state`` parameter, if one was sent in the
                  authorization request.
    :returns: The authorization response parameters as a dict.
    :raises InvalidSignatureError: If the signature does not verify.
    :raises ExpiredSignedResponseError: If the response has expired.
    :raises InvalidAudienceError: If the response is meant for another client.
    :raises InvalidIssuerError: If the issuer does not match.
    :raises MismatchingStateError: If the state does not match.
    :raises OAuth2Error: If the response carries an OAuth2 error.
    """
    jwt = _import_jwt()
    algorithms = algorithms or ['HS256']

    decode_options = {'require': ['exp', 'iat', 'iss', 'aud']}
    decode_kwargs = {
        'algorithms': algorithms,
        'options': decode_options,
    }
    if audience is not None:
        decode_kwargs['audience'] = audience
    else:
        decode_options['verify_aud'] = False
    if issuer is not None:
        decode_kwargs['issuer'] = issuer

    try:
        claims = jwt.decode(response, key, **decode_kwargs)
    except jwt.ExpiredSignatureError as e:
        raise ExpiredSignedResponseError() from e
    except jwt.InvalidAudienceError as e:
        raise InvalidAudienceError() from e
    except jwt.InvalidIssuerError as e:
        raise InvalidIssuerError() from e
    except jwt.InvalidSignatureError as e:
        raise InvalidSignatureError() from e
    except jwt.InvalidTokenError as e:
        raise InvalidSignedResponseError() from e

    params = {k: v for k, v in claims.items()
              if k not in ('iss', 'aud', 'exp', 'iat', 'nbf', 'jti')}

    if state and params.get('state') != state:
        raise errors.MismatchingStateError()

    if 'error' in params:
        errors.raise_from_error(params.get('error'), params)

    return params
