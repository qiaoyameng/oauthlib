"""
oauthlib.oauth2.rfc6749.jarm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

JWT Secured Authorization Response Mode (JARM) for OAuth 2.0.

This module implements helpers to wrap authorization response parameters
(both success and error parameters) in a signed JWT, delivered to the
client through the ``query`` or ``form_post`` response modes, as well as
helpers for clients to extract and validate such responses.
"""
import datetime
import html
import logging
import urllib.parse as urlparse

from .errors import MismatchingStateError, MissingCodeError, ServerError

log = logging.getLogger(__name__)

#: Response modes that trigger a JWT secured authorization response.
#: ``jwt`` is an alias of ``query.jwt``.
JWT_RESPONSE_MODES = ('jwt', 'query.jwt', 'form_post.jwt')

FORM_POST_HTML_TEMPLATE = """<html>
<head><title>Authorization Response</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{action}">
{inputs}
<noscript><p>JavaScript is disabled. Press the button to continue.</p>
<input type="submit" value="Continue"/></noscript>
</form>
</body>
</html>"""


def is_jarm_response_mode(response_mode):
    """Return True if the response mode requires a JWT wrapped response."""
    return response_mode in JWT_RESPONSE_MODES


def generate_jarm_response(params, key, algorithm='HS256', issuer=None,
                           audience=None, expires_in=600):
    """Wrap authorization response parameters in a signed JWT.

    :param params: A dict (or iterable of two-tuples) of OAuth 2.0
                   authorization response parameters, e.g. ``code`` and
                   ``state`` on success or ``error`` on failure.
    :param key: The key used to sign the JWT.
    :param algorithm: The JWS signing algorithm, defaults to ``HS256``.
    :param issuer: Value of the ``iss`` claim, identifying the
                   authorization server.
    :param audience: Value of the ``aud`` claim, bound to the client_id
                     the response is intended for.
    :param expires_in: Lifetime of the JWT in seconds, defaults to 600.
    :returns: The signed JWT as a string.
    :raises: ServerError if the response cannot be signed. Callers must
             not fall back to a plaintext response in this case.
    """
    import jwt  # noqa: PLC0415

    now = datetime.datetime.now(datetime.timezone.utc)

    claims = dict(params)
    claims['iss'] = issuer
    claims['aud'] = audience
    claims['iat'] = now
    claims['exp'] = now + datetime.timedelta(seconds=expires_in)

    try:
        token = jwt.encode(claims, key, algorithm=algorithm)
    except Exception as e:
        log.error('Failed to sign the JWT authorization response: %r.', e)
        raise ServerError(
            description='Unable to sign the authorization response.') from e

    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def validate_jarm_response(response, key, algorithms=None, issuer=None,
                           audience=None, state=None):
    """Validate a JWT secured authorization response and return its claims.

    The signature is verified using ``key`` and the allowed ``algorithms``.
    The ``exp`` claim is always verified, ``iss`` and ``aud`` are verified
    when ``issuer`` and ``audience`` are provided.

    :param response: The JWT secured authorization response.
    :param key: The key used to verify the JWT signature.
    :param algorithms: List of allowed JWS signing algorithms.
    :param issuer: Expected value of the ``iss`` claim, if any.
    :param audience: Expected value of the ``aud`` claim, normally the
                     client_id of the receiving client.
    :param state: The state parameter from the authorization request.
    :returns: The response parameters as a dict.
    :raises: jwt.InvalidTokenError (and subclasses) if the JWT is invalid,
             expired or issued for another audience.
    :raises: MismatchingStateError if the state does not match.
    """
    import jwt  # noqa: PLC0415

    options = {}
    decode_kwargs = {}
    if audience is None:
        options['verify_aud'] = False
    else:
        decode_kwargs['audience'] = audience
    if issuer is not None:
        decode_kwargs['issuer'] = issuer

    claims = jwt.decode(response, key, algorithms=algorithms,
                        options=options, **decode_kwargs)

    if state is not None and claims.get('state') != state:
        raise MismatchingStateError()

    return claims


def extract_jarm_response(uri=None, body=None):
    """Extract the JWT secured authorization response.

    The JWT is conveyed in the ``response`` parameter, either in the query
    component of the redirection URI (``query.jwt`` mode) or in the
    urlencoded body of the form_post response (``form_post.jwt`` mode).

    :param uri: The full redirect URI back to the client, if any.
    :param body: The urlencoded form_post response body, if any.
    :returns: The JWT as a string.
    :raises: MissingCodeError if no ``response`` parameter is found.
    """
    params = {}
    if uri is not None:
        query = urlparse.urlparse(uri).query
        params.update(urlparse.parse_qsl(query, keep_blank_values=True))
    if body:
        params.update(urlparse.parse_qsl(body, keep_blank_values=True))

    response = params.get('response')
    if not response:
        raise MissingCodeError(
            'Missing JWT response parameter in authorization response.')
    return response


def create_form_post_html(redirect_uri, params):
    """Create an auto-submitting HTML form for the form_post response mode.

    :param redirect_uri: The client redirection URI to post the form to.
    :param params: Iterable of two-tuples with the response parameters.
    :returns: The HTML document as a string.
    """
    inputs = '\n'.join(
        '<input type="hidden" name="{}" value="{}"/>'.format(
            html.escape(str(name), quote=True),
            html.escape(str(value), quote=True))
        for name, value in params)
    return FORM_POST_HTML_TEMPLATE.format(
        action=html.escape(redirect_uri, quote=True), inputs=inputs)
