"""
oauthlib.oauth2.rfc9396
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of the server side logic needed for
`RFC 9396`_ OAuth 2.0 Rich Authorization Requests.

Rich Authorization Requests allow clients to convey fine-grained
authorization data in the structured ``authorization_details`` request
parameter (for example a payment amount and its creditor) which cannot
be expressed with the plain ``scope`` string.

The authorization server registers one
:class:`AuthorizationDetailsValidator` per authorization details ``type``
in an :class:`AuthorizationDetailsRegistry`.  The registry is then handed
to the grant type (e.g. ``AuthorizationCodeGrant``) which uses it to:

* validate the details of the authorization request and bind the
  validated result to the authorization code,
* ensure the token request only asks for the same or narrower details
  than the ones bound to the authorization code.  What "narrower" means
  is decided by the server side policy of each type, through
  :meth:`AuthorizationDetailsValidator.is_within`.

.. _`RFC 9396`: https://www.rfc-editor.org/rfc/rfc9396.html
"""
import json
import logging

from ..rfc6749 import errors

log = logging.getLogger('oauthlib')


class AuthorizationDetailsValidator:
    """Server side policy for one ``authorization_details`` type.

    Implementations validate the authorization details of their type and
    decide whether requested details are narrower than granted ones.
    """

    def validate(self, detail, request):
        """Validate one authorization detail of this type.

        Called both on the authorization request and, when the client
        asks for narrower details, on the token request.

        :param detail: A dict, one element of the ``authorization_details``
                       JSON array, guaranteed to carry this validator's
                       ``type``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :return: The validated (and possibly normalized) detail.  The
                 returned value is bound to the authorization code and
                 later carried into the token response.  Returning
                 ``None`` keeps the detail unchanged.
        :raises: oauthlib.oauth2.rfc6749.errors.InvalidAuthorizationDetailsError
                 if the detail is not acceptable.
        """
        return detail

    def is_within(self, requested, granted, request):
        """Tell if ``requested`` is narrower than or equal to ``granted``.

        Both arguments are single authorization details of this type.
        ``granted`` was validated during the authorization request and
        bound to the authorization code, ``requested`` was validated
        during the token request.

        The default implementation accepts only details identical to
        the granted ones.  Override it to implement the type specific
        "narrower" policy, e.g. a lower payment amount for the same
        creditor.

        :param requested: A dict, the detail from the token request.
        :param granted: A dict, the detail bound to the authorization code.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False
        """
        return requested == granted


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON object member: %r' % key)
        result[key] = value
    return result


def parse_authorization_details(raw):
    """Parse and structurally validate an ``authorization_details`` value.

    The value must be a JSON array of objects, each carrying a non-empty
    string ``type`` member.  Duplicate JSON object members and any other
    top level structure are rejected.

    :param raw: The raw ``authorization_details`` parameter.
    :return: The parsed list of authorization detail dicts.
    :raises: oauthlib.oauth2.rfc6749.errors.InvalidAuthorizationDetailsError
    """
    try:
        details = json.loads(raw, object_pairs_hook=_object_without_duplicates)
    except (TypeError, ValueError) as e:
        raise errors.InvalidAuthorizationDetailsError(
            description='Invalid authorization_details: %s' % e) from e
    if not isinstance(details, list) or not details:
        raise errors.InvalidAuthorizationDetailsError(
            description='authorization_details must be a non-empty JSON array.')
    for detail in details:
        if not isinstance(detail, dict):
            raise errors.InvalidAuthorizationDetailsError(
                description='authorization_details elements must be JSON objects.')
        if not isinstance(detail.get('type'), str) or not detail['type']:
            raise errors.InvalidAuthorizationDetailsError(
                description='authorization_details elements must contain a string "type" member.')
    return details


class AuthorizationDetailsRegistry:
    """Registry of the authorization details types supported by a server.

    >>> registry = AuthorizationDetailsRegistry()
    >>> registry.register('payment', PaymentDetailsValidator())
    >>> grant = AuthorizationCodeGrant(validator,
    ...     authorization_details_registry=registry)
    """

    def __init__(self):
        self._validators = {}

    def register(self, type_, validator):
        """Register a validator for an authorization details ``type``.

        :param type_: The authorization details type, e.g. ``"payment"``.
        :param validator: An AuthorizationDetailsValidator handling the type.
        """
        if not isinstance(type_, str) or not type_:
            raise ValueError('Authorization details type must be a non-empty string.')
        if not isinstance(validator, AuthorizationDetailsValidator):
            raise ValueError('validator must be an AuthorizationDetailsValidator.')
        self._validators[type_] = validator
        return validator

    def get(self, type_):
        """Return the validator registered for ``type_``, if any."""
        return self._validators.get(type_)

    def __contains__(self, type_):
        return type_ in self._validators

    def validate_details(self, raw, request):
        """Parse ``raw`` and validate each detail with its type's validator.

        :param raw: The raw ``authorization_details`` parameter.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :return: The list of validated authorization details.
        :raises: oauthlib.oauth2.rfc6749.errors.InvalidAuthorizationDetailsError
                 on malformed input or unregistered types.
        """
        details = parse_authorization_details(raw)
        return [self._validate_detail(detail, request) for detail in details]

    def is_within_granted(self, requested, granted, request):
        """Tell if ``requested`` details are covered by ``granted`` ones.

        Every requested detail must be narrower than or equal to at
        least one granted detail of the same type, as decided by the
        type's server side policy.

        :param requested: List of validated details from the token request.
        :param granted: List of details bound to the authorization code.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False
        """
        granted = granted or []
        for detail in requested:
            validator = self.get(detail['type'])
            if validator is None:
                log.debug('No validator registered for authorization '
                          'details type %r.', detail['type'])
                return False
            candidates = [g for g in granted
                          if isinstance(g, dict) and g.get('type') == detail['type']]
            if not any(validator.is_within(detail, candidate, request)
                       for candidate in candidates):
                log.debug('Authorization detail %r is not within the '
                          'details granted to the authorization code.', detail)
                return False
        return True

    def _validate_detail(self, detail, request):
        validator = self.get(detail['type'])
        if validator is None:
            raise errors.InvalidAuthorizationDetailsError(
                description='Unknown authorization details type: %s' % detail['type'],
                request=request)
        validated = validator.validate(detail, request)
        return detail if validated is None else validated
