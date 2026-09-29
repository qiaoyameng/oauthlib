"""
oauthlib.openid.connect.core.claims
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resolve Aggregated and Distributed Claims as defined in
`OpenID Connect Core 1.0, section 5.6.2`_.

A claims document (for example a UserInfo response or an ID Token) may
contain the members ``_claim_names`` and ``_claim_sources`` instead of
the actual claim values:

* ``_claim_names`` maps a claim name to the name of the claim source
  that is authoritative for it.
* ``_claim_sources`` maps a claim source name to either an object with
  a ``JWT`` member (Aggregated Claims) or an object with ``endpoint``
  and optionally ``access_token`` members (Distributed Claims).

This module resolves such references into a flat claims dictionary.
Each source only ever contributes the claims explicitly mapped to it,
``sub`` can never be delegated to a source, and access credentials are
never echoed back in error messages.

.. _`OpenID Connect Core 1.0, section 5.6.2`:
    https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
"""
import logging

log = logging.getLogger(__name__)

CLAIM_NAMES_KEY = '_claim_names'
CLAIM_SOURCES_KEY = '_claim_sources'

#: Claims that must always come from the OpenID Provider itself and may
#: never be supplied or overridden by an external claim source.
PROTECTED_CLAIMS = frozenset({'sub'})

#: Mapping keys reserved by the spec; sources may not inject them.
RESERVED_KEYS = frozenset({CLAIM_NAMES_KEY, CLAIM_SOURCES_KEY})

REDACTED = '<redacted>'


class ClaimResolutionDiagnostic:
    """A single problem encountered while resolving external claims.

    Diagnostics never contain access credentials; any known credential
    is replaced with ``<redacted>`` before the message is stored.
    """

    def __init__(self, code, message, source=None):
        self.code = code
        self.message = message
        self.source = source

    def __repr__(self):
        return 'ClaimResolutionDiagnostic(code=%r, source=%r, message=%r)' % (
            self.code, self.source, self.message)

    def __str__(self):
        if self.source is not None:
            return '%s: %s (source: %s)' % (self.code, self.message, self.source)
        return '%s: %s' % (self.code, self.message)


class ClaimResolutionError(Exception):
    """Raised in strict mode when external claims cannot be fully resolved.

    Carries the list of :class:`ClaimResolutionDiagnostic` that caused
    the failure in ``diagnostics``.  The exception text never contains
    access credentials.
    """

    def __init__(self, diagnostics):
        self.diagnostics = list(diagnostics)
        message = 'Failed to resolve external claims: ' + '; '.join(
            str(diagnostic) for diagnostic in self.diagnostics)
        super().__init__(message)


def _decode_jwt_unverified(token):
    """Decode a JWT payload without verifying its signature.

    Used only as a fallback when the caller does not supply a
    ``jwt_decoder``; a warning is logged because trusting an unverified
    aggregated claims JWT is not safe in production.
    """
    import jwt  # noqa: PLC0415

    log.warning('Decoding an aggregated claims JWT without signature '
                'verification; pass jwt_decoder to resolve_claims to '
                'verify signatures.')
    return jwt.decode(token, options={'verify_signature': False})


class _ClaimResolver:
    """Stateful helper holding the callbacks, diagnostics and secrets."""

    def __init__(self, fetcher, jwt_decoder):
        self.fetcher = fetcher
        self.jwt_decoder = jwt_decoder or _decode_jwt_unverified
        self.diagnostics = []
        # Access credentials seen so far; scrubbed from every message.
        self.secrets = []

    def _redact(self, text):
        text = str(text)
        for secret in self.secrets:
            if secret:
                text = text.replace(secret, REDACTED)
        return text

    def _error(self, code, message, source=None):
        self.diagnostics.append(
            ClaimResolutionDiagnostic(code, self._redact(message), source))

    def resolve(self, claims, chain=()):
        """Resolve one claims document, recursing into nested sources.

        ``chain`` holds the names of the sources currently being
        resolved so circular mappings can be detected.
        """
        result = {name: value for name, value in claims.items()
                  if name not in RESERVED_KEYS}

        claim_names = claims.get(CLAIM_NAMES_KEY) or {}
        claim_sources = claims.get(CLAIM_SOURCES_KEY) or {}
        if not isinstance(claim_names, dict):
            self._error('malformed_mapping',
                        '_claim_names must be a JSON object')
            claim_names = {}
        if not isinstance(claim_sources, dict):
            self._error('malformed_mapping',
                        '_claim_sources must be a JSON object')
            claim_sources = {}

        # Remember credentials up front so later error text can be scrubbed.
        for config in claim_sources.values():
            if isinstance(config, dict) and config.get('access_token'):
                self.secrets.append(config['access_token'])

        # Group the requested claims by the source responsible for them.
        by_source = {}
        for claim_name, source_name in claim_names.items():
            if claim_name in PROTECTED_CLAIMS:
                self._error('protected_claim',
                            'Claim %r cannot be delegated to an external '
                            'claim source' % claim_name, source_name)
                continue
            if claim_name in RESERVED_KEYS:
                self._error('reserved_claim',
                            'Claim %r is reserved and cannot be delegated '
                            'to an external claim source' % claim_name,
                            source_name)
                continue
            by_source.setdefault(source_name, []).append(claim_name)

        # Load each referenced source exactly once.
        payloads = {}
        for source_name in by_source:
            if source_name in chain:
                self._error('circular_mapping',
                            'Circular claim source mapping involving '
                            'source %r' % source_name, source_name)
                continue
            config = claim_sources.get(source_name)
            if config is None:
                self._error('missing_source',
                            'Referenced claim source %r is not present in '
                            '_claim_sources' % source_name, source_name)
                continue
            payload = self._load_source(source_name, config, chain)
            if payload is not None:
                payloads[source_name] = payload

        # A source must not volunteer a claim owned by another source.
        for source_name, payload in payloads.items():
            for key in payload:
                owner = claim_names.get(key)
                if owner is not None and owner != source_name:
                    self._error('duplicate_claim',
                                'Claim %r is mapped to source %r but was '
                                'also provided by source %r'
                                % (key, owner, source_name), source_name)

        # Merge only the claims explicitly mapped to each source.  Any
        # other attribute a source returns is dropped, and ``sub`` can
        # never arrive here because delegating it was rejected above.
        for source_name, claim_list in by_source.items():
            payload = payloads.get(source_name)
            if payload is None:
                continue
            for claim_name in claim_list:
                if claim_name in payload:
                    result[claim_name] = payload[claim_name]
                else:
                    self._error('claim_not_found',
                                'Claim %r was not provided by its claim '
                                'source' % claim_name, source_name)
        return result

    def _load_source(self, source_name, config, chain):
        """Fetch and recursively resolve the claims of a single source."""
        if not isinstance(config, dict):
            self._error('malformed_source',
                        'Claim source %r must be a JSON object'
                        % source_name, source_name)
            return None

        if 'JWT' in config:
            try:
                payload = self.jwt_decoder(config['JWT'])
            except Exception as exc:
                self._error('jwt_decode_failed',
                            'Could not decode the aggregated claims JWT '
                            'of source %r: %s' % (source_name, exc),
                            source_name)
                return None
        elif 'endpoint' in config:
            if self.fetcher is None:
                self._error('fetcher_missing',
                            'No fetcher callable was provided for the '
                            'distributed claim source %r' % source_name,
                            source_name)
                return None
            try:
                payload = self.fetcher(config['endpoint'],
                                       config.get('access_token'))
            except Exception as exc:
                self._error('fetch_failed',
                            'Could not retrieve distributed claims for '
                            'source %r: %s' % (source_name, exc),
                            source_name)
                return None
        else:
            self._error('malformed_source',
                        'Claim source %r has neither a JWT nor an '
                        'endpoint member' % source_name, source_name)
            return None

        if not isinstance(payload, dict):
            self._error('malformed_payload',
                        'Claim source %r did not yield a JSON object'
                        % source_name, source_name)
            return None

        # A source may itself reference further sources; resolve them
        # with this source on the chain to catch circular mappings.
        return self.resolve(payload, chain + (source_name,))


def resolve_claims(claims, fetcher=None, jwt_decoder=None, strict=True):
    """Resolve Aggregated and Distributed Claims in a claims document.

    :param claims: dict of claims, possibly containing ``_claim_names``
        and ``_claim_sources`` members.
    :param fetcher: callable invoked as ``fetcher(endpoint,
        access_token)`` for each distributed claim source; must return
        the claims document served by that endpoint as a dict.  Required
        when distributed sources are used.
    :param jwt_decoder: callable invoked as ``jwt_decoder(token)`` for
        each aggregated claim source; must verify the signed JWT and
        return its payload as a dict.  If omitted, JWTs are decoded
        *without* signature verification and a warning is logged.
    :param strict: when True (the default), raise
        :class:`ClaimResolutionError` if any diagnostic was produced;
        when False, return partial results together with the
        diagnostics.
    :returns: a ``(resolved_claims, diagnostics)`` tuple.  The resolved
        claims never contain ``_claim_names``/``_claim_sources`` and only
        ever include source attributes explicitly mapped in
        ``_claim_names``.
    :raises ClaimResolutionError: in strict mode, if any diagnostic was
        produced.  Error text never contains access credentials.
    """
    if not isinstance(claims, dict):
        raise TypeError('claims must be a dict, got %r' % type(claims))
    resolver = _ClaimResolver(fetcher, jwt_decoder)
    resolved = resolver.resolve(claims)
    if strict and resolver.diagnostics:
        raise ClaimResolutionError(resolver.diagnostics)
    return resolved, resolver.diagnostics
