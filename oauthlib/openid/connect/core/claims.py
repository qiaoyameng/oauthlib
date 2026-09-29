"""
oauthlib.openid.connect.core.claims
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Support for OpenID Connect aggregated and distributed claims.

The ``_claim_names`` and ``_claim_sources`` members of a UserInfo response
(or any other claim-bearing object) describe claims that are not embedded
directly in the response:

* Aggregated claims are supplied as a signed JWT nested inside the
  ``JWT`` member of a claim source descriptor.
* Distributed claims live behind an ``endpoint`` and are retrieved using a
  caller provided ``fetch_distributed_claims`` callable.

Only the claims that ``_claim_names`` explicitly attributes to a source are
taken from it: a source can never override ``sub`` or smuggle additional
attributes into the profile. Malformed mappings (missing sources, duplicate
ownership or cyclic references) are diagnosed and access credentials never
appear in the produced error text.
"""
from dataclasses import dataclass, field
from urllib.parse import urlsplit

#: Reserved members describing the claim graph rather than claims.
CLAIM_NAMES_MEMBER = '_claim_names'
CLAIM_SOURCES_MEMBER = '_claim_sources'
_RESERVED_MEMBERS = (CLAIM_NAMES_MEMBER, CLAIM_SOURCES_MEMBER)

#: Maximum number of nested source levels that may be traversed.
MAX_SOURCE_DEPTH = 10

#: Internal sentinel marking that a source callback failed (error recorded).
_CALLBACK_FAILED = object()


class ClaimResolutionError(Exception):
    """Base class for errors encountered while resolving external claims."""

    #: Short, stable identifier for the error kind.
    code = 'claim_resolution_error'
    #: Human readable template. Placeholders: {source}, {claim}, {detail}.
    message = 'Failed to resolve external claims.'

    def __init__(self, source=None, claim=None, detail=None):
        self.source = source
        self.claim = claim
        self.detail = detail
        super().__init__(self.render())

    def render(self):
        source = self.source if isinstance(self.source, str) and self.source else '?'
        return (self.message
                .replace('{source}', source)
                .replace('{claim}', self.claim or '?')
                .replace('{detail}', self.detail or 'no additional detail'))


class MissingClaimSourceError(ClaimResolutionError):
    """A ``_claim_names`` entry points at an unknown claim source."""

    code = 'missing_claim_source'
    message = "Claim '{claim}' references unknown claim source '{source}'."


class DuplicateClaimOwnershipError(ClaimResolutionError):
    """The same claim is provided by more than one place."""

    code = 'duplicate_claim_ownership'
    message = ("Claim '{claim}' has more than one owner (existing owner "
               "'{source}'); only a single, unambiguous owner is allowed.")


class ProtectedClaimError(ClaimResolutionError):
    """An external source attempted to provide a protected claim."""

    code = 'protected_claim'
    message = "Claim source '{source}' may not provide the protected claim '{claim}'."


class CyclicClaimMappingError(ClaimResolutionError):
    """The ``_claim_names`` graph contains a cycle or excessive nesting."""

    code = 'cyclic_claim_mapping'
    message = "Cyclic claim mapping detected at source '{source}' ({detail})."


class InvalidClaimSourceError(ClaimResolutionError):
    """A claim source descriptor or its payload is malformed."""

    code = 'invalid_claim_source'
    message = "Claim source '{source}' is invalid: {detail}."


class ClaimNotProvidedError(ClaimResolutionError):
    """A reachable source did not contain an attributed claim."""

    code = 'claim_not_provided'
    message = "Claim source '{source}' did not provide claim '{claim}'."


@dataclass
class ClaimResolutionResult:
    """Outcome of :func:`resolve_claims`.

    ``claims`` holds every claim that could be resolved; ``errors`` holds the
    :class:`ClaimResolutionError` instances for everything that failed. The
    reserved ``_claim_names``/``_claim_sources`` members never appear in
    ``claims`` and the input mapping is left untouched.
    """

    claims: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    @property
    def ok(self):
        """``True`` when the complete claim graph resolved without errors."""
        return not self.errors


def _safe_endpoint(endpoint):
    """Return a credential free representation of an endpoint URL."""
    try:
        parts = urlsplit(str(endpoint))
    except (ValueError, TypeError):
        return '<invalid-endpoint>'
    host = parts.hostname or ''
    if parts.port:
        host = f'{host}:{parts.port}'
    authority = f'//{host}{parts.path}' if host else (parts.path or '')
    return f'{parts.scheme}:{authority}' if parts.scheme else (
        authority or '<invalid-endpoint>')


def resolve_claims(userinfo, fetch_distributed_claims=None,
                   verify_aggregated_claims=None, strict=False):
    """Resolve aggregated and distributed claims in ``userinfo``.

    :param userinfo: Mapping with the profile claims and, optionally, the
        ``_claim_names`` and ``_claim_sources`` members.
    :param fetch_distributed_claims: ``callable(descriptor) -> mapping`` used
        to retrieve sources carrying an ``endpoint``. The descriptor is
        passed as a copy so the callable cannot mutate the claim graph.
    :param verify_aggregated_claims: ``callable(descriptor) -> mapping`` used
        to verify and decode sources carrying an inline signed ``JWT``.
    :param strict: When ``True`` the first error is raised. When ``False``
        (the default) successfully resolved claims are returned together with
        the collected errors, allowing explicit partial results.
    :returns: :class:`ClaimResolutionResult`.
    """
    result = ClaimResolutionResult()

    def fail(error):
        if strict:
            raise error
        result.errors.append(error)

    #: Descriptor identities currently being resolved (cycle detection).
    chain = []

    def resolve_universe(container, sources, depth, owner, allowed=None):
        """Resolve one ``_claim_names``/``_claim_sources`` level.

        ``allowed`` restricts which claims this level may produce. It is
        ``None`` at the top level (every local profile claim is real) and the
        exact set a parent attributed to a source everywhere else, so a
        source cannot smuggle in unrequested attributes.
        """
        resolved = {}
        owners = {}

        def take(claim, value, claim_owner):
            if claim in resolved:
                fail(DuplicateClaimOwnershipError(
                    claim=claim, source=owners.get(claim)))
                return
            resolved[claim] = value
            owners[claim] = claim_owner

        names = container.get(CLAIM_NAMES_MEMBER)
        if names is None:
            names = {}
        elif not isinstance(names, dict):
            fail(InvalidClaimSourceError(
                source=owner,
                detail=f'{CLAIM_NAMES_MEMBER} must be a JSON object'))
            names = {}

        if sources is None:
            sources = {}
        elif not isinstance(sources, dict):
            fail(InvalidClaimSourceError(
                source=owner,
                detail=f'{CLAIM_SOURCES_MEMBER} must be a JSON object'))
            sources = {}

        # Local claims are claimed first so an external attribution of the
        # same member is diagnosed as a collision instead of overwriting. The
        # top level container may carry ``sub``; a source payload may not.
        for claim, value in container.items():
            if claim in _RESERVED_MEMBERS:
                continue
            if allowed is not None and claim not in allowed:
                # An attribute the parent did not ask this source for.
                continue
            if claim == 'sub' and depth > 0:
                fail(ProtectedClaimError(source=owner, claim=claim))
                continue
            take(claim, value, owner)

        grouped = {}
        for claim, source_name in names.items():
            if allowed is not None and claim not in allowed:
                continue
            if claim == 'sub':
                fail(ProtectedClaimError(source=source_name, claim=claim))
                continue
            if claim in _RESERVED_MEMBERS:
                fail(InvalidClaimSourceError(
                    source=source_name,
                    detail=f"reserved member '{claim}' cannot be attributed to a source"))
                continue
            if not isinstance(source_name, str):
                fail(InvalidClaimSourceError(
                    source=str(source_name),
                    detail=f"source reference for claim '{claim}' must be a string name"))
                continue
            grouped.setdefault(source_name, []).append(claim)

        for source_name, wanted in grouped.items():
            if source_name not in sources:
                for claim in wanted:
                    fail(MissingClaimSourceError(source=source_name, claim=claim))
                continue
            payload, used_graph = resolve_source(
                source_name, sources[source_name], depth, set(wanted))
            if payload is None:
                # The source-level failure (retrieval, verification, ...) was
                # already diagnosed; do not stack redundant per-claim errors.
                continue
            for claim in wanted:
                if claim not in payload:
                    # A nested claim graph has already diagnosed the reason.
                    if not used_graph:
                        fail(ClaimNotProvidedError(source=source_name, claim=claim))
                    continue
                take(claim, payload[claim], source_name)

        return resolved

    def resolve_source(source_name, descriptor, depth, wanted):
        """Fetch/decode one source and resolve its nested graph.

        Returns ``(payload, used_graph)`` where ``payload`` is ``None`` when
        the source could not be resolved and ``used_graph`` is ``True`` when
        the payload itself carried ``_claim_names``/``_claim_sources``.
        """
        next_depth = depth + 1
        if next_depth > MAX_SOURCE_DEPTH:
            fail(CyclicClaimMappingError(
                source=source_name,
                detail=f'nesting limit of {MAX_SOURCE_DEPTH} sources exceeded'))
            return None, False

        descriptor_id = id(descriptor)
        if descriptor_id in chain:
            fail(CyclicClaimMappingError(
                source=source_name, detail='source graph references itself'))
            return None, False
        chain.append(descriptor_id)
        try:
            if not isinstance(descriptor, dict):
                fail(InvalidClaimSourceError(
                    source=source_name,
                    detail='source descriptor must be a JSON object'))
                return None, False

            has_jwt = 'JWT' in descriptor
            has_endpoint = 'endpoint' in descriptor
            if has_jwt and has_endpoint:
                fail(InvalidClaimSourceError(
                    source=source_name,
                    detail='source must not contain both JWT and endpoint'))
                return None, False
            if not has_jwt and not has_endpoint:
                fail(InvalidClaimSourceError(
                    source=source_name,
                    detail='source must contain a JWT or an endpoint'))
                return None, False

            if has_jwt:
                payload = invoke_source(
                    descriptor, verify_aggregated_claims,
                    'verify_aggregated_claims',
                    'aggregated claim token could not be verified',
                    source_name)
            else:
                endpoint = descriptor.get('endpoint')
                if not isinstance(endpoint, str) or not endpoint:
                    fail(InvalidClaimSourceError(
                        source=source_name,
                        detail='endpoint must be a non-empty string'))
                    return None, False
                payload = invoke_source(
                    descriptor, fetch_distributed_claims,
                    'fetch_distributed_claims',
                    'distributed claim retrieval failed',
                    _safe_endpoint(endpoint))
            if payload is _CALLBACK_FAILED:
                return None, False

            if not isinstance(payload, dict):
                fail(InvalidClaimSourceError(
                    source=source_name,
                    detail=f'source payload must be a JSON object, got '
                           f'{type(payload).__name__}'))
                return None, False

            used_graph = any(member in payload for member in _RESERVED_MEMBERS)
            if used_graph:
                payload = resolve_universe(
                    payload, payload.get(CLAIM_SOURCES_MEMBER),
                    next_depth, source_name, allowed=wanted)
            return payload, used_graph
        finally:
            chain.pop()

    def invoke_source(descriptor, callback, callback_name, failure_detail,
                      error_source):
        if not callback:
            fail(InvalidClaimSourceError(
                source=error_source,
                detail=f'{callback_name} callable is required but was not provided'))
            return _CALLBACK_FAILED
        try:
            return callback(dict(descriptor))
        except ClaimResolutionError as exc:
            fail(exc)
            return _CALLBACK_FAILED
        except Exception as exc:  # noqa: BLE001 - normalise callback errors
            # Deliberately exclude the exception message: callbacks may embed
            # request URLs containing access tokens.
            fail(InvalidClaimSourceError(
                source=error_source,
                detail=f'{failure_detail} ({type(exc).__name__})'))
            return _CALLBACK_FAILED

    if not isinstance(userinfo, dict):
        fail(InvalidClaimSourceError(
            source=None,
            detail=f'userinfo must be a JSON object, got {type(userinfo).__name__}'))
        return result

    result.claims = resolve_universe(
        userinfo, userinfo.get(CLAIM_SOURCES_MEMBER), 0, 'userinfo')
    return result

