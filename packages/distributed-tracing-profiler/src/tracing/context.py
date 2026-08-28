"""W3C TraceContext standard implementation and async-safe context propagation.

Conforms strictly to W3C TraceContext Recommendation:
- traceparent: version-trace_id-parent_id-trace_flags (e.g. 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01)
- tracestate: list of key=value pairs (max 32 members, max 512 chars)

DevSecOps Guardrails:
- CWE-330 / CWE-208: Uses secrets.token_hex() and hmac.compare_digest()
"""

from __future__ import annotations

import contextvars
import hmac
import re
import secrets
from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tracing.span import Span

# RFC W3C TraceContext Constants & Regexes
TRACEPARENT_PATTERN = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(?:-.*)?$")
TRACESTATE_KEY_PATTERN = re.compile(
    r"^(?:[a-z0-9_*/-]{1,256}|[a-z0-9_*/-]{1,241}@[a-z0-9_*/-]{1,14})$"
)
TRACESTATE_VALUE_PATTERN = re.compile(r"^[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,256}$")

INVALID_TRACE_ID = "0" * 32
INVALID_SPAN_ID = "0" * 16

# ContextVar for async-safe and thread-safe current span storage
_CURRENT_SPAN: contextvars.ContextVar[Span | None] = contextvars.ContextVar(
    "current_span", default=None
)


def generate_trace_id() -> str:
    """Generate a cryptographically secure 16-byte (32 hex char) Trace ID.

    Guarantees non-zero identifier according to W3C TraceContext specification.
    Mitigates CWE-330 using secrets.token_hex().
    """
    while True:
        tid = secrets.token_hex(16).lower()
        if not hmac.compare_digest(tid, INVALID_TRACE_ID):
            return tid


def generate_span_id() -> str:
    """Generate a cryptographically secure 8-byte (16 hex char) Span ID.

    Guarantees non-zero identifier according to W3C TraceContext specification.
    Mitigates CWE-330 using secrets.token_hex().
    """
    while True:
        sid = secrets.token_hex(8).lower()
        if not hmac.compare_digest(sid, INVALID_SPAN_ID):
            return sid


def validate_trace_id(trace_id: str) -> bool:
    """Validate that trace_id is 32 lowercase hex chars and non-zero."""
    if not isinstance(trace_id, str) or len(trace_id) != 32:
        return False
    if not re.fullmatch(r"[0-9a-f]{32}", trace_id):
        return False
    return not hmac.compare_digest(trace_id, INVALID_TRACE_ID)


def validate_span_id(span_id: str) -> bool:
    """Validate that span_id is 16 lowercase hex chars and non-zero."""
    if not isinstance(span_id, str) or len(span_id) != 16:
        return False
    if not re.fullmatch(r"[0-9a-f]{16}", span_id):
        return False
    return not hmac.compare_digest(span_id, INVALID_SPAN_ID)


def validate_tracestate(tracestate: str) -> bool:
    """Validate tracestate string according to W3C TraceContext specification."""
    if not isinstance(tracestate, str) or len(tracestate) > 512:
        return False
    if not tracestate.strip():
        return True
    members = tracestate.split(",")
    if len(members) > 32:
        return False
    for raw_member in members:
        if not raw_member.strip():
            return False
        if "=" not in raw_member:
            return False
        key_part, _, val_part = raw_member.partition("=")
        key = key_part.strip()
        val = val_part
        if not TRACESTATE_KEY_PATTERN.fullmatch(key):
            return False
        if not TRACESTATE_VALUE_PATTERN.fullmatch(val):
            return False
        if val.endswith(" ") or val.startswith(" "):
            return False
    return True


@dataclass(frozen=True, slots=True)
class SpanContext:
    """Immutable representation of W3C TraceContext."""

    trace_id: str
    span_id: str
    trace_flags: int = 1
    tracestate: str | None = None
    is_remote: bool = False

    def __post_init__(self) -> None:
        if not validate_trace_id(self.trace_id):
            raise ValueError(f"Invalid trace_id: {self.trace_id!r}")
        if not validate_span_id(self.span_id):
            raise ValueError(f"Invalid span_id: {self.span_id!r}")
        if not (0 <= self.trace_flags <= 255):
            raise ValueError(f"Invalid trace_flags (must be 0-255): {self.trace_flags}")
        if self.tracestate is not None and not validate_tracestate(self.tracestate):
            raise ValueError(f"Invalid tracestate: {self.tracestate!r}")

    @property
    def is_sampled(self) -> bool:
        """Check if sampled flag (bit 0) is set."""
        return bool(self.trace_flags & 0x01)

    @property
    def traceparent(self) -> str:
        """Format W3C traceparent header string."""
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags:02x}"

    @classmethod
    def create_root(
        cls, is_sampled: bool = True, tracestate: str | None = None
    ) -> SpanContext:
        """Create a new root SpanContext with secure IDs."""
        return cls(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
            trace_flags=1 if is_sampled else 0,
            tracestate=tracestate,
            is_remote=False,
        )

    def create_child(
        self, is_sampled: bool | None = None, tracestate: str | None = None
    ) -> SpanContext:
        """Create a child SpanContext inheriting trace_id and updating span_id."""
        flags = self.trace_flags if is_sampled is None else (1 if is_sampled else 0)
        return SpanContext(
            trace_id=self.trace_id,
            span_id=generate_span_id(),
            trace_flags=flags,
            tracestate=tracestate if tracestate is not None else self.tracestate,
            is_remote=False,
        )


def parse_traceparent(traceparent: str) -> tuple[str, str, str, int] | None:
    """Parse a W3C traceparent header.

    Returns tuple of (version, trace_id, parent_id, trace_flags) or None if invalid.
    """
    if not isinstance(traceparent, str):
        return None
    raw = traceparent.strip().lower()
    if len(raw) < 55:
        return None

    match = TRACEPARENT_PATTERN.match(raw)
    if not match:
        return None

    version, trace_id, parent_id, flags_hex = match.groups()

    # Version 'ff' is forbidden by W3C specification
    if version == "ff":
        return None

    # For version '00', length must be exactly 55 characters
    if version == "00" and len(raw) != 55:
        return None

    # Validate non-zero identifiers
    if not validate_trace_id(trace_id) or not validate_span_id(parent_id):
        return None

    try:
        flags = int(flags_hex, 16)
    except ValueError:
        return None

    return version, trace_id, parent_id, flags


def extract_context(
    carrier: Mapping[str, Any] | Iterable[tuple[Any, Any]]
) -> SpanContext | None:
    """Extract W3C TraceContext from headers carrier (mapping or list of tuples).

    Handles string and byte keys/values case-insensitively.
    """
    traceparent_val: str | None = None
    tracestate_val: str | None = None

    items: Iterable[tuple[Any, Any]]
    if isinstance(carrier, Mapping):
        items = carrier.items()
    elif isinstance(carrier, Iterable):
        items = carrier
    else:
        return None

    for raw_k, raw_v in items:
        k = raw_k.decode("latin1") if isinstance(raw_k, (bytes, bytearray)) else str(raw_k)
        k_lower = k.lower()
        if k_lower == "traceparent":
            v = raw_v.decode("latin1") if isinstance(raw_v, (bytes, bytearray)) else str(raw_v)
            traceparent_val = v.strip()
        elif k_lower == "tracestate":
            v = raw_v.decode("latin1") if isinstance(raw_v, (bytes, bytearray)) else str(raw_v)
            tracestate_val = v.strip()

    if not traceparent_val:
        return None

    parsed = parse_traceparent(traceparent_val)
    if not parsed:
        return None

    _, trace_id, parent_id, flags = parsed

    # Validate tracestate if present
    validated_state: str | None = None
    if tracestate_val and validate_tracestate(tracestate_val):
        validated_state = tracestate_val

    try:
        return SpanContext(
            trace_id=trace_id,
            span_id=parent_id,
            trace_flags=flags,
            tracestate=validated_state,
            is_remote=True,
        )
    except ValueError:
        return None


def inject_context(context: SpanContext, carrier: MutableMapping[str, str]) -> None:
    """Inject W3C TraceContext into a mutable header carrier."""
    carrier["traceparent"] = context.traceparent
    if context.tracestate:
        carrier["tracestate"] = context.tracestate


def get_current_span() -> Span | None:
    """Retrieve the current active Span in this async/thread context."""
    return _CURRENT_SPAN.get()


def set_current_span(span: Span | None) -> contextvars.Token[Span | None]:
    """Set the current active Span in this async/thread context."""
    return _CURRENT_SPAN.set(span)


def detach_span(token: contextvars.Token[Span | None]) -> None:
    """Detach active Span token to restore previous context."""
    _CURRENT_SPAN.reset(token)


@contextmanager
def use_span(span: Span | None) -> Iterator[Span | None]:
    """Context manager to attach a span as current and detach cleanly upon exit."""
    token = set_current_span(span)
    try:
        yield span
    finally:
        detach_span(token)
