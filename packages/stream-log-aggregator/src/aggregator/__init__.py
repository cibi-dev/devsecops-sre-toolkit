"""Stream Log Aggregator

Enterprise-grade asynchronous multi-channel log ingestion daemon with
PII sanitization, Grok parsing, backpressure, and persistent disk buffer.
"""

from typing import Any, Dict, List, Optional
import itertools
import time
from pydantic import BaseModel, Field, field_validator

__version__ = "0.1.0"
__author__ = "cibi-dev"

# Guardrail CWE-400: Max single log event size (64 KB)
MAX_EVENT_SIZE_BYTES = 64 * 1024

_id_counter = itertools.count(1)


class LogEvent(BaseModel):
    """Normalized log event passing through the aggregation pipeline."""
    id: str = Field(default_factory=lambda: f"{int(time.time() * 1000):x}-{next(_id_counter):x}")
    timestamp: float = Field(default_factory=time.time)
    source: str = Field(default="unknown")
    raw: str = Field(default="")
    message: str = Field(default="")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

    @field_validator("raw", "message", mode="before")
    @classmethod
    def validate_size_limit(cls, v: Any) -> str:
        """Enforce CWE-400 resource quota on string fields."""
        if isinstance(v, bytes):
            v = v.decode("utf-8", errors="replace")
        s = str(v)
        if len(s) > MAX_EVENT_SIZE_BYTES:
            # Truncate and mark
            return s[:MAX_EVENT_SIZE_BYTES] + "...[TRUNCATED_OVER_64KB]"
        return s

    @classmethod
    def create(
        cls,
        raw: str,
        source: str = "direct",
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> "LogEvent":
        """Fast factory method to initialize event from raw text."""
        sanitized_raw = str(raw)
        if len(sanitized_raw) > MAX_EVENT_SIZE_BYTES:
            sanitized_raw = sanitized_raw[:MAX_EVENT_SIZE_BYTES] + "...[TRUNCATED_OVER_64KB]"

        return cls(
            id=f"{int(time.time() * 1000):x}-{next(_id_counter):x}",
            timestamp=time.time(),
            source=source,
            raw=sanitized_raw,
            message=sanitized_raw,
            metadata=metadata or {},
            tags=tags or [],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Export event as dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Export event as JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEvent":
        """Deserialize from dictionary."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> "LogEvent":
        """Deserialize from JSON string."""
        return cls.model_validate_json(json_str)


__all__ = [
    "LogEvent",
    "MAX_EVENT_SIZE_BYTES",
    "__version__",
]
