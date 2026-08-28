"""Log Event Transformers (PII Sanitization, Grok / Regex Parsing, JSON Normalization)."""

import abc
from typing import Any, Dict
from aggregator import LogEvent


class BaseTransformer(abc.ABC):
    """Abstract base class for pipeline transformers."""

    def __init__(self, name: str):
        self.name = name
        self._processed_count: int = 0
        self._modified_count: int = 0
        self._errors_count: int = 0

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return transformer metrics."""
        return {
            "name": self.name,
            "processed": self._processed_count,
            "modified": self._modified_count,
            "errors": self._errors_count,
        }

    @abc.abstractmethod
    def transform(self, event: LogEvent) -> LogEvent:
        """Process and optionally mutate the LogEvent."""
        pass
