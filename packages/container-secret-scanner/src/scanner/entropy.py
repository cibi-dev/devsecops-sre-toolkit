"""Shannon Entropy calculation module for secret detection and false positive filtering."""

from __future__ import annotations

import collections
import math
from typing import Dict


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    Formula:
        H(S) = - sum(p_i * log2(p_i))
    where p_i is the empirical probability (frequency / length) of each unique character.

    Args:
        data: The input string to analyze.

    Returns:
        Entropy in bits (float). Returns 0.0 for empty strings or strings with length <= 1.
    """
    if not data or len(data) <= 1:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy: float = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
    """Check if a string exceeds a Shannon entropy threshold.

    Args:
        data: The candidate secret string.
        threshold: Minimum Shannon entropy in bits (default 4.5).

    Returns:
        True if entropy is greater than or equal to threshold, False otherwise.
    """
    if not data:
        return False
    return shannon_entropy(data) >= threshold


def character_frequency(data: str) -> Dict[str, float]:
    """Return the relative frequency distribution of characters in data.

    Args:
        data: Input string.

    Returns:
        Dictionary mapping character to its normalized frequency [0.0, 1.0].
    """
    if not data:
        return {}
    length = len(data)
    counts = collections.Counter(data)
    return {char: round(count / length, 4) for char, count in counts.items()}
