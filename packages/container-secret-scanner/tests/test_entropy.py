"""Unit tests for Shannon Entropy calculation and thresholding."""

import math
import pytest
from scanner.entropy import character_frequency, is_high_entropy, shannon_entropy


def test_entropy_empty_string():
    """Empty string returns 0.0 entropy."""
    assert shannon_entropy("") == 0.0
    assert not is_high_entropy("")


def test_entropy_single_character():
    """Single character string returns 0.0 entropy."""
    assert shannon_entropy("a") == 0.0
    assert shannon_entropy("Z") == 0.0


def test_entropy_homogeneous_string():
    """Repeated single character returns 0.0 entropy."""
    assert shannon_entropy("AAAAAAAAAAAA") == 0.0
    assert not is_high_entropy("AAAAAAAAAAAA")


def test_entropy_binary_uniform():
    """Two symbols with equal probability have entropy of exactly 1.0 bit."""
    # 4 zeros, 4 ones
    data = "00001111"
    assert shannon_entropy(data) == 1.0


def test_entropy_quaternary_uniform():
    """Four symbols with equal probability have entropy of exactly 2.0 bits."""
    data = "ABCD" * 10
    assert shannon_entropy(data) == 2.0


def test_entropy_hex_uniform():
    """16 unique symbols with equal distribution have entropy of 4.0 bits."""
    hex_chars = "0123456789abcdef"
    data = hex_chars * 5
    assert math.isclose(shannon_entropy(data), 4.0, abs_tol=0.001)


def test_entropy_base64_high():
    """Base64 random string exceeds 4.5 bits threshold."""
    # 64 unique characters
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    data = chars * 2
    ent = shannon_entropy(data)
    assert ent == 6.0
    assert is_high_entropy(data, threshold=4.5)
    assert is_high_entropy(data, threshold=5.5)


def test_entropy_english_text_is_low():
    """Standard English prose typically has lower entropy (~3.0-3.8 bits)."""
    text = "The quick brown fox jumps over the lazy dog and runs through the forest."
    ent = shannon_entropy(text)
    assert ent < 4.5
    assert not is_high_entropy(text, threshold=4.5)


def test_character_frequency_distribution():
    """Validate character frequency map calculation."""
    data = "AABB"
    freq = character_frequency(data)
    assert freq["A"] == 0.5
    assert freq["B"] == 0.5
    assert character_frequency("") == {}
