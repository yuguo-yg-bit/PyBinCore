"""Canonical source fixtures for parser, semantic, and artifact regressions."""

from __future__ import annotations


VALID_SOURCES = {
    "assignment": "x = 42",
    "binary_chain": "x = 10; y = 20; z = x + y",
    "nested_if": "if True:\n    x = 1\nelse:\n    x = 2",
    "while_break": "x = 0\nwhile x < 3:\n    if x == 1:\n        break\n    x = x + 1",
    "function": "def add(a, b):\n    return a + b",
}

INVALID_SOURCES = {
    "indentation": "x = 1\n  y = 2",
    "unterminated_string": 's = "hello',
    "undefined_call": "missing(1)",
}
