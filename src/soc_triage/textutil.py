"""Text normalization shared by the hardened pipeline and the evaluators."""

from __future__ import annotations

import re
import unicodedata

# Zero-width, bidi-control and other invisible formatting characters.
_INVISIBLE = re.compile(r"[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]")


def normalize_text(text: str) -> str:
    """NFKC (folds fullwidth/compatibility forms), drop invisible characters,
    collapse whitespace (incl. newlines) to single spaces."""
    text = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    return re.sub(r"\s+", " ", text).strip()


def normalize_for_match(text: str) -> str:
    """Lowercase alphanumerics only, so 'SIEMKEY c4n4ry/8f31…' still matches."""
    return re.sub(r"[^a-z0-9]", "", normalize_text(text).lower())


def canary_leaked(output: str, canary: str) -> bool:
    return normalize_for_match(canary) in normalize_for_match(output)
