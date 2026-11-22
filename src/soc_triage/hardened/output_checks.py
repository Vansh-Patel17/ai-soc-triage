"""Layer: deterministic output checks. Any violation fails the result closed.

Checks:
  canary_leak     - the system-prompt canary appears in raw output (normalized)
  nonce_echo      - the per-request delimiter nonce appears in raw output
  verbatim_copy   - summary/recommended_action is copied verbatim from an input field
  injection_echo  - output repeats distinctive tokens or 5-word phrases from input
                    fields that the injection patterns flagged as suspicious
                    (so this check shares detector.PATTERNS for locating them,
                    even when the detector layer itself is switched off)
"""

from __future__ import annotations

import re

from ..schema import TriageVerdict
from ..textutil import canary_leaked, normalize_text

_SHINGLE = 5


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z]{2,}", normalize_text(text).lower())


def _shingles(words: list[str]) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + _SHINGLE]) for i in range(len(words) - _SHINGLE + 1)}


def _rare_tokens(text: str) -> set[str]:
    """Distinctive identifiers like CHG-20931 or HIJACKED-7731-ZULU:
    hyphen/underscore-joined, containing both letters and digits."""
    toks = re.findall(r"[a-z0-9]+(?:[-_][a-z0-9]+)+", normalize_text(text).lower())
    return {t for t in toks if len(t) >= 6 and re.search(r"[a-z]", t) and re.search(r"\d", t)}


def check_output(raw: str, verdict: TriageVerdict | None, fields: dict[str, str], *,
                 canary: str | None = None, nonce: str | None = None,
                 suspicious_fields: dict[str, str] | None = None) -> list[str]:
    violations: list[str] = []
    if canary and canary_leaked(raw, canary):
        violations.append("canary_leak")
    if nonce and nonce.lower() in raw.lower():
        violations.append("nonce_echo")
    if verdict is None:
        return violations

    out_texts = [verdict.summary, verdict.recommended_action]
    norm_fields = {k: normalize_text(v).lower() for k, v in fields.items()}
    for text in out_texts:
        t = normalize_text(text).lower().rstrip(".")
        if len(t) >= 12:
            hit = next((k for k, v in norm_fields.items() if t in v), None)
            if hit:
                violations.append(f"verbatim_copy:{hit}")
                break

    if suspicious_fields:
        out_norm = " ".join(normalize_text(t).lower() for t in out_texts)
        out_shingles = _shingles(_words(out_norm))
        for name, value in suspicious_fields.items():
            if any(tok in out_norm for tok in _rare_tokens(value)) or (_shingles(_words(value)) & out_shingles):
                violations.append(f"injection_echo:{name}")
                break
    return violations
