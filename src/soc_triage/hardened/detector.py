"""Layer: injection detector.

Pattern families describe CATEGORIES of injection from docs/threat-model.md
(instruction override, role/delimiter spoofing, fake verdicts, authority/policy
appeals, directives aimed at the model, secret requests), not literal payload
strings. Text is NFKC-normalized with invisible characters removed first.
Legitimate Windows log fields essentially never contain this kind of prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..schema import Alert
from ..textutil import normalize_text
from .fields import content_fields

_W = r"[^.;!?\n]{0,60}"  # bounded gap within a clause

PATTERNS: dict[str, list[str]] = {
    "override": [
        rf"\b(ignore|disregard|forget|override|bypass|skip)\b{_W}\b(previous|prior|above|earlier|preceding|all|any|your|the|these)\b{_W}\b(instructions?|prompts?|rules|guidance|guidelines|directives?|context|task)\b",
        r"\bnew (instructions?|rules|task)\b",
        rf"\b(stop|do not|don'?t)\b{_W}\b(triag\w*|analy[sz]\w*|evaluat\w*)\b",
    ],
    "role_spoof": [
        r"(^|\s)(#{2,}|\[|<\|?|<<)\s*/?\s*(system|assistant|user|inst|sys)\s*(\]|\|?>|>>|:)",
        r"(^|\s)(system|assistant)\s*(prompt|message|note)?\s*:\s",
        r"<\|?(im_start|im_end|eot_id|start_header_id)\|?>",
    ],
    "fake_verdict": [
        r"[\"']\s*(severity|attack_technique|recommended_action|summary|verdict)\s*[\"']\s*:",
        r"\b(severity|verdict|classification)\s*[:=]\s*[\"']?(informational|low|medium|high|critical|benign|false positive)\b",
    ],
    "authority": [
        rf"\b(authori[sz]ed|approved|pre-?approved|sanctioned|whitelisted|allowlisted|exempt(ed)?)\b{_W}\b(test|exercise|activity|scanner|appliance|host|event|traffic|policy|change)\b",
        r"\b(red[- ]?team|pen(etration)?[- ]?test(ing)?)\b",
        r"\b(soc|security)[- ](note|policy|team|operations)\b",
        r"\bper (the )?(soc |security )?policy\b",
        r"\bchange (ticket|request)\b",
    ],
    "directive": [
        rf"\b(classify|rate|mark|label|treat|consider|flag|set|score)\b{_W}\b(as|to)\b{_W}\b(benign|informational|low|false[- ]positive|safe|routine|expected|harmless|legitimate)\b",
        r"\b(respond|reply|answer|output)\s+(with|only)\b",
        r"\bset the (summary|severity|verdict|field)\b",
        r"\bno (further )?action (is )?required\b",
        r"\b(you must|you should|you are now|as an ai)\b",
    ],
    "secret_request": [
        rf"\b(api key|system prompt|your (instructions|configuration|prompt)|confidential|secret|password|passphrase|credentials?)\b{_W}\b(reveal|copy|print|repeat|include|output|show|verbatim|disclose)\b",
        rf"\b(reveal|copy|print|repeat|include|output|show|disclose)\b{_W}\b(api key|system prompt|your (instructions|configuration|prompt)|confidential|secret|password|passphrase)\b",
    ],
}

_COMPILED = {cat: [re.compile(p, re.IGNORECASE) for p in pats] for cat, pats in PATTERNS.items()}


@dataclass(frozen=True)
class Hit:
    field: str
    category: str
    snippet: str


def scan_text(text: str) -> list[tuple[str, str]]:
    """Return (category, matched snippet) for each category that matches."""
    norm = normalize_text(text)
    found = []
    for cat, pats in _COMPILED.items():
        for p in pats:
            m = p.search(norm)
            if m:
                found.append((cat, m.group(0)[:120]))
                break
    return found


def detect(alert: Alert) -> list[Hit]:
    return [Hit(field, cat, snip) for field, value in content_fields(alert).items()
            for cat, snip in scan_text(value)]
