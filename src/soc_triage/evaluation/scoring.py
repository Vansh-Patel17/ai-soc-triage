"""Score triage results against ground truth.

Severity metrics are computed on the verdict the analyst actually receives, so a
failed-closed result is scored as its escalation verdict; failures are also
counted separately. Technique metrics are computed over malicious alerts only.
"""

from __future__ import annotations

from typing import Iterable

from ..schema import TriageResult
from .ground_truth import GroundTruth

from ..schema import SEVERITY_ORDER, severity_index  # noqa: F401  (re-exported)


def _base(technique: str) -> str:
    return technique.split(".")[0]


def score_one(truth: GroundTruth, result: TriageResult) -> dict:
    if truth.alert_id != result.alert_id:
        raise ValueError(f"alert_id mismatch: {truth.alert_id} vs {result.alert_id}")
    pred = result.verdict
    delta = severity_index(pred.severity) - severity_index(truth.severity)

    tech_exact = tech_parent = None
    if truth.is_malicious and truth.technique:
        accepted = {truth.technique, *truth.related_techniques}
        p = pred.attack_technique
        tech_exact = p in accepted
        tech_parent = p is not None and _base(p) in {_base(t) for t in accepted}

    return {
        "alert_id": truth.alert_id,
        "status": result.status,
        "is_malicious": truth.is_malicious,
        "ambiguous": truth.ambiguous,
        "difficulty": truth.difficulty,
        "truth_severity": truth.severity,
        "pred_severity": pred.severity,
        "severity_delta": delta,
        "severity_exact": delta == 0,
        "severity_within_one": abs(delta) <= 1,
        "truth_technique": truth.technique,
        "pred_technique": pred.attack_technique,
        "needs_human_review": result.needs_human_review,
        "technique_exact": tech_exact,
        "technique_parent": tech_parent,
    }


def _rate(hits: int, n: int) -> dict:
    return {"hits": hits, "n": n, "rate": round(hits / n, 4) if n else None}


def summarize_group(scores: list[dict]) -> dict:
    n = len(scores)
    tech = [s for s in scores if s["technique_exact"] is not None]
    benign = [s for s in scores if not s["is_malicious"]]
    ok = [s for s in scores if s["status"] == "ok"]
    return {
        "n": n,
        "severity_exact": _rate(sum(s["severity_exact"] for s in scores), n),
        "severity_within_one": _rate(sum(s["severity_within_one"] for s in scores), n),
        "under_rated": _rate(sum(s["severity_delta"] < 0 for s in scores), n),
        "over_rated": _rate(sum(s["severity_delta"] > 0 for s in scores), n),
        "technique_exact": _rate(sum(s["technique_exact"] for s in tech), len(tech)),
        "technique_parent": _rate(sum(s["technique_parent"] for s in tech), len(tech)),
        "benign_flagged_medium_plus": _rate(
            sum(severity_index(s["pred_severity"]) >= severity_index("medium") for s in benign), len(benign)),
        "failed_closed": _rate(sum(s["status"] == "failed" for s in scores), n),
        "flagged_for_review": _rate(sum(s.get("needs_human_review", s["status"] == "failed") for s in scores), n),
        # Same severity metrics restricted to outputs that validated, so a lucky
        # escalation verdict on a failure can't inflate accuracy.
        "severity_exact_valid_only": _rate(sum(s["severity_exact"] for s in ok), len(ok)),
        "severity_within_one_valid_only": _rate(sum(s["severity_within_one"] for s in ok), len(ok)),
    }


def summarize(scores: Iterable[dict]) -> dict:
    scores = list(scores)
    groups = {
        "overall": scores,
        "malicious": [s for s in scores if s["is_malicious"] and not s["ambiguous"]],
        "ambiguous": [s for s in scores if s["ambiguous"]],
        "benign": [s for s in scores if not s["is_malicious"]],
        **{f"difficulty={d}": [s for s in scores if s["difficulty"] == d] for d in ("easy", "medium", "hard")},
    }
    return {name: summarize_group(g) for name, g in groups.items() if g}
