"""Integrity checks for eval/alerts.json and eval/ground_truth.json.

These run without data/ (the raw .evtx files are gitignored).
"""

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from soc_triage.evaluation.ground_truth import GroundTruth
from soc_triage.schema import Alert

ROOT = Path(__file__).resolve().parents[1]
ALERTS_PATH = ROOT / "eval" / "alerts.json"
TRUTH_PATH = ROOT / "eval" / "ground_truth.json"


@pytest.fixture(scope="module")
def alerts() -> list[Alert]:
    return [Alert.model_validate(a) for a in json.loads(ALERTS_PATH.read_text(encoding="utf-8"))]


@pytest.fixture(scope="module")
def truths() -> list[GroundTruth]:
    return [GroundTruth.model_validate(t) for t in json.loads(TRUTH_PATH.read_text(encoding="utf-8"))]


def test_one_to_one_ids(alerts, truths):
    a_ids = [a.alert_id for a in alerts]
    t_ids = [t.alert_id for t in truths]
    assert len(set(a_ids)) == len(a_ids)
    assert set(a_ids) == set(t_ids)


def test_size_and_mix(alerts, truths):
    assert 20 <= len(alerts) <= 40
    sev = Counter(t.severity for t in truths)
    diff = Counter(t.difficulty for t in truths)
    assert sev["informational"] >= 8, "need benign alerts to measure false positives"
    assert sum(t.is_malicious for t in truths) >= 15
    assert diff["hard"] >= 5 and diff["easy"] >= 5
    assert any(t.ambiguous for t in truths)


def test_labels_consistent(truths):
    for t in truths:
        if t.is_malicious:
            assert t.technique and t.severity != "informational", t.alert_id
        else:
            assert t.technique is None and t.severity == "informational", t.alert_id


def test_no_label_or_provenance_leak_into_alerts(alerts, truths):
    """The model-visible file must not reveal labels or the source filename."""
    raw = ALERTS_PATH.read_text(encoding="utf-8")
    for key in ("severity", "technique", "is_malicious", "ground_truth", "source_file", "difficulty"):
        assert f'"{key}"' not in raw
    assert not re.search(r"\bT1\d{3}(\.\d{3})?\b", raw), "ATT&CK ID present in alerts"
    for t in truths:
        stem = Path(t.source_file).stem
        assert stem not in raw, f"source filename leaked: {stem}"


def test_real_log_contents_preserved(alerts):
    """Giveaway strings that are genuine field values must NOT be scrubbed."""
    raw = ALERTS_PATH.read_text(encoding="utf-8")
    for s in ("EfsPotato.exe", "UACME.exe", "mimilsa.log", "WerTrigger.exe"):
        assert s in raw, s


def test_pipeline_does_not_import_evaluation():
    """Ground truth must never be reachable from pipeline code."""
    pkg = ROOT / "src" / "soc_triage"
    for py in pkg.rglob("*.py"):
        if "evaluation" in py.relative_to(pkg).parts:
            continue
        text = py.read_text(encoding="utf-8")
        assert not re.search(r"\bevaluation\b|ground_truth", text), f"{py} references evaluation code"
