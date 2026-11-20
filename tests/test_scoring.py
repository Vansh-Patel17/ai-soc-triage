from soc_triage.evaluation.ground_truth import GroundTruth
from soc_triage.evaluation.scoring import score_one, summarize
from soc_triage.schema import TriageResult, TriageVerdict
from soc_triage.triage import ESCALATION_VERDICT


def _truth(aid, sev, tech=None, related=(), malicious=True, ambiguous=False, difficulty="easy"):
    return GroundTruth(alert_id=aid, is_malicious=malicious, severity=sev, technique=tech,
                       related_techniques=list(related), difficulty=difficulty, ambiguous=ambiguous,
                       source_file="f.evtx", source_record_id=1, note="n")


def _result(aid, sev, tech, status="ok"):
    verdict = ESCALATION_VERDICT if status == "failed" else TriageVerdict(
        summary="s", severity=sev, attack_technique=tech, recommended_action="a")
    return TriageResult(alert_id=aid, status=status, verdict=verdict, needs_human_review=status == "failed",
                        model="m")


def test_severity_exact_and_within_one():
    s = score_one(_truth("a", "critical", "T1003.006"), _result("a", "high", "T1003.006"))
    assert not s["severity_exact"] and s["severity_within_one"] and s["severity_delta"] == -1
    s = score_one(_truth("a", "critical", "T1003.006"), _result("a", "medium", None))
    assert not s["severity_within_one"] and s["severity_delta"] == -2


def test_technique_exact_related_and_parent():
    t = _truth("a", "high", "T1218.005", related=("T1566.001",))
    assert score_one(t, _result("a", "high", "T1218.005"))["technique_exact"]
    assert score_one(t, _result("a", "high", "T1566.001"))["technique_exact"]
    s = score_one(t, _result("a", "high", "T1218"))
    assert not s["technique_exact"] and s["technique_parent"]
    s = score_one(t, _result("a", "high", None))
    assert s["technique_exact"] is False and s["technique_parent"] is False


def test_benign_has_no_technique_score():
    s = score_one(_truth("b", "informational", malicious=False), _result("b", "low", None))
    assert s["technique_exact"] is None


def test_failed_closed_scored_as_escalation():
    s = score_one(_truth("a", "informational", malicious=False), _result("a", None, None, status="failed"))
    assert s["status"] == "failed" and s["pred_severity"] == "high"


def test_summarize_groups():
    scores = [
        score_one(_truth("a", "critical", "T1003.006", difficulty="hard"), _result("a", "critical", "T1003")),
        score_one(_truth("b", "informational", malicious=False), _result("b", "medium", None)),
        score_one(_truth("c", "medium", "T1572", ambiguous=True), _result("c", "x", None, status="failed")),
    ]
    summ = summarize(scores)
    assert summ["overall"]["n"] == 3 and summ["malicious"]["n"] == 1
    assert summ["malicious"]["technique_parent"]["hits"] == 1
    assert summ["benign"]["benign_flagged_medium_plus"]["hits"] == 1
    assert summ["overall"]["failed_closed"]["hits"] == 1


def test_valid_only_excludes_lucky_escalation():
    # Failure whose escalation "high" equals truth "high" must not count as accurate in valid-only.
    scores = [score_one(_truth("a", "high", "T1068"), _result("a", None, None, status="failed")),
              score_one(_truth("b", "high", "T1068"), _result("b", "low", None))]
    summ = summarize(scores)["overall"]
    assert summ["severity_exact"]["hits"] == 1
    assert summ["severity_exact_valid_only"] == {"hits": 0, "n": 1, "rate": 0.0}
