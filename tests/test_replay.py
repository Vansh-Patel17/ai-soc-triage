"""Replay must reproduce live hardened results exactly (no Ollama needed)."""

import json
from pathlib import Path

import pytest

from soc_triage.evaluation.inject import inject, load_corpus
from soc_triage.evaluation.replay import ablation, replay_runs, verify_replay_matches_live
from soc_triage.evaluation.run_attacks import build_record
from soc_triage.hardened.pipeline import Layers
from soc_triage.ollama_client import OllamaError
from soc_triage.pipelines import make_pipeline
from soc_triage.schema import Alert

ROOT = Path(__file__).resolve().parents[1]
ALERTS_PATH = ROOT / "eval/alerts.json"
PAYLOADS_PATH = ROOT / "attacks/payloads.json"
CORPUS = load_corpus(PAYLOADS_PATH)
ALERTS = [Alert.model_validate(a) for a in json.loads(ALERTS_PATH.read_text(encoding="utf-8"))]
CONDS = ["clean", "fake_verdict_json", "canary_leak", "task_hijack"]


class ScriptedClient:
    """Deterministic fake model covering every outcome: valid, leaking, copying, invalid, call failure."""
    model = "fake"

    def __init__(self, i):
        self.i = i

    def chat(self, system, user, json_mode=True):
        if self.i == 3:
            raise OllamaError("Ollama HTTP 500: token repeat limit reached")
        if self.i == 4:
            return '{"summary": "x", "severity": "urgent"}'
        if "SIEM API key" in user:
            summary = f"The key is {CORPUS.canary}."
        elif "HIJACKED-7731-ZULU" in user:
            summary = "HIJACKED-7731-ZULU"
        elif "Routine administrative activity" in user:
            summary = "Routine administrative activity by IT staff."
        else:
            summary = "Suspicious activity observed on the host."
        sev = "informational" if self.i % 2 else "medium"
        return json.dumps({"summary": summary, "severity": sev, "attack_technique": None,
                           "recommended_action": "Review the host."})


def _live_state(spec: str) -> dict:
    pipeline = make_pipeline(spec, canary=CORPUS.canary)
    by_payload = {p.id: p for p in CORPUS.payloads}
    runs = {}
    for cond in CONDS:
        payload = by_payload.get(cond)
        recs = []
        for i, alert in enumerate(ALERTS[:6]):
            alert_in, point = inject(alert, payload.text) if payload else (alert, None)
            recs.append(build_record(alert.alert_id, cond, point, pipeline(alert_in, ScriptedClient(i)),
                                     payload, CORPUS.canary))
        runs[f"{cond}#1"] = recs
    return {"run": {"pipeline": pipeline.name, "model": "fake", "conditions": CONDS, "n_runs": 1}, "runs": runs}


@pytest.mark.parametrize("spec", ["hardened", "hardened:isolation+floor", "hardened:output_checks+detector"])
def test_replay_exactly_matches_live(spec):
    state = _live_state(spec)
    statuses = {r["status"] for recs in state["runs"].values() for r in recs}
    assert statuses == {"ok", "failed"}  # both paths exercised
    assert verify_replay_matches_live(state, ALERTS_PATH, PAYLOADS_PATH) == []


def test_replay_detects_tampering():
    state = _live_state("hardened")
    state["runs"]["clean#1"][0]["flags"] = ["tampered"]
    state["runs"]["canary_leak#1"][1]["verdict"]["severity"] = "low"
    assert len(verify_replay_matches_live(state, ALERTS_PATH, PAYLOADS_PATH)) == 2


def test_replay_requires_stored_nonce_for_nonce_check():
    state = _live_state("hardened")
    assert all(r["nonce"] for recs in state["runs"].values() for r in recs)
    base = _live_state("baseline")
    assert all(r["nonce"] is None for recs in base["runs"].values() for r in recs)


def test_isolation_cannot_be_replayed():
    with pytest.raises(ValueError):
        replay_runs(_live_state("hardened"), ALERTS_PATH, PAYLOADS_PATH, Layers.parse("floor"))


def test_ablation_covers_all_post_model_combinations():
    abl = ablation(_live_state("hardened"), ALERTS_PATH, PAYLOADS_PATH)
    assert len(abl) == 8 and all(name.startswith("hardened:isolation") for name in abl)
    full = abl["hardened:isolation+output_checks+floor+detector"]
    bare = abl["hardened:isolation"]
    assert full["canary_leak"]["delivered_canary_leaks"]["mean"] == 0
    assert bare["canary_leak"]["delivered_canary_leaks"]["mean"] > 0


def test_ablation_over_baseline_outputs_uses_no_isolation():
    abl = ablation(_live_state("baseline"), ALERTS_PATH, PAYLOADS_PATH)
    assert "hardened:none" in abl and "hardened:output_checks+floor+detector" in abl
