"""Pipeline tests with a fake model client (no Ollama needed)."""

import json

import pytest

from soc_triage.ollama_client import OllamaError
from soc_triage.prompt import build_user_prompt
from soc_triage.schema import Alert
from soc_triage.triage import ESCALATION_VERDICT, triage_alert

ALERT = Alert(alert_id="ALR-test", timestamp="2020-01-01T00:00:00Z", provider="Microsoft-Windows-Sysmon",
              channel="Microsoft-Windows-Sysmon/Operational", event_id=1, hostname="PC01",
              user="PC01\\bob", process_name="C:\\x\\evil.exe", command_line="evil.exe --go",
              extra={"CurrentDirectory": "C:\\x\\"})

GOOD = {"summary": "Suspicious binary executed.", "severity": "high", "attack_technique": "T1204.002",
        "recommended_action": "Isolate host and collect the binary."}


class FakeClient:
    model = "fake"

    def __init__(self, reply=None, exc=None):
        self.reply, self.exc, self.calls = reply, exc, []

    def chat(self, system, user, json_mode=True):
        self.calls.append((system, user))
        if self.exc:
            raise self.exc
        return self.reply


def test_valid_output_accepted():
    r = triage_alert(ALERT, FakeClient(json.dumps(GOOD)))
    assert r.status == "ok" and not r.needs_human_review
    assert r.verdict.severity == "high" and r.verdict.attack_technique == "T1204.002"


def test_benign_null_technique_accepted():
    r = triage_alert(ALERT, FakeClient(json.dumps({**GOOD, "severity": "informational",
                                                   "attack_technique": None})))
    assert r.status == "ok" and r.verdict.attack_technique is None


@pytest.mark.parametrize("reply", [
    "not json at all",
    "",
    json.dumps({**GOOD, "severity": "urgent"}),                  # not in scale
    json.dumps({**GOOD, "severity": "High"}),                    # wrong case
    json.dumps({**GOOD, "attack_technique": "Credential Dumping"}),  # name, not ID
    json.dumps({**GOOD, "attack_technique": "T1003.6"}),         # malformed ID
    json.dumps({k: v for k, v in GOOD.items() if k != "summary"}),   # missing key
    json.dumps({**GOOD, "is_false_positive": True}),             # extra key
    json.dumps({**GOOD, "summary": ""}),                         # empty
    json.dumps([GOOD]),                                          # wrong shape
])
def test_malformed_output_fails_closed(reply):
    r = triage_alert(ALERT, FakeClient(reply))
    assert r.status == "failed" and r.needs_human_review
    assert r.verdict == ESCALATION_VERDICT and r.verdict.severity == "high"
    assert r.error


def test_unreachable_model_fails_closed():
    r = triage_alert(ALERT, FakeClient(exc=OllamaError("connection refused")))
    assert r.status == "failed" and r.needs_human_review and r.verdict.severity == "high"


def test_baseline_prompt_passes_fields_plainly():
    prompt = build_user_prompt(ALERT)
    assert "command_line: evil.exe --go" in prompt
    assert "CurrentDirectory: C:\\x\\" in prompt
