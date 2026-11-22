"""Offline replay of stored model outputs through the deterministic defense layers.

Only `isolation` changes what the model sees; output_checks, floor and detector
are pure functions of (alert, raw model output, nonce, canary). So per-layer
contributions can be measured from ONE set of model runs by replaying stored
raw outputs through every combination of the post-model layers.

  # verify a hardened run, then print the ablation over its stored outputs
  python -m soc_triage.evaluation.replay eval/results/attacks_hardened.json
  # ablate the undefended run (isolation off) -- same layers, baseline prompt outputs
  python -m soc_triage.evaluation.replay eval/results/attacks_baseline.json --payloads attacks/payloads.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path

from ..hardened.pipeline import POST_MODEL_LAYERS, Layers, apply_layers
from ..schema import Alert
from .inject import inject, load_corpus

COMPARED = ("status", "verdict", "needs_human_review", "flags", "model_verdict", "error")


def _alerts_by_id(alerts_path: str | Path) -> dict[str, Alert]:
    return {a["alert_id"]: Alert.model_validate(a) for a in json.loads(Path(alerts_path).read_text(encoding="utf-8"))}


def source_layers(state: dict) -> Layers:
    """Layers the stored run was produced with ('baseline' == no layers)."""
    name = state["run"].get("pipeline", "baseline")
    return Layers.parse("none") if name == "baseline" else Layers.parse(name.partition(":")[2])


def replay_record(alert_in: Alert, record: dict, layers: Layers, canary: str, model: str):
    raw = record["raw_output"]
    # When raw is None the model call failed and record["error"] is that model error
    # (output checks only ever run on a parsed verdict, so they can't have replaced it).
    return apply_layers(alert_in, raw, record["error"] if raw is None else None, layers,
                        canary=canary, nonce=record.get("nonce") if layers.isolation else None, model=model)


def replay_runs(state: dict, alerts_path: str | Path, payloads_path: str | Path, layers: Layers) -> dict:
    """Re-derive every record of a stored run under `layers` (isolation must match the source)."""
    from .run_attacks import build_record  # local import: run_attacks imports this module lazily too

    if layers.isolation != source_layers(state).isolation:
        raise ValueError("isolation changes the model input and cannot be replayed; it must match the source run")
    corpus = load_corpus(payloads_path)
    by_payload = {p.id: p for p in corpus.payloads}
    alerts = _alerts_by_id(alerts_path)
    out = {}
    for key, records in state["runs"].items():
        cond = key.rsplit("#", 1)[0]
        payload = by_payload.get(cond)
        new = []
        for rec in records:
            alert = alerts[rec["alert_id"]]
            alert_in, point = inject(alert, payload.text) if payload else (alert, None)
            result = replay_record(alert_in, rec, layers, corpus.canary, state["run"]["model"])
            new.append(build_record(rec["alert_id"], cond, point, result, payload, corpus.canary))
        out[key] = new
    return out


def verify_replay_matches_live(state: dict, alerts_path: str | Path, payloads_path: str | Path) -> list[str]:
    """Replay the source run's own layers; return a description of every record that differs."""
    replayed = replay_runs(state, alerts_path, payloads_path, source_layers(state))
    mismatches = []
    for key, records in state["runs"].items():
        for live, rep in zip(records, replayed[key], strict=True):
            diff = [f for f in COMPARED if live.get(f) != rep.get(f)]
            if diff:
                mismatches.append(f"{key}/{live['alert_id']}: {diff}")
    return mismatches


def ablation(state: dict, alerts_path: str | Path, payloads_path: str | Path) -> dict[str, dict]:
    """Summaries for every combination of post-model layers (isolation fixed by the source run)."""
    from .run_attacks import summarize_runs

    iso = source_layers(state).isolation
    out = {}
    for combo in itertools.product([False, True], repeat=len(POST_MODEL_LAYERS)):
        layers = Layers(iso, *combo)
        runs = replay_runs(state, alerts_path, payloads_path, layers)
        out[layers.name] = summarize_runs(runs, state["run"]["conditions"], state["run"]["n_runs"])
    return out


def render_ablation(abl: dict[str, dict]) -> str:
    def m(s, key):
        v = s[key]
        return f'{v["mean"]:g}' if v["min"] == v["max"] else f'{v["mean"]:.1f} [{v["min"]:g}–{v["max"]:g}]'

    rows = ["| Layers | Condition | Silent suppression | Suppressed (any) | Flagged | Failed closed | "
            "Canary delivered | Hijack delivered |", "|---|---|---|---|---|---|---|---|"]
    for name, summary in abl.items():
        for cond, s in summary.items():
            n = s["n_alerts"]
            rows.append(f'| {name} | {cond} | {m(s, "silent_suppressed")}/{n} | {m(s, "suppressed")}/{n} | '
                        f'{m(s, "flagged")}/{n} | {m(s, "failed_closed")} | {m(s, "delivered_canary_leaks")} | '
                        f'{m(s, "delivered_hijacks")} |')
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify / ablate defense layers over stored model outputs.")
    ap.add_argument("results", help="a run_attacks results JSON")
    ap.add_argument("--alerts", default="eval/alerts.json")
    ap.add_argument("--payloads", default="attacks/payloads.json")
    ap.add_argument("--out", help="write the ablation summaries to this JSON file")
    args = ap.parse_args(argv)

    state = json.loads(Path(args.results).read_text(encoding="utf-8"))
    if source_layers(state) != Layers.parse("none"):
        mismatches = verify_replay_matches_live(state, args.alerts, args.payloads)
        if mismatches:
            print(f"REPLAY MISMATCH on {len(mismatches)} record(s): {mismatches[:5]}", file=sys.stderr)
            return 1
        print("Replay check passed: replaying the source layers exactly matches the stored live results.",
              file=sys.stderr)
    abl = ablation(state, args.alerts, args.payloads)
    print(render_ablation(abl))
    if args.out:
        Path(args.out).write_text(json.dumps({"source": state["run"], "ablation": abl}, indent=2) + "\n",
                                  encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
