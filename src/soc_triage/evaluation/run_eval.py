"""Run the triage pipeline over every alert and score against ground truth.

  python -m soc_triage.evaluation.run_eval --out eval/results/baseline_clean.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from ..ollama_client import OllamaClient
from ..prompt import SYSTEM_PROMPT
from ..schema import Alert
from ..triage import triage_alert
from .ground_truth import GroundTruth
from .scoring import score_one, summarize

TABLE_ROWS = [("severity_exact", "Severity exact match"),
              ("severity_within_one", "Severity within one level"),
              ("severity_exact_valid_only", "Severity exact (valid outputs only)"),
              ("severity_within_one_valid_only", "Severity within one (valid outputs only)"),
              ("under_rated", "Under-rated (below truth)"),
              ("over_rated", "Over-rated (above truth)"),
              ("technique_exact", "Technique exact (primary/related)"),
              ("technique_parent", "Technique parent match"),
              ("benign_flagged_medium_plus", "Benign flagged >= medium"),
              ("failed_closed", "Failed closed")]


def _git_state() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout.strip())
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def _cell(m: dict) -> str:
    return "–" if not m["n"] else f'{m["hits"]}/{m["n"]} ({m["rate"]:.0%})'


def render_table(summary: dict) -> str:
    cols = [c for c in ("overall", "malicious", "ambiguous", "benign", "difficulty=easy", "difficulty=medium",
                        "difficulty=hard") if c in summary]
    head = "| Metric | " + " | ".join(f'{c.replace("difficulty=", "diff:")} (n={summary[c]["n"]})' for c in cols) + " |"
    sep = "|---|" + "---|" * len(cols)
    rows = [f"| {label} | " + " | ".join(_cell(summary[c][key]) for c in cols) + " |" for key, label in TABLE_ROWS]
    return "\n".join([head, sep, *rows])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Batch-evaluate triage against ground truth.")
    ap.add_argument("--alerts", default="eval/alerts.json")
    ap.add_argument("--truth", default="eval/ground_truth.json")
    ap.add_argument("--out", required=True, help="results JSON path")
    ap.add_argument("--label", default="baseline-clean", help="run label recorded in the results")
    ap.add_argument("--model", help="override OLLAMA_MODEL")
    ap.add_argument("--limit", type=int, help="only the first N alerts (smoke test)")
    args = ap.parse_args(argv)

    load_dotenv()
    alerts = [Alert.model_validate(a) for a in json.loads(Path(args.alerts).read_text(encoding="utf-8"))]
    truths = {t["alert_id"]: GroundTruth.model_validate(t)
              for t in json.loads(Path(args.truth).read_text(encoding="utf-8"))}
    if args.limit:
        alerts = alerts[: args.limit]
    client = OllamaClient(model=args.model)

    records, scores = [], []
    started = datetime.now(timezone.utc)
    for i, alert in enumerate(alerts, 1):
        t0 = time.perf_counter()
        result = triage_alert(alert, client)
        elapsed = round(time.perf_counter() - t0, 2)
        score = score_one(truths[alert.alert_id], result)
        scores.append(score)
        records.append({**score, "latency_s": elapsed, "error": result.error, "verdict": result.verdict.model_dump(),
                        "raw_output": result.raw_output})
        mark = "FAIL" if result.status == "failed" else ("=" if score["severity_exact"] else f'{score["severity_delta"]:+d}')
        print(f"[{i:2d}/{len(alerts)}] {alert.alert_id} truth={score['truth_severity']:<13} "
              f"pred={score['pred_severity']:<13} {mark:>4}  tech={score['pred_technique']} "
              f"({elapsed}s)", file=sys.stderr)

    summary = summarize(scores)
    out = {
        "run": {
            "label": args.label,
            "started_utc": started.isoformat(timespec="seconds"),
            "model": client.model,
            "ollama_url": client.url,
            "decoding": {"temperature": 0, "seed": client.seed},
            "prompt_builder": "baseline-plain (no injection defense)",
            "system_prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
            "git": _git_state(),
            "n_alerts": len(alerts),
        },
        "summary": summary,
        "results": records,
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(render_table(summary))
    print(f"\nSaved {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
