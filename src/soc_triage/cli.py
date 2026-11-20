"""Triage alerts from the command line.

  python -m soc_triage.cli ALR-1234567890 [ALR-...]     # by ID from eval/alerts.json
  python -m soc_triage.cli --file alert.json            # a single alert object
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from .ollama_client import OllamaClient
from .schema import Alert
from .triage import triage_alert


def _load_alerts(args: argparse.Namespace) -> list[Alert]:
    if args.file:
        return [Alert.model_validate_json(Path(args.file).read_text(encoding="utf-8"))]
    by_id = {a["alert_id"]: a for a in json.loads(Path(args.alerts).read_text(encoding="utf-8"))}
    missing = [i for i in args.alert_ids if i not in by_id]
    if missing:
        sys.exit(f"Unknown alert ID(s): {', '.join(missing)}")
    return [Alert.model_validate(by_id[i]) for i in args.alert_ids]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soc_triage", description="Triage alerts with a local LLM.")
    ap.add_argument("alert_ids", nargs="*", help="alert IDs to look up in --alerts")
    ap.add_argument("--file", help="path to a JSON file containing one alert")
    ap.add_argument("--alerts", default="eval/alerts.json", help="alerts file for ID lookup")
    ap.add_argument("--model", help="override OLLAMA_MODEL")
    ap.add_argument("--raw", action="store_true", help="include the raw model output")
    args = ap.parse_args(argv)
    if bool(args.file) == bool(args.alert_ids):
        ap.error("give either alert IDs or --file")

    load_dotenv()
    client = OllamaClient(model=args.model)
    exit_code = 0
    for alert in _load_alerts(args):
        result = triage_alert(alert, client)
        out = result.model_dump(mode="json", exclude=None if args.raw else {"raw_output"})
        print(json.dumps(out, indent=2, ensure_ascii=False))
        if result.status == "failed":
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
