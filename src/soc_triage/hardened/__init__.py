"""Hardened triage pipeline: independently switchable defense layers.

Layers (see pipeline.Layers):
  isolation      - alert fields as JSON inside per-request random delimiters, with
                   an explicit "untrusted data, never instructions" rule
  output_checks  - fail closed if output contains the canary, the delimiter nonce,
                   or text copied/echoed from the (suspicious) input
  floor          - rule-based minimum severity; a model verdict below it is raised
                   and flagged for human review
  detector       - injection patterns in input fields raise severity to high and
                   flag the alert instead of trusting the model

The baseline pipeline (prompt.py / triage.triage_alert) is untouched.
"""
