"""Evaluation-only code (ground truth, scoring).

The triage pipeline must NEVER import this package: ground-truth labels must
not be able to reach the model. Enforced by tests/test_dataset.py.
"""
