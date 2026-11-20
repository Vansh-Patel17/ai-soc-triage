"""Minimal client for the local Ollama chat API."""

from __future__ import annotations

import os

import requests

DEFAULT_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:latest"


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, url: str | None = None, model: str | None = None, timeout: float = 180.0,
                 seed: int = 42):
        self.url = (url or os.getenv("OLLAMA_URL") or DEFAULT_URL).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL
        self.timeout = timeout
        self.seed = seed

    def chat(self, system: str, user: str, json_mode: bool = True) -> str:
        """Send one system+user exchange; return the raw assistant text."""
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            # Deterministic decoding so eval runs are reproducible.
            "options": {"temperature": 0, "seed": self.seed},
        }
        if json_mode:
            body["format"] = "json"
        try:
            resp = requests.post(f"{self.url}/api/chat", json=body, timeout=self.timeout)
        except requests.RequestException as ex:
            raise OllamaError(f"Ollama request failed: {ex}") from ex
        if not resp.ok:
            # Ollama puts the reason in the body, e.g. "token repeat limit reached".
            raise OllamaError(f"Ollama HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()["message"]["content"]
        except (KeyError, TypeError, ValueError) as ex:
            raise OllamaError(f"Unexpected Ollama response: {ex}") from ex
