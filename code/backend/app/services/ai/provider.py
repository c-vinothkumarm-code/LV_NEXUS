"""Configurable AI provider. Gemini first; OpenAI can be switched on by configuration alone.

Providers only return text. They are given no tools and no credentials, so a model cannot act on anything."""
from __future__ import annotations

from typing import Protocol

import httpx

from app.core.config import Settings
from app.core.logging import mask, redact


class AIProvider(Protocol):
    name: str

    def generate(self, system: str, prompt: str) -> str: ...


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None):
        self.key, self.model, self.client = api_key, model, client or httpx.Client(timeout=45)

    def generate(self, system: str, prompt: str) -> str:
        prompt = mask(redact(prompt))  # no e-mails, IPs, key IDs or secrets ever leave for the model
        resp = self.client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            headers={"x-goog-api-key": self.key},
            json={"systemInstruction": {"parts": [{"text": system}]}, "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                  "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2}})
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None):
        self.key, self.model, self.client = api_key, model, client or httpx.Client(timeout=45)

    def generate(self, system: str, prompt: str) -> str:
        prompt = mask(redact(prompt))  # no e-mails, IPs, key IDs or secrets ever leave for the model
        resp = self.client.post("https://api.openai.com/v1/chat/completions", headers={"Authorization": f"Bearer {self.key}"},
                                json={"model": self.model, "response_format": {"type": "json_object"},
                                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]})
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def build_provider(settings: Settings) -> AIProvider | None:
    """None when AI is switched off or incompletely configured; callers then carry on without it."""
    if settings.ai_provider == "gemini" and settings.gemini_api_key and settings.gemini_model:
        return GeminiProvider(settings.gemini_api_key, settings.gemini_model)
    if settings.ai_provider == "openai" and settings.openai_api_key and settings.openai_model:
        return OpenAIProvider(settings.openai_api_key, settings.openai_model)
    return None
