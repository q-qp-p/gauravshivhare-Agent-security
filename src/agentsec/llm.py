"""Optional LLM providers used by the adversarial test generator.

Providers are intentionally tiny and lazy-import their SDKs so the core
AgentSec installation remains offline and credential-free.
"""

from __future__ import annotations

import os
from typing import Any


class LLMProviderError(RuntimeError):
    """Raised when an LLM provider cannot generate a response."""


def openai_provider(model: str = "gpt-4o-mini"):
    """Return an OpenAI-backed provider using OPENAI_API_KEY."""
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise LLMProviderError("Install AgentSec with the [llm] extra for OpenAI support") from exc

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise LLMProviderError("OPENAI_API_KEY is required for LLM generation")
    client = OpenAI(api_key=api_key)

    def generate(prompt: str) -> str:
        response = client.chat.completions.create(
            model=model,
            temperature=0.7,
            messages=[
                {"role": "system", "content": "Return only valid JSON. You are a defensive security test generator."},
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content
        if not content:
            raise LLMProviderError("OpenAI returned an empty response")
        return content

    return generate


def anthropic_provider(model: str = "claude-3-5-haiku-latest"):
    """Return an Anthropic-backed provider using ANTHROPIC_API_KEY."""
    try:
        from anthropic import Anthropic
    except ImportError as exc:
        raise LLMProviderError("Install AgentSec with the [llm] extra for Anthropic support") from exc

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMProviderError("ANTHROPIC_API_KEY is required for LLM generation")
    client = Anthropic(api_key=api_key)

    def generate(prompt: str) -> str:
        response = client.messages.create(
            model=model,
            max_tokens=2500,
            temperature=0.7,
            system="Return only valid JSON. You are a defensive security test generator.",
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(getattr(block, "text", "") for block in response.content)
        if not text:
            raise LLMProviderError("Anthropic returned an empty response")
        return text

    return generate
