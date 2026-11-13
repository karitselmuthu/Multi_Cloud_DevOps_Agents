"""Multi-model gateway. LLM_PROVIDER = mock (default, offline) | anthropic | openai. Add a provider = add a function."""
import os

import httpx


def _anthropic(prompt, system):
    r = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"},
        json={
            "model": os.getenv("LLM_MODEL", "claude-sonnet-5-5"),
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["content"][0]["text"]


def _openai(prompt, system):
    r = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
        json={
            "model": os.getenv("LLM_MODEL", "gpt-4o"),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _mock(prompt, system):
    return f"[mock LLM] {system[:60]}... (set LLM_PROVIDER=anthropic|openai for real output)"


PROVIDERS = {"mock": _mock, "anthropic": _anthropic, "openai": _openai}


def complete(prompt, system=""):
    return PROVIDERS[os.getenv("LLM_PROVIDER", "mock")](prompt, system)
