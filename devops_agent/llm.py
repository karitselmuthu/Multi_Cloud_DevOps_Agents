"""Multi-model gateway. LLM_PROVIDER = mock (default, offline) | anthropic | openai. Add a provider = add a function."""
import os
import time

import httpx

from . import obs


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
    j = r.json()
    return j["content"][0]["text"], j.get("usage", {}).get("input_tokens", 0), j.get("usage", {}).get("output_tokens", 0)


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
    j = r.json()
    return j["choices"][0]["message"]["content"], j.get("usage", {}).get("prompt_tokens", 0), j.get("usage", {}).get("completion_tokens", 0)


def _mock(prompt, system):
    return f"[mock LLM] {system[:60]}... (set LLM_PROVIDER=anthropic|openai for real output)", 0, 0


PROVIDERS = {"mock": _mock, "anthropic": _anthropic, "openai": _openai}


def complete(prompt, system="", stage=""):
    provider, t0 = os.getenv("LLM_PROVIDER", "mock"), time.time()
    try:
        text, tin, tout = PROVIDERS[provider](prompt, system)
    except Exception as e:
        obs.inc("llm_errors_total", provider=provider)
        obs.log("llm.error", provider=provider, stage=stage, error=str(e))
        raise
    ms = int((time.time() - t0) * 1000)
    obs.inc("llm_calls_total", provider=provider)
    obs.inc("llm_input_tokens_total", tin, provider=provider)
    obs.inc("llm_output_tokens_total", tout, provider=provider)
    obs.inc("llm_latency_ms_total", ms, provider=provider)
    obs.log("llm.call", provider=provider, stage=stage, ms=ms, input_tokens=tin, output_tokens=tout)
    return text
