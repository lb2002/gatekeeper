"""Model backends. Both speak the OpenAI-compatible Chat Completions protocol:

- Muse Spark via the Meta Model API (https://api.meta.ai/v1, Standard mode only).
- Muse Glimmer locally via llama.cpp's llama-server (default http://127.0.0.1:8080/v1).
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass

import httpx

from gatekeeper.evidence.bundle import Bundle
from gatekeeper.models.prompt import PROMPT_VERSION, messages
from gatekeeper.models.validate import citation_errors
from gatekeeper.schema import Verdict, verdict_json_schema

META_API_URL = "https://api.meta.ai/v1"
SPARK_MODEL = "muse-spark-1.3"  # Standard mode; never the "-contributor" variants
LOCAL_URL = os.environ.get("GK_LOCAL_URL", "http://127.0.0.1:8080/v1")

# USD per 1M tokens (dev.meta.ai/docs/pricing-rate-limits, Oct 2026)
SPARK_PRICE = {"input": 1.25, "cached_input": 0.15, "output": 4.25}


@dataclass
class ModelResult:
    backend: str
    model: str
    verdict: Verdict | None
    raw: str
    errors: list[str]
    latency_s: float
    input_tokens: int = 0
    cached_tokens: int = 0
    output_tokens: int = 0

    @property
    def cost_usd(self) -> float:
        if self.backend != "spark":
            return 0.0
        uncached = max(self.input_tokens - self.cached_tokens, 0)
        return (
            uncached * SPARK_PRICE["input"]
            + self.cached_tokens * SPARK_PRICE["cached_input"]
            + self.output_tokens * SPARK_PRICE["output"]
        ) / 1e6


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def _parse(raw: str) -> tuple[Verdict | None, list[str]]:
    text = raw.strip()
    m = _JSON_OBJECT.search(text)
    if not m:
        return None, ["no JSON object in output"]
    try:
        return Verdict.model_validate(json.loads(m.group(0))), []
    except (ValueError, TypeError) as exc:
        return None, [f"invalid verdict JSON: {exc}"[:300]]


def _chat(
    url: str,
    headers: dict,
    payload: dict,
    timeout: float,
) -> tuple[str, dict, float]:
    start = time.monotonic()
    resp = httpx.post(f"{url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"].get("content") or ""
    return content, data.get("usage") or {}, time.monotonic() - start


def classify_spark(bundle: Bundle, api_key: str | None = None, timeout: float = 120) -> ModelResult:
    key = api_key or os.environ["MODEL_API_KEY"]
    payload = {
        "model": SPARK_MODEL,
        "messages": messages(bundle),
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "verdict", "schema": verdict_json_schema(), "strict": True},
        },
        "prompt_cache_key": PROMPT_VERSION,
        "max_tokens": 1200,
    }
    raw, usage, latency = _chat(META_API_URL, {"Authorization": f"Bearer {key}"}, payload, timeout)
    verdict, errors = _parse(raw)
    if verdict:
        errors += citation_errors(verdict, bundle)
    details = usage.get("prompt_tokens_details") or {}
    return ModelResult(
        backend="spark",
        model=SPARK_MODEL,
        verdict=verdict,
        raw=raw,
        errors=errors,
        latency_s=latency,
        input_tokens=int(usage.get("prompt_tokens", 0)),
        cached_tokens=int(details.get("cached_tokens", 0) or 0),
        output_tokens=int(usage.get("completion_tokens", 0)),
    )


def classify_local(bundle: Bundle, url: str = LOCAL_URL, model: str = "muse-glimmer", timeout: float = 600) -> ModelResult:
    payload = {
        "model": model,
        "messages": messages(bundle),
        # llama-server turns a JSON schema into a grammar, so output is always parseable.
        "response_format": {"type": "json_schema", "json_schema": {"name": "verdict", "schema": verdict_json_schema()}},
        "temperature": 0.2,
        "max_tokens": 800,
    }
    raw, usage, latency = _chat(url, {}, payload, timeout)
    verdict, errors = _parse(raw)
    if verdict:
        errors += citation_errors(verdict, bundle)
    return ModelResult(
        backend="glimmer-local",
        model=model,
        verdict=verdict,
        raw=raw,
        errors=errors,
        latency_s=latency,
        input_tokens=int(usage.get("prompt_tokens", 0)),
        output_tokens=int(usage.get("completion_tokens", 0)),
    )
