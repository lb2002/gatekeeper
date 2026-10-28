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
FIREWORKS_URL = "https://api.fireworks.ai/inference/v1"
SPARK_OPEN_FIREWORKS_MODEL = "accounts/fireworks/models/muse-spark-open"  # Glimmer is no longer serverless there
BASETEN_URL = "https://inference.baseten.co/v1"
SPARK_OPEN_BASETEN_MODEL = "meta-models/muse-spark-open-1026"  # the hackathon key only works with this id

# USD per 1M tokens (dev.meta.ai/docs/pricing-rate-limits, Oct 2026)
SPARK_PRICE = {"input": 1.25, "cached_input": 0.15, "output": 4.25}
# USD per 1M tokens, Fireworks serverless (fireworks.ai/models/fireworks/muse-spark-open, Oct 2026)
SPARK_OPEN_FIREWORKS_PRICE = {"input": 1.25, "cached_input": 0.15, "output": 4.25}
# Baseten Model APIs list the same rates for Muse Spark Open (third-party price trackers, Oct 2026)
SPARK_OPEN_BASETEN_PRICE = {"input": 1.25, "cached_input": 0.15, "output": 4.25}
PRICES = {"spark": SPARK_PRICE, "spark-open-fireworks": SPARK_OPEN_FIREWORKS_PRICE,
          "spark-open-baseten": SPARK_OPEN_BASETEN_PRICE}


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
        price = PRICES.get(self.backend)
        if price is None:
            return 0.0
        uncached = max(self.input_tokens - self.cached_tokens, 0)
        return (
            uncached * price["input"] + self.cached_tokens * price["cached_input"] + self.output_tokens * price["output"]
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
    choice = data["choices"][0]
    content = choice["message"].get("content") or ""
    if not content:
        content = f"<empty content, finish_reason={choice.get('finish_reason')}, message keys={sorted(choice['message'])}>"
    return content, data.get("usage") or {}, time.monotonic() - start


def classify_spark(
    bundle: Bundle, api_key: str | None = None, timeout: float = 120, reasoning_effort: str = "low"
) -> ModelResult:
    key = api_key or os.environ["MODEL_API_KEY"]
    payload = {
        "model": SPARK_MODEL,
        "messages": messages(bundle),
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "verdict", "schema": verdict_json_schema(), "strict": True},
        },
        "prompt_cache_key": PROMPT_VERSION,
        # Spark always reasons ("none" is a 400) and max_tokens caps reasoning plus the answer.
        "reasoning_effort": reasoning_effort,
        "max_tokens": 4000,
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


def classify_local(
    bundle: Bundle, url: str = LOCAL_URL, model: str = "muse-glimmer", timeout: float = 600, compact: bool = True
) -> ModelResult:
    payload = {
        "model": model,
        "messages": messages(bundle, compact=compact),
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


def classify_spark_open_fireworks(
    bundle: Bundle, api_key: str | None = None, timeout: float = 120, model: str = SPARK_OPEN_FIREWORKS_MODEL
) -> ModelResult:
    """Muse Spark Open (Meta open weights) on Fireworks serverless."""
    key = api_key or os.environ["FIREWORKS_API_KEY"]
    return _classify_spark_open(bundle, FIREWORKS_URL, key, model, "spark-open-fireworks", timeout)


def classify_spark_open_baseten(
    bundle: Bundle, api_key: str | None = None, timeout: float = 120, model: str = SPARK_OPEN_BASETEN_MODEL
) -> ModelResult:
    """The same Muse Spark Open weights on Baseten Model APIs (hackathon credits)."""
    key = api_key or os.environ["BASETEN_API_KEY"]
    return _classify_spark_open(bundle, BASETEN_URL, key, model, "spark-open-baseten", timeout)


def _classify_spark_open(bundle: Bundle, url: str, key: str, model: str, backend: str, timeout: float) -> ModelResult:
    payload = {
        "model": model,
        "messages": messages(bundle),
        "response_format": {"type": "json_schema", "json_schema": {"name": "verdict", "schema": verdict_json_schema(), "strict": True}},
        "reasoning_effort": "low",
        "max_tokens": 4000,  # covers reasoning plus the verdict
    }
    raw, usage, latency = _chat(url, {"Authorization": f"Bearer {key}"}, payload, timeout)
    verdict, errors = _parse(raw)
    if verdict:
        errors += citation_errors(verdict, bundle)
    details = usage.get("prompt_tokens_details") or {}
    return ModelResult(
        backend=backend,
        model=model,
        verdict=verdict,
        raw=raw,
        errors=errors,
        latency_s=latency,
        input_tokens=int(usage.get("prompt_tokens", 0)),
        cached_tokens=int(details.get("cached_tokens", 0) or 0),
        output_tokens=int(usage.get("completion_tokens", 0)),
    )
