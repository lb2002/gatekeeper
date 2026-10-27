"""Laptop worker: lease flagged bundles from the monitor API, classify them with the local
Muse Glimmer (llama-server), and post the verdicts back. Only text excerpts are transferred."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable

import httpx

from gatekeeper.evidence.bundle import RenderedBundle
from gatekeeper.models.backends import ModelResult, classify_local


def load_env(path: Path = Path(".env")) -> None:
    """Minimal .env loader (KEY=VALUE lines); existing environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"'))


class MonitorApi:
    def __init__(self, base_url: str, token: str, timeout: float = 60):
        self.client = httpx.Client(base_url=base_url.rstrip("/"), headers={"Authorization": f"Bearer {token}"}, timeout=timeout)

    def status(self) -> dict:
        r = self.client.get("/status")
        r.raise_for_status()
        return r.json()

    def lease(self, backend: str) -> dict | None:
        r = self.client.get("/work", params={"backend": backend})
        r.raise_for_status()
        data = r.json()
        return data if data.get("key") else None

    def submit(self, key: str, result: ModelResult) -> None:
        r = self.client.post(
            "/verdict",
            json={
                "key": key,
                "backend": result.backend,
                "model": result.model,
                "verdict": result.verdict.model_dump(mode="json") if result.verdict else None,
                "errors": result.errors,
                "latency_s": result.latency_s,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "cost_usd": result.cost_usd,
            },
        )
        r.raise_for_status()


def run(
    api: MonitorApi,
    classify: Callable[[RenderedBundle], ModelResult] = classify_local,
    backend: str = "glimmer-local",
    max_items: int | None = None,
    idle_sleep: float = 60,
    on_result: Callable[[dict, ModelResult], None] | None = None,
) -> int:
    done = 0
    while max_items is None or done < max_items:
        item = api.lease(backend)
        if item is None:
            if max_items is not None:
                break
            time.sleep(idle_sleep)
            continue
        bundle = RenderedBundle.from_record(item)
        try:
            result = classify(bundle)
        except httpx.HTTPError as exc:
            result = ModelResult(backend, "unavailable", None, "", [f"model error: {exc}"[:300]], 0.0)
        api.submit(item["key"], result)
        if on_result:
            on_result(item, result)
        done += 1
    return done
