"""Popular npm package names (wooorm/npm-high-impact, MIT), cached locally."""

from __future__ import annotations

import re
from pathlib import Path

import httpx

SOURCE_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"
DEFAULT_CACHE = Path("data/popular.txt")
_NAME = re.compile(r"'((?:@[a-z0-9][\w.~-]*/)?[a-z0-9][\w.~-]*)'")


def parse_top_js(source: str) -> list[str]:
    return _NAME.findall(source)


def load_popular(cache: Path = DEFAULT_CACHE, client: httpx.Client | None = None) -> set[str]:
    if cache.exists():
        return {line.strip() for line in cache.read_text(encoding="utf-8").splitlines() if line.strip()}
    own = client is None
    client = client or httpx.Client(timeout=60, follow_redirects=True)
    try:
        resp = client.get(SOURCE_URL)
        resp.raise_for_status()
        names = parse_top_js(resp.text)
    finally:
        if own:
            client.close()
    if len(names) < 1000:
        raise RuntimeError(f"popular list looks wrong: only {len(names)} names parsed")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("\n".join(names) + "\n", encoding="utf-8")
    return set(names)
