"""Shared train / live-test splits for the trained classifiers.

- train: dataset train split + real npm versions published before LIVE_TEST_FROM (labelled with a
  week of OSV hindsight); package names in the malicious time-split test set are dropped.
- test: the time-split test set (unchanged).
- live_test: real npm versions from LIVE_TEST_FROM on (history) plus the monitor's own live sample,
  i.e. later days the model never saw. Used to measure false positives on everyday packages.
"""

from __future__ import annotations

import json
from pathlib import Path

LIVE_TEST_FROM = "2026-10-22"


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_splits(data: Path) -> dict[str, list[dict]]:
    base = _read(data / "datasets" / "malicious.jsonl") + _read(data / "datasets" / "benign.jsonl")
    test = [r for r in base if r["split"] == "test"]
    blocked = {r["name"] for r in test}
    # npm's takedown placeholders ("0.0.1-security", "security holding package") replace removed malware;
    # they contain no code and would teach the model a label shortcut
    history = [r for r in _read(data / "datasets" / "live_history.jsonl")
               if r["name"] not in blocked and "-security" not in r["version"] and "security holding" not in r["bundle"]]
    live = []
    for path in sorted((data / "live_samples").glob("*.jsonl")) if (data / "live_samples").exists() else []:
        live += [{**r, "label": "benign", "kind": "live_sample", "cluster": r["name"]} for r in _read(path)]
    train = [r for r in base if r["split"] == "train"] + [r for r in history if (r.get("published_at") or "") < LIVE_TEST_FROM]
    live_test = [r for r in history if (r.get("published_at") or "") >= LIVE_TEST_FROM]
    seen = {(r["name"], r["version"]) for r in live_test}
    live_test += [r for r in live if (r["name"], r["version"]) not in seen and r["name"] not in blocked]
    train_names = {r["name"] for r in train}
    live_test = [r for r in live_test if r["name"] not in train_names]  # no package seen in training
    return {"train": train, "test": test, "live_test": live_test}


def rates(scores: list[float], rows: list[dict], threshold: float) -> dict:
    mal = [s for s, r in zip(scores, rows) if r["label"] == "malicious"]
    ben = [s for s, r in zip(scores, rows) if r["label"] != "malicious"]
    return {
        "n_malicious": len(mal), "n_benign": len(ben),
        "recall": round(sum(s >= threshold for s in mal) / len(mal), 3) if mal else None,
        "fpr": round(sum(s >= threshold for s in ben) / len(ben), 4) if ben else None,
        "false_positives": sum(s >= threshold for s in ben),
    }
