"""Detection metrics with bootstrap confidence intervals.

Every system is reduced to a risk score per package (higher = more likely malicious):
- rules: the static content score,
- models: a verdict mapped to [0, 1] (see `verdict_risk`).
"""

from __future__ import annotations

import random
from dataclasses import dataclass


def verdict_risk(verdict: str | None, confidence: float | None) -> float:
    """Map a model verdict to a monotone risk score. Unusable outputs count as benign (fail open)."""
    c = 0.5 if confidence is None else max(0.0, min(1.0, float(confidence)))
    if verdict == "malicious":
        return 0.5 + 0.5 * c
    if verdict == "suspicious":
        return 0.5
    if verdict == "benign":
        return 0.5 - 0.5 * c
    return 0.0


@dataclass
class Point:
    threshold: float
    recall: float
    fpr: float
    precision: float


def _counts(scores: list[float], labels: list[int], thr: float) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for s, y in zip(scores, labels):
        flagged = s >= thr
        if y and flagged:
            tp += 1
        elif y:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def curve(scores: list[float], labels: list[int]) -> list[Point]:
    out = []
    for thr in sorted(set(scores), reverse=True):
        tp, fp, tn, fn = _counts(scores, labels, thr)
        out.append(Point(thr, tp / max(tp + fn, 1), fp / max(fp + tn, 1), tp / max(tp + fp, 1)))
    return out


def recall_at_fpr(scores: list[float], labels: list[int], max_fpr: float = 0.01) -> Point | None:
    """Best recall among thresholds whose false-positive rate is at most `max_fpr`."""
    ok = [p for p in curve(scores, labels) if p.fpr <= max_fpr]
    return max(ok, key=lambda p: (p.recall, p.threshold)) if ok else None


def pr_auc(scores: list[float], labels: list[int]) -> float:
    """Average precision (area under the precision-recall curve, step-wise)."""
    positives = sum(labels)
    if positives == 0:
        return 0.0
    ranked = sorted(zip(scores, labels), key=lambda t: -t[0])
    tp = 0
    ap = 0.0
    for i, (_, y) in enumerate(ranked, start=1):
        if y:
            tp += 1
            ap += tp / i
    return ap / positives


def at_threshold(scores: list[float], labels: list[int], thr: float) -> Point:
    tp, fp, tn, fn = _counts(scores, labels, thr)
    return Point(thr, tp / max(tp + fn, 1), fp / max(fp + tn, 1), tp / max(tp + fp, 1))


def bootstrap(
    scores: list[float], labels: list[int], stat, n: int = 1000, seed: int = 7
) -> tuple[float, float, float]:
    """(point estimate, 2.5th percentile, 97.5th percentile) of `stat(scores, labels)`."""
    rng = random.Random(seed)
    idx = list(range(len(scores)))
    est = stat(scores, labels)
    samples = []
    for _ in range(n):
        pick = [rng.choice(idx) for _ in idx]
        samples.append(stat([scores[i] for i in pick], [labels[i] for i in pick]))
    samples.sort()
    return est, samples[int(0.025 * n)], samples[int(0.975 * n) - 1]
