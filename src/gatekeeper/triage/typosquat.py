"""Cheap typosquatting check against a list of popular package names."""

from __future__ import annotations

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
MIN_TARGET_LEN = 5


def damerau_levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    """Optimal string alignment distance, with an early exit once it exceeds `max_dist`."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > max_dist:
            return max_dist + 1
        prev2, prev = prev, cur
    return prev[-1]


def _base(name: str) -> str:
    return name.split("/")[-1].lower()


def _canonical(name: str) -> str:
    return _base(name).replace("-", "").replace("_", "").replace(".", "").translate(HOMOGLYPHS)


def _similar(a: str, b: str) -> bool:
    if a == b or len(b) < MIN_TARGET_LEN:
        return False
    if _canonical(a) == _canonical(b):
        return True  # separator or homoglyph swap
    limit = 1 if len(b) < 9 else 2
    return damerau_levenshtein(a, b, limit) <= limit


def typosquat_target(name: str, popular: set[str]) -> str | None:
    """Return the popular package that `name` likely imitates, or None.

    Unscoped names are compared with unscoped popular names. Scoped names are only flagged when
    their scope imitates a popular scope (e.g. `@typescript_eslint/parser`); comparing base names
    across unrelated scopes produced mostly false positives.
    """
    if name in popular:
        return None
    if name.startswith("@") and "/" in name:
        scope = name[1:].split("/", 1)[0].lower()
        popular_scopes = {t[1:].split("/", 1)[0].lower() for t in popular if t.startswith("@") and "/" in t}
        if scope in popular_scopes:
            return None
        for target_scope in popular_scopes:
            if _similar(scope, target_scope):
                return f"@{target_scope}/*"
        return None
    base = name.lower()
    for target in popular:
        if target.startswith("@"):
            continue
        if _similar(base, target.lower()):
            return target
    return None
