"""Fast first-stage classifier: TF-IDF over the evidence bundle plus the rule hits, logistic regression.

Trained only on ground-truth dataset labels (never on Muse Spark outputs, which the Meta API terms
forbid as training data). It scores a bundle in milliseconds and decides which packages the
language models need to look at; it does not replace their cited verdicts.
"""

from __future__ import annotations

import re

_LINE_NO = re.compile(r"^\s*\d+\| ", re.MULTILINE)
TOKEN_PATTERN = r"[A-Za-z_$][A-Za-z0-9_$]{1,40}|[0-9]{1,6}|[^\sA-Za-z0-9]{1,3}"


def clean_text(bundle_text: str, name: str, version: str, rules: list[str]) -> str:
    """Bundle text with the package identity masked, so the model learns code, not names."""
    text = _LINE_NO.sub("", bundle_text)
    for value, mask in ((name, " PKGNAME "), (name.split("/")[-1], " PKGNAME "), (version, " PKGVERSION ")):
        if value:
            text = text.replace(value, mask)
    return text + "\n" + " ".join(f"RULE_{r}" for r in rules)


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    vec = TfidfVectorizer(
        token_pattern=TOKEN_PATTERN, lowercase=False, ngram_range=(1, 2), min_df=3,
        max_features=300_000, sublinear_tf=True, dtype="float32",
    )
    return make_pipeline(vec, LogisticRegression(C=4.0, class_weight="balanced", max_iter=2000))


def risk(model, records: list[dict]) -> list[float]:
    texts = [clean_text(r["bundle"], r["name"], r["version"], r.get("rules", [])) for r in records]
    return [float(p) for p in model.predict_proba(texts)[:, 1]]
