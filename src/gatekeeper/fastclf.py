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
    """Bundle text with the package identity masked, so the model learns code, not names.

    Name and version are attacker-chosen, so they are masked only in identity contexts (the
    manifest's name/version fields and `name@version`), never inside code: a package named
    "curl" must not be able to erase `curl` from its own install script."""
    text = _LINE_NO.sub("", bundle_text)
    n, v = re.escape(name), re.escape(version)
    text = re.sub(rf'("name"\s*:\s*"){n}"', r'\1PKGNAME"', text)
    text = re.sub(rf'("version"\s*:\s*"){v}"', r'\1PKGVERSION"', text)
    text = re.sub(rf"(?<![\w@/.-]){n}@{v}(?![\w.-])", "PKGNAME@PKGVERSION", text)
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


def export_model(pipeline, threshold: float) -> dict:
    """The fitted TF-IDF + logistic regression as plain numbers (no pickle), for local scoring."""
    vec, lr = pipeline.steps[0][1], pipeline.steps[1][1]
    terms = [""] * len(vec.vocabulary_)
    for term, idx in vec.vocabulary_.items():
        terms[idx] = term
    return {
        "format": "gatekeeper-fastclf-1", "token_pattern": TOKEN_PATTERN, "ngram_max": vec.ngram_range[1],
        "terms": terms, "idf": [float(x) for x in vec.idf_], "coef": [float(x) for x in lr.coef_[0]],
        "intercept": float(lr.intercept_[0]), "threshold": float(threshold),
    }


class PortableModel:
    """Scores like the exported scikit-learn pipeline (sublinear TF, IDF, L2 norm, logistic) in pure Python."""

    def __init__(self, data: dict):
        if data.get("format") != "gatekeeper-fastclf-1":
            raise ValueError("unknown model format")
        self.pattern = re.compile(data["token_pattern"])
        self.ngram_max = int(data["ngram_max"])
        self.index = {t: i for i, t in enumerate(data["terms"])}
        self.idf, self.coef = data["idf"], data["coef"]
        self.intercept, self.threshold = data["intercept"], data["threshold"]

    def risk_text(self, text: str) -> float:
        import math

        tokens = self.pattern.findall(text)
        counts: dict[int, int] = {}
        for n in range(1, self.ngram_max + 1):
            for i in range(len(tokens) - n + 1):
                idx = self.index.get(" ".join(tokens[i : i + n]))
                if idx is not None:
                    counts[idx] = counts.get(idx, 0) + 1
        weights = {i: (1 + math.log(c)) * self.idf[i] for i, c in counts.items()}
        norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
        z = self.intercept + sum(w / norm * self.coef[i] for i, w in weights.items())
        return 1 / (1 + math.exp(-max(-60.0, min(60.0, z))))

    def risk(self, bundle_text: str, name: str, version: str, rules: list[str]) -> float:
        return self.risk_text(clean_text(bundle_text, name, version, rules))
