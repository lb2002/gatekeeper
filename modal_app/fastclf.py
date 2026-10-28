"""Train and evaluate the fast first-stage classifier on the time-split datasets (CPU only).

    uv run modal run modal_app/fastclf.py::train
"""

import json
import pickle
import time
from pathlib import Path

import modal

app = modal.App("gatekeeper-fastclf")
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("scikit-learn==1.5.2", "httpx>=0.27", "pydantic>=2.7")
    .add_local_python_source("gatekeeper")
)
data_volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
DATA = Path("/data")


def _rows(split: str) -> list[dict]:
    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        path = DATA / "datasets" / name
        rows += [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r for r in rows if r["split"] == split]


@app.function(image=image, volumes={str(DATA): data_volume}, timeout=3600, cpu=4.0, memory=16384)
def train() -> dict:
    from gatekeeper.fastclf import build_pipeline, clean_text, export_model, risk

    data_volume.reload()
    from sklearn.model_selection import cross_val_predict

    tr, te = _rows("train"), _rows("test")
    x = [clean_text(r["bundle"], r["name"], r["version"], r.get("rules", [])) for r in tr]
    y = [1 if r["label"] == "malicious" else 0 for r in tr]
    # threshold at 1% false positives on out-of-fold training predictions (the test set stays untouched)
    oof = cross_val_predict(build_pipeline(), x, y, cv=5, method="predict_proba")[:, 1]
    benign_oof = sorted(s for s, label in zip(oof, y) if label == 0)
    threshold = float(benign_oof[int(0.99 * len(benign_oof))])
    model = build_pipeline()
    t = time.time()
    model.fit(x, y)
    fit_s = time.time() - t
    t = time.time()
    scores = risk(model, te)
    per_item_ms = (time.time() - t) / max(len(te), 1) * 1000

    out_path = DATA / "eval" / "fastclf-test.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for r, s in zip(te, scores):
            fh.write(json.dumps({"name": r["name"], "version": r["version"], "label": r["label"],
                                 "kind": r["kind"], "risk": s}) + "\n")
    (DATA / "models").mkdir(exist_ok=True)
    (DATA / "models" / "fastclf.pkl").write_bytes(pickle.dumps({"model": model, "threshold": threshold}))
    (DATA / "models" / "fastclf.json").write_text(json.dumps(export_model(model, threshold)))
    labels = [1 if r["label"] == "malicious" else 0 for r in te]
    tp = sum(s >= threshold and l for s, l in zip(scores, labels))
    fp = sum(s >= threshold and not l for s, l in zip(scores, labels))

    # most indicative features, as a sanity check against shortcut learning
    vec, lr = model.steps[0][1], model.steps[1][1]
    names = vec.get_feature_names_out()
    order = lr.coef_[0].argsort()
    stats = {
        "n_train": len(tr), "n_test": len(te), "fit_s": round(fit_s), "ms_per_item": round(per_item_ms, 2),
        "threshold": round(threshold, 4), "test_recall_at_threshold": round(tp / max(sum(labels), 1), 3),
        "test_fpr_at_threshold": round(fp / max(len(labels) - sum(labels), 1), 3),
        "top_malicious": [names[i] for i in order[-12:][::-1]],
        "top_benign": [names[i] for i in order[:12]],
    }
    data_volume.commit()
    print(json.dumps(stats, indent=1))
    return stats


@app.function(image=image, volumes={str(DATA): data_volume}, timeout=1800, cpu=2.0, memory=8192)
def export() -> dict:
    """Export the trained pipeline to JSON and check the pure-Python scorer agrees with scikit-learn."""
    from gatekeeper.fastclf import PortableModel, export_model, risk

    data_volume.reload()
    saved = pickle.loads((DATA / "models" / "fastclf.pkl").read_bytes())
    data = export_model(saved["model"], saved["threshold"])
    (DATA / "models" / "fastclf.json").write_text(json.dumps(data))
    portable = PortableModel(data)
    rows = _rows("test")[:300]
    ref = risk(saved["model"], rows)
    mine = [portable.risk(r["bundle"], r["name"], r["version"], r.get("rules", [])) for r in rows]
    worst = max(abs(a - b) for a, b in zip(ref, mine))
    data_volume.commit()
    out = {"terms": len(data["terms"]), "max_abs_diff": worst, "threshold": data["threshold"],
           "size_mb": round(len(json.dumps(data)) / 1e6, 1)}
    print(json.dumps(out))
    return out
