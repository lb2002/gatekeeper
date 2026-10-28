"""Batch evaluation of Muse Glimmer (the same Q4_K_M GGUF the laptop guard uses) on Modal GPUs.

    uv run modal run modal_app/evaluate.py::download_model          # once, into a Volume
    uv run modal run modal_app/evaluate.py::eval_glimmer --split test
    uv run modal run modal_app/evaluate.py::report

Inputs are the text bundles built by modal_app/dataset.py; no package archives are involved.
"""

import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import modal

app = modal.App("gatekeeper-eval")

LLAMA_TAG = "b11921"
GGUF_REPO = "meta-models/Muse-Glimmer-30B-GGUF"
GGUF_FILE = "Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf"

gpu_image = (
    modal.Image.from_registry("nvidia/cuda:12.4.1-devel-ubuntu22.04", add_python="3.12")
    .apt_install("git", "cmake", "build-essential", "libcurl4-openssl-dev")
    .run_commands(
        f"git clone --depth 1 --branch {LLAMA_TAG} https://github.com/ggml-org/llama.cpp /opt/llama.cpp",
        "cd /opt/llama.cpp && cmake -B build -DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=80 -DBUILD_SHARED_LIBS=OFF "
        "-DLLAMA_CURL=OFF && cmake --build build --config Release -j 8 --target llama-server",
    )
    .pip_install("httpx>=0.27", "pydantic>=2.7", "typer>=0.12", "rich>=13.7", "huggingface_hub>=0.25")
    .add_local_python_source("gatekeeper")
)
cpu_image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "httpx>=0.27", "pydantic>=2.7", "typer>=0.12", "rich>=13.7", "huggingface_hub>=0.25"
).add_local_python_source("gatekeeper")

data_volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
model_volume = modal.Volume.from_name("gatekeeper-models", create_if_missing=True)
DATA = Path("/data")
MODELS = Path("/models")


@app.function(image=cpu_image, volumes={str(MODELS): model_volume}, timeout=3600, cpu=2.0, memory=4096)
def download_model() -> str:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(GGUF_REPO, GGUF_FILE, local_dir=str(MODELS / "glimmer"))
    model_volume.commit()
    return path


def _load(split: str, limit: int | None) -> list[dict]:
    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        path = DATA / "datasets" / name
        rows += [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = [r for r in rows if r["split"] == split]
    rows.sort(key=lambda r: (r["label"], r["name"]))
    if limit:
        # keep both classes when limiting
        mal = [r for r in rows if r["label"] == "malicious"][: limit // 2]
        ben = [r for r in rows if r["label"] == "benign"][: limit - len(mal)]
        rows = mal + ben
    return rows


@app.function(
    image=gpu_image,
    gpu="A100-80GB",
    volumes={str(DATA): data_volume, str(MODELS): model_volume},
    timeout=3 * 3600,
    cpu=8.0,
    memory=32768,
)
def eval_glimmer(split: str = "test", limit: int = 0, parallel: int = 8, tag: str = "zeroshot", lora: str = "") -> dict:
    import httpx

    from gatekeeper.evidence.bundle import RenderedBundle
    from gatekeeper.models.backends import classify_local

    model = MODELS / "glimmer" / GGUF_FILE
    cmd = [
        "/opt/llama.cpp/build/bin/llama-server", "-m", str(model), "--jinja", "-ngl", "99", "-fa", "on",
        "-np", str(parallel), "-c", str(8192 * parallel), "--host", "127.0.0.1", "--port", "8080",
        "--reasoning-format", "deepseek", "--reasoning-effort", "minimal", "--reasoning-budget", "48",
        "--alias", "muse-glimmer",
    ]
    if lora:
        cmd += ["--lora", str(MODELS / lora)]
    server = subprocess.Popen(cmd)
    for _ in range(300):
        try:
            if httpx.get("http://127.0.0.1:8080/health", timeout=2).json().get("status") == "ok":
                break
        except Exception:
            pass
        time.sleep(2)
    rows = _load(split, limit or None)
    started = time.time()

    def one(r: dict) -> dict:
        res = classify_local(RenderedBundle.from_record(r), url="http://127.0.0.1:8080/v1", timeout=900)
        v = res.verdict
        return {
            "name": r["name"], "version": r["version"], "label": r["label"], "kind": r["kind"],
            "hard_negative": r.get("hard_negative", False), "content_score": r["content_score"],
            "verdict": v.verdict.value if v else None, "confidence": v.confidence if v else None,
            "category": v.category.value if v else None, "injection": v.injection_attempt_observed if v else None,
            "errors": res.errors, "latency_s": res.latency_s, "output_tokens": res.output_tokens,
        }

    out_path = DATA / "eval" / f"glimmer-{tag}-{split}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=parallel) as ex, out_path.open("w", encoding="utf-8") as fh:
        for i, rec in enumerate(ex.map(one, rows), start=1):
            results.append(rec)
            fh.write(json.dumps(rec) + "\n")
            if i % 50 == 0:
                print(f"{i}/{len(rows)} done, {time.time() - started:.0f}s")
    server.terminate()
    data_volume.commit()
    stats = {"n": len(results), "seconds": round(time.time() - started), "unusable": sum(r["verdict"] is None for r in results)}
    print(json.dumps(stats))
    return stats


@app.function(image=cpu_image, volumes={str(DATA): data_volume}, timeout=600)
def report(split: str = "test") -> dict:
    """Metrics for every prediction file of this split plus the rules baseline."""
    from gatekeeper.eval.metrics import at_threshold, bootstrap, curve, pr_auc, recall_at_fpr, verdict_risk

    data_volume.reload()
    rows = _load(split, None)
    labels = [1 if r["label"] == "malicious" else 0 for r in rows]
    systems = {"rules (content score)": [float(r["content_score"]) for r in rows]}
    scored = {"rules (content score)"}  # systems with a continuous risk score instead of a verdict
    key = {(r["name"], r["version"], r["label"]): i for i, r in enumerate(rows)}
    for path in sorted((DATA / "eval").glob(f"*-{split}.jsonl")):
        scores = [0.0] * len(rows)
        seen = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            p = json.loads(line)
            i = key.get((p["name"], p["version"], p["label"]))
            if i is not None:
                scores[i] = p["risk"] if "risk" in p else verdict_risk(p["verdict"], p["confidence"])
                if "risk" in p:
                    scored.add(path.stem)
                seen += 1
        if seen:
            systems[path.stem] = scores
    hard = [i for i, r in enumerate(rows) if r.get("hard_negative")]
    out = {"n_malicious": sum(labels), "n_benign": len(labels) - sum(labels), "systems": {}}
    for name, scores in systems.items():
        p1 = recall_at_fpr(scores, labels, 0.01)
        ap = bootstrap(scores, labels, pr_auc, n=500)
        res = {"pr_auc": [round(x, 3) for x in ap], "recall_at_1pct_fpr": round(p1.recall, 3) if p1 else None}
        # as a filter: share of benign packages still passed on when keeping 95% / 99% of malware
        for target in (0.95, 0.99):
            ok = [pt for pt in curve(scores, labels) if pt.recall >= target]
            res[f"benign_passed_at_{int(target * 100)}pct_recall"] = round(min(pt.fpr for pt in ok), 3) if ok else None
        if name not in scored:
            flag = at_threshold(scores, labels, 0.5)  # "malicious or suspicious" blocks
            res["block_recall"] = round(flag.recall, 3)
            res["block_fpr"] = round(flag.fpr, 3)
            res["hard_negative_fpr"] = round(sum(scores[i] >= 0.5 for i in hard) / max(len(hard), 1), 3)
        out["systems"][name] = res
    print(json.dumps(out, indent=1))
    return out
