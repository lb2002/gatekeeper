"""Fine-tune Meta's Llama Guard 3 1B into a malicious-package classifier (LoRA + classification head).

Trained only on ground-truth dataset labels (never on Muse Spark outputs). The time-split test set
is only scored once, after the threshold has been fixed on a validation split of the training data.

    uv run modal run modal_app/guardtune.py::train
"""

import json
import time
from pathlib import Path

import modal

app = modal.App("gatekeeper-guardtune")
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("torch==2.5.1", "transformers==4.46.3", "peft==0.13.2", "accelerate==1.1.1",
                 "httpx>=0.27", "pydantic>=2.7")
    .add_local_python_source("gatekeeper")
)
data_volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
DATA = Path("/data")
BASE = "meta-llama/Llama-Guard-3-1B"
MAX_TOKENS = 2048
VAL_FRACTION = 0.1


def _rows(split: str) -> list[dict]:
    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        path = DATA / "datasets" / name
        rows += [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r for r in rows if r["split"] == split]


@app.function(image=image, gpu="A10G", volumes={str(DATA): data_volume},
              secrets=[modal.Secret.from_name("huggingface")], timeout=3 * 3600, cpu=4.0, memory=32768)
def train(epochs: int = 2, lr: float = 2e-4, batch: int = 4, accum: int = 4) -> dict:
    import random

    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    from gatekeeper.fastclf import clean_text

    data_volume.reload()
    train_rows, test_rows = _rows("train"), _rows("test")
    # validation split by cluster/name so near-duplicates do not leak into the threshold choice
    rng = random.Random(7)
    groups = sorted({r.get("cluster") or r["name"] for r in train_rows})
    rng.shuffle(groups)
    val_groups = set(groups[: int(len(groups) * VAL_FRACTION)])
    val_rows = [r for r in train_rows if (r.get("cluster") or r["name"]) in val_groups]
    fit_rows = [r for r in train_rows if (r.get("cluster") or r["name"]) not in val_groups]

    tok = AutoTokenizer.from_pretrained(BASE)
    tok.pad_token = tok.pad_token or tok.eos_token
    model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2, torch_dtype=torch.bfloat16)
    model.config.pad_token_id = tok.pad_token_id
    model = get_peft_model(model, LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, task_type="SEQ_CLS",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    ))
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    model.cuda()

    def encode(rows):
        texts = [clean_text(r["bundle"], r["name"], r["version"], r.get("rules", [])) for r in rows]
        return tok(texts, truncation=True, max_length=MAX_TOKENS, padding=True, return_tensors="pt")

    def label(rows):
        return torch.tensor([1 if r["label"] == "malicious" else 0 for r in rows])

    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr, weight_decay=0.0)
    steps_total = epochs * (len(fit_rows) // (batch * accum) + 1)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=lr, total_steps=steps_total, pct_start=0.05)
    started = time.time()
    model.train()
    step = 0
    for epoch in range(epochs):
        order = fit_rows[:]
        rng.shuffle(order)
        for i in range(0, len(order), batch):
            chunk = order[i : i + batch]
            enc = {k: v.cuda() for k, v in encode(chunk).items()}
            with torch.autocast("cuda", dtype=torch.bfloat16):
                out = model(**enc, labels=label(chunk).cuda())
            (out.loss / accum).backward()
            if (i // batch + 1) % accum == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                sched.step()
                opt.zero_grad()
                step += 1
                if step % 25 == 0:
                    print(f"epoch {epoch} step {step}/{steps_total} loss {out.loss.item():.4f} {time.time() - started:.0f}s", flush=True)

    @torch.no_grad()
    def score(rows):
        model.eval()
        out = []
        for i in range(0, len(rows), 8):
            enc = {k: v.cuda() for k, v in encode(rows[i : i + 8]).items()}
            with torch.autocast("cuda", dtype=torch.bfloat16):
                logits = model(**enc).logits.float()
            out += torch.softmax(logits, -1)[:, 1].tolist()
        return out

    val_scores = score(val_rows)
    benign_val = sorted(s for s, r in zip(val_scores, val_rows) if r["label"] == "benign")
    threshold = benign_val[min(len(benign_val) - 1, int(0.99 * len(benign_val)))] if benign_val else 0.5
    t = time.time()
    test_scores = score(test_rows)
    ms_per_item = (time.time() - t) / max(len(test_rows), 1) * 1000

    out_path = DATA / "eval" / "llamaguard1b-test.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for r, s in zip(test_rows, test_scores):
            fh.write(json.dumps({"name": r["name"], "version": r["version"], "label": r["label"], "kind": r["kind"], "risk": s}) + "\n")
    adapter_dir = DATA / "models" / "llamaguard1b-gatekeeper"
    model.save_pretrained(str(adapter_dir))
    tok.save_pretrained(str(adapter_dir))
    (adapter_dir / "threshold.json").write_text(json.dumps({"threshold": threshold, "max_tokens": MAX_TOKENS}))

    labels = [1 if r["label"] == "malicious" else 0 for r in test_rows]
    tp = sum(s >= threshold and y for s, y in zip(test_scores, labels))
    fp = sum(s >= threshold and not y for s, y in zip(test_scores, labels))
    stats = {
        "n_fit": len(fit_rows), "n_val": len(val_rows), "n_test": len(test_rows), "train_s": round(time.time() - started),
        "threshold": round(threshold, 4), "test_recall_at_threshold": round(tp / max(sum(labels), 1), 3),
        "test_fpr_at_threshold": round(fp / max(len(labels) - sum(labels), 1), 3), "gpu_ms_per_item": round(ms_per_item, 1),
    }
    data_volume.commit()
    print(json.dumps(stats, indent=1))
    return stats
