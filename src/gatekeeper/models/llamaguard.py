"""Gatekeeper's fine-tuned Llama Guard 3 1B (LoRA + classification head), see modal_app/guardtune.py.

Scores an evidence bundle with the probability that the package is malicious. It was trained on
bundles without the registry-signal header line, so that line is removed before scoring.
"""

from __future__ import annotations

import json
from pathlib import Path

from gatekeeper.fastclf import clean_text

BASE = "meta-llama/Llama-Guard-3-1B"
BACKEND = "llamaguard-1b"


def prepare(bundle_text: str, name: str, version: str, rules: list[str]) -> str:
    lines = [line for line in bundle_text.splitlines() if not line.startswith("registry signals:")]
    return clean_text("\n".join(lines), name, version, rules)


class LlamaGuardScorer:
    def __init__(self, adapter_dir: str | Path, device: str = "cuda"):
        import torch
        from peft import PeftModel
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        adapter_dir = Path(adapter_dir)
        meta = json.loads((adapter_dir / "threshold.json").read_text())
        self.threshold, self.max_tokens = float(meta["threshold"]), int(meta["max_tokens"])
        self.tok = AutoTokenizer.from_pretrained(str(adapter_dir))
        dtype = torch.bfloat16 if device == "cuda" else torch.float32
        base = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2, torch_dtype=dtype)
        base.config.pad_token_id = self.tok.pad_token_id
        self.model = PeftModel.from_pretrained(base, str(adapter_dir)).to(device).eval()
        self.device, self.dtype, self.torch = device, dtype, torch

    def risk(self, texts: list[str], batch: int = 8) -> list[float]:
        torch = self.torch
        out: list[float] = []
        with torch.no_grad():
            for i in range(0, len(texts), batch):
                enc = self.tok(texts[i : i + batch], truncation=True, max_length=self.max_tokens, padding=True,
                               return_tensors="pt").to(self.device)
                with torch.autocast(self.device, dtype=self.dtype, enabled=self.device == "cuda"):
                    logits = self.model(**enc).logits.float()
                out += torch.softmax(logits, -1)[:, 1].tolist()
        return out
