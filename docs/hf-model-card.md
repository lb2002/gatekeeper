---
base_model: meta-llama/Llama-Guard-3-1B
library_name: peft
license: llama3.2
pipeline_tag: text-classification
tags:
- security
- malware-detection
- npm
- supply-chain
- lora
---

# Llama-Guard-3-1B-Gatekeeper-npm

A LoRA adapter plus classification head that turns Meta's [Llama Guard 3 1B](https://huggingface.co/meta-llama/Llama-Guard-3-1B)
into a classifier for **malicious npm packages**. It reads a Gatekeeper *evidence bundle* (numbered excerpts of a
package's install scripts and code, never executed) and returns the probability that the package is malicious.

Built with Llama. Part of [Gatekeeper](https://github.com/lb2002/gatekeeper), open-source npm malware detection on
Meta's models, made for the Meta Global AI Developer Hackathon (Oct 26 - Nov 4, 2026).

## How it is used

In Gatekeeper's live monitor it runs every 30 minutes over every npm version the rules and a small TF-IDF classifier
let through, as a cheap safety net in front of the Muse models (Muse Spark Open judges every flag; Muse Glimmer
runs locally). Its flags are never reported on their own: a detection needs a Muse verdict or a human, so it can run
wide, at a threshold that passes about 5% of live npm.

```python
from gatekeeper.models.llamaguard import LlamaGuardScorer, prepare

scorer = LlamaGuardScorer("path/to/this/adapter", device="cuda")   # or "cpu"
risk = scorer.risk([prepare(bundle_text, name, version, rules)])[0]
flag = risk >= 0.02   # the monitor's routing threshold; threshold.json holds the validation threshold (0.103)
```

`bundle_text` comes from `gatekeeper.evidence.bundle.build_bundle(...)`; see the Gatekeeper repository.

## Training

- Data: the DataDog malicious-software-packages dataset (npm part, Apache-2.0) for malicious samples; real npm
  releases (not only popular packages) as benign samples. Campaign clusters deduplicated.
- Time split: trained on samples discovered up to May 2026, validated on a held-out 10% of the training period, tested
  once on samples discovered from July 2026 (June left out as a gap).
- Labels are ground truth only. No outputs of Muse Spark or any other model were used as training targets.
- LoRA r=16, alpha=32 on all attention and MLP projections, plus the classification head; 2 epochs, lr 2e-4,
  max 2,048 tokens.

## Results (time-split test set: 212 malicious, 590 benign incl. 71 hard negatives with install scripts)

| Metric | Value |
|---|---|
| PR-AUC (95% CI) | 0.86 (0.82-0.89) |
| Recall at 1% false-positive rate | 61% |
| False positives on unseen live npm releases | 1.2% at threshold 0.3 (0.2% on the monitor's own stream) |
| Recall at about 5% live false positives | 70% (threshold 0.02) |

An earlier version (v1) trained with popular packages as the benign class scored 0.97 PR-AUC offline but flagged 37%
of real npm releases: it had learned "unpolished = malicious". This v2 uses real npm releases as negatives. On its own
it is weaker than the zero-shot Muse models (PR-AUC 0.87-0.88); it is meant as a fast pre-filter.

## Limitations

- It sees only the evidence bundle (at most ~8,000 characters of selected excerpts). Payloads in native binaries,
  dependencies or files over the read cap are invisible to it.
- npm only. Scores are not calibrated probabilities.
- A high score is a reason to look closer, not proof.

## License

This adapter is a derivative of Llama Guard 3 1B and is distributed under the
[Llama 3.2 Community License](https://www.llama.com/llama3_2/license/) and subject to the
[Llama 3.2 Acceptable Use Policy](https://www.llama.com/llama3_2/use-policy/). Llama 3.2 is licensed under the Llama 3.2
Community License, Copyright © Meta Platforms, Inc. All Rights Reserved.
