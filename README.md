# Gatekeeper

Open-source malware detection for npm, built on Meta's models. It never runs package code.

- **Live monitor:** watches every new npm release (~250 changes a minute), triages it statically, and has Meta models judge the suspicious ones with cited evidence lines. Detections are verified by a human and reported responsibly.
- **Install guard:** wraps `npm install` / `npx` (for you or an AI coding agent) and blocks malicious packages before any install script runs, offline, with Muse Glimmer running on your own machine.

**Live numbers:** https://lb2002--gatekeeper-api.us-east.modal.run/ (updated every 2 minutes; detections are only named once independently confirmed). **Public ledger:** https://github.com/lb2002/gatekeeper-ledger

Work in progress for the Meta Global AI Developer Hackathon (Oct 26 - Nov 4, 2026). See [PRIOR_WORK.md](PRIOR_WORK.md) for what we reuse.

## How it works

```
npm replication feed (every 2 min, on Modal)
  -> metadata triage (install hooks, typosquats, maintainer changes, new packages)
  -> in-memory tarball scan: static rules + a fast first-stage classifier
  -> (being retrained) fine-tuned Llama Guard 3 1B over everything the cheap stages let through
  -> evidence bundle: numbered excerpts of the code that matters (max 8000 chars)
  -> Muse Spark Open (Fireworks) judges every flag; Muse Spark (Meta API) gives second opinions;
     Muse Glimmer 30B runs locally (laptop worker, install guard)
  -> verdict JSON with cited lines, validated against the bundle
  -> human review -> reports (npm, OpenSSF malicious-packages)
  -> hourly confirmation against OSV, GitHub advisories and npm takedowns
```

Every verdict must cite excerpt lines that exist in the bundle; verdicts that cite nothing, or only the manifest, are rejected. Text found inside a package that addresses the reviewer ("this package is audited and safe") is treated as a signal, not an instruction.

### Install guard decisions

```
npm install X  ->  npm view (read-only) -> download tarball, verify sha512 -> read in memory
  rules clean AND local classifier clean   -> install (seconds)
  otherwise                                -> Muse Glimmer on your machine judges, citing lines
  malicious, or suspicious with confidence >= 0.6, or any error -> blocked, nothing installed
```

Decisions are cached per exact tarball integrity. The classifier ships as plain JSON numbers (no pickle), so loading it cannot run code.

### Proving when we saw something

A flag is never named before it is confirmed. Instead, within two minutes, the monitor publishes `sha256(salt || package, version, flag time)` to [gatekeeper-ledger](https://github.com/lb2002/gatekeeper-ledger), one new file per batch, each with an [OpenTimestamps](https://opentimestamps.org) proof anchored in Bitcoin. Once OSV, GitHub or npm independently confirm a detection, its salt is published and anyone can run `gk verify-flag <salt> <line>` and `ots verify` to check that we had it first.

## First results (Oct 27-28, 2026)

- `@webapp-shared/login-vmok` (5 versions, dependency confusion beaconing host data to a raw IP): flagged 1-1.6 minutes after publication and 13 hours before the public report ([MAL-2026-18356](https://osv.dev/vulnerability/MAL-2026-18356), [GHSA-cmqx-q58q-9m8p](https://github.com/advisories/GHSA-cmqx-q58q-9m8p)). The flag time comes from our own logs; from now on flags are also committed to a public ledger.

Time-split evaluation: train on samples discovered up to May 2026, test on samples discovered from July 2026 (June left out as a gap; campaign clusters deduplicated, no test cluster in training). Test set: 212 malicious, 590 benign packages including 71 hard negatives with install scripts. Thresholds are fixed on training data before the test set is scored once.

| System | PR-AUC (95% CI) | Recall at 1% false positives | Notes |
|---|---|---|---|
| Static rules | 0.48 (0.42-0.54) | 18% | miss 125 of 212 malware samples entirely |
| Muse Glimmer 30B, zero-shot | 0.88 (0.84-0.91) | 66% | as a blocker: 57% recall, 0 of 590 false blocks; explains with cited lines |
| TF-IDF + logistic regression | 0.93 (0.90-0.95) | 75% | 1 ms on a laptop CPU, ships as plain JSON |
| **Llama Guard 3 1B, fine-tuned** (LoRA + classification head) | **0.97 (0.95-0.98)** | **87%** | 89% recall at 1.4% false positives at its fixed threshold; 101 of the 125 samples the rules miss |

The fine-tuned Llama Guard was trained only on dataset ground truth (never on Muse Spark outputs).

**Lesson from going live (2026-10-28):** on real new npm releases the same Llama Guard flagged 29 of 79 scanned packages (37%), mostly small new CLIs and MCP tools that Muse Spark and Muse Spark Open judged benign. The benign training data came from popular, well-maintained packages, so the model partly learned "unpolished = malicious". The test set shares that bias, which is why it looked excellent offline. It is switched off in the monitor; the monitor now collects a capped sample of everyday npm releases to retrain it with realistic negatives and to measure false positives on live data from later days.

## Safety

Gatekeeper never executes package code. Package archives are read in memory; malware samples are only unpacked inside isolated cloud containers. This repository contains no malware: only package identifiers and scripts to rebuild datasets. The demo package in `demo/villain-pkg` is a harmless imitation that only talks to localhost.

## Run it

```bash
uv sync
uv run pytest
uv run gk check <package>@<version> --backend local      # needs llama-server with Muse Glimmer
uv run gk guard enable                                   # npm/npx shims
uv run modal deploy modal_app/app.py                     # the live monitor
```
