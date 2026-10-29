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
  -> every 15 min: fine-tuned Llama Guard 3 1B (v2) over everything the cheap stages let through
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

| System | PR-AUC (95% CI) | Recall at 1% FP (test) | False positives on live npm (later days) |
|---|---|---|---|
| Static rules | 0.48 (0.42-0.54) | 18% | - |
| **Muse Glimmer 30B, zero-shot** | **0.88 (0.84-0.91)** | **66%** | as a blocker: 0 of 590 false blocks; explains with cited lines |
| Muse Spark 1.3, zero-shot (Meta API) | 0.87 (0.84-0.91) | 59% | as a blocker: 1 of 590 false blocks |
| Muse Spark Open, zero-shot (Baseten) | 0.88 (0.84-0.91) | 60% | as a blocker: 1 of 590 false blocks |
| TF-IDF + logistic regression (real npm negatives) | 0.87 (0.83-0.90) | 62% | 2.0% |
| Llama Guard 3 1B fine-tuned, v1 (popular packages as negatives) | 0.97 (0.95-0.98) | 87% | **37%**: unusable |
| Llama Guard 3 1B fine-tuned, v2 (real npm negatives) | 0.86 (0.82-0.89) | 61% | 1.2% at threshold 0.3 (0.2% on the monitor's own stream) |

Live false positives are measured on 1,459 npm releases from days the models never saw (published 2026-10-22, labelled with a week of OSV hindsight, plus the monitor's own sample from 2026-10-28). Most remaining false positives there are SEO spam packages (`0.0.0-stage`).

**Meta models agree on what they see.** Muse Spark, Muse Spark Open and Muse Glimmer reach the same level (PR-AUC 0.87-0.88) and block 55-57% of the test malware. When Spark and Spark Open both say malicious or suspicious, not one of the 590 benign test packages is blocked; any one of the three catches 60%. The 85 samples all three miss are mostly not a model problem: 78 have no suspicious line in their evidence at all (the payload sits in a dependency, a native binary, or a file over the 1 MB read cap). Gatekeeper therefore also checks every new version's dependencies against the 222k npm names OSV lists as malicious (a clean wrapper that installs known malware is flagged on that alone; 0 hits on 17,768 ordinary npm releases).

**Lesson 2:** Spark Open first lost 35% of its test answers (and 20% of live verdicts): under strict JSON output it sometimes repeated itself inside the free-text `summary` until the 4,000-token limit. Length caps in the JSON schema (enforced by constrained decoding) fixed it: answers dropped from up to 4,000 to ~250 tokens, and PR-AUC rose from 0.78 to 0.88.

**Lesson:** v1 looked excellent offline but flagged 37% of live npm releases. Its benign training data were popular, well-maintained packages, so it learned "unpolished = malicious", and the offline test shared that bias. Retrained with real npm releases as negatives (v2), it is usable as a safety net, and the honest ranking changes: zero-shot Muse Glimmer is the strongest detector, and the small models serve as fast pre-filters in front of it. The thresholds of the small models are fixed on training data; the monitor's Llama Guard threshold (0.3, stricter than validation) was chosen after looking at the 2026-10-22 slice, so the monitor's own stream is the cleaner check. Fine-tuned models were trained only on ground truth (never on Muse Spark outputs).

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
