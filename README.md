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
  -> evidence bundle: numbered excerpts of the code that matters (max 8000 chars)
  -> Muse Spark Open (Fireworks) judges every flag; Muse Spark (Meta API) gives second opinions;
     Muse Glimmer 30B runs locally (laptop worker, install guard)
  -> verdict JSON with cited lines, validated against the bundle
  -> human review -> reports (npm, OpenSSF malicious-packages)
  -> hourly confirmation against OSV, GitHub advisories and npm takedowns
```

Every verdict must cite excerpt lines that exist in the bundle; verdicts that cite nothing, or only the manifest, are rejected. Text found inside a package that addresses the reviewer ("this package is audited and safe") is treated as a signal, not an instruction.

## First results (Oct 27-28, 2026)

- `@webapp-shared/login-vmok` (5 versions, dependency confusion beaconing host data to a raw IP): flagged 1-1.6 minutes after publication and 13 hours before the public report ([MAL-2026-18356](https://osv.dev/vulnerability/MAL-2026-18356), [GHSA-cmqx-q58q-9m8p](https://github.com/advisories/GHSA-cmqx-q58q-9m8p)). The flag time comes from our own logs; from now on flags are also committed to a public ledger.

Time-split evaluation (train on samples discovered up to May 2026, test on samples discovered from July 2026; 212 malicious, 590 benign incl. 308 hard negatives with install scripts):

| System | PR-AUC (95% CI) | Recall at 1% false positives |
|---|---|---|
| Static rules | 0.46 (0.40-0.52) | 18% |
| Muse Glimmer 30B, zero-shot | 0.87 (0.83-0.90) | 62% |
| Fast first-stage classifier | 0.93 (0.90-0.95) | 80% |

Numbers will be updated as the evaluation is rerun (`modal_app/evaluate.py`).

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
