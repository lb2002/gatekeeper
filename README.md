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
npm install X  ->  npm view (read-only)
  X is listed as malicious by OSV (asked live; offline: a local copy of OSV's 222k malicious npm names),
    or a dependency of X is on that list                      -> blocked
  -> download tarball, verify sha512 -> read in memory
  rules clean AND local classifier clean   -> clean
  otherwise                                -> Muse Glimmer on your machine judges, citing lines
  malicious, or suspicious with confidence >= 0.6, or any error -> blocked, nothing installed
  clean, but X was published less than 24 h ago -> held, with the newest older version suggested
```

The waiting period is there because the rest of the ecosystem catches up quickly. Of 742 npm malware reports in OSV for October 2026, measured from the npm publish time of the malicious version to the report's import into OSV, 33% were public within an hour, 58% within a day, 74% within three days (median 10 h). A model catches what is new; the waiting period plus the live OSV lookup catch much of what the model misses. As a rough estimate (assuming the two are independent), the model's ~57% plus a 24 h wait block about 4 in 5 malicious versions, and a 72 h wait (`GK_MIN_AGE_HOURS=72`) about 9 in 10. `GK_MIN_AGE_HOURS=0` turns the wait off, `--gk-allow` overrides one install, and `GK_OFFLINE=1` never contacts OSV (the live lookup sends only the package name and version).

A note on OSV timestamps: an entry's `published` field is set by the reporter and is often backdated to the package's own publish time (301 of the 742 entries above look like that), so it says nothing about when the warning became public. Gatekeeper uses the import time into OSV (or the first commit to OpenSSF malicious-packages) everywhere, including for its own lead times below.

`gk guard update-osv` refreshes the offline list (a 3 MB copy the monitor rebuilds daily; `--from-osv` builds it yourself from OSV's `npm/all.zip`).

Decisions are cached per exact tarball integrity. The classifier ships as plain JSON numbers (no pickle), so loading it cannot run code.

### Proving when we saw something

A flag is never named before it is confirmed. Instead, within two minutes, the monitor publishes `sha256(salt || package, version, flag time)` to [gatekeeper-ledger](https://github.com/lb2002/gatekeeper-ledger), one new file per batch, each with an [OpenTimestamps](https://opentimestamps.org) proof anchored in Bitcoin. Once OSV, GitHub or npm independently confirm a detection, its salt is published and anyone can run `gk verify-flag <salt> <line>` and `ots verify` to check that we had it first.

## Live results (Oct 27-30, 2026)

In its first three days the monitor read 238,117 new npm versions, scanned 38,178 archives and queued 1,717 for the models. **13 packages (30 versions) it flagged have since been independently confirmed as malware** by OSV / OpenSSF malicious-packages, GitHub or npm. Median time from npm publication to our flag: about 1 minute. **10 of the 13 were flagged before any public report, by a median of 23 hours.**

| Package (versions) | What it does | Flagged after publish | Ahead of the public report |
|---|---|---|---|
| `@webapp-shared/login-vmok` (5) | dependency confusion: postinstall beacons host data to a raw IP | 1.0-1.6 min | 13 h ([MAL-2026-18356](https://osv.dev/vulnerability/MAL-2026-18356)) |
| `identity-two-factor` | dependency confusion aimed at one company: postinstall POSTs host, user and CI data to webhook.site | 1.8 min | 26 h ([MAL-2026-18367](https://osv.dev/vulnerability/MAL-2026-18367)) |
| `spectral-net-probe` | postinstall calls a Cloudflare quick tunnel | 1.6 min | 25 h ([MAL-2026-18368](https://osv.dev/vulnerability/MAL-2026-18368)) |
| `cjlowuxbnexkhgpzq` | random-name package with an install-time network call (GitHub malware advisory) | 0.1 min | 29 h ([MAL-2026-18381](https://osv.dev/vulnerability/MAL-2026-18381)) |
| `@zmtcdn/components`, `@zmtcdn/ui` | dependency confusion: postinstall POSTs hostname, user, platform and env | 0-2 min | 23 h ([MAL-2026-18372](https://osv.dev/vulnerability/MAL-2026-18372), [-18373](https://osv.dev/vulnerability/MAL-2026-18373)) |
| `black-spindle`, `black-spindle-2` (4) | postinstall runs `curl` against a throwaway host | 0-1.8 min | 1-22 h ([MAL-2026-18359](https://osv.dev/vulnerability/MAL-2026-18359), [-18376](https://osv.dev/vulnerability/MAL-2026-18376)) |
| `spectral-core` (10) | no install script at all: a `binding.gyp` action (run by node-gyp on install) reads process environments and AWS instance metadata and POSTs them to webhook.site; a new version every ~15 min | 0.2-3.3 min | 18-20 h ([MAL-2026-18377](https://osv.dev/vulnerability/MAL-2026-18377)) |
| `@dmangal/curse-dependent-ecto` (3) | the same `binding.gyp` trick: greps the machine for secrets and POSTs every env var | 0.3-1.5 min | 17 h ([MAL-2026-18375](https://osv.dev/vulnerability/MAL-2026-18375)) |
| 3 `dowload_ebok_*` packages | SEO spam (flagged by Llama Guard only) | ~1 min | none (reported the same minute) |

"Ahead of the public report" uses the report's import time into OSV, not the backdated `published` field (see above). Every flag time is committed to the public ledger before confirmation. Only flags at least one model called malicious or suspicious count; packages that sat in the queue but were judged benign do not, even when OSV listed them later.

What the monitor misses is tracked too: every hour it checks each new OSV npm malware report against its own logs (recall, publish-to-flag time, misses). Most misses so far were versions it never downloaded (placeholder or already-removed versions) or that showed no suspicious code in the archive. The monitor was down from about 15:00 to 22:00 UTC on Oct 29 (it stalled on packages with hundreds of new versions; fixed and alerting since).

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
