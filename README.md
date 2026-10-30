# Gatekeeper

Open-source malware detection for npm, built on Meta's models. It never runs package code.

- **Live monitor:** watches every new npm release (~250 changes a minute), triages it statically, and has Meta models judge the suspicious ones with cited evidence lines. Detections are reported to OpenSSF (by a human, or automatically when the static proof is unambiguous).
- **Install guard:** wraps `npm install` / `npx` (for you or an AI coding agent) and blocks malicious packages before any install script runs, offline, with Muse Glimmer running on your own machine.

**So far (Oct 27-30):** 10 malicious packages flagged that were later confirmed by OSV / GitHub / npm, **every one before the public report, by a median of 23 hours**, about a minute after publication. Of the malware published while the monitor was running, it flagged 56% ([what it missed](#live-results-oct-27-30-2026)). Every flag time is in a public, timestamped ledger.

**Live numbers:** https://lb2002--gatekeeper-api.us-east.modal.run/ (updated every 2 minutes; detections are only named once independently confirmed). **Public ledger:** https://github.com/lb2002/gatekeeper-ledger

Built for the Meta Global AI Developer Hackathon (Oct 26 - Nov 4, 2026). See [PRIOR_WORK.md](PRIOR_WORK.md) for what we reuse.

## How it works

![Gatekeeper architecture](docs/architecture.svg)

```
npm replication feed (every 2 min, on Modal)
  -> metadata triage (install hooks, typosquats, maintainer changes, new packages, OSV-listed dependencies)
  -> in-memory tarball scan: static rules + a fast first-stage classifier;
     every package younger than 72 h that runs code at install time goes to the models
  -> every 15 min: fine-tuned Llama Guard 3 1B (v2) over everything the cheap stages let through
  -> evidence bundle: numbered excerpts of the code that matters (max 8000 chars)
  -> Muse Spark Open (Fireworks, Baseten) judges every flag; Muse Spark (Meta API) gives second opinions;
     Muse Glimmer 30B runs locally (laptop worker, install guard)
  -> verdict JSON with cited lines, validated against the bundle
  -> reports to OpenSSF malicious-packages: human review, or automatic when the static proof is unambiguous
  -> hourly confirmation against OSV, GitHub advisories and npm takedowns
```

**Campaign memory.** Attackers re-upload under new names and reuse their collector. The endpoints of packages at least two Muse models call malicious (URLs to a public IP, webhook.site and similar tokens, tunnel subdomains; never shared hosts like `webhook.site` alone) are remembered, and any later package that sends to one is flagged and linked to the earlier one. Backtest on 6,628 scanned archives: no false hits, and two more packages of a live dependency-confusion campaign. The same goes for npm accounts: any new version from an account that published such a package is scanned and judged regardless of its score (attackers often publish a clean clone first and the payload later).

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

Worked example: `spectral-core@3.0.7` was flagged at 20:30:20 UTC on Oct 28. Its revealed line and salt (in `revealed/2026-10.jsonl`) hash to a digest in `commitments/2026-10-28/203107-67c23a.txt`; `ots upgrade` + `ots verify` on that batch's proof point to Bitcoin block 973597, mined at 20:42:17 UTC that evening (its merkle root `db5b3791…` matches any block explorer). The first public report (OSV import of MAL-2026-18377) came 18.5 hours later.

## Live results (Oct 27-30, 2026)

In its first three days the monitor read 238,117 new npm versions, scanned 38,178 archives and queued 1,717 for the models. **10 packages (27 versions) it flagged have since been independently confirmed as malware** by OSV / OpenSSF malicious-packages, GitHub or npm, **every one of them before any public report: by a median of 23 hours.** Median time from npm publication to our flag: about 1 minute.

![Flagged by Gatekeeper vs. first public report](docs/lead-times.svg)

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

"Ahead of the public report" uses the report's import time into OSV, not the backdated `published` field (see above). Every flag time is committed to the public ledger before confirmation. Only flags at least one model called malicious or suspicious count; packages that sat in the queue but were judged benign do not, even when OSV listed them later. For two of them (`spectral-core`, `@dmangal/curse-dependent-ecto`) we opened OpenSSF reports ([#1681](https://github.com/ossf/malicious-packages/pull/1681), [#1682](https://github.com/ossf/malicious-packages/pull/1682)) about 15 hours before another scanner's entries for the same packages landed.

**Live recall.** Every hour the monitor takes each new OSV npm malware report and checks it against its own logs. Since it started (Oct 27, 14:02 UTC), OSV reported 18 malicious npm packages whose malware was published while it was watching: **it flagged 10 (56%), all before the report.** Of the 8 misses, OSV's own write-ups for 5 say no harmful behaviour was found (keyword matches in pentest tools and agent CLIs); the other 3 were brand-new packages with a `postinstall` hook whose code did not trip the rules (scores 4-7 of the 9 needed). Since Oct 30, every package younger than 72 hours that runs code at install time goes to a model regardless of its score: about 100-150 versions a day, under $1 a day with Muse Spark Open.

Two traps in measuring this: OSV's `published` date is often backdated (see above), and most of the 81 reports about older malware list npm's own placeholder versions (`0.0.0-stage`, `0.0.1-security`, published by npm when it removes a package). Seeing only those means the malware came out before the monitor started, so they are excluded rather than counted as misses, and the monitor no longer scans them. The monitor was down from about 15:00 to 22:00 UTC on Oct 29 (it stalled on packages with hundreds of new versions; fixed, with alerts since).

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

Live false positives are measured on 1,459 npm releases from days the models never saw (published 2026-10-22, labelled with a week of OSV hindsight, plus the monitor's own sample from 2026-10-28). Most remaining false positives there are SEO spam packages.

**Meta models agree on what they see.** Muse Spark, Muse Spark Open and Muse Glimmer reach the same level (PR-AUC 0.87-0.88) and block 55-57% of the test malware. When Spark and Spark Open both say malicious or suspicious, not one of the 590 benign test packages is blocked; any one of the three catches 60%. The 85 samples all three miss are mostly not a model problem: 78 have no suspicious line in their evidence at all (the payload sits in a dependency, a native binary, or a file over the 1 MB read cap). Gatekeeper therefore also checks every new version's dependencies against the 222k npm names OSV lists as malicious (a clean wrapper that installs known malware is flagged on that alone; 0 hits on 17,768 ordinary npm releases).

**Lesson: cap the free text.** Spark Open first lost 35% of its test answers (and 20% of live verdicts): under strict JSON output it sometimes repeated itself inside the free-text `summary` until the 4,000-token limit. Length caps in the JSON schema (enforced by constrained decoding) fixed it: answers dropped from up to 4,000 to ~250 tokens, and PR-AUC rose from 0.78 to 0.88.

**Lesson: test on real traffic.** Llama Guard v1 looked excellent offline but flagged 37% of live npm releases. Its benign training data were popular, well-maintained packages, so it learned "unpolished = malicious", and the offline test shared that bias. Retrained with real npm releases as negatives (v2), it is usable as a safety net, and the honest ranking changes: zero-shot Muse Glimmer is the strongest detector, and the small models serve as fast pre-filters in front of it. The thresholds of the small models are fixed on training data; the monitor's Llama Guard threshold (0.3, stricter than validation) was chosen after looking at the 2026-10-22 slice, so the monitor's own stream is the cleaner check. Fine-tuned models were trained only on ground truth (never on Muse Spark outputs).

## Safety

Gatekeeper never executes package code. Package archives are read in memory; malware samples are only unpacked inside isolated cloud containers. This repository contains no malware: only package identifiers and scripts to rebuild datasets. The demo package in `demo/villain-pkg` is a harmless imitation that only talks to localhost.

## Try the install guard

Needs Python with [uv](https://docs.astral.sh/uv/) and Node/npm. No account or API key.

```bash
uv sync
uv run gk guard enable        # writes npm/npx shims to ~/.gatekeeper/bin
uv run gk guard update-osv    # offline list of 222k malicious npm names (3 MB)
uv run gk guard shell         # Windows: a PowerShell with the shims first on PATH
# macOS/Linux instead: export PATH="$HOME/.gatekeeper/bin:$PATH"
npm install <package>         # checked before anything is installed
```

Known-malicious packages and dependencies are blocked and brand-new versions are held without any model. Archives the static rules flag go to Muse Glimmer through a local [llama.cpp](https://github.com/ggml-org/llama.cpp) server (`llama-server -m Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf --jinja -fa on -c 8192 --port 8080 --reasoning-format deepseek --reasoning-budget 48 --alias muse-glimmer`, the [official GGUF](https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF); `GK_LOCAL_URL` points elsewhere). Without it those installs fail closed (blocked, `--gk-allow` to override). `demo/` has a harmless typosquat and a local registry to see a block end to end.

## Run it

```bash
uv sync
uv run pytest
uv run gk check <package>@<version> --backend local      # needs llama-server with Muse Glimmer
uv run gk guard enable                                   # npm/npx shims
uv run gk guard update-osv                               # offline list of 222k malicious npm names
uv run modal deploy modal_app/app.py                     # the live monitor
```
