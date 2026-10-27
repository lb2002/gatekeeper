# Gatekeeper

Static malware detection for npm, built on Meta's Muse models.

- **Live monitor:** watches every new npm release, flags malicious packages without ever running their code, and queues them for human verification and responsible reporting.
- **Install guard:** checks `npm install` / `npx` (by you or by an AI coding agent) on your own machine with Muse Glimmer, Meta's open-weight model, and blocks malicious packages before any install script runs.

Work in progress for the Meta Global AI Developer Hackathon (Oct 26 - Nov 4, 2026). See [PRIOR_WORK.md](PRIOR_WORK.md) for what we reuse.

## Safety

Gatekeeper never executes package code. Package archives are read in memory; malware samples are only unpacked inside isolated cloud containers. This repository contains no malware: only package identifiers and scripts to rebuild datasets.
