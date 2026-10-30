# Install guard: what it covers and what it does not

The guard sits in front of `npm` and `npx` (shims on PATH) for people and AI coding agents. Its job: no package
code from the registry runs on the machine unless Gatekeeper has looked at that exact version first.

## How it decides what to check

It does not parse npm's command line itself. A hand-written parser kept missing cases a review found
(`npm -p install x`, `npm it x`, `npm create x`, `npx --editor a b`, abbreviations, `--` handling). Instead,
`src/gatekeeper/guard/npm_argv.js` asks the installed npm, through npm's own modules:

- `@npmcli/config`: options, shorthands, abbreviations, `.npmrc` files, `npm_config_*` variables;
- `cmd-list.deref`: command aliases and abbreviations;
- `npm-package-arg`: whether a spec comes from the registry, git, a URL or a local path;
- `pacote`: the exact version npm will pick, using the same registry, tag and `--before` settings.

If that fails for any reason (missing node, malformed config, timeout), the command is blocked; there is no fallback.

## What is blocked or checked

| Situation | Result |
|---|---|
| Package or a dependency listed as malicious by OSV (live lookup; offline copy of 222k names) | blocked |
| Registry package the static rules or local classifier flag | Muse Glimmer judges it locally; malicious or suspicious (>= 0.6) blocks |
| Public package that loads or declares a package nobody can read on the public registry | blocked (needs network; `--gk-allow` for a known case) |
| Exact version younger than 24 h | held, newest older version suggested |
| Tag or range (`@next`, `^1`) | resolved with the 24 h cutoff; that version is checked |
| Dependencies npm resolves itself | the real npm runs with `--before=<24 h ago>`, so no dependency younger than 24 h is installed |
| Spec from git, a URL or a tarball | blocked (no registry metadata or integrity hash to check) |
| `npm init`/`npm create x` | `create-x` is checked like any other package |
| `npm link x`, `npm install-test x`, `npx -p x`, `npm exec x` | checked |
| `pack`/`cache add`/`diff`/`view`/`publish` with a git spec | blocked (building a git package runs its `prepare` script) |
| `package-lock.json` entry pointing outside the registry | blocked (npm installs locked dependencies from their `resolved` URL) |
| Registry, proxy or TLS setting in the project's own `.npmrc` | blocked for every command that contacts a registry, unless `GK_TRUST_PROJECT_REGISTRY=1` |

Verdicts are cached per tarball integrity. `--gk-allow` skips every check for one command.

## What it does not cover (accepted)

- **Dependencies are not read by the model.** Only the package named on the command line is analysed. The tree
  is protected by the OSV list (direct dependencies) and the 24 h `--before` cutoff, not by code review.
- **`npm install` / `npm ci` with no arguments** install what the project's `package.json` and lockfile say. The
  lockfile check and `--before` apply; nothing is model-checked.
- **A `--before` the user sets to a future date** turns off the dependency cutoff (the named package is still held).
- **Running npm by its full path**, or another package manager (pnpm, yarn, bun), bypasses the shims.
- **The model can be wrong.** On the time-split test set the Muse models block 55-57% of malware (Muse Glimmer with no
  false blocks out of 590 benign packages); the OSV list and the waiting period exist because of the rest.
