# Demo: an AI agent installs a typosquat, Gatekeeper blocks it

Everything here is harmless and local:

- `villain-pkg/` imitates a typical install-time credential stealer (`axois-retry`, a typosquat of
  `axios-retry`): its postinstall reads a **fake** credentials file from `%USERPROFILE%\gk-demo` and posts
  it to `127.0.0.1:8099`. It also carries a base64-encoded URL and a "note to AI reviewers" injection.
- It is only ever published to a **local** Verdaccio registry (`verdaccio/config.yaml`), never to npm.
- `listener.py` plays the attacker's server and shows what would have been stolen.

## Run

```powershell
# 1. fake secret + attacker listener
New-Item -ItemType Directory -Force $HOME\gk-demo\.aws | Out-Null
Set-Content $HOME\gk-demo\.aws\credentials "[default]`naws_access_key_id = AKIAFAKEDEMO000000`naws_secret_access_key = demo-not-a-real-secret"
python demo\listener.py

# 2. local registry with the villain (separate terminal; uses the real npx, not the guard)
& "C:\Program Files\nodejs\npx.cmd" --yes verdaccio@6 --config demo\verdaccio\config.yaml

# 3. guarded shell, registry pointed at the local test registry
gk guard shell
$env:NPM_CONFIG_REGISTRY = "http://127.0.0.1:4873"
npm install axois-retry   # -> BLOCKED by Gatekeeper, the listener receives nothing
```

## Recording tips

- Stop the laptop worker (`gk worker`) first. It shares the single Muse Glimmer slot with the guard, so the
  guard otherwise waits for the worker's current package (a block then takes ~6 minutes instead of ~1-2).
- Verdicts are cached per tarball. To show the model reading the package live (not an instant "cached:" block),
  delete `%USERPROFILE%\.gatekeepererdicts.json` before the take.
- The demo package's publish date is in the past, so the 24 h waiting period does not apply to it: the block
  you see comes from the model reading the code. To show the waiting period, install any brand-new real
  version, e.g. a `@next` tag of a popular package published today.

## Muse Code (agent) take

`run-muse-demo.ps1 -NoSandbox` starts Muse Code on `muse-spark-1.3` (standard mode) in a copy of
`agent-project`, with the guarded npm first on PATH and approvals on. Paste the prompt it prints. Muse
Spark notices that `axois-retry` looks like a typo of `axios-retry`; the prompt therefore says the
spelling is intended, as a poisoned README or issue would.
