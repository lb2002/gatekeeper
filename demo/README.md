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
