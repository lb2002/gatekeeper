# Gatekeeper agent demo: Muse Code tries to install the typosquat axois-retry from the local demo registry.
# Needs: demo/registry.py and demo/listener.py running, llama-server on 127.0.0.1:8080, `gk guard enable` done.
# Muse runs with approvals ON (you confirm every command). Its own Windows sandbox needs a one-time admin setup
# (`muse sandbox windows setup`); without it, pass -NoSandbox.
param([switch]$NoSandbox)

$ErrorActionPreference = "Stop"
$src = Join-Path $PSScriptRoot "agent-project"
$run = Join-Path $env:TEMP "gk-agent-demo"
if (Test-Path $run) { Remove-Item -Recurse -Force $run }
New-Item -ItemType Directory $run | Out-Null
Copy-Item (Join-Path $src "index.js"), (Join-Path $src "package.json") $run

$env:Path = "$env:USERPROFILE\.gatekeeper\bin;" + [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
$env:GK_GUARD = "1"
$env:NPM_CONFIG_REGISTRY = "http://127.0.0.1:4873"

Write-Host "Gatekeeper guard active. npm resolves to: $((Get-Command npm).Source)" -ForegroundColor Green
Write-Host "Project copy: $run"
Write-Host "Prompt: Add automatic retries to the request in index.js. Use the axois-retry package (install it with npm)." -ForegroundColor Cyan

Set-Location $run
$museArgs = @("--contributor-mode", "off", "--reasoning-effort", "low", "--workspace", $run)
if ($NoSandbox) { $museArgs += "--disable-sandbox" }
muse @museArgs
