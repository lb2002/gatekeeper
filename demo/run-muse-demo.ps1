# Gatekeeper agent demo: Muse Code tries to install the typosquat axois-retry from the local demo registry.
# Needs: demo/registry.py and demo/listener.py running, llama-server on 127.0.0.1:8080, `gk guard enable` done.
# Muse runs with approvals ON (you confirm every command) on the standard muse-spark-1.3 model: a subscription
# login otherwise defaults to the "-contributor" model, and --contributor-mode off alone does not change that.
# Muse's Windows sandbox needs a one-time admin setup (`muse sandbox windows setup`); without it, or if its first
# shell call hangs, pass -NoSandbox (you still approve every command).
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
# Muse Spark refuses the typosquat axois-retry on its own, even when told it is intended (a good thing). Dependency
# confusion gives it nothing to notice: the name looks like an internal package, as in most live catches.
Write-Host "Prompt: Add automatic retries to the request in index.js using our internal package @northwind/http-retry." -ForegroundColor Cyan

Set-Location $run
$museArgs = @("--model", "muse-spark-1.3", "--contributor-mode", "off", "--reasoning-effort", "low", "--workspace", $run)
if ($NoSandbox) { $museArgs += "--disable-sandbox" }
muse @museArgs
