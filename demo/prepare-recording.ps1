# Gets the laptop ready for the guard and Muse Code takes: run it once before recording.
#   .\demo\prepare-recording.ps1          show what is ready
#   .\demo\prepare-recording.ps1 -Start   also start what is missing, each in its own window
# Everything here is local and harmless: the "credentials" are fake and the attacker is a listener on 127.0.0.1.
param([switch]$Start)

$root = Split-Path $PSScriptRoot -Parent
$llama = Join-Path (Split-Path $root -Parent) "tools\llama.cpp\llama-server.exe"
$model = Join-Path (Split-Path $root -Parent) "models\glimmer\Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf"
$verdicts = Join-Path $env:USERPROFILE ".gatekeeper\verdicts.json"

function Listening($port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
}

function Service($name, $port, $command) {
    if (Listening $port) { Write-Host "ready    $name (port $port)" -ForegroundColor Green; return }
    Write-Host "missing  $name (port $port)" -ForegroundColor Yellow
    if ($Start) { Start-Process powershell -WorkingDirectory $root -ArgumentList "-NoExit", "-Command", $command }
}

$secret = Join-Path $env:USERPROFILE "gk-demo\.aws"
if (-not (Test-Path $secret)) {
    New-Item -ItemType Directory -Force $secret | Out-Null
    Set-Content (Join-Path $secret "credentials") "[default]`naws_access_key_id = AKIAFAKEDEMO000000`naws_secret_access_key = demo-not-a-real-secret"
}
Write-Host "ready    fake credentials in $secret" -ForegroundColor Green

Service "demo registry" 4873 "uv run python demo\registry.py"
Service "attacker listener" 8099 "uv run python demo\listener.py"
Service "Muse Glimmer" 8080 "& '$llama' -m '$model' --jinja -ngl 16 -fa on -c 8192 -np 1 -t 6 --host 127.0.0.1 --port 8080 --reasoning-format deepseek --reasoning-effort minimal --reasoning-budget 48 --alias muse-glimmer"

$workers = Get-CimInstance Win32_Process -Filter "Name = 'gk.exe'" | Where-Object { $_.CommandLine -match "worker" }
if ($workers) {
    Write-Host "STOP     gk worker is running and shares Muse Glimmer: a block then takes 5 minutes instead of 1-2" -ForegroundColor Red
} else {
    Write-Host "ready    no gk worker running" -ForegroundColor Green
}

if (Test-Path $verdicts) {
    if ($Start) { Remove-Item $verdicts; Write-Host "ready    verdict cache cleared, the model will read the package live" -ForegroundColor Green }
    else { Write-Host "note     verdict cache exists: a repeat take would answer instantly (-Start clears it)" -ForegroundColor Yellow }
} else {
    Write-Host "ready    verdict cache empty" -ForegroundColor Green
}

Write-Host "`nThen: .\demo\run-muse-demo.ps1 -NoSandbox"
