# Store the Baseten API key without it appearing on screen, in shell history or in git:
#   1. BASETEN_API_KEY in .env (gitignored), replacing an older value
#   2. Modal secret "baseten-api" for the monitor (via a temp file that is deleted right after)
#   3. one tiny test call to check that the key works (prints only the HTTP status)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$envFile = Join-Path $root ".env"

$secure = Read-Host "Baseten API key (input hidden)" -AsSecureString
$key = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if (-not $key.Trim()) { throw "empty key" }
$key = $key.Trim()

$utf8 = New-Object System.Text.UTF8Encoding($false)
$lines = @()
if (Test-Path $envFile) { $lines = @([IO.File]::ReadAllLines($envFile) | Where-Object { $_ -notmatch '^\s*BASETEN_API_KEY\s*=' }) }
$lines += "BASETEN_API_KEY=$key"
[IO.File]::WriteAllLines($envFile, $lines, $utf8)
Write-Host "written to $envFile" -ForegroundColor Green

$tmp = Join-Path $env:TEMP ("gk-baseten-" + [guid]::NewGuid().ToString("N") + ".env")
try {
    [IO.File]::WriteAllText($tmp, "BASETEN_API_KEY=$key`n", $utf8)
    Push-Location $root
    # --from-dotenv needs python-dotenv; PowerShell 5.1 must not turn modal's stderr into a terminating error
    $ErrorActionPreference = "Continue"
    $out = & uv run --with python-dotenv modal secret create baseten-api --from-dotenv $tmp --force 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    Pop-Location
    if ($code -ne 0) {
        Write-Host "Modal secret NOT saved (exit $code):" -ForegroundColor Red
        Write-Host ($out -replace [regex]::Escape($key), "***")
    } else {
        Write-Host "Modal secret 'baseten-api' saved" -ForegroundColor Green
    }
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

$body = '{"model":"meta-models/muse-spark-open-1026","messages":[{"role":"user","content":"Reply with OK."}],"max_tokens":200}'
try {
    $r = Invoke-WebRequest "https://inference.baseten.co/v1/chat/completions" -Method Post -Body $body -ContentType "application/json" `
        -Headers @{ Authorization = "Bearer $key" } -UseBasicParsing -TimeoutSec 60
    Write-Host "test call: HTTP $($r.StatusCode), key works" -ForegroundColor Green
} catch {
    Write-Host "test call failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
$key = $null
