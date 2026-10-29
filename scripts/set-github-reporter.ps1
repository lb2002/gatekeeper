# Store the GitHub token for automatic OpenSSF reports without it appearing on screen, in shell history or in git:
#   1. Modal secret "github-reporter" (GITHUB_REPORT_TOKEN), via a temp file that is deleted right after
#   2. one read-only test call that prints only the account name and the token's scopes
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

$secure = Read-Host "GitHub token (input hidden)" -AsSecureString
$key = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if (-not $key.Trim()) { throw "empty token" }
$key = $key.Trim()

$utf8 = New-Object System.Text.UTF8Encoding($false)
$tmp = Join-Path $env:TEMP ("gk-github-" + [guid]::NewGuid().ToString("N") + ".env")
try {
    [IO.File]::WriteAllText($tmp, "GITHUB_REPORT_TOKEN=$key`n", $utf8)
    Push-Location $root
    $ErrorActionPreference = "Continue"
    $out = & uv run --with python-dotenv modal secret create github-reporter --from-dotenv $tmp --force 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    Pop-Location
    if ($code -ne 0) {
        Write-Host "Modal secret NOT saved (exit $code):" -ForegroundColor Red
        Write-Host ($out -replace [regex]::Escape($key), "***")
    } else {
        Write-Host "Modal secret 'github-reporter' saved" -ForegroundColor Green
    }
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

try {
    $r = Invoke-WebRequest "https://api.github.com/user" -Headers @{ Authorization = "Bearer $key"; "User-Agent" = "gatekeeper" } -UseBasicParsing -TimeoutSec 30
    $login = ($r.Content | ConvertFrom-Json).login
    Write-Host "test call: HTTP $($r.StatusCode), account $login, scopes: $($r.Headers['X-OAuth-Scopes'])" -ForegroundColor Green
} catch {
    Write-Host "test call failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
$key = $null
