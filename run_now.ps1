# -*- coding: utf-8 -*-
<#
    Разовая проверка с логированием. Это то, что запускается и из планировщика,
    и вручную.

      powershell -ExecutionPolicy Bypass -File run_now.ps1
      powershell -ExecutionPolicy Bypass -File run_now.ps1 -Limit 20 -NoPublish
#>

param(
    [int]$Limit = 0,
    [switch]$NoPublish,
    [switch]$SkipTun,
    [switch]$Console,
    [switch]$Quiet
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Filter = Join-Path $ScriptDir "filter_servers.py"
$logDir = Join-Path $ScriptDir "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Get-PythonPath {
    foreach ($cand in @("pythonw.exe", "python.exe")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) {
            $exe = $cmd.Source
            if ($exe -match "WindowsApps") { continue }
            return $exe
        }
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) { return $py.Source }
    throw "Не найден интерпретатор Python"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "run-$stamp.log"

$python = Get-PythonPath
$useW = $python -match "pythonw\.exe$"

$pyArgs = @("-u", $Filter)
if ($NoPublish) { $pyArgs += "--no-publish" }
if ($SkipTun)   { $pyArgs += "--skip-tun" }
if ($Limit -gt 0) { $pyArgs += @("--limit", "$Limit") }
if ($Quiet)    { $pyArgs += "--quiet" }

$env:PYTHONIOENCODING = "utf-8"

if ($useW -and -not $Console) {
    # pythonw не пишет в консоль — всё в файл
    Start-Process -FilePath $python `
        -ArgumentList $pyArgs `
        -WorkingDirectory $ScriptDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $logFile `
        -RedirectStandardError "$logFile.err"
} else {
    & $python @pyArgs 2>&1 | Tee-Object -FilePath $logFile
}

if (-not $useW -and -not $Console) {
    Write-Host ""
    Write-Host "Лог: $logFile"
}