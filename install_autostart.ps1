# -*- coding: utf-8 -*-
<#
    Ставит и снимает автозапуск.

    Основной способ — задача в планировщике Windows (с задержкой после входа,
    чтобы не мешать старту). Регистрация задачи требует прав администратора,
    поэтому если их нет, ставится копия в папку автозагрузки: запускается
    при входе так же, но без задержки и без повышения прав.

    Запуск:
      powershell -ExecutionPolicy Bypass -File install_autostart.ps1
      powershell -ExecutionPolicy Bypass -File install_autostart.ps1 -Uninstall
#>

param(
    [switch]$Uninstall,
    [int]$DelaySeconds = 120,
    [string]$TaskName = "ShareSub Gemini Filter"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Filter = Join-Path $ScriptDir "filter_servers.py"

function Get-PythonPath {
    # Ищем python, который умеет работать без окна консоли
    foreach ($cand in @("pythonw.exe", "python.exe")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) {
            $exe = $cmd.Source
            if ($exe -match "WindowsApps") { continue }  # заглушка из Store
            return $exe
        }
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) { return $py.Source }
    throw "Не найден интерпретатор Python"
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Задача '$TaskName' удалена."
    } else {
        Write-Host "Задача '$TaskName' не найдена."
    }
    return
}

if (-not (Test-Path $Filter)) {
    throw "Не найден filter_servers.py рядом с этим скриптом: $Filter"
}

$python = Get-PythonPath
$runner = Join-Path $ScriptDir "run_hidden.vbs"
$logDir = Join-Path $ScriptDir "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# Путь автозагрузки текущего пользователя
$startup = Join-Path ([Environment]::GetFolderPath("Startup")) "ShareSubGeminiFilter.vbs"
# Комментарий намеренно латиницей: VBScript читает файл в ANSI, кириллица
# в нём превращается в мусор.
$startupBody = @"
' ShareSub Gemini filter autostart (generated, safe to delete)
Option Explicit
Dim shell
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$ScriptDir\run_now.ps1"" -Quiet", 0, False
"@

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Задача '$TaskName' удалена."
    } else {
        Write-Host "Задача '$TaskName' не найдена."
    }
    if (Test-Path $startup) {
        Remove-Item $startup -Force
        Write-Host "Ярлык автозагрузки удалён: $startup"
    }
    return
}

$trigger = New-ScheduledTaskTrigger -AtLogOn
$trigger.Delay = "PT${DelaySeconds}S"

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

# Запуск через VBS-шим: WScript.Shell.Run(..., 0) не создаёт окно консоли
# вообще — надёжнее, чем полагаться на -WindowStyle Hidden.
$action = New-ScheduledTaskAction `
    -Execute "wscript.exe" `
    -Argument "`"$runner`"" `
    -WorkingDirectory $ScriptDir

$installed = $false
try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Фильтрует подписку ShareSub по доступности Gemini и публикует на example.com/workgemini" `
        -Force | Out-Null
    $installed = $true
    Write-Host "Задача '$TaskName' создана в планировщике."
    Write-Host "  триггер   : вход в систему, задержка ${DelaySeconds}с"
} catch {
    Write-Host "Планировщик не дал зарегистрировать задачу (нужны права администратора)."
    Write-Host "Ставлю автозапуск через папку автозагрузки — работает так же, при входе."
}

# Папка автозагрузки ставится в любом случае: если задача есть, дублируем только
# если её нет — иначе фильтр стартовал бы дважды.
$taskExists = $null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
if (-not $taskExists) {
    Set-Content -Path $startup -Value $startupBody -Encoding ASCII
    Write-Host "  автозагрузка: $startup"
}

Write-Host "  python    : $python"
Write-Host "  запуск    : $runner  (без окон)"
Write-Host ""
Write-Host "Проверить сейчас (тоже без окон):"
Write-Host "  wscript `"$runner`""
Write-Host "Посмотреть результат в консоли:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$ScriptDir\run_now.ps1`" -Console"
Write-Host "Логи: $logDir"