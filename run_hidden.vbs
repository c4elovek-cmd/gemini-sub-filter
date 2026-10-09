' Запуск проверки без единого окна.
' WScript.Shell.Run с флагом 0 (hidden) не создаёт окно консоли вообще —
' это надёжнее, чем полагаться на -WindowStyle Hidden у PowerShell.

Option Explicit

Dim fso, scriptDir, cmd, shell
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden " & _
      "-File """ & scriptDir & "\run_now.ps1"" -Quiet"

Set shell = CreateObject("WScript.Shell")
' 0 = скрыто, False = не ждать завершения
shell.Run cmd, 0, False