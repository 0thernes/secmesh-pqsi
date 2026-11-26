# SPDX-License-Identifier: Apache-2.0
# SecMesh-PQSI v3.0.0 — Windows Background Service / Scheduled Task Installer (Opt-In)
# Usage (elevated PowerShell):
#   pwsh -File deploy\install-windows-service.ps1 -InstallDir "Z:\[Vibe Coded (AI)]\ANTIGRAVITY\secmesh-pqsi" -Mode DryRun
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [ValidateSet('DryRun', 'Register', 'Remove')]
    [string]$Mode = 'DryRun',
    [string]$TaskName = 'SecMesh-PQSI-v3-Daemon'
)

$ErrorActionPreference = 'Stop'
$cliPath = Join-Path $InstallDir 'node\src\secmesh-cli.mjs'
if (-not (Test-Path -LiteralPath $cliPath)) {
    throw "SecMesh CLI not found at: $cliPath"
}

$nodeBin = (Get-Command node -ErrorAction Stop).Source
Write-Host "SecMesh-PQSI v3.0 Windows Service Helper"
Write-Host "  Node Binary : $nodeBin"
Write-Host "  CLI Entry   : $cliPath"
Write-Host "  Task Name   : $TaskName"
Write-Host "  Mode        : $Mode"

if ($Mode -eq 'DryRun') {
    Write-Host "[DryRun] Would register SYSTEM startup task running: `"$nodeBin`" `"$cliPath`" audit"
    Write-Host "[DryRun] For kernel L3 Wintun NIC, place official signed wintun.dll in System32 or InstallDir."
    exit 0
}

if ($Mode -eq 'Remove') {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task: $TaskName"
    exit 0
}

$action = New-ScheduledTaskAction -Execute $nodeBin -Argument "`"$cliPath`" audit" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Registered hardened Windows task '$TaskName' under LOCAL SERVICE."
