# Register a current-user PowerMap process that starts at logon and records
# stdout/stderr locally. Run after scripts/install.ps1 has installed a release.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('client', 'server')]
    [string]$Role,

    [string]$BinaryPath,

    [string]$ConfigPath,

    [switch]$StartNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDirectory = Join-Path $env:LOCALAPPDATA 'PowerMap'
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $stateDirectory "bin\powermap-$Role.exe"
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "PowerMap binary not found: $BinaryPath. Run scripts/install.ps1 first or pass -BinaryPath."
}

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path (Join-Path $env:APPDATA 'powermap') "powermap-$Role.toml"
}

$logDirectory = Join-Path $stateDirectory 'logs'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$logPath = Join-Path $logDirectory "powermap-$Role.log"
$wrapperPath = Join-Path $stateDirectory "run-powermap-$Role.ps1"

function Quote-PowerShellLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

$escapedBinary = Quote-PowerShellLiteral ([System.IO.Path]::GetFullPath($BinaryPath))
$escapedConfig = Quote-PowerShellLiteral ([System.IO.Path]::GetFullPath($ConfigPath))
$escapedLog = Quote-PowerShellLiteral ([System.IO.Path]::GetFullPath($logPath))
$wrapper = @"
`$ErrorActionPreference = 'Stop'
`$binary = $escapedBinary
`$arguments = @('--config', $escapedConfig)
& `$binary @arguments *>> $escapedLog
exit `$LASTEXITCODE
"@
Set-Content -LiteralPath $wrapperPath -Value $wrapper -Encoding utf8 -Force

$taskName = "PowerMap-$Role"
$argument = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$wrapperPath`""
$action = New-ScheduledTaskAction -Execute "$PSHOME\powershell.exe" -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

if ($PSCmdlet.ShouldProcess($taskName, 'Register current-user PowerMap scheduled task')) {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "PowerMap $Role managed process" -Force | Out-Null
    Write-Host "Registered $taskName. Logs: $logPath"
    if ($StartNow) {
        Start-ScheduledTask -TaskName $taskName
        Write-Host "Started $taskName."
    }
}
