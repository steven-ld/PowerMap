# Register one PowerMap process that starts at logon and keeps the unified
# configuration at %APPDATA%\powermap\powermap.toml.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BinaryPath,
    [string]$ConfigPath,
    [switch]$StartNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDirectory = Join-Path $env:LOCALAPPDATA 'PowerMap'
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $stateDirectory 'bin\powermap.exe'
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw 'PowerMap binary not found. Run scripts/install.ps1 first or pass -BinaryPath.'
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path (Join-Path $env:APPDATA 'powermap') 'powermap.toml'
}

$logDirectory = Join-Path $stateDirectory 'logs'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$logPath = Join-Path $logDirectory 'powermap.log'
$wrapperPath = Join-Path $stateDirectory 'run-powermap.ps1'

function Quote-PowerShellLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

$wrapper = @"
`$ErrorActionPreference = 'Stop'
& $(Quote-PowerShellLiteral ([System.IO.Path]::GetFullPath($BinaryPath))) --config $(Quote-PowerShellLiteral ([System.IO.Path]::GetFullPath($ConfigPath))) *>> $(Quote-PowerShellLiteral ([System.IO.Path]::GetFullPath($logPath)))
exit `$LASTEXITCODE
"@
Set-Content -LiteralPath $wrapperPath -Value $wrapper -Encoding utf8 -Force

$action = New-ScheduledTaskAction -Execute "$PSHOME\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$wrapperPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

if ($PSCmdlet.ShouldProcess('PowerMap', 'Register unified PowerMap task')) {
    Register-ScheduledTask -TaskName 'PowerMap' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'PowerMap unified managed process' -Force | Out-Null
    Write-Host "Registered PowerMap. Logs: $logPath"
    if ($StartNow) { Start-ScheduledTask -TaskName 'PowerMap' }
}
