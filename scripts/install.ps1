# Install released PowerMap binaries for the current Windows user.
[CmdletBinding()]
param(
    [ValidatePattern('^(latest|v[0-9][0-9A-Za-z.\-+]*)$')]
    [string]$Version = $(if ($env:POWERMAP_VERSION) { $env:POWERMAP_VERSION } else { 'latest' }),

    [string]$InstallDir = $(if ($env:POWERMAP_INSTALL_DIR) {
        $env:POWERMAP_INSTALL_DIR
    }
    elseif ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA 'PowerMap\bin'
    }
    else {
        Join-Path $HOME 'AppData\Local\PowerMap\bin'
    })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'steven-ld/PowerMap'
$target = 'x86_64-pc-windows-msvc'
$archive = "powermap-$target.zip"
$checksumFile = "powermap-$target.sha256"

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'PowerMap currently publishes Windows binaries only for 64-bit systems.'
}

if ($Version -eq 'latest') {
    $baseUrl = "https://github.com/$repository/releases/latest/download"
    $releasePage = "https://github.com/$repository/releases/latest"
}
else {
    $baseUrl = "https://github.com/$repository/releases/download/$Version"
    $releasePage = "https://github.com/$repository/releases/tag/$Version"
}

function Download-ReleaseAsset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Asset,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Invoke-WebRequest -Uri "$baseUrl/$Asset" -OutFile $OutputPath -UseBasicParsing
    }
    catch {
        $message = "Unable to download $Asset for $target from PowerMap $Version. " +
            'The release may not include assets for this platform yet, or the network request failed. ' +
            "Release page: $releasePage"
        if ($Version -eq 'latest') {
            $message += ' Retry shortly, or install a published version explicitly: .\install.ps1 -Version v0.2.0'
        }
        throw $message
    }
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("powermap-install-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

try {
    $archivePath = Join-Path $temporaryDirectory $archive
    $checksumPath = Join-Path $temporaryDirectory $checksumFile

    Write-Host "Downloading PowerMap $Version for $target..."
    Download-ReleaseAsset -Asset $archive -OutputPath $archivePath
    Download-ReleaseAsset -Asset $checksumFile -OutputPath $checksumPath

    $expectedChecksum = (Get-Content -LiteralPath $checksumPath -Raw).Trim().Split([char[]]" `t", [System.StringSplitOptions]::RemoveEmptyEntries)[0]
    if ($expectedChecksum -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "Invalid SHA-256 checksum in $checksumFile."
    }

    $actualChecksum = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if (-not $actualChecksum.Equals($expectedChecksum, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 mismatch for $archive. The download was not installed."
    }

    $unpackDirectory = Join-Path $temporaryDirectory 'unpacked'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $unpackDirectory -Force
    $server = Get-ChildItem -LiteralPath $unpackDirectory -Filter 'powermap-server.exe' -File -Recurse | Select-Object -First 1
    $client = Get-ChildItem -LiteralPath $unpackDirectory -Filter 'powermap-client.exe' -File -Recurse | Select-Object -First 1
    if ($null -eq $server -or $null -eq $client) {
        throw "The release archive does not contain both PowerMap executables."
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -LiteralPath $server.FullName -Destination (Join-Path $InstallDir 'powermap-server.exe') -Force
    Copy-Item -LiteralPath $client.FullName -Destination (Join-Path $InstallDir 'powermap-client.exe') -Force

    Write-Host "Installed powermap-server.exe and powermap-client.exe to $InstallDir"
    $pathEntries = $env:Path -split [System.IO.Path]::PathSeparator
    if ($pathEntries -notcontains $InstallDir) {
        Write-Host "Add $InstallDir to your user PATH to run PowerMap from any terminal."
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
