param(
    [string]$Configuration = "release",
    [string]$TorExpertBundleUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.14/tor-expert-bundle-windows-x86_64-15.0.14.tar.gz",
    [string]$OutDir = "dist/fauna-windows-x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$outPath = Join-Path $repoRoot $OutDir
$tempPath = Join-Path $repoRoot "target/fauna-package"
$stagePath = Join-Path $tempPath "fauna-windows-x64"
$exePath = Join-Path $repoRoot "target/$Configuration/fauna-desktop.exe"

if (!(Test-Path $exePath)) {
    throw "Fauna executable not found at $exePath. Run: cargo build -p fauna-desktop --release"
}

if (Test-Path $tempPath) {
    Remove-Item -LiteralPath $tempPath -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $stagePath | Out-Null

Copy-Item -LiteralPath $exePath -Destination (Join-Path $stagePath "Fauna.exe")
Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination $stagePath
Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination $stagePath

$bundlePath = Join-Path $tempPath "tor-expert-bundle.tar.gz"
Write-Host "Downloading Tor Expert Bundle..."
Invoke-WebRequest -Uri $TorExpertBundleUrl -OutFile $bundlePath

$extractPath = Join-Path $tempPath "tor-src"
New-Item -ItemType Directory -Force -Path $extractPath | Out-Null
tar -xzf $bundlePath -C $extractPath

$torExe = Get-ChildItem -LiteralPath $extractPath -Recurse -Filter "tor.exe" | Select-Object -First 1
if ($null -eq $torExe) {
    throw "tor.exe was not found in the Tor Expert Bundle."
}

$torOut = Join-Path $stagePath "bin/tor"
New-Item -ItemType Directory -Force -Path $torOut | Out-Null
$torSourceGlob = Join-Path $torExe.Directory.FullName "*"
Copy-Item -Path $torSourceGlob -Destination $torOut -Recurse -Force

$notice = @"
Fauna bundles Tor Expert Bundle for onion-service connectivity.
Tor Project download page: https://www.torproject.org/download/tor/
Bundled URL: $TorExpertBundleUrl

Tor is distributed by The Tor Project, Inc. Fauna starts a local Tor process
only for Fauna connectivity and keeps message payload encryption in fauna-core.
"@
$notice | Set-Content -LiteralPath (Join-Path $stagePath "THIRD_PARTY_NOTICES.txt") -Encoding UTF8

$zipPath = Join-Path $repoRoot "dist/fauna-windows-x64.zip"
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot "dist") | Out-Null
Compress-Archive -Path (Join-Path $stagePath "*") -DestinationPath $zipPath -Force
if (!(Test-Path $zipPath)) {
    throw "Package zip was not created at $zipPath"
}

if (Test-Path $outPath) {
    try {
        Remove-Item -LiteralPath $outPath -Recurse -Force
        Copy-Item -LiteralPath $stagePath -Destination $outPath -Recurse -Force
    } catch {
        Write-Warning "Could not refresh $outPath because a file may be in use. The zip package was still created successfully."
    }
} else {
    Copy-Item -LiteralPath $stagePath -Destination $outPath -Recurse -Force
}

Write-Host "Package created: $zipPath"
