#
# groky installer for Windows PowerShell
# https://github.com/yuWorm/groky
#
#   irm https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.ps1 | iex
#   $env:GROKY_VERSION="0.1.15"; irm ... | iex
#
# A pinned GROKY_VERSION downloads github.com/releases/download directly
# (no api.github.com). Unpinned still hits /releases/latest.
#

param(
    [Parameter(Position = 0)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

if (-not $Version -and $env:GROKY_VERSION) { $Version = $env:GROKY_VERSION }

$Repo = if ($env:GROKY_REPO) { $env:GROKY_REPO } else { 'yuWorm/groky' }
$BinDir = if ($env:GROKY_BIN_DIR) { $env:GROKY_BIN_DIR } else { Join-Path $env:USERPROFILE '.groky\bin' }

$headers = @{ 'Accept' = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
$token = $env:GROKY_GITHUB_TOKEN
if (-not $token) { $token = $env:GITHUB_TOKEN }
if ($token) { $headers['Authorization'] = "Bearer $token" }

if ($Version) {
    $tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
    Write-Host "Fetching groky $tag from $Repo (direct download, no GitHub API)..."
} else {
    Write-Host "Fetching latest groky release from $Repo..."
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $api -Headers $headers
    $tag = $release.tag_name
}

$ver = $tag.TrimStart('v')
$assetName = "groky-$ver-windows-x86_64.exe"
$url = "https://github.com/$Repo/releases/download/$tag/$assetName"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$dest = Join-Path $BinDir 'groky.exe'
$tmp = Join-Path $BinDir 'groky.exe.tmp'
Write-Host "  Downloading $assetName..."
Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
if (Test-Path $dest) {
    Move-Item -Force $dest (Join-Path $BinDir 'groky.exe.old') -ErrorAction SilentlyContinue
}
Move-Item -Force $tmp $dest
Remove-Item -Force (Join-Path $BinDir 'groky.exe.old') -ErrorAction SilentlyContinue

$already = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($already -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$BinDir;$already", 'User')
    $env:Path = "$BinDir;$env:Path"
    Write-Host "  Added $BinDir to the user PATH"
}

Write-Host ""
Write-Host "groky $ver installed to $dest"
Write-Host "Run:  groky --version"
Write-Host "This does not replace official grok (%USERPROFILE%\.grok\bin\grok.exe)."
