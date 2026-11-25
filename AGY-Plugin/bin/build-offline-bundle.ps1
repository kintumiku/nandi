[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$OutputDir = ".\nandi-mdm-bundle",
    [string]$PythonVersion = "312",
    [string]$Platform = "win_amd64",
    [string]$AntigravityInstaller = "",
    [string]$PythonInstaller = "",
    [string]$IssuingCaCert = "",
    [string]$CustomCaPemPath = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginRoot = Split-Path -Parent $ScriptDir
$FullPluginRoot = [System.IO.Path]::GetFullPath($PluginRoot).TrimEnd('\')
$ResolvedOutputBase = if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir
} else {
    Join-Path (Get-Location).Path $OutputDir
}
$FullOutputDir = [System.IO.Path]::GetFullPath($ResolvedOutputBase).TrimEnd('\')

if ($FullOutputDir.Equals($FullPluginRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $FullOutputDir.StartsWith($FullPluginRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDir ($FullOutputDir) must be outside AGY-Plugin ($FullPluginRoot) to prevent recursive copying."
}

$OptionalFiles = New-Object System.Collections.Generic.List[hashtable]
$OptionalFiles.Add(@{ Name = "-AntigravityInstaller"; Path = $AntigravityInstaller; Dest = "Antigravity-x64.exe" })
$OptionalFiles.Add(@{ Name = "-PythonInstaller"; Path = $PythonInstaller; Dest = "python-3.12-amd64.exe" })
$OptionalFiles.Add(@{ Name = "-IssuingCaCert"; Path = $IssuingCaCert; Dest = "inter.crt" })
$OptionalFiles.Add(@{ Name = "-CustomCaPemPath"; Path = $CustomCaPemPath; Dest = "corp-root-ca.pem" })

foreach ($Entry in $OptionalFiles) {
    if ((-not [string]::IsNullOrWhiteSpace($Entry.Path)) -and (-not (Test-Path $Entry.Path -PathType Leaf))) {
        throw "Specified $($Entry.Name) file not found: $($Entry.Path)"
    }
}

$WheelsDir = Join-Path $FullOutputDir "wheels"
New-Item -ItemType Directory -Path $WheelsDir -Force | Out-Null

Write-Host "[1/3] Downloading pinned Python $PythonVersion ($Platform) wheels into $WheelsDir..."
$Packages = New-Object System.Collections.Generic.List[string]
foreach ($BasePkg in @("google-auth", "requests", "urllib3", "certifi")) {
    $Packages.Add($BasePkg)
}
if (Test-Path (Join-Path $ScriptDir "channels\install-workloadx509.ps1") -PathType Leaf) {
    $Packages.Add("cryptography")
}
& pip download @($Packages.ToArray()) --platform $Platform --python-version $PythonVersion --only-binary=:all: -d $WheelsDir
if ($LASTEXITCODE -ne 0) {
    throw "pip download failed with exit code $LASTEXITCODE"
}

Write-Host "[2/3] Staging clean AGY-Plugin and MDM installer entrypoint..."
$DestPlugin = Join-Path $FullOutputDir "AGY-Plugin"
if (Test-Path $DestPlugin) { Remove-Item -Path $DestPlugin -Recurse -Force }
Copy-Item -Path $PluginRoot -Destination $DestPlugin -Recurse -Force

foreach ($TransientRel in @(".venv", "logs")) {
    $TransientPath = Join-Path $DestPlugin $TransientRel
    if (Test-Path $TransientPath) { Remove-Item -Path $TransientPath -Recurse -Force }
}
New-Item -ItemType Directory -Path (Join-Path $DestPlugin "logs") -Force | Out-Null
Get-ChildItem -Path $DestPlugin -Directory -Recurse -Force -Filter "__pycache__" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -Path $_.FullName -Recurse -Force }
Get-ChildItem -Path (Join-Path $DestPlugin "bin") -Filter "install-nandi.*" -File -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -Path $_.FullName -Force }

$InstallerSrc = Join-Path $ScriptDir "install-enterprise-windows.ps1"
if (Test-Path $InstallerSrc -PathType Leaf) {
    Copy-Item -Path $InstallerSrc -Destination (Join-Path $FullOutputDir "install-enterprise-windows.ps1") -Force
}

Write-Host "[3/3] Staging optional installers and certificates..."
foreach ($Entry in $OptionalFiles) {
    if (-not [string]::IsNullOrWhiteSpace($Entry.Path)) {
        Copy-Item -Path $Entry.Path -Destination (Join-Path $FullOutputDir $Entry.Dest) -Force
    }
}

Write-Host "Offline MDM bundle ready at: $FullOutputDir"
