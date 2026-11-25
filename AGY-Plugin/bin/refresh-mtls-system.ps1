[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$InstallRoot = "C:\Program Files\Nandi",
    [string]$ProgramDataRoot = "C:\ProgramData\Nandi",
    [string]$WorkloadAudience = "",
    [string]$ServiceAccountEmail = "",
    [string]$CertThumbprint = "",
    [string]$TrustChainPath = "C:\ProgramData\Nandi\certs\inter.crt"
)

$ErrorActionPreference = "Stop"

$PluginRoot = if ((-not $PSBoundParameters.ContainsKey("InstallRoot")) -and
    (Test-Path (Join-Path $PSScriptRoot "..\src\cli\refresh_adc_token.py") -PathType Leaf)) {
    (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
} else {
    Join-Path $InstallRoot "AGY-Plugin"
}
$CacheDir = Join-Path $ProgramDataRoot "cache"
$TokenFile = Join-Path $CacheDir "access_token"
$CredConfigPath = Join-Path $ProgramDataRoot "certs\private\cred-config.json"
$VenvPython = Join-Path $PluginRoot ".venv\Scripts\python.exe"
$RefreshCliPath = Join-Path $PluginRoot "src\cli\refresh_adc_token.py"
$MtlsCommonPath = Join-Path $PluginRoot "bin\mtls-sts-common.ps1"
if (-not (Test-Path $MtlsCommonPath -PathType Leaf)) {
    $MtlsCommonPath = Join-Path $PSScriptRoot "mtls-sts-common.ps1"
}

function Invoke-Icacls {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & icacls @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE for arguments: $($Arguments -join ' ')"
    }
}

New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
Invoke-Icacls -Arguments @($CacheDir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")

if (-not (Test-Path $CredConfigPath -PathType Leaf)) {
    if (-not (Test-Path $MtlsCommonPath -PathType Leaf)) {
        throw "Missing SYSTEM credential config at $CredConfigPath and mTLS helper not found at $MtlsCommonPath"
    }
    if ([string]::IsNullOrWhiteSpace($WorkloadAudience)) {
        throw "Certificate-store mTLS refresh requires -WorkloadAudience"
    }
    . $MtlsCommonPath
    Invoke-CertStoreMtlsTokenRefresh `
        -StoreScope "LocalMachine" `
        -Audience $WorkloadAudience `
        -OutputTokenFile $TokenFile `
        -ServiceAccountEmail $ServiceAccountEmail `
        -CertThumbprint $CertThumbprint `
        -TrustChainPath $TrustChainPath
    exit 0
}

foreach ($ReqFile in @($VenvPython, $RefreshCliPath)) {
    if (-not (Test-Path $ReqFile -PathType Leaf)) {
        throw "Required SYSTEM mTLS refresh dependency missing: $ReqFile"
    }
}
& $VenvPython $RefreshCliPath $CredConfigPath $TokenFile "15"
if ($LASTEXITCODE -ne 0) {
    throw "SYSTEM mTLS token refresh failed with exit code $LASTEXITCODE"
}
