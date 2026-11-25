[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [string]$AuthMode,
    [string]$InstallRoot = "C:\Program Files\Nandi",
    [string]$WorkloadAudience = "",
    [string]$CertThumbprint = "",
    [string]$TrustChainPath = "C:\ProgramData\Nandi\certs\inter.crt"
)

$ErrorActionPreference = "Stop"

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$PluginRoot = if ((-not $PSBoundParameters.ContainsKey("InstallRoot")) -and
    (Test-Path (Join-Path $PSScriptRoot "..\src\cli\refresh_adc_token.py") -PathType Leaf)) {
    (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
} else {
    Join-Path $InstallRoot "AGY-Plugin"
}
$EffectiveInstallRoot = if ($PSBoundParameters.ContainsKey("InstallRoot")) {
    $InstallRoot
} else {
    Split-Path -Parent $PluginRoot
}
$UserNandiDir = Join-Path $env:LOCALAPPDATA "Nandi"
$UserCacheDir = Join-Path $UserNandiDir "cache"
$UserLogsDir = Join-Path $UserNandiDir "logs"
$UserAuditLog = Join-Path $UserLogsDir "fsi_audit.log"
$TokenFile = Join-Path $UserCacheDir "access_token"
$VenvPython = Join-Path $PluginRoot ".venv\Scripts\python.exe"
$RefreshCliPath = Join-Path $PluginRoot "src\cli\refresh_adc_token.py"

New-Item -ItemType Directory -Path $UserCacheDir -Force | Out-Null
New-Item -ItemType Directory -Path $UserLogsDir -Force | Out-Null

function Set-UserEnvSafe {
    param([string]$Name, [string]$Value)
    $RegPath = "Registry::HKEY_CURRENT_USER\Environment"
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type String
    Set-Item -Path "Env:\$Name" -Value $Value
}

function Publish-EnvironmentChangeSafe {
    try {
        if (-not ("Nandi.Win32EnvBroadcast" -as [type])) {
            Add-Type -Namespace Nandi -Name Win32EnvBroadcast -MemberDefinition @"
using System;
using System.Runtime.InteropServices;
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        }
        $Result = [UIntPtr]::Zero
        [void][Nandi.Win32EnvBroadcast]::SendMessageTimeout(
            [IntPtr]0xFFFF, 0x001A, [UIntPtr]::Zero, "Environment", 0x0002, 500, [ref]$Result
        )
    } catch {}
}

function Write-Utf8NoBomAtomic {
    param([string]$Path, [string]$Content)
    $TmpPath = "$Path.tmp.$PID"
    try {
        [System.IO.File]::WriteAllText($TmpPath, $Content, $Utf8NoBom)
        Move-Item -Path $TmpPath -Destination $Path -Force
    } finally {
        if (Test-Path $TmpPath) { Remove-Item -Path $TmpPath -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-PythonTokenRefresh {
    param([string]$PythonExe, [string]$CredConfigPath, [string]$TargetTokenPath)
    foreach ($ReqFile in @($PythonExe, $RefreshCliPath, $CredConfigPath)) {
        if (-not (Test-Path $ReqFile -PathType Leaf)) {
            throw "Required token refresh dependency not found: $ReqFile"
        }
    }
    & $PythonExe $RefreshCliPath $CredConfigPath $TargetTokenPath "15"
    if ($LASTEXITCODE -ne 0) {
        throw "Python google-auth token refresh failed with exit code $LASTEXITCODE"
    }
}

Set-UserEnvSafe -Name "FSI_AUDIT_LOG_PATH" -Value $UserAuditLog

$ModeSlug = $AuthMode.Trim().ToLowerInvariant()
$SyncChannelModule = Join-Path $PluginRoot "bin\channels\sync-$ModeSlug.ps1"
if (-not (Test-Path $SyncChannelModule -PathType Leaf)) {
    $SyncChannelModule = Join-Path $PSScriptRoot "channels\sync-$ModeSlug.ps1"
}
if (-not (Test-Path $SyncChannelModule -PathType Leaf)) {
    throw "Unsupported or uninstalled user sync AuthMode '$AuthMode' (missing $SyncChannelModule)."
}
. $SyncChannelModule

# Restore ~/.gemini/config/hooks.json only if missing or drifted; ignore IT read-only locks.
$GoldenHooks = Join-Path $EffectiveInstallRoot "hooks.golden.json"
if (Test-Path $GoldenHooks -PathType Leaf) {
    $GeminiCfgDir = Join-Path $env:USERPROFILE ".gemini\config"
    $UserHooksPath = Join-Path $GeminiCfgDir "hooks.json"
    try {
        if (-not (Test-Path $GeminiCfgDir)) {
            New-Item -ItemType Directory -Path $GeminiCfgDir -Force | Out-Null
        }
        $DesiredHooks = [System.IO.File]::ReadAllText($GoldenHooks, $Utf8NoBom)
        if ((-not (Test-Path $UserHooksPath -PathType Leaf)) -or
            ([System.IO.File]::ReadAllText($UserHooksPath, $Utf8NoBom) -ne $DesiredHooks)) {
            Write-Utf8NoBomAtomic -Path $UserHooksPath -Content $DesiredHooks
        }
    } catch [System.UnauthorizedAccessException] {
        Write-Verbose "hooks.json is read-only under IT policy; skipping user-level rewrite."
    } catch [System.IO.IOException] {
        if (-not (Test-Path $UserHooksPath -PathType Leaf)) { throw }
    }
}
