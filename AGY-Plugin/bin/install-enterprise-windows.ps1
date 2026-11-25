[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [string]$AuthMode,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(//iam\.googleapis\.com/)?locations/[^/]+/workforcePools/[^/]+/providers/[^/]+$')]
    [string]$WifProvider,

    [Parameter(Mandatory = $true)]
    [string]$ProjectId,

    [string]$Location = "asia-south1",
    [string]$TemplateId = "Nandi-compliance-template",
    [ValidateSet("fsi-model-armor-guard", "fsi-unified-guard")]
    [string]$GuardProfile = "fsi-model-armor-guard",
    [string]$CustomCaPemPath = "",
    [switch]$EnableGranularGeminiAcls
)

$ErrorActionPreference = "Stop"

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$BundleDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallRoot = "C:\Program Files\Nandi"
$ProgramDataRoot = "C:\ProgramData\Nandi"
$HelperBinDir = Join-Path $ProgramDataRoot "bin"
$AntigravityDir = "C:\Program Files\Google\Antigravity"
$AntigravityPolicyDir = "C:\ProgramData\Antigravity"

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    $Parent = Split-Path -Parent $Path
    if ($Parent -and (-not (Test-Path $Parent))) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Set-MachineEnvSafe {
    param([string]$Name, [string]$Value)
    # Write directly to HKLM instead of [Environment]::SetEnvironmentVariable(..., "Machine"),
    # which calls SendMessageTimeout(..., SMTO_NORMAL) and hangs in Session 0 (SYSTEM).
    $RegPath = "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment"
    Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type String
    Set-Item -Path "Env:\$Name" -Value $Value
}

function Invoke-Icacls {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & icacls @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE for arguments: $($Arguments -join ' ')"
    }
}

function Reset-LockedDirectory {
    param([string]$Path, [switch]$SystemOnly)
    if (Test-Path $Path) { Remove-Item -Path $Path -Recurse -Force }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Invoke-Icacls -Arguments @($Path, "/setowner", "*S-1-5-32-544")
    if ($SystemOnly) {
        Invoke-Icacls -Arguments @($Path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
    } else {
        Invoke-Icacls -Arguments @($Path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    }
}

function Set-YamlQuotedScalar {
    param([string]$YamlText, [string]$Key, [string]$Value)
    $YamlEscaped = ($Value -replace "\\", "\\") -replace '"', '\"'
    $RegexSafe = $YamlEscaped -replace '\$', '$$$$'
    $Pattern = "(?m)^([ \t]*$([regex]::Escape($Key)):[ \t]*).*$"
    if ($YamlText -match $Pattern) {
        return ($YamlText -replace $Pattern, ('${1}"' + $RegexSafe + '"'))
    }
    $AnchorPattern = "(?m)^([ \t]*template_id:[ \t]*.*)$"
    if ($YamlText -match $AnchorPattern) {
        return ($YamlText -replace $AnchorPattern, ('${1}' + "`n  " + $Key + ': "' + $RegexSafe + '"'))
    }
    return $YamlText
}

function Test-Python312x64 {
    param([string]$ExePath)
    if ([string]::IsNullOrWhiteSpace($ExePath) -or (-not (Test-Path $ExePath -PathType Leaf))) {
        return $false
    }
    if (($ExePath -match '\\WindowsApps\\') -or ($ExePath -match '^[A-Za-z]:\\Users\\')) {
        return $false
    }
    & $ExePath -c "import struct, sys; sys.exit(0 if sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)"
    return ($LASTEXITCODE -eq 0)
}

function Resolve-SystemPython312 {
    $Candidates = New-Object System.Collections.Generic.List[string]
    $Candidates.Add("C:\Program Files\Python312\python.exe")
    foreach ($Hit in (Get-Command python.exe -All -ErrorAction SilentlyContinue)) {
        if ($Hit.Source -and (-not $Candidates.Contains($Hit.Source))) {
            $Candidates.Add($Hit.Source)
        }
    }
    foreach ($Candidate in $Candidates) {
        if (Test-Python312x64 -ExePath $Candidate) { return $Candidate }
    }
    return ""
}

# Stage 0: Validate bundle contents and channel-specific parameters upfront.
$SrcPlugin = Join-Path $BundleDir "AGY-Plugin"
if (-not (Test-Path $SrcPlugin -PathType Container)) {
    $ParentCandidate = Split-Path -Parent $BundleDir
    if (Test-Path (Join-Path $ParentCandidate "plugin.json") -PathType Leaf) {
        $SrcPlugin = $ParentCandidate
    } else {
        throw "AGY-Plugin folder not found in bundle at $SrcPlugin"
    }
}
$WheelsDir = Join-Path $BundleDir "wheels"
if (-not (Test-Path $WheelsDir -PathType Container)) {
    throw "Offline wheels folder not found in bundle at $WheelsDir"
}
if ($CustomCaPemPath -and (-not (Test-Path $CustomCaPemPath -PathType Leaf))) {
    throw "Specified -CustomCaPemPath not found: $CustomCaPemPath"
}

$ModeSlug = $AuthMode.Trim().ToLowerInvariant()
$SrcChannelModule = Join-Path $SrcPlugin "bin\channels\install-$ModeSlug.ps1"
if (-not (Test-Path $SrcChannelModule -PathType Leaf)) {
    throw "Unsupported or uninstalled -AuthMode '$AuthMode' (missing channel module $SrcChannelModule)."
}
. $SrcChannelModule
$WifProviderName = $WifProvider -replace '^//iam\.googleapis\.com/', ''
$TokenFileSetting = Test-ChannelParameters

# Stage 1: Silent Antigravity (NSIS /S) and 64-bit Python 3.12 installation.
Write-Host "[Stage 1/6] Installing Antigravity and verifying 64-bit Python 3.12..."
$AgyInstaller = Join-Path $BundleDir "Antigravity-x64.exe"
if (Test-Path $AgyInstaller -PathType Leaf) {
    $AgyProc = Start-Process -FilePath $AgyInstaller -ArgumentList "/S", "/ALLUSERS", "/NORESTART", "/D=$AntigravityDir" -Wait -PassThru
    if ($AgyProc.ExitCode -ne 0) {
        throw "Antigravity NSIS installer failed with exit code $($AgyProc.ExitCode)"
    }
}
$AppUpdateYml = Join-Path $AntigravityDir "resources\app-update.yml"
if (Test-Path $AppUpdateYml -PathType Leaf) {
    Remove-Item -Path $AppUpdateYml -Force
}

$PythonExe = Resolve-SystemPython312
if (-not $PythonExe) {
    $PyInstaller = Join-Path $BundleDir "python-3.12-amd64.exe"
    if (-not (Test-Path $PyInstaller -PathType Leaf)) {
        throw "64-bit machine-wide Python 3.12 is not installed and $PyInstaller was not found in bundle."
    }
    $PyProc = Start-Process -FilePath $PyInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait -PassThru
    if ($PyProc.ExitCode -ne 0) {
        throw "Python installer failed with exit code $($PyProc.ExitCode)"
    }
    $PythonExe = "C:\Program Files\Python312\python.exe"
    if (-not (Test-Python312x64 -ExePath $PythonExe)) {
        throw "Installed Python at $PythonExe did not pass 64-bit Python 3.12 verification."
    }
}

# Stage 2: Anti-squatting directories, plugin staging, and offline .venv.
Write-Host "[Stage 2/6] Staging Nandi plugin and building offline Python .venv..."
foreach ($LockedDir in @(
    $InstallRoot,
    $ProgramDataRoot,
    $HelperBinDir,
    (Join-Path $ProgramDataRoot "cache"),
    (Join-Path $ProgramDataRoot "certs"),
    $AntigravityPolicyDir
)) {
    Reset-LockedDirectory -Path $LockedDir
}

$DestPlugin = Join-Path $InstallRoot "AGY-Plugin"
Copy-Item -Path $SrcPlugin -Destination $DestPlugin -Recurse -Force

$VenvDir = Join-Path $DestPlugin ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
& $PythonExe -m venv --clear $VenvDir
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create Python venv at $VenvDir"
}

$PipPackages = New-Object System.Collections.Generic.List[string]
foreach ($BasePkg in @("google-auth", "requests", "urllib3", "certifi")) {
    $PipPackages.Add($BasePkg)
}
if (Get-ChildItem -Path $WheelsDir -Filter "cryptography*" -File -ErrorAction SilentlyContinue) {
    $PipPackages.Add("cryptography")
}
& $VenvPython -m pip install --no-index --find-links $WheelsDir @($PipPackages.ToArray())
if ($LASTEXITCODE -ne 0) {
    throw "Offline pip install from $WheelsDir failed with exit code $LASTEXITCODE"
}

# Stage 3: Dual Corporate Root CA Bundle (Automatic Cert:\LocalMachine\Root or Manual PEM).
Write-Host "[Stage 3/6] Building combined CA bundle for TLS inspection proxy compatibility..."
$CertsDir = Join-Path $ProgramDataRoot "certs"
$CombinedCaPath = Join-Path $CertsDir "combined-ca-bundle.pem"
$RefreshCliPath = Join-Path $DestPlugin "src\cli\refresh_adc_token.py"

$ExtraCaPem = if ($CustomCaPemPath) {
    [System.IO.File]::ReadAllText($CustomCaPemPath, $Utf8NoBom)
} else {
    $PemBlocks = New-Object System.Collections.Generic.List[string]
    foreach ($Cert in (Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue)) {
        $Base64 = [System.Convert]::ToBase64String($Cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
        $PemBlocks.Add("-----BEGIN CERTIFICATE-----`n$Base64`n-----END CERTIFICATE-----")
    }
    ($PemBlocks -join "`n") + "`n"
}

# Avoid piping native python.exe into Select-Object -First 1, which kills python.exe in PS 5.1.
$CertifiLines = @(& $VenvPython $RefreshCliPath --print-certifi)
$CertifiExit = $LASTEXITCODE
$CertifiPath = if ($CertifiLines.Count -gt 0) { ([string]$CertifiLines[0]).Trim() } else { "" }
if (($CertifiExit -ne 0) -or [string]::IsNullOrWhiteSpace($CertifiPath) -or (-not (Test-Path $CertifiPath -PathType Leaf))) {
    throw "Failed to resolve certifi CA bundle path from $VenvPython (exit $CertifiExit)"
}
$CertifiPem = [System.IO.File]::ReadAllText($CertifiPath, $Utf8NoBom)
if ([string]::IsNullOrWhiteSpace($CertifiPem)) {
    throw "Resolved certifi CA bundle at $CertifiPath is empty."
}
Write-Utf8NoBom -Path $CombinedCaPath -Content ($CertifiPem.TrimEnd() + "`n`n" + $ExtraCaPem.TrimStart())
Set-MachineEnvSafe -Name "REQUESTS_CA_BUNDLE" -Value $CombinedCaPath
Set-MachineEnvSafe -Name "SSL_CERT_FILE" -Value $CombinedCaPath

# Stage 4: Channel credential artifacts, admin_settings.json, and config.yaml.
Write-Host "[Stage 4/6] Writing locked policy, credential configs, and config.yaml..."
Install-ChannelCredentialArtifacts

$AdminSettings = @{
    caCertPath = $CombinedCaPath
    authControls = @{
        wifProvider = $WifProviderName
        disableConsumerLogin = $true
    }
    pluginControls = @{
        pluginsDisabled = $true
        marketplaceDisabled = $true
    }
}
Write-Utf8NoBom -Path (Join-Path $AntigravityPolicyDir "admin_settings.json") -Content ($AdminSettings | ConvertTo-Json -Depth 4)

$ConfigYamlPath = Join-Path $DestPlugin "config\config.yaml"
if (-not (Test-Path $ConfigYamlPath -PathType Leaf)) {
    throw "config.yaml not found at $ConfigYamlPath"
}
$CfgText = [System.IO.File]::ReadAllText($ConfigYamlPath, $Utf8NoBom)
$CfgText = Set-YamlQuotedScalar -YamlText $CfgText -Key "project_id" -Value $ProjectId
$CfgText = Set-YamlQuotedScalar -YamlText $CfgText -Key "location" -Value $Location
$CfgText = Set-YamlQuotedScalar -YamlText $CfgText -Key "template_id" -Value $TemplateId
$CfgText = Set-YamlQuotedScalar -YamlText $CfgText -Key "token_file" -Value $TokenFileSetting
Write-Utf8NoBom -Path $ConfigYamlPath -Content $CfgText

# Stage 5: Seed hooks.golden.json and existing user profiles.
Write-Host "[Stage 5/6] Seeding golden hooks.json for existing user profiles..."
$HookScriptPath = if ($GuardProfile -eq "fsi-unified-guard") {
    Join-Path $DestPlugin "src\hooks\combined_guard_hook.py"
} else {
    Join-Path $DestPlugin "src\hooks\model_armor_hook.py"
}
$HookTimeoutSeconds = if ($GuardProfile -eq "fsi-unified-guard") { 35 } else { 30 }
$HookCmdPrefix = "`"$VenvPython`" `"$HookScriptPath`""
$GoldenHooksObj = @{
    $GuardProfile = @{
        enabled = $true
        PreInvocation = @(
            @{ type = "command"; command = "$HookCmdPrefix --event=pre_invocation"; timeout = $HookTimeoutSeconds }
        )
        PreToolUse = @(
            @{
                matcher = ".*"
                hooks = @(
                    @{ type = "command"; command = "$HookCmdPrefix --event=pre_tool_use"; timeout = $HookTimeoutSeconds }
                )
            }
        )
        PostInvocation = @(
            @{ type = "command"; command = "$HookCmdPrefix --event=post_invocation"; timeout = 15 }
        )
    }
}
$GoldenHooksJson = $GoldenHooksObj | ConvertTo-Json -Depth 10
Write-Utf8NoBom -Path (Join-Path $InstallRoot "hooks.golden.json") -Content $GoldenHooksJson

$UserProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
foreach ($ProfileDir in $UserProfiles) {
    $GeminiRootDir = Join-Path $ProfileDir.FullName ".gemini"
    $GeminiCfgDir = Join-Path $GeminiRootDir "config"
    $HooksPath = Join-Path $GeminiCfgDir "hooks.json"
    if (-not (Test-Path $GeminiCfgDir)) {
        New-Item -ItemType Directory -Path $GeminiCfgDir -Force | Out-Null
    }
    Write-Utf8NoBom -Path $HooksPath -Content $GoldenHooksJson
    if ($EnableGranularGeminiAcls) {
        foreach ($LockedGeminiDir in @($GeminiRootDir, $GeminiCfgDir)) {
            Invoke-Icacls -Arguments @($LockedGeminiDir, "/setowner", "*S-1-5-18")
            Invoke-Icacls -Arguments @(
                $LockedGeminiDir,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-3-0:(OI)(CI)(IO)F",
                "*S-1-5-32-545:(RX,WD,AD)",
                "*S-1-5-32-545:(OI)(CI)(IO)M"
            )
            Invoke-Icacls -Arguments @($LockedGeminiDir, "/deny", "*S-1-5-32-545:(DE)")
        }
        Invoke-Icacls -Arguments @($HooksPath, "/setowner", "*S-1-5-18")
        Invoke-Icacls -Arguments @($HooksPath, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-5-32-545:RX")
    }
}

# Stage 6: Register battery-safe Scheduled Task for the selected credential channel.
Write-Host "[Stage 6/6] Registering battery-safe Scheduled Task..."
$TaskSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$RepeatTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 25)
Register-ChannelScheduledTask

Write-Host "Nandi enterprise installation completed successfully for AuthMode=$AuthMode."
