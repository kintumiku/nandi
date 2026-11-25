# Architecture 2 (WorkloadX509 Options 2A and 2B) installer channel module
# dot-sourced by install-enterprise-windows.ps1.

$script:IsOption2A = $false
$script:IsOption2B = $false
$script:UsePemMode = $false
$script:WorkloadAudienceNormalized = ""

function Test-ChannelParameters {
    if ([string]::IsNullOrWhiteSpace($WorkloadAudience)) {
        throw "Architecture 2 (WorkloadX509) requires -WorkloadAudience."
    }
    $script:WorkloadAudienceNormalized = if ($WorkloadAudience.Trim().StartsWith("//iam.googleapis.com/")) {
        $WorkloadAudience.Trim()
    } else {
        "//iam.googleapis.com/" + $WorkloadAudience.Trim().TrimStart("/")
    }
    if ($script:WorkloadAudienceNormalized -notmatch '^//iam\.googleapis\.com/projects/\d+/locations/global/workloadIdentityPools/[^/]+/providers/[^/]+$') {
        throw "Invalid -WorkloadAudience '$WorkloadAudience'. Expected //iam.googleapis.com/projects/<NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>."
    }

    $script:IsOption2A = -not [string]::IsNullOrWhiteSpace($ServiceAccountEmail)
    $script:IsOption2B = [string]::IsNullOrWhiteSpace($ServiceAccountEmail)
    if ($script:IsOption2A) {
        $HasCertPath = -not [string]::IsNullOrWhiteSpace($MachineCertPath)
        $HasKeyPath = -not [string]::IsNullOrWhiteSpace($MachineKeyPath)
        if ($HasCertPath -ne $HasKeyPath) {
            throw "Pass both -MachineCertPath and -MachineKeyPath, or neither."
        }
        if ($HasCertPath) {
            foreach ($PemPath in @($MachineCertPath, $MachineKeyPath)) {
                if (-not (Test-Path $PemPath -PathType Leaf)) {
                    throw "PEM file not found: $PemPath"
                }
                $FullPemPath = [System.IO.Path]::GetFullPath($PemPath)
                foreach ($ManagedRoot in @($ProgramDataRoot, $InstallRoot)) {
                    if ($FullPemPath.StartsWith($ManagedRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "$PemPath is under $ManagedRoot, which this installer deletes and recreates. Keep it elsewhere."
                    }
                }
            }
            $script:UsePemMode = $true
        }
        return (Join-Path $ProgramDataRoot "cache\access_token")
    }
    return "%LOCALAPPDATA%\Nandi\cache\access_token"
}

function Install-ChannelCredentialArtifacts {
    $SrcInter = Join-Path $BundleDir "inter.crt"
    $DestInter = Join-Path $CertsDir "inter.crt"
    if (Test-Path $SrcInter -PathType Leaf) {
        Copy-Item -Path $SrcInter -Destination $DestInter -Force
    }
    if (-not $script:IsOption2A) { return }

    $PrivateCertsDir = Join-Path $CertsDir "private"
    Reset-LockedDirectory -Path $PrivateCertsDir -SystemOnly
    if (-not $script:UsePemMode) { return }

    $CertConfigPath = Join-Path $PrivateCertsDir "certificate_config.json"
    $CertConfig = @{
        version = 1
        cert_configs = @{
            workload = @{
                cert_path = ($MachineCertPath -replace "\\", "/")
                key_path = ($MachineKeyPath -replace "\\", "/")
            }
        }
    }
    Write-Utf8NoBom -Path $CertConfigPath -Content ($CertConfig | ConvertTo-Json -Depth 6)

    $CertSource = @{ certificate_config_location = ($CertConfigPath -replace "\\", "/") }
    if (Test-Path $DestInter -PathType Leaf) {
        $CertSource["trust_chain_path"] = ($DestInter -replace "\\", "/")
    }
    $Cred2A = @{
        universe_domain = "googleapis.com"
        type = "external_account"
        audience = $script:WorkloadAudienceNormalized
        subject_token_type = "urn:ietf:params:oauth:token-type:mtls"
        token_url = "https://sts.mtls.googleapis.com/v1/token"
        service_account_impersonation_url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${ServiceAccountEmail}:generateAccessToken"
        credential_source = @{ certificate = $CertSource }
    }
    Write-Utf8NoBom -Path (Join-Path $PrivateCertsDir "cred-config.json") -Content ($Cred2A | ConvertTo-Json -Depth 6)
}

function Register-ChannelScheduledTask {
    if ($script:IsOption2A) {
        $RefreshScript = Join-Path $DestPlugin "bin\refresh-mtls-system.ps1"
        $ArgParts = @("-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", "`"$RefreshScript`"", "-WorkloadAudience", "`"$script:WorkloadAudienceNormalized`"", "-ServiceAccountEmail", "`"$ServiceAccountEmail`"")
        $InitialRefreshArgs = @{
            InstallRoot = $InstallRoot
            ProgramDataRoot = $ProgramDataRoot
            WorkloadAudience = $script:WorkloadAudienceNormalized
            ServiceAccountEmail = $ServiceAccountEmail
        }
        if ($CertThumbprint) {
            $ArgParts += @("-CertThumbprint", "`"$CertThumbprint`"")
            $InitialRefreshArgs["CertThumbprint"] = $CertThumbprint
        }
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($ArgParts -join " ")
        $StartupTrigger = New-ScheduledTaskTrigger -AtStartup
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "Nandi-System-mTLS-Refresh" -Action $Action -Trigger @($StartupTrigger, $RepeatTrigger) -Principal $Principal -Settings $TaskSettings -Force | Out-Null
        & $RefreshScript @InitialRefreshArgs
    } else {
        $SyncScript = Join-Path $DestPlugin "bin\sync-user-nandi.ps1"
        $ArgParts = @("-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", "`"$SyncScript`"", "-AuthMode", "WorkloadX509User", "-WorkloadAudience", "`"$script:WorkloadAudienceNormalized`"")
        if ($CertThumbprint) {
            $ArgParts += @("-CertThumbprint", "`"$CertThumbprint`"")
        }
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($ArgParts -join " ")
        $LogonTrigger = New-ScheduledTaskTrigger -AtLogOn
        $Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-4" -RunLevel Limited
        Register-ScheduledTask -TaskName "Nandi-User-mTLS-Sync" -Action $Action -Trigger @($LogonTrigger, $RepeatTrigger) -Principal $Principal -Settings $TaskSettings -Force | Out-Null
        Start-ScheduledTask -TaskName "Nandi-User-mTLS-Sync" -ErrorAction SilentlyContinue
    }
}
