# Architecture 1 (WorkforceOIDC) installer channel module dot-sourced by install-enterprise-windows.ps1.

function Test-ChannelParameters {
    if ($ProjectNumber -notmatch '^\d+$') {
        throw "Architecture 1 (WorkforceOIDC) requires a numeric GCP -ProjectNumber for workforce_pool_user_project."
    }
    if ($IdpTokenFile -and $IdpTokenExecutable) {
        throw "Pass either -IdpTokenFile or -IdpTokenExecutable, not both."
    }
    if ($IdpTokenExecutable) {
        $TrimmedIdp = $IdpTokenExecutable.Trim()
        $ForwardIdp = $TrimmedIdp -replace "\\", "/"
        if ($TrimmedIdp.StartsWith('"') -or
            ((Test-Path $TrimmedIdp -PathType Leaf) -and ($TrimmedIdp -match '\s')) -or
            ($ForwardIdp -match '^[A-Za-z]:/Program Files')) {
            throw "Invalid -IdpTokenExecutable: executable path cannot contain spaces. Stage under C:\ProgramData\Nandi\bin."
        }
    }
    return "%LOCALAPPDATA%\Nandi\cache\access_token"
}

function Install-ChannelCredentialArtifacts {
    $SrcIdpPs1 = Join-Path $DestPlugin "bin\get-idp-oidc-token.ps1"
    if (-not (Test-Path $SrcIdpPs1 -PathType Leaf)) {
        throw "Required WorkforceOIDC helper missing at $SrcIdpPs1"
    }
    Copy-Item -Path $SrcIdpPs1 -Destination (Join-Path $HelperBinDir "get-idp-oidc-token.ps1") -Force

    $CredSource = if ($IdpTokenFile) {
        @{ file = ($IdpTokenFile -replace "\\", "/") }
    } else {
        $ExecCmd = if ($IdpTokenExecutable) {
            ($IdpTokenExecutable.Trim() -replace "\\", "/")
        } else {
            $DefaultIdpScript = ((Join-Path $HelperBinDir "get-idp-oidc-token.ps1") -replace "\\", "/")
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $DefaultIdpScript"
        }
        @{
            executable = @{
                command = $ExecCmd
                timeout_millis = 10000
                output_file = "__USER_OUTPUT_FILE__"
            }
        }
    }
    $CredTemplate = @{
        universe_domain = "googleapis.com"
        type = "external_account"
        audience = "//iam.googleapis.com/$WifProviderName"
        subject_token_type = "urn:ietf:params:oauth:token-type:id_token"
        token_url = "https://sts.googleapis.com/v1/token"
        workforce_pool_user_project = $ProjectNumber
        credential_source = $CredSource
    }
    Write-Utf8NoBom -Path (Join-Path $InstallRoot "cred-config.template.json") -Content ($CredTemplate | ConvertTo-Json -Depth 6)
    if (-not $IdpTokenFile) {
        Set-MachineEnvSafe -Name "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES" -Value "1"
    }
}

function Register-ChannelScheduledTask {
    $SyncScript = Join-Path $DestPlugin "bin\sync-user-nandi.ps1"
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$SyncScript`" -AuthMode WorkforceOIDC"
    $LogonTrigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-4" -RunLevel Limited
    Register-ScheduledTask -TaskName "Nandi-User-WIF-Sync" -Action $Action -Trigger @($LogonTrigger, $RepeatTrigger) -Principal $Principal -Settings $TaskSettings -Force | Out-Null
    Start-ScheduledTask -TaskName "Nandi-User-WIF-Sync" -ErrorAction SilentlyContinue
}
