# Architecture 2 Option 2B (WorkloadX509User) user-session sync module
# dot-sourced by sync-user-nandi.ps1 (no service_account_impersonation_url).

Set-UserEnvSafe -Name "GCP_ACCESS_TOKEN_FILE" -Value $TokenFile
Publish-EnvironmentChangeSafe

$UserCertConfig = Join-Path $UserNandiDir "cred-config.json"
if (Test-Path $UserCertConfig -PathType Leaf) {
    Invoke-PythonTokenRefresh -PythonExe $VenvPython -CredConfigPath $UserCertConfig -TargetTokenPath $TokenFile
} else {
    $MtlsCommonPath = Join-Path $PluginRoot "bin\mtls-sts-common.ps1"
    if (-not (Test-Path $MtlsCommonPath -PathType Leaf)) {
        $MtlsCommonPath = Join-Path $PSScriptRoot "..\mtls-sts-common.ps1"
    }
    if (-not (Test-Path $MtlsCommonPath -PathType Leaf)) {
        throw "mTLS PowerShell helper not found at $MtlsCommonPath"
    }
    if ([string]::IsNullOrWhiteSpace($WorkloadAudience)) {
        throw "WorkloadX509User requires -WorkloadAudience"
    }
    . $MtlsCommonPath
    Invoke-CertStoreMtlsTokenRefresh `
        -StoreScope "CurrentUser" `
        -Audience $WorkloadAudience `
        -OutputTokenFile $TokenFile `
        -CertThumbprint $CertThumbprint `
        -TrustChainPath $TrustChainPath
}
