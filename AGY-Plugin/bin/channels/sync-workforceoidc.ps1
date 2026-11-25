# Architecture 1 (WorkforceOIDC) user-session sync module dot-sourced by sync-user-nandi.ps1.

$TemplatePath = Join-Path $EffectiveInstallRoot "cred-config.template.json"
$UserCredConfig = Join-Path $UserNandiDir "cred-config.json"
$OutputFileForward = (Join-Path $UserCacheDir "idp_oidc_cache.json") -replace "\\", "/"

if (-not (Test-Path $TemplatePath -PathType Leaf)) {
    throw "Credential config template not found at $TemplatePath"
}
$Rendered = [System.IO.File]::ReadAllText($TemplatePath, $Utf8NoBom).Replace("__USER_OUTPUT_FILE__", $OutputFileForward)
Write-Utf8NoBomAtomic -Path $UserCredConfig -Content $Rendered

Set-UserEnvSafe -Name "GOOGLE_APPLICATION_CREDENTIALS" -Value $UserCredConfig
Set-UserEnvSafe -Name "GCP_ACCESS_TOKEN_FILE" -Value $TokenFile
Publish-EnvironmentChangeSafe
$env:GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = "1"
Invoke-PythonTokenRefresh -PythonExe $VenvPython -CredConfigPath $UserCredConfig -TargetTokenPath $TokenFile
