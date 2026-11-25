# Pluggable external-account executable script implementing Google Auth AIP-4117
# (https://google.aip.dev/auth/4117) natively in Windows PowerShell 5.1 (.NET 4.8).

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-CorporateOidcToken {
    param([string[]]$CliArgs)
    for ($i = 0; $i -lt ($CliArgs.Count - 1); $i++) {
        if ([string]::Equals($CliArgs[$i], "--token-file", [System.StringComparison]::OrdinalIgnoreCase)) {
            $FileToken = [System.IO.File]::ReadAllText($CliArgs[$i + 1], [System.Text.Encoding]::UTF8).Trim()
            if (-not [string]::IsNullOrWhiteSpace($FileToken)) {
                return $FileToken
            }
        }
    }
    $EnvToken = [System.Environment]::GetEnvironmentVariable("NANDI_IDP_OIDC_TOKEN")
    if (-not [string]::IsNullOrWhiteSpace($EnvToken)) {
        return $EnvToken.Trim()
    }
    throw "No OIDC ID token source configured. Set NANDI_IDP_OIDC_TOKEN, pass -IdpTokenFile, or customize get-idp-oidc-token.ps1."
}

function Get-ClampedExpirationEpoch {
    param([string]$IdToken, [int64]$NowEpoch)
    $DefaultExpiry = $NowEpoch + 2700
    $Parts = $IdToken.Split('.')
    if (($Parts.Length -eq 3) -and $Parts[0].StartsWith("eyJ", [System.StringComparison]::Ordinal) -and ($Parts[1].Length -gt 0)) {
        $B64 = $Parts[1].Replace('-', '+').Replace('_', '/')
        switch ($B64.Length % 4) {
            2 { $B64 += "==" }
            3 { $B64 += "=" }
            1 { throw "Malformed base64url JWT payload." }
        }
        $PayloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($B64))
        $Claims = $PayloadJson | ConvertFrom-Json
        if ($Claims -and ($null -ne $Claims.exp)) {
            $JwtExp = [System.Convert]::ToInt64($Claims.exp)
            if ($JwtExp -le ($NowEpoch + 60)) {
                throw "Acquired OIDC ID token is expired or expires within 60 seconds."
            }
            $SafeJwtExp = $JwtExp - 60
            if ($SafeJwtExp -lt $DefaultExpiry) {
                return $SafeJwtExp
            }
        }
    }
    return $DefaultExpiry
}

function Write-CacheAtomic {
    param([string]$TargetPath, [string]$JsonText)
    $ParentDir = Split-Path -Parent $TargetPath
    if ($ParentDir -and (-not (Test-Path $ParentDir))) {
        New-Item -ItemType Directory -Path $ParentDir -Force | Out-Null
    }
    $TmpPath = "$TargetPath.tmp.$PID"
    $NoBom = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($TmpPath, $JsonText, $NoBom)
        if (Test-Path $TargetPath -PathType Leaf) {
            [System.IO.File]::Replace($TmpPath, $TargetPath, $null)
        } else {
            [System.IO.File]::Move($TmpPath, $TargetPath)
        }
    } finally {
        if (Test-Path $TmpPath -PathType Leaf) {
            Remove-Item -Path $TmpPath -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    $UnixEpochUtc = New-Object System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    $IdToken = Get-CorporateOidcToken -CliArgs $args
    $NowEpoch = [int64]([System.DateTime]::UtcNow - $UnixEpochUtc).TotalSeconds
    $ExpirationEpoch = Get-ClampedExpirationEpoch -IdToken $IdToken -NowEpoch $NowEpoch
    $ResponseJson = ([ordered]@{
        version = 1
        success = $true
        token_type = "urn:ietf:params:oauth:token-type:id_token"
        id_token = $IdToken
        expiration_time = [int64]$ExpirationEpoch
    } | ConvertTo-Json -Compress)

    $OutputFile = [System.Environment]::GetEnvironmentVariable("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE")
    if (-not [string]::IsNullOrWhiteSpace($OutputFile)) {
        Write-CacheAtomic -TargetPath $OutputFile -JsonText $ResponseJson
    }
    [System.Console]::Out.WriteLine($ResponseJson)
    exit 0
} catch {
    $ErrJson = ([ordered]@{
        version = 1
        success = $false
        code = "IDP_TOKEN_ACQUISITION_FAILED"
        message = $_.Exception.Message
    } | ConvertTo-Json -Compress)
    [System.Console]::Out.WriteLine($ErrJson)
    exit 1
}
