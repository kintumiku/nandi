# Shared native .NET Framework 4.8 X.509 certificate-store mTLS STS helper
# dot-sourced by refresh-mtls-system.ps1 (Option 2A) and sync-workloadx509user.ps1 (Option 2B).

function Read-PemCertificatesAsBase64Der {
    param([string]$PemPath = "")
    $Result = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($PemPath)) {
        return ,$Result.ToArray()
    }
    if (-not (Test-Path $PemPath -PathType Leaf)) {
        throw "Trust chain PEM file not found: $PemPath"
    }
    $Pem = [System.IO.File]::ReadAllText($PemPath, [System.Text.Encoding]::ASCII)
    $PemBegin = "-----BEGIN CERTIFICATE-----"
    $PemEnd = "-----END CERTIFICATE-----"
    $Cursor = 0
    while ($true) {
        $BeginIdx = $Pem.IndexOf($PemBegin, $Cursor, [System.StringComparison]::Ordinal)
        if ($BeginIdx -lt 0) { break }
        $BodyStart = $BeginIdx + $PemBegin.Length
        $EndIdx = $Pem.IndexOf($PemEnd, $BodyStart, [System.StringComparison]::Ordinal)
        if ($EndIdx -lt 0) { throw "Unterminated certificate block in $PemPath" }
        $RawB64 = $Pem.Substring($BodyStart, $EndIdx - $BodyStart) -replace "[\r\n\t ]", ""
        $Result.Add([System.Convert]::ToBase64String([System.Convert]::FromBase64String($RawB64)))
        $Cursor = $EndIdx + $PemEnd.Length
    }
    if ($Result.Count -eq 0) { throw "No PEM certificates found in $PemPath" }
    return ,$Result.ToArray()
}

function Test-ClientAuthenticationEku {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($Ext in $Certificate.Extensions) {
        if ($Ext.Oid -and ($Ext.Oid.Value -eq "2.5.29.37")) {
            $EkuExt = $Ext -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
            if (-not $EkuExt) { return $true }
            foreach ($Oid in $EkuExt.EnhancedKeyUsages) {
                if ($Oid -and ($Oid.Value -eq "1.3.6.1.5.5.7.3.2")) { return $true }
            }
            return $false
        }
    }
    return $true
}

function Test-ByteArrayEqual {
    param([byte[]]$Left, [byte[]]$Right)
    if (($null -eq $Left) -or ($null -eq $Right) -or ($Left.Length -ne $Right.Length)) { return $false }
    for ($i = 0; $i -lt $Left.Length; $i++) {
        if ($Left[$i] -ne $Right[$i]) { return $false }
    }
    return $true
}

function Invoke-RestPost {
    param(
        [string]$Uri,
        [string]$ContentType,
        [byte[]]$BodyBytes,
        [string]$BearerToken = "",
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCertificate = $null
    )
    $Req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Uri)
    $Req.Method = "POST"
    $Req.ContentType = $ContentType
    $Req.Timeout = 10000
    if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
        $Req.Headers.Add("Authorization", "Bearer $BearerToken")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:HTTPS_PROXY)) {
        $Req.Proxy = New-Object System.Net.WebProxy($env:HTTPS_PROXY)
    }
    if ($null -ne $ClientCertificate) {
        [void]$Req.ClientCertificates.Add($ClientCertificate)
    }
    $Stream = $Req.GetRequestStream()
    try {
        $Stream.Write($BodyBytes, 0, $BodyBytes.Length)
    } finally {
        $Stream.Dispose()
    }
    $Resp = [System.Net.HttpWebResponse]$Req.GetResponse()
    try {
        $Reader = New-Object System.IO.StreamReader($Resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try {
            return ($Reader.ReadToEnd() | ConvertFrom-Json)
        } finally {
            $Reader.Dispose()
        }
    } finally {
        $Resp.Dispose()
    }
}

function Write-TokenFileAtomic {
    param([string]$TargetPath, [string]$TokenValue)
    $ParentDir = Split-Path -Parent $TargetPath
    if ($ParentDir -and (-not (Test-Path $ParentDir))) {
        New-Item -ItemType Directory -Path $ParentDir -Force | Out-Null
    }
    $TmpPath = "$TargetPath.tmp.$PID"
    $NoBom = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($TmpPath, $TokenValue, $NoBom)
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

function Invoke-CertStoreMtlsTokenRefresh {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("LocalMachine", "CurrentUser")]
        [string]$StoreScope,
        [Parameter(Mandatory = $true)]
        [string]$Audience,
        [Parameter(Mandatory = $true)]
        [string]$OutputTokenFile,
        [string]$ServiceAccountEmail = "",
        [string]$CertThumbprint = "",
        [string]$TrustChainPath = ""
    )
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
    $TrustChainDerB64 = @()
    if ((-not [string]::IsNullOrWhiteSpace($TrustChainPath)) -and (Test-Path $TrustChainPath -PathType Leaf)) {
        $TrustChainDerB64 = @(Read-PemCertificatesAsBase64Der -PemPath $TrustChainPath)
    }

    [byte[]]$ExpectedIssuerRaw = $null
    if ([string]::IsNullOrWhiteSpace($CertThumbprint) -and ($TrustChainDerB64.Count -gt 0)) {
        $IssuingCa = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            ,([System.Convert]::FromBase64String($TrustChainDerB64[0]))
        )
        try { $ExpectedIssuerRaw = $IssuingCa.SubjectName.RawData } finally { $IssuingCa.Dispose() }
    }

    $StoreLoc = if ($StoreScope -eq "CurrentUser") {
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    } else {
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    }
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My, $StoreLoc
    )
    $Store.Open(
        [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
        [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
    )
    $SelectedCert = $null
    try {
        $Candidates = if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
            $Store.Certificates
        } else {
            $Store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                ($CertThumbprint -replace "\s", "").ToUpperInvariant(),
                $false
            )
        }

        $Now = [System.DateTime]::Now
        $Best = $null
        foreach ($Candidate in $Candidates) {
            if ((-not $Candidate.HasPrivateKey) -or ($Now -lt $Candidate.NotBefore) -or ($Now -gt $Candidate.NotAfter)) {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
                if (-not (Test-ClientAuthenticationEku -Certificate $Candidate)) { continue }
                if (($null -ne $ExpectedIssuerRaw) -and
                    (-not (Test-ByteArrayEqual -Left $Candidate.IssuerName.RawData -Right $ExpectedIssuerRaw))) {
                    continue
                }
            }
            if (($null -eq $Best) -or ($Candidate.NotAfter -gt $Best.NotAfter)) {
                $Best = $Candidate
            }
        }
        if ($null -eq $Best) {
            throw "No unexpired client-auth certificate matching the configured issuer found in Cert:\$StoreLoc\My."
        }

        $SelectedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Best)
        $ChainList = New-Object System.Collections.Generic.List[string]
        $ChainList.Add([System.Convert]::ToBase64String($SelectedCert.RawData))
        foreach ($InterB64 in $TrustChainDerB64) { $ChainList.Add($InterB64) }
        $SubjectToken = '["' + ($ChainList.ToArray() -join '","') + '"]'

        $FormBody =
            "grant_type=" + [System.Uri]::EscapeDataString("urn:ietf:params:oauth:grant-type:token-exchange") +
            "&audience=" + [System.Uri]::EscapeDataString($Audience) +
            "&scope=" + [System.Uri]::EscapeDataString($CloudPlatformScope) +
            "&requested_token_type=" + [System.Uri]::EscapeDataString("urn:ietf:params:oauth:token-type:access_token") +
            "&subject_token_type=" + [System.Uri]::EscapeDataString("urn:ietf:params:oauth:token-type:mtls") +
            "&subject_token=" + [System.Uri]::EscapeDataString($SubjectToken)
        $StsJson = Invoke-RestPost `
            -Uri "https://sts.mtls.googleapis.com/v1/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -BodyBytes ([System.Text.Encoding]::UTF8.GetBytes($FormBody)) `
            -ClientCertificate $SelectedCert
        $StsToken = if ($StsJson -and $StsJson.access_token) { ([string]$StsJson.access_token).Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($StsToken)) {
            throw "STS mTLS response did not contain access_token."
        }

        $FinalToken = $StsToken
        if (-not [string]::IsNullOrWhiteSpace($ServiceAccountEmail)) {
            $IamUrl = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
                [System.Uri]::EscapeDataString($ServiceAccountEmail) + ":generateAccessToken"
            $IamPayload = (@{ scope = @($CloudPlatformScope); lifetime = "3600s" } | ConvertTo-Json -Compress)
            $IamJson = Invoke-RestPost `
                -Uri $IamUrl `
                -ContentType "application/json; charset=utf-8" `
                -BodyBytes ([System.Text.Encoding]::UTF8.GetBytes($IamPayload)) `
                -BearerToken $StsToken
            $FinalToken = if ($IamJson -and $IamJson.accessToken) { ([string]$IamJson.accessToken).Trim() } else { "" }
            if ([string]::IsNullOrWhiteSpace($FinalToken)) {
                throw "IAM Credentials response did not contain accessToken."
            }
        }
        Write-TokenFileAtomic -TargetPath $OutputTokenFile -TokenValue $FinalToken
    } finally {
        if ($null -ne $SelectedCert) { $SelectedCert.Dispose() }
        $Store.Close()
    }
}
