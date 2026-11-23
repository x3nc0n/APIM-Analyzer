#Requires -Version 7
<#
Performs one explicitly selected APIM credential operation on an instance included in scope.csv.
Run Check-ApimExposure.ps1 first and review Microsoft's rotation guidance before making changes.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$ResourceId,
    [Parameter(Mandatory)]
    [ValidateSet('SubscriptionPrimary', 'SubscriptionSecondary', 'ManagementPrimary', 'ManagementSecondary', 'NamedValue', 'RefreshKeyVault')]
    [string]$Action,
    [string]$ItemId,
    [string]$ScopeFile = (Join-Path $PWD 'apim-exposure\scope.csv')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Apim-Helpers.ps1')

$ResourceId = $ResourceId.Trim().TrimEnd('/')
if ($ResourceId -notmatch '^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([^/?#]+)/providers/Microsoft\.ApiManagement/service/([^/?#]+)$') {
    throw 'ResourceId must be a complete APIM service resource ID.'
}
$subscriptionId = [guid]::Empty
if (-not [guid]::TryParse($Matches[1], [ref]$subscriptionId) -or $subscriptionId -eq [guid]::Empty) {
    throw 'ResourceId contains an invalid Azure subscription ID.'
}
foreach ($segment in @($Matches[2], $Matches[3])) {
    if ($segment -match '[%\\]' -or $segment -in '.', '..') { throw 'ResourceId contains an invalid path segment.' }
}
$needsItem = $Action -in 'SubscriptionPrimary', 'SubscriptionSecondary', 'NamedValue', 'RefreshKeyVault'
if ($needsItem -and ([string]::IsNullOrWhiteSpace($ItemId) -or $ItemId -match '[/\\%?#]' -or $ItemId -in '.', '..')) {
    throw "$Action requires a valid, single-segment ItemId."
}
if (-not $needsItem -and $ItemId) { throw "$Action does not accept ItemId." }
if (-not (Test-Path -LiteralPath $ScopeFile -PathType Leaf)) {
    throw "Scope file not found: $ScopeFile. Run Check-ApimExposure.ps1 first."
}
$rows = @(Import-Csv -LiteralPath $ScopeFile)
if (-not $rows.Count) { throw "Scope file is empty: $ScopeFile." }
$decisions = @{}
foreach ($row in $rows) {
    if ([string]::IsNullOrWhiteSpace($row.id) -or $row.PSObject.Properties.Name -notcontains 'inScope') {
        throw "Invalid scope file ${ScopeFile}: every row must have id and inScope columns."
    }
    $id = $row.id.Trim().TrimEnd('/')
    if ($decisions.ContainsKey($id)) { throw "Duplicate resource ID in scope file: $id" }
    $decisions[$id] = ConvertTo-ReportBoolean $row.inScope "inScope for $id in $ScopeFile"
}
if (-not $decisions.ContainsKey($ResourceId) -or -not $decisions[$ResourceId]) {
    throw 'The target is not explicitly in scope in the exposure scan. Review and regenerate scope.csv before rotating.'
}

$base = "https://management.azure.com$ResourceId"
$api = 'api-version=2024-05-01'
$encodedItem = if ($needsItem) { [uri]::EscapeDataString($ItemId) }
$path = switch ($Action) {
    'SubscriptionPrimary'   { "/subscriptions/$encodedItem/regeneratePrimaryKey" }
    'SubscriptionSecondary' { "/subscriptions/$encodedItem/regenerateSecondaryKey" }
    'ManagementPrimary'     { '/tenant/access/regeneratePrimaryKey' }
    'ManagementSecondary'   { '/tenant/access/regenerateSecondaryKey' }
    'NamedValue'            { "/namedValues/$encodedItem" }
    'RefreshKeyVault'       { "/namedValues/$encodedItem/refreshSecret" }
}

if ($Action -like 'Subscription*' -or $Action -like 'Management*') {
    Write-Warning 'Regeneration immediately invalidates the selected key. Move every caller off it and verify access before continuing. Rotate the other key separately only after callers have switched and been tested.'
} elseif ($Action -eq 'RefreshKeyVault') {
    Write-Warning 'Create the replacement at the issuer and in Key Vault first. Update version-pinned references before refreshing. Test APIM before revoking the old credential.'
} else {
    Write-Warning 'Create the replacement at the issuer first. Updating APIM does not revoke the old credential; test APIM before revoking it.'
}
if (-not $PSCmdlet.ShouldProcess("$ResourceId$path", "Perform $Action")) { return }

$token = Invoke-AzJson @('account', 'get-access-token', '--subscription', $subscriptionId.ToString(), '--resource', 'https://management.azure.com/')
if (-not $token.accessToken) { throw 'Could not get an Azure Resource Manager token. Run az login.' }
$headers = @{ Authorization = "Bearer $($token.accessToken)" }
$itemUrl = "$base/namedValues/$encodedItem`?$api"
if ($Action -in 'NamedValue', 'RefreshKeyVault') {
    try { $current = Invoke-WebRequest -Method GET -Uri $itemUrl -Headers $headers -ErrorAction Stop }
    catch { throw 'Could not read named value metadata. Check Azure permissions and the target; no change was made.' }
    try { $metadata = $current.Content | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Named value metadata was not valid JSON; no change was made.' }
    if ($metadata.properties.secret -isnot [bool] -or -not $metadata.properties.secret) {
        throw 'The target is not a secret named value; no change was made.'
    }
    if ($null -ne $metadata.properties.keyVault -and [string]::IsNullOrWhiteSpace("$($metadata.properties.keyVault.secretIdentifier)")) {
        throw 'Named value Key Vault metadata is incomplete; no change was made.'
    }
    $isKeyVault = $null -ne $metadata.properties.keyVault
    if (($Action -eq 'NamedValue' -and $isKeyVault) -or ($Action -eq 'RefreshKeyVault' -and -not $isKeyVault)) {
        throw 'The named value storage type does not match the selected action; no change was made.'
    }
}
$request = @{ Method = 'POST'; Uri = "$base$path`?$api"; Headers = $headers; ErrorAction = 'Stop' }
if ($Action -eq 'NamedValue') {
    $etag = @($current.Headers['ETag'])[0]
    if (-not $etag) { throw 'Named value response did not include an ETag; no change was made.' }
    $secure = Read-Host 'Replacement named value (input is hidden)' -AsSecureString
    $value = [System.Net.NetworkCredential]::new('', $secure).Password
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Replacement value must not be empty; no change was made.' }
    $request.Method = 'PATCH'
    $request.Headers['If-Match'] = "$etag"
    $request.ContentType = 'application/json'
    $request.Body = @{ properties = @{ value = $value } } | ConvertTo-Json -Depth 4 -Compress
}
try {
    $response = Invoke-WebRequest @request
} catch {
    throw 'Azure rejected the request or the connection failed. The outcome may be unknown; inspect the target before retrying.'
} finally {
    [void]$request.Remove('Body')
    $value = $null; $secure = $null
}
$status = [int]$response.StatusCode
if ($Action -in 'NamedValue', 'RefreshKeyVault') {
    if ($status -eq 202) {
        Write-Warning 'Azure accepted an asynchronous operation; completion is not confirmed. Check the named value provisioning state and test the replacement before revoking the old credential.'
    } elseif ($status -eq 200) {
        Write-Host 'Azure completed the APIM operation. Test the replacement before revoking the old credential.'
    } else { throw "Unexpected HTTP $status; inspect the target before retrying." }
} elseif ($status -eq 204) {
    Write-Host 'Azure regenerated the selected key. Distribute and test the replacement securely before rotating the other key.'
} else { throw "Unexpected HTTP $status; inspect the target before retrying." }
