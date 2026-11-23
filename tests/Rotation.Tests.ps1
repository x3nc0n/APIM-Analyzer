#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:rotationScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Rotate-ApimCredential.ps1'
    function az { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) throw 'Unmocked az call' }
}

Describe 'Targeted credential rotation' {
    BeforeEach {
        $script:id = '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/resourceGroups/test/providers/Microsoft.ApiManagement/service/example'
        $script:scope = Join-Path $TestDrive 'scope.csv'
        [pscustomobject]@{ id = $script:id; inScope = 'True' } | Export-Csv $script:scope
        $global:rotationStatus = 204
        $global:rotationMetadata = @{ properties = @{ secret = $true; keyVault = $null } }
        Mock Write-Warning {}
        Mock Write-Host {}
        Mock az {
            $global:LASTEXITCODE = 0
            '{"accessToken":"fake-token"}'
        }
        Mock Read-Host { ConvertTo-SecureString 'replacement-value' -AsPlainText -Force }
        Mock Invoke-WebRequest {
            param($Method, $Uri, $Headers, $Body)
            if ($Method -eq 'GET') {
                return [pscustomobject]@{ StatusCode = 200; Content = ($global:rotationMetadata | ConvertTo-Json -Depth 6); Headers = @{ ETag = '"etag-1"' } }
            }
            [pscustomobject]@{ StatusCode = $global:rotationStatus; Content = '' }
        }
    }
    AfterEach {
        Remove-Variable rotationStatus, rotationMetadata -Scope Global
    }

    It 'previews without requesting a token or changing anything' {
        & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action SubscriptionPrimary -ItemId 'customer' -WhatIf
        Should -Invoke az -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'rejects excluded, absent, malformed and duplicate scope decisions without any Azure call' {
        foreach ($rows in @(
            @([pscustomobject]@{ id = $script:id; inScope = 'False' }),
            @([pscustomobject]@{ id = "$script:id-other"; inScope = 'True' }),
            @([pscustomobject]@{ id = $script:id; inScope = 'maybe' }),
            @([pscustomobject]@{ id = $script:id; inScope = 'True' }, [pscustomobject]@{ id = $script:id; inScope = 'True' })
        )) {
            $rows | Export-Csv $script:scope
            { & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action ManagementPrimary -Confirm:$false } | Should -Throw
        }
        Should -Invoke az -Times 0 -Exactly
    }

    It 'regenerates only the selected <action> key' -ForEach @(
        @{ action = 'SubscriptionPrimary'; suffix = '/subscriptions/client/regeneratePrimaryKey'; item = 'client' }
        @{ action = 'SubscriptionSecondary'; suffix = '/subscriptions/client/regenerateSecondaryKey'; item = 'client' }
        @{ action = 'ManagementPrimary'; suffix = '/tenant/access/regeneratePrimaryKey'; item = '' }
        @{ action = 'ManagementSecondary'; suffix = '/tenant/access/regenerateSecondaryKey'; item = '' }
    ) {
        & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action $action -ItemId $item -Confirm:$false
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $Uri -eq "https://management.azure.com$script:id$suffix`?api-version=2024-05-01" }
    }

    It 'patches only the replacement using the current ETag without returning it' {
        $global:rotationStatus = 200
        $output = & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action NamedValue -ItemId 'secret' -Confirm:$false
        "$output" | Should -Not -Match 'replacement-value'
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'PATCH' -and $Headers['If-Match'] -eq '"etag-1"' -and ($Body | ConvertFrom-Json).properties.value -eq 'replacement-value'
        }
    }

    It 'refreshes a Key Vault reference and warns when the request is asynchronous' {
        $global:rotationMetadata.properties.keyVault = @{ secretIdentifier = 'https://example.vault.azure.net/secrets/item' }
        $global:rotationStatus = 202
        & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action RefreshKeyVault -ItemId 'secret' -Confirm:$false
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $Uri -like '*/namedValues/secret/refreshSecret?*' }
        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*completion is not confirmed*' }
    }

    It 'does not modify a named value of the wrong storage type' {
        { & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action RefreshKeyVault -ItemId 'secret' -Confirm:$false } | Should -Throw '*storage type*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        Should -Invoke Read-Host -Times 0 -Exactly
    }

    It 'refuses incomplete Key Vault metadata instead of treating it as an APIM secret' {
        $global:rotationMetadata.properties.keyVault = @{}
        { & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action NamedValue -ItemId 'secret' -Confirm:$false } | Should -Throw '*metadata is incomplete*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -eq 'PATCH' }
        Should -Invoke Read-Host -Times 0 -Exactly
    }

    It 'warns when a named value update is accepted but not completed' {
        $global:rotationStatus = 202
        & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action NamedValue -ItemId 'secret' -Confirm:$false
        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*completion is not confirmed*' }
    }

    It 'fails visibly on unexpected status or failed requests' {
        $global:rotationStatus = 200
        { & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action ManagementPrimary -Confirm:$false } | Should -Throw '*Unexpected HTTP 200*'
        Mock Invoke-WebRequest { throw 'sensitive server response' }
        { & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action ManagementPrimary -Confirm:$false } | Should -Throw '*outcome may be unknown*'
    }

    It 'rejects path injection before contacting Azure' {
        { & $script:rotationScript -ResourceId $script:id -ScopeFile $script:scope -Action SubscriptionPrimary -ItemId '../other' -Confirm:$false } | Should -Throw '*single-segment*'
        Should -Invoke az -Times 0 -Exactly
    }
}
