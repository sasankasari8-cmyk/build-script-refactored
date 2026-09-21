<#!n.SYNOPSIS
  Interactive Entra OIDC/OAuth configuration helper for PowerShell.

.DESCRIPTION
  Configures Lower/QA and Prod Entra applications and saves configuration locally.
  User.Read is enabled by default; optional OIDC scopes can be selected.
  For OIDC/CC clients, creates the cc_client application role on a selected API,
  assigns it to the client service principal, and grants the assignment.
  CC/OIDC clients default to requestedAccessTokenVersion = 2 in the app manifest.

  Naming rules:
    OIDC       -> cc_client
    Web        -> ac_client
    SPA        -> ac_pkce_client
    Custom API -> _api

  IMPORTANT: The CSV contains client secrets. Do not publish or commit it.
#>

[CmdletBinding()]
param([string]$ConfigPath = (Join-Path $PSScriptRoot 'entra-oidc-config.csv'))

$ErrorActionPreference = 'Stop'

function Ensure-Graph {
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
    }
}

function Read-Required([string]$Prompt) {
    do { $value = Read-Host $Prompt } while ([string]::IsNullOrWhiteSpace($value))
    $value.Trim()
}

function Read-YesNo([string]$Prompt, [bool]$Default = $true) {
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $value = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim().ToLowerInvariant() -in @('y', 'yes')
}

function Select-ApplicationType {
    do {
        Write-Host "`nSelect application type" -ForegroundColor Cyan
        Write-Host '1. OIDC/CC client   (cc_client)'
        Write-Host '2. Web client        (ac_client)'
        Write-Host '3. SPA client        (ac_pkce_client)'
        Write-Host '4. Custom API        (_api)'
        switch (Read-Host 'Select an application type') {
            '1' { return [PSCustomObject]@{ Name='OIDC'; Suffix='cc_client'; Redirect='web' } }
            '2' { return [PSCustomObject]@{ Name='Web'; Suffix='ac_client'; Redirect='web' } }
            '3' { return [PSCustomObject]@{ Name='SPA'; Suffix='ac_pkce_client'; Redirect='spa' } }
            '4' { return [PSCustomObject]@{ Name='Custom API'; Suffix='_api'; Redirect=$null } }
            default { Write-Host 'Choose 1, 2, 3, or 4.' -ForegroundColor Yellow }
        }
    } while ($true)
}

function Save-Config([object]$Config) {
    $rows = @()
    if (Test-Path -LiteralPath $ConfigPath) {
        $rows = @(Import-Csv -LiteralPath $ConfigPath | Where-Object {
            -not ($_.Environment -eq $Config.Environment -and $_.ApplicationType -eq $Config.ApplicationType)
        })
    }
    @($rows + $Config) | Export-Csv -LiteralPath $ConfigPath -NoTypeInformation -Force
    Write-Host "Saved $($Config.ApplicationName) to $ConfigPath" -ForegroundColor Green
}

function Select-OidcScopes {
    $scopes = @('openid', 'profile', 'email', 'offline_access')
    $selected = @()
    Write-Host "`nOptional OpenID Connect scopes (User.Read is enabled by default separately)." -ForegroundColor Cyan
    foreach ($scope in $scopes) {
        if (Read-YesNo "Add OIDC scope '$scope'?" $false) { $selected += $scope }
    }
    return @($selected | Select-Object -Unique)
}

function Select-GraphPermissions {
    $permissions = @('User.Read')
    Write-Host "`nMicrosoft Graph delegated permissions" -ForegroundColor Cyan
    Write-Host 'User.Read will be enabled by default.'
    $additional = Read-Host 'Additional Graph delegated permissions (comma-separated, blank for none; e.g. Mail.Read, Calendars.Read)'
    if (-not [string]::IsNullOrWhiteSpace($additional)) {
        $permissions += @($additional -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    return @($permissions | Select-Object -Unique)
}

function Get-ApplicationByDisplayName([string]$DisplayName) {
    $filter = [uri]::EscapeDataString("displayName eq '$($DisplayName.Replace("'", "''"))'")
    $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter"
    if ($response.value -and $response.value.Count -gt 0) { return $response.value[0] }
    return $null
}

function Get-OrCreateServicePrincipal([string]$AppId) {
    $filter = [uri]::EscapeDataString("appId eq '$AppId'")
    $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter"
    if ($response.value -and $response.value.Count -gt 0) { return $response.value[0] }
    return Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        -Body (@{ appId=$AppId } | ConvertTo-Json) -ContentType 'application/json'
}

function Enable-GraphPermissions {
    param(
        [Parameter(Mandatory)]$Application,
        [Parameter(Mandatory)][string[]]$PermissionNames
    )

    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $graphSp = Get-OrCreateServicePrincipal $graphAppId
    $resourceId = $graphSp.id
    $requiredResourceAccess = @($Application.requiredResourceAccess)
    $graphAccess = $requiredResourceAccess | Where-Object { $_.resourceAppId -eq $graphAppId }
    if (-not $graphAccess) {
        $graphAccess = [PSCustomObject]@{ resourceAppId=$graphAppId; resourceAccess=@() }
        $requiredResourceAccess += $graphAccess
    }

    $resourceAccess = @($graphAccess.resourceAccess)
    foreach ($name in $PermissionNames) {
        $permission = @($graphSp.oauth2PermissionScopes) | Where-Object { $_.value -eq $name } | Select-Object -First 1
        if (-not $permission) { throw "Microsoft Graph delegated permission '$name' was not found." }
        if (-not (@($resourceAccess) | Where-Object { $_.id -eq $permission.id -and $_.type -eq 'Scope' })) {
            $resourceAccess += [PSCustomObject]@{ id=$permission.id; type='Scope' }
        }
    }
    $graphAccess.resourceAccess = $resourceAccess
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.id)" `
        -Body (@{ requiredResourceAccess=$requiredResourceAccess } | ConvertTo-Json -Depth 10) -ContentType 'application/json'

    $clientSp = Get-OrCreateServicePrincipal $Application.appId
    $grantResponse = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId%20eq%20'$($clientSp.id)'%20and%20resourceId%20eq%20'$resourceId'"
    $grant = @($grantResponse.value) | Select-Object -First 1
    $requested = @($PermissionNames | Select-Object -Unique)
    if ($grant) {
        $newScopes = @(@($grant.scope -split ' ' | Where-Object { $_ }) + $requested | Select-Object -Unique)
        if (($newScopes -join ' ') -ne $grant.scope) {
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" `
                -Body (@{ scope=($newScopes -join ' ') } | ConvertTo-Json) -ContentType 'application/json'
        }
    } else {
        Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' `
            -Body (@{ clientId=$clientSp.id; consentType='AllPrincipals'; resourceId=$resourceId; scope=($requested -join ' ') } | ConvertTo-Json) `
            -ContentType 'application/json'
    }
    Write-Host "Enabled Graph permissions and granted consent: $($PermissionNames -join ', ')" -ForegroundColor Green
}

function Configure-CcClientAppRole {
    param([Parameter(Mandatory)]$ClientApplication)

    Write-Host "`nCC client application role configuration" -ForegroundColor Cyan
    $apiName = Read-Required 'API application display name that should expose the cc_client role'
    $apiApplication = Get-ApplicationByDisplayName $apiName
    if (-not $apiApplication) { throw "API application '$apiName' was not found." }

    $role = @($apiApplication.appRoles) | Where-Object { $_.value -eq 'cc_client' } | Select-Object -First 1
    if (-not $role) {
        $role = [PSCustomObject]@{
            id=[guid]::NewGuid().ToString()
            allowedMemberTypes=@('Application')
            description='Allows the cc_client application to call this API.'
            displayName='cc_client'
            isEnabled=$true
            value='cc_client'
        }
        $updatedRoles = @($apiApplication.appRoles) + $role
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($apiApplication.id)" `
            -Body (@{ appRoles=$updatedRoles } | ConvertTo-Json -Depth 20) -ContentType 'application/json'
        Write-Host "Created application role 'cc_client' on '$apiName'." -ForegroundColor Green
    } else {
        Write-Host "Application role 'cc_client' already exists on '$apiName'." -ForegroundColor Yellow
    }

    $clientSp = Get-OrCreateServicePrincipal $ClientApplication.appId
    $apiSp = Get-OrCreateServicePrincipal $apiApplication.appId
    $assignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($clientSp.id)/appRoleAssignments"
    $existing = @($assignments.value) | Where-Object { $_.resourceId -eq $apiSp.id -and $_.appRoleId -eq $role.id } | Select-Object -First 1
    if (-not $existing) {
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($clientSp.id)/appRoleAssignments" `
            -Body (@{ principalId=$clientSp.id; resourceId=$apiSp.id; appRoleId=$role.id } | ConvertTo-Json) -ContentType 'application/json'
        Write-Host "Assigned and granted 'cc_client' to the client service principal." -ForegroundColor Green
    } else {
        Write-Host "The 'cc_client' app-role assignment already exists." -ForegroundColor Yellow
    }

    return [PSCustomObject]@{ ApiApplicationName=$apiName; ApiApplicationId=$apiApplication.appId; Role='cc_client' }
}

function Configure-Environment {
    param([Parameter(Mandatory)][string]$Environment)

    Ensure-Graph
    $type = Select-ApplicationType
    $tenantId = Read-Required "$Environment Tenant ID (GUID or domain)"
    $baseName = Read-Host 'Application base name [personal]'
    if ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = 'personal' }
    $environmentPart = if ($Environment -eq 'Lower') { 'qa-' } else { '' }
    $applicationPrefix = 'application-'
    $defaultName = "$applicationPrefix$baseName-$environmentPart$($type.Suffix)"
    $displayName = Read-Host "Application display name [$defaultName]"
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $defaultName }
    elseif (-not $displayName.StartsWith($applicationPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $displayName = "$applicationPrefix$displayName"
    }
    $redirectUri = $null
    if ($type.Redirect) { $redirectUri = Read-Required "$Environment $($type.Name) redirect URI" }
    $scope = Read-Required "$Environment API scope value (for example access_as_user)"
    $oidcScopes = Select-OidcScopes
    $graphPermissions = Select-GraphPermissions
    $days = Read-Host 'Secret validity in days [365]'
    if ([string]::IsNullOrWhiteSpace($days)) { $days = 365 }

    Connect-MgGraph -TenantId $tenantId -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'
    $app = Get-ApplicationByDisplayName $displayName
    if ($app) { Write-Host "Using existing app $displayName" -ForegroundColor Yellow }
    else {
        $app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' `
            -Body (@{ displayName=$displayName; signInAudience='AzureADMyOrg' } | ConvertTo-Json) -ContentType 'application/json'
    }

    if ($type.Name -eq 'OIDC') {
        $manifestPatch = @{ requestedAccessTokenVersion = 2 }
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
            -Body ($manifestPatch | ConvertTo-Json -Depth 10) -ContentType 'application/json'
        Write-Host 'Defaulted CC/OIDC app manifest requestedAccessTokenVersion to 2.' -ForegroundColor Green
    }

    Enable-GraphPermissions -Application $app -PermissionNames $graphPermissions
    $ccRole = $null
    if ($type.Name -eq 'OIDC') { $ccRole = Configure-CcClientAppRole -ClientApplication $app }

    if ($type.Redirect) {
        $section = @{}
        $section[$type.Redirect] = @{ redirectUris=@($redirectUri) }
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
            -Body ($section | ConvertTo-Json -Depth 10) -ContentType 'application/json'
    }

    $credential = @{ passwordCredential=@{ displayName="build-$($Environment.ToLower())-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"; endDateTime=[DateTime]::UtcNow.AddDays([int]$days).ToString('o') } } | ConvertTo-Json -Depth 10
    $password = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/addPassword" -Body $credential -ContentType 'application/json'
    if ([string]::IsNullOrWhiteSpace($password.secretText)) { throw 'Microsoft Graph did not return secretText.' }

    Save-Config ([PSCustomObject]@{
        Environment=$Environment; ApplicationType=$type.Name; ApplicationName=$displayName
        TenantId=$tenantId; ClientId=$app.appId; ClientSecret=$password.secretText; ObjectId=$app.id
        Authority="https://login.microsoftonline.com/$tenantId/v2.0"; RedirectUri=$redirectUri
        Scope=$scope; OidcScopes=($oidcScopes -join ' '); GraphPermissions=($graphPermissions -join ' ')
        ApiApplicationName=if ($ccRole) { $ccRole.ApiApplicationName } else { '' }
        ApiApplicationId=if ($ccRole) { $ccRole.ApiApplicationId } else { '' }
        ApplicationRole=if ($ccRole) { $ccRole.Role } else { '' }
        SecretExpires=$password.endDateTime; CreatedUtc=[DateTime]::UtcNow.ToString('o')
    })
}

Write-Host "`nEntra OIDC/OAuth configuration" -ForegroundColor Cyan
Write-Host '1. Configure Lower/QA environment'
Write-Host '2. Configure Prod environment'

switch (Read-Host 'Select an option') {
    '1' { try { Configure-Environment 'Lower' } catch { Write-Host "ERROR: $_" -ForegroundColor Red } }
    '2' { try { Configure-Environment 'Prod' } catch { Write-Host "ERROR: $_" -ForegroundColor Red } }
    default { Write-Host 'Choose 1 or 2.' -ForegroundColor Yellow }
}
