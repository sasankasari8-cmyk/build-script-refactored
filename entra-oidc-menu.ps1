<#
.SYNOPSIS
  Entra OIDC/OAuth configuration helper.
.DESCRIPTION
  Reads application information from CSV by default. Use -Interactive for prompt-based mode.
  CSV columns: Environment,ApplicationType,ApplicationName,TenantId,RedirectUri,Scope,OidcScopes,GraphPermissions,SecretDays,ApiApplicationName.
  ApplicationType values: OIDC, Web, SPA, Custom API.
  IMPORTANT: The CSV contains client secrets after processing. Do not publish or commit it.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'entra-oidc-config.csv'),
    [switch]$Interactive
)
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
    $value.Trim().ToLowerInvariant() -in @('y','yes')
}
function Get-ApplicationType([string]$Name) {
    switch ($Name.Trim().ToLowerInvariant()) {
        'oidc' { return [pscustomobject]@{ Name='OIDC'; Redirect='web' } }
        'web' { return [pscustomobject]@{ Name='Web'; Redirect='web' } }
        'spa' { return [pscustomobject]@{ Name='SPA'; Redirect='spa' } }
        'custom api' { return [pscustomobject]@{ Name='Custom API'; Redirect=$null } }
        default { throw "Unsupported ApplicationType '$Name'. Use OIDC, Web, SPA, or Custom API." }
    }
}
function Select-ApplicationType {
    do {
        Write-Host "`nSelect application type" -ForegroundColor Cyan
        Write-Host '1. OIDC/CC client'; Write-Host '2. Web client'; Write-Host '3. SPA client'; Write-Host '4. Custom API'
        switch (Read-Host 'Select an application type') {
            '1' { return [pscustomobject]@{ Name='OIDC'; Redirect='web' } }
            '2' { return [pscustomobject]@{ Name='Web'; Redirect='web' } }
            '3' { return [pscustomobject]@{ Name='SPA'; Redirect='spa' } }
            '4' { return [pscustomobject]@{ Name='Custom API'; Redirect=$null } }
            default { Write-Host 'Choose 1, 2, 3, or 4.' -ForegroundColor Yellow }
        }
    } while ($true)
}
function Convert-CsvList([object]$Value, [string]$Delimiter=',') {
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return @() }
    @(([string]$Value -split $Delimiter | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -Unique)
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
function Get-ApplicationByDisplayName([string]$DisplayName) {
    $filter = [uri]::EscapeDataString("displayName eq '$($DisplayName.Replace("'", "''"))'")
    $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter"
    if ($response.value) { return $response.value | Select-Object -First 1 }
    return $null
}
function Get-OrCreateServicePrincipal([string]$AppId) {
    $filter = [uri]::EscapeDataString("appId eq '$AppId'")
    $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter"
    if ($response.value) { return $response.value | Select-Object -First 1 }
    Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body (@{appId=$AppId}|ConvertTo-Json) -ContentType 'application/json'
}
function Enable-GraphPermissions {
    param([Parameter(Mandatory)]$Application,[Parameter(Mandatory)][string[]]$PermissionNames)
    $graphAppId='00000003-0000-0000-c000-000000000000'; $graphSp=Get-OrCreateServicePrincipal $graphAppId
    $required=@($Application.requiredResourceAccess); $graphAccess=$required|Where-Object {$_.resourceAppId -eq $graphAppId}
    if (-not $graphAccess) { $graphAccess=[pscustomobject]@{resourceAppId=$graphAppId;resourceAccess=@()}; $required+=$graphAccess }
    $resourceAccess=@($graphAccess.resourceAccess)
    foreach ($name in $PermissionNames) {
        $permission=@($graphSp.oauth2PermissionScopes)|Where-Object {$_.value -eq $name}|Select-Object -First 1
        if (-not $permission) { throw "Microsoft Graph delegated permission '$name' was not found." }
        if (-not(@($resourceAccess)|Where-Object {$_.id -eq $permission.id -and $_.type -eq 'Scope'})) { $resourceAccess+=[pscustomobject]@{id=$permission.id;type='Scope'} }
    }
    $graphAccess.resourceAccess=$resourceAccess
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.id)" -Body (@{requiredResourceAccess=$required}|ConvertTo-Json -Depth 10) -ContentType 'application/json'
    $clientSp=Get-OrCreateServicePrincipal $Application.appId
    $grants=Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId%20eq%20'$($clientSp.id)'%20and%20resourceId%20eq%20'$($graphSp.id)'"
    $grant=@($grants.value)|Select-Object -First 1; $requested=@($PermissionNames|Select-Object -Unique)
    if ($grant) {
        $newScopes=@(@($grant.scope -split ' '|Where-Object {$_})+$requested|Select-Object -Unique)
        if (($newScopes -join ' ') -ne $grant.scope) { Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" -Body (@{scope=($newScopes -join ' ')}|ConvertTo-Json) -ContentType 'application/json' }
    } else { Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body (@{clientId=$clientSp.id;consentType='AllPrincipals';resourceId=$graphSp.id;scope=($requested -join ' ')}|ConvertTo-Json) -ContentType 'application/json' }
}
function Configure-CcClientAppRole {
    param([Parameter(Mandatory)]$ClientApplication,[string]$ApiApplicationName,[switch]$FromCsv)
    if ([string]::IsNullOrWhiteSpace($ApiApplicationName)) { if ($FromCsv) { throw 'ApiApplicationName is required for an OIDC CSV row.' }; $ApiApplicationName=Read-Required 'API application display name that should expose the cc_client role' }
    $api=Get-ApplicationByDisplayName $ApiApplicationName; if (-not $api) { throw "API application '$ApiApplicationName' was not found." }
    $role=@($api.appRoles)|Where-Object {$_.value -eq 'cc_client'}|Select-Object -First 1
    if (-not $role) { $role=[pscustomobject]@{id=[guid]::NewGuid().ToString();allowedMemberTypes=@('Application');description='Allows the cc_client application to call this API.';displayName='cc_client';isEnabled=$true;value='cc_client'}; Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($api.id)" -Body (@{appRoles=@($api.appRoles)+$role}|ConvertTo-Json -Depth 20) -ContentType 'application/json' }
    $clientSp=Get-OrCreateServicePrincipal $ClientApplication.appId; $apiSp=Get-OrCreateServicePrincipal $api.appId
    $assignments=Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($clientSp.id)/appRoleAssignments"
    $existing=@($assignments.value)|Where-Object {$_.resourceId -eq $apiSp.id -and $_.appRoleId -eq $role.id}|Select-Object -First 1
    if (-not $existing) { Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($clientSp.id)/appRoleAssignments" -Body (@{principalId=$clientSp.id;resourceId=$apiSp.id;appRoleId=$role.id}|ConvertTo-Json) -ContentType 'application/json' }
    [pscustomobject]@{ApiApplicationName=$ApiApplicationName;ApiApplicationId=$api.appId;Role='cc_client'}
}
function Configure-Environment {
    param([Parameter(Mandatory)][string]$Environment,[pscustomobject]$CsvRow,[switch]$FromCsv)
    Ensure-Graph
    if ($FromCsv) {
        $type=Get-ApplicationType $CsvRow.ApplicationType; $tenantId=[string]$CsvRow.TenantId; $displayName=[string]$CsvRow.ApplicationName; $redirectUri=[string]$CsvRow.RedirectUri; $scope=[string]$CsvRow.Scope; $oidcScopes=@(Convert-CsvList $CsvRow.OidcScopes ' '); $graphPermissions=@(Convert-CsvList $CsvRow.GraphPermissions ','); if ($graphPermissions.Count -eq 0) {$graphPermissions=@('User.Read')}; if ($graphPermissions -notcontains 'User.Read') {$graphPermissions=@('User.Read')+$graphPermissions}; $days=if ([string]::IsNullOrWhiteSpace($CsvRow.SecretDays)) {365} else {[int]$CsvRow.SecretDays}; $apiName=[string]$CsvRow.ApiApplicationName
        if ([string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($displayName) -or [string]::IsNullOrWhiteSpace($scope)) { throw 'TenantId, ApplicationName, and Scope are required in every CSV row.' }
        if ($type.Redirect -and [string]::IsNullOrWhiteSpace($redirectUri)) { throw "RedirectUri is required for $($type.Name)." }
    } else {
        $type=Select-ApplicationType; $tenantId=Read-Required "$Environment Tenant ID"; $displayName=Read-Required 'Application display name'; $redirectUri=if ($type.Redirect) {Read-Required "$Environment redirect URI"} else {$null}; $scope=Read-Required "$Environment API scope value"; $oidcScopes=@('openid','profile','email','offline_access')|Where-Object {Read-YesNo "Add OIDC scope '$_'?" $false}; $graphPermissions=@('User.Read'); $days=365; $apiName=$null
    }
    Connect-MgGraph -TenantId $tenantId -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'
    $app=Get-ApplicationByDisplayName $displayName
    if (-not $app) { $app=Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body (@{displayName=$displayName;signInAudience='AzureADMyOrg'}|ConvertTo-Json) -ContentType 'application/json' }
    if ($type.Name -in @('OIDC','Custom API')) { Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body (@{requestedAccessTokenVersion=2}|ConvertTo-Json) -ContentType 'application/json' }
    Enable-GraphPermissions -Application $app -PermissionNames $graphPermissions
    $ccRole=if ($type.Name -eq 'OIDC') { Configure-CcClientAppRole -ClientApplication $app -ApiApplicationName $apiName -FromCsv:$FromCsv } else {$null}
    if ($type.Redirect) { $section=@{}; $section[$type.Redirect]=@{redirectUris=@($redirectUri)}; Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body ($section|ConvertTo-Json -Depth 10) -ContentType 'application/json' }
    $credential=@{passwordCredential=@{displayName="build-$($Environment.ToLower())-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))";endDateTime=[DateTime]::UtcNow.AddDays([int]$days).ToString('o')}}
    $password=Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/addPassword" -Body ($credential|ConvertTo-Json -Depth 10) -ContentType 'application/json'; if ([string]::IsNullOrWhiteSpace($password.secretText)) {throw 'Microsoft Graph did not return secretText.'}
    Save-Config ([pscustomobject]@{Environment=$Environment;ApplicationType=$type.Name;ApplicationName=$displayName;TenantId=$tenantId;ClientId=$app.appId;ClientSecret=$password.secretText;ObjectId=$app.id;Authority="https://login.microsoftonline.com/$tenantId/v2.0";RedirectUri=$redirectUri;Scope=$scope;OidcScopes=($oidcScopes -join ' ');GraphPermissions=($graphPermissions -join ', ');ApiApplicationName=if($ccRole){$ccRole.ApiApplicationName}else{''};ApiApplicationId=if($ccRole){$ccRole.ApiApplicationId}else{''};ApplicationRole=if($ccRole){$ccRole.Role}else{''};SecretExpires=$password.endDateTime;CreatedUtc=[DateTime]::UtcNow.ToString('o')})
}
if ($Interactive) { $environment=if ((Read-Host '1. Configure Lower/QA  2. Configure Prod') -eq '1') {'Lower'} else {'Prod'}; try {Configure-Environment $environment} catch {Write-Host "ERROR: $_" -ForegroundColor Red} } else { if (-not (Test-Path -LiteralPath $ConfigPath)) {throw "CSV file not found: $ConfigPath"}; $rows=@(Import-Csv -LiteralPath $ConfigPath); if ($rows.Count -eq 0) {throw 'CSV file contains no application rows.'}; foreach($row in $rows) {try {Configure-Environment ([string]$row.Environment) -CsvRow $row -FromCsv} catch {Write-Host "ERROR [$($row.Environment)/$($row.ApplicationType)]: $_" -ForegroundColor Red}} }
