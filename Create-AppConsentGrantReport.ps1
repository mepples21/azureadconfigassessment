<# 
.SYNOPSIS
    Lists and categorizes risk for delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

.PARAMETER AdminUPN
    The user principal name of an administrator in your tenant with at least Global Reader permissions.

.PARAMETER AdminUPN
    The user principal name of an administrator in your tenant with at least Global Reader permissions.

.PARAMETER Path
    The path to output results to in Excel format.

.EXAMPLE
    PS C:\> .\Create-AppConsentGrantReport.ps1 -AdminUPN globalreader@contoso.onmicrosoft.com -Path .\output.xlsx
    Generates an Excel report and pivot chart that shows all consents and emphasizes risky consents.
#>

[CmdletBinding()]
param
(
    # Interactive sign in using, use this option normally
    [Parameter(
        Mandatory=$true,
        ParameterSetName="Interactive"
    )]
    [string]
    $AdminUPN,

    # For use when doing non-interactive sign in or script testing
    [Parameter(
        Mandatory=$true,
        ParameterSetName="NonInteractive"
    )]
    [string]
    $PasswordFilePath,

    [Parameter(
        Mandatory=$true,
        ParameterSetName="NonInteractive"
    )]
    [string]
    $Username,

    # Output file location
    [Parameter(Mandatory=$true)]
    [string]
    $Path
)

function Start-MSCloudIdSession
{
    if ($AdminUPN) {
        Connect-AzureAD -AccountId $AdminUPN
    }
    elseif ($PasswordFilePath) {
        $password = Get-Content $PasswordFilePath | ConvertTo-SecureString
        $credential = New-Object System.Management.Automation.PsCredential($Username, $password)
        Connect-AzureAD -Credential $Credential
    }
}

function Load-Module ($m) {

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m
            }
            else {

                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}

Function Get-MSCloudIdConsentGrantList
{
    [CmdletBinding()]
    param(
        [int] $PrecacheSize = 999
    )
    # An in-memory cache of objects by {object ID} andy by {object class, object ID} 
    $script:ObjectByObjectId = @{}
    $script:ObjectByObjectClassId = @{}

    # Function to add an object to the cache
    function CacheObject($Object) {
        if ($Object) {
            if (-not $script:ObjectByObjectClassId.ContainsKey($Object.ObjectType)) {
                $script:ObjectByObjectClassId[$Object.ObjectType] = @{}
            }
            $script:ObjectByObjectClassId[$Object.ObjectType][$Object.ObjectId] = $Object
            $script:ObjectByObjectId[$Object.ObjectId] = $Object
        }
    }

    # Function to retrieve an object from the cache (if it's there), or from Azure AD (if not).
    function GetObjectByObjectId($ObjectId) {
        if (-not $script:ObjectByObjectId.ContainsKey($ObjectId)) {
            Write-Verbose ("Querying Azure AD for object '{0}'" -f $ObjectId)
            try {
                $object = Get-AzureADObjectByObjectId -ObjectId $ObjectId
                CacheObject -Object $object
                Write-Progress -Activity "Caching Objects"
            } catch { 
                Write-Verbose "Object not found."
            }
        }
        return $script:ObjectByObjectId[$ObjectId]
    }
   
    # Get all ServicePrincipal objects and add to the cache
    Write-Verbose "Retrieving ServicePrincipal objects..."
    $servicePrincipals = Get-AzureADServicePrincipal -All $true 

    #there is a limitation on how Azure AD Graph retrieves the list of OAuth2PermissionGrants
    #we have to traverse all service principals and gather them separately.
    # Originally, we could have done this 
    # $Oauth2PermGrants = Get-AzureADOAuth2PermissionGrant -All $true 
    
    $Oauth2PermGrants = @()

    $count = 0
    foreach ($sp in $servicePrincipals)
    {
        CacheObject -Object $sp
        $spPermGrants = Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $sp.ObjectId -All $true
        $Oauth2PermGrants += $spPermGrants
        $count++
        Write-Progress -activity "Caching Objects from Azure AD . . ." -status "Cached: $count of $($servicePrincipals.Count)" -percentComplete (($count / $servicePrincipals.Count)  * 100)
    }  

    # Get one page of User objects and add to the cache
    Write-Verbose "Retrieving User objects..."
    Get-AzureADUser -Top $PrecacheSize | ForEach-Object { CacheObject -Object $_ }

    # Get all existing OAuth2 permission grants, get the client, resource and scope details
    $count = 0
    foreach ($grant in $Oauth2PermGrants)
    {
        $count++
        Write-Progress -Activity "Processing Delegated Permission Grants..." -Status "Processing $count of $($Oauth2PermGrants.count)" -PercentComplete (($count / $Oauth2PermGrants.count) * 100)
        if ($grant.Scope) 
        {
            $grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {               
                $scope = $_
                $client = GetObjectByObjectId -ObjectId $grant.ClientId
                $resource = GetObjectByObjectId -ObjectId $grant.ResourceId
                $principalDisplayName = ""
                if ($grant.PrincipalId) {
                    $principal = GetObjectByObjectId -ObjectId $grant.PrincipalId
                    $principalDisplayName = $principal.DisplayName
                }

                $scopestring = @()
                $scopearray = @()
                $scopestring = $grant.Scope.ToString()
                $scopestring = $scopestring.Trim()
                $scopearray = $scopestring.split(" ")
                $risk = $null

                # Evaluate all the scopes
                foreach ($item in $scopearray) {

                    # Check permission table for an exact match
                    $risk = $null
                    $risk = ($permstable | where {$_.Permission -eq "$item" -and $_.Type -eq "Delegated"}).Risk

                    # Search for matching root level permission
                    if (!$risk) {
                        # Shorten $item string to do matching search
                        $itemroot = @()
                        $itemroot = $item.Split(".")[0]
                        $risk = ($permstable | where {$_.Permission -eq "$itemroot" -and $_.Type -eq "Delegated"}).Risk
                    }

                    New-Object PSObject -Property ([ordered]@{
                        "PermissionType" = $grant.ConsentType
                        "ClientObjectId" = $grant.ClientId
                        "ClientDisplayName" = $client.DisplayName
                        "ResourceObjectId" = $grant.ResourceId
                        "ResourceObjectIdFilter" = $grant.ResourceId
                        "ResourceDisplayName" = $resource.DisplayName
                        "Permission" = $scope
                        "PermissionFilter" = $scope
                        "ConsentType" = $grant.ConsentType
                        "PrincipalObjectId" = $grant.PrincipalId
                        "PrincipalDisplayName" = $principalDisplayName
                        "Risk" = $Risk
                        "RiskFilter" = $Risk
                    })
                }
            }
        }
    }
    
    # Iterate over all ServicePrincipal objects and get app permissions
    Write-Verbose "Retrieving AppRoleAssignments..."
    $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object {
        $sp = $_.Value

        # $count = 0
        # $servicePrincipals = Get-AzureADServicePrincipal  -All $true

        Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true `
        | Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | ForEach-Object {

            # $count++
            # Write-Progress -Activity "Processing Application Permission Grants..." -Status "Processing $count of $($ServicePrincipals.count)" -PercentComplete (($count / $ServicePrincipals.count) * 100)

            $assignment = $_
            
            $client = GetObjectByObjectId -ObjectId $assignment.PrincipalId
            $resource = GetObjectByObjectId -ObjectId $assignment.ResourceId            
            $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

            $scopestring = @()
            $scopearray = @()
            $scopestring = $grant.Scope.ToString()
            $scopestring = $scopestring.Trim()
            $scopearray = $scopestring.split(" ")
            $risk = $null
            foreach ($item in $scopearray) {

                # Check permission table for an exact match
                $risk = $null
                $risk = ($permstable | where {$_.Permission -eq "$item" -and $_.Type -eq "Application"}).Risk

                # Search for matching root level permission
                if (!$risk) {
                    # Shorten $item string to do matching search
                    $itemroot = @()
                    $itemroot = $item.Split(".")[0]
                    $risk = ($permstable | where {$_.Permission -eq "$itemroot" -and $_.Type -eq "Application"}).Risk
                }
                
                New-Object PSObject -Property ([ordered]@{
                    "PermissionType" = "Application"
                    "ClientObjectId" = $assignment.PrincipalId
                    "ClientDisplayName" = $client.DisplayName
                    "ResourceObjectId" = $assignment.ResourceId
                    "ResourceObjectIdFilter" = $grant.ResourceId
                    "ResourceDisplayName" = $resource.DisplayName
                    "Permission" = $appRole.Value
                    "PermissionFilter" = $appRole.Value
                    "Risk" = $Risk
                    "RiskFilter" = $Risk
                })
            }

            Write-Progress -Activity "Processing Application Permission Grants..."

        }
    }
}

# Check for PowerShell Modules
if (Get-Module -ListAvailable -Name AzureAD*) {
} 
else {
    Write-Host "Azure AD module not installed, installing..."
    Install-Module AzureAD
}

if (Get-Module -ListAvailable -Name ImportExcel) {    
} 
else {
    Write-Host "ImportExcel module not installed, installing..."
    Install-Module ImportExcel
}

# Create hash table of permissions and permissions risk
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mepples21/azureadconfigassessment/master/permstest.csv' -OutFile .\output\permissiontable_temp.csv
$permstable = Import-Csv .\output\permissiontable_temp.csv -Delimiter ','

Load-Module "AzureAD"
Load-Module "ImportExcel"

Start-MSCloudIdSession -AdminUPN $AdminUPN

$data = Get-MSCloudIdConsentGrantList

# Delete the existing output file if it already exists
$OutputFileExists = Test-Path $Path
if ($OutputFileExists -eq $true) {
    Get-ChildItem $Path | Remove-Item -Force
}

# Permissions per App Table and Chart
$pt = New-PivotTableDefinition -SourceWorkSheet ConsentGrantData `
        -PivotTableName "PermissionsPivotTable" `
        -PivotFilter PermissionType,PrincipalDisplayName,RiskFilter,PermissionFilter,ResourceObjectIdFilter `
        -PivotRows Risk,ResourceDisplayName,Permission `
        -PivotColumns PermissionType `
        -PivotData @{Permission='Count'} `
        -IncludePivotChart `
        -ChartType ColumnStacked `
        -ChartHeight 800 `
        -ChartWidth 1200 `
        -ChartRow 4 `
        -ChartColumn 5

$excel = $data | Export-Excel -Path $Path -WorksheetName ConsentGrantData `
        -PivotTableDefinition $pt `
        -AutoSize `
        -Activate `
        -HideSheet * `
        -UnHideSheet "PermissionsPivotTable" `
        -PassThru

$sheet = $excel.Workbook.Worksheets["PermissionsPivotTable"]
Add-ConditionalFormatting -Worksheet $sheet -Range "A1:A1048576" -RuleType Equal -ConditionValue "High"  -ForeGroundColor White -BackgroundColor Red -Bold -Underline
Add-ConditionalFormatting -Worksheet $sheet -Range "A1:A1048576" -RuleType Equal -ConditionValue "Medium"  -ForeGroundColor Black -BackgroundColor Orange -Bold -Underline
Add-ConditionalFormatting -Worksheet $sheet -Range "A1:A1048576" -RuleType Equal -ConditionValue "Low"  -ForeGroundColor Black -BackgroundColor Yellow -Bold -Underline
Export-Excel -ExcelPackage $excel -Show