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

<# 
 .Synopsis
  Gets a report of all members of roles 

 .Description
  This functions returns a list of consent grants in the directory

 .Example
  Get-MSCloudIdConsentGrantList | Export-Csv -Path ".\ConsentGrantList.csv" 
#>

<# 
.SYNOPSIS
    Lists delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

.PARAMETER PrecacheSize
    The number of users to pre-load into a cache. For tenants with over a thousand users,
    increasing this may improve performance of the script.

.EXAMPLE
    PS C:\> .\Get-AzureADPSPermissions.ps1 | Export-Csv -Path "permissions.csv" -NoTypeInformation
    Generates a CSV report of all permissions granted to all apps.

.EXAMPLE
    PS C:\> .\Get-AzureADPSPermissions.ps1 -ApplicationPermissions -ShowProgress | Where-Object { $_.Permission -eq "Directory.Read.All" }
    Get all apps which have application permissions for Directory.Read.All.
#>

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
    Get-AzureADUser -Top $PrecacheSize | ForEach-Object {
        CacheObject -Object $_ 
    }

    # Get all existing OAuth2 permission grants, get the client, resource and scope details
    foreach ($grant in $Oauth2PermGrants)
    {
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
                foreach ($item in $scopearray) {
                    $grantrisk = $permstable."$item"
                    # Determine if the risk level is set and if it should be raised or not
                    if ($risk -eq $null) {
                        # Set the risk level if it is not already set
                        $risk = $grantrisk
                    } elseif ($risk -eq $grantrisk) {
                        # Risk level is equivalent
                    } elseif ($risk -eq "Low" -and ($grantrisk -eq "Medium" -or $grantrisk -eq "High")) {
                        # Raise risk from Low to Medium or High
                        $risk = $grantrisk
                    } elseif ($risk -eq "Medium" -and $grantrisk -eq "High") {
                        # Raise risk from Medium to High
                        $risk = $grantrisk
                    } else {
                        # This path is when the grantrisk is lower than the overall risk
                    }
                }
                
                New-Object PSObject -Property ([ordered]@{
                    "PermissionType" = "Delegated"
                                    
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

                Write-Progress -Activity "Assessing Delegated Permissions..."
                
            }
        }
    }
    
    # Iterate over all ServicePrincipal objects and get app permissions
    Write-Verbose "Retrieving AppRoleAssignments..."
    $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object {
        $sp = $_.Value

        Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId  -All $true `
        | Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | ForEach-Object {
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
                $grantrisk = $permstable."$item"
                # Determine if the risk level is set and if it should be raised or not
                if ($risk -eq $null) {
                    # Set the risk level if it is not already set
                    $risk = $grantrisk
                } elseif ($risk -eq $grantrisk) {
                    # Risk level is equivalent
                } elseif ($risk -eq "Low" -and ($grantrisk -eq "Medium" -or $grantrisk -eq "High")) {
                    # Raise risk from Low to Medium or High
                    $risk = $grantrisk
                } elseif ($risk -eq "Medium" -and $grantrisk -eq "High") {
                    # Raise risk from Medium to High
                    $risk = $grantrisk
                } else {
                    # This path is when the grantrisk is lower than the overall risk
                }
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

            Write-Progress -Activity "Assessing Application Permissions..."

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
$permsdata = Invoke-WebRequest -Uri https://raw.githubusercontent.com/mepples21/aad_apis/master/permissions.json -UseBasicParsing
$permstable = @()
$permstable = $permsdata.Content | ConvertFrom-Json -AsHashtable

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
        -PivotFilter ConsentType,PrincipalDisplayName,RiskFilter,PermissionFilter,ResourceObjectIdFilter `
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

<# to do list

    - progress indicators

/#>