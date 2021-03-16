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

    [Parameter(
        Mandatory=$false
    )]
    [int]
    $ProximityToEndDate,

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
                Install-Module -Name $m -Force -Scope CurrentUser
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


Load-Module AzureAD
Start-MSCloudIdSession

$apps = Get-AzureADApplication -All $true
$data = @()

$count = 0
foreach($app in $apps)
{
    $appObjectId = $app.ObjectId
    $appName = $app.DisplayName
    

    $appKeys = Get-AzureADApplicationKeyCredential -ObjectId $appObjectId

    foreach($appKey in $appKeys)
    {        
        $daysToExpiration = (New-TimeSpan -Start (Get-Date) -End $appKey.EndDate).Days

        $result = New-Object PSObject
        $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $appName
        $result  | Add-Member -MemberType NoteProperty -Name "Object Id" -Value $appObjectId
        $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Application"
        $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value $appKey.Type
        $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $appKey.StartDate
        $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $appKey.EndDate
        $result  | Add-Member -MemberType NoteProperty -Name "DaysToExpiration" -Value $daysToExpiration
        $result  | Add-Member -MemberType NoteProperty -Name "Usage" -Value $appKey.Usage
        $data += $result
    }

    $appKeys = Get-AzureADApplicationPasswordCredential -ObjectId $appObjectId
    
    foreach($appKey in $app.PasswordCredentials)
    {        
        $daysToExpiration = (New-TimeSpan -Start (Get-Date) -End $appKey.EndDate).Days

        $result = New-Object PSObject
        $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $appName
        $result  | Add-Member -MemberType NoteProperty -Name "Object Id" -Value $appObjectId
        $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Application"
        $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value "Password"
        $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $appKey.StartDate
        $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $appKey.EndDate
        $result  | Add-Member -MemberType NoteProperty -Name "DaysToExpiration" -Value $daysToExpiration
        $data += $result
    }
    $count++
    Write-Progress -activity "Processing Application Credentials . . ." -status "Processed: $count of $($apps.Count) Applications" -percentComplete (($count / $apps.Count)  * 100)
}


$servicePrincipals = Get-AzureADServicePrincipal -All $true

$count = 0
foreach($sp in $servicePrincipals)
{
    $spName = $sp.DisplayName
    $spObjectId = $sp.ObjectId

    $spKeys = Get-AzureADServicePrincipalKeyCredential -ObjectId $spObjectId        

    foreach($spKey in $spKeys)
    {
        $daysToExpiration = (New-TimeSpan -Start (Get-Date) -End $spKey.EndDate).Days

        $result = New-Object PSObject
        $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $spName
        $result  | Add-Member -MemberType NoteProperty -Name "Object Id" -Value $spObjectId
        $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Service Principal"
        $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value $spKey.Type
        $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $spKey.StartDate
        $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $spKey.EndDate
        $result  | Add-Member -MemberType NoteProperty -Name "DaysToExpiration" -Value $daysToExpiration
        $result  | Add-Member -MemberType NoteProperty -Name "Usage" -Value $spKey.Usage
        $data += $result
    }    
    
    $spKeys = Get-AzureADServicePrincipalPasswordCredential -ObjectId $spObjectId    

    
    foreach($spKey in $spKeys)
    {
        $daysToExpiration = (New-TimeSpan -Start (Get-Date) -End $spKey.EndDate).Days
        
        $result = New-Object PSObject
        $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $spName
        $result  | Add-Member -MemberType NoteProperty -Name "Object Id" -Value $spObjectId
        $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Service Principal"
        $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value "Password"
        $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $spKey.StartDate
        $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $spKey.EndDate
        $result  | Add-Member -MemberType NoteProperty -Name "DaysToExpiration" -Value $daysToExpiration
        $data += $result
    }    
    $count++
    Write-Progress -activity "Processing Service Principal Credentials . . ." -status "Processed: $count of $($servicePrincipals.Count) Service Principals" -percentComplete (($count / $servicePrincipals.Count)  * 100)
}

# Filter down to only items expiring within a specified number of days, if a number has been specified
if ($ProximityToEndDate) {
    $exportData = $data | Where-Object {$_.DaysToExpiration -le $ProximityToEndDate}
} else {
    $exportData = $data
}

$exportData | Export-Csv -Path $Path -NoTypeInformation
Write-Host "Application and Service Principal Credential information has been written to $Path"