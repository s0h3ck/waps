
import-module activedirectory

# GetCurrentDomain
$CurrentDomain = Get-ADDomain | Select-Object -Property InfrastructureMaster

# Gets one or omre Active Directory computers name
$ADComputers = Get-ADComputer -Filter * -Property * | Select-Object -Property Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,IPv4Address,Enabled

# Get one or more Active Directory users
$ADUsers = Get-ADUser -Filter * | Select-Object -Property Name

# Get one or more Active Directory users name sorted by no expiry date
$ADUsersExpiryDate = Get-ADUser -filter * -Properties "DisplayName", "msDs-UserPasswordExpiryTimeComputed" | Select-Object -Property "name",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} | Sort-Object ExpiryDate

# Gets one or more Active Directory groups.
$AGGroups = Get-ADGroup -filter * | Select-Object -Property Name | Sort-Object Name

$GroupObject = @()
foreach ($identity in $AGGroups) {

    $ADGroupName = Get-adgroupmember -Identity $identity.Name | Select-Object -Property Name
    
    $NameObject = @()
    foreach ($name in $ADGroupName)
    {
        $NameObject += $name
    }

    $OutputObject = New-Object -Type PSObject 
    $OutputObject | Add-Member -MemberType NoteProperty -Name $identity.Name -Value $NameObject.name

    $GroupObject += $OutputObject
}

$ReportObj = New-Object -Type PSObject
$ReportObj | Add-Member -MemberType NoteProperty -Name CurrentDomain -Value $CurrentDomain
$ReportObj | Add-Member -MemberType NoteProperty -Name ActiveDirectoryComputers -Value $ADComputers
$ReportObj | Add-Member -MemberType NoteProperty -Name ActiveDirectoryUsers -Value $ADUsers
$ReportObj | Add-Member -MemberType NoteProperty -Name ActiveDirectoryUsersExpiryDate -Value $ADUsersExpiryDate
$ReportObj | Add-Member -MemberType NoteProperty -Name ActiveDirectoryGroups -Value $GroupObject

$ReportObj | ConvertTo-Json -Depth 10 # not standard with RFC 7159