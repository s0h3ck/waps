Param([string]$verbosity)

If (-not ([string]::IsNullOrEmpty($verbosity))) {

    $global:verbose = $verbosity

} Else {
    
    $global:verbose = "1"

}

# Log file destination

$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
[System.String]$scriptDirectoryPath  = (Get-Item -Path ".\").FullName
[System.String]$secpolFilePath       = join-path $scriptDirectoryPath "secedit-$env:COMPUTERNAME-$timestamp.txt"
[System.String]$jsonFilePath         = join-path $scriptDirectoryPath "json-$env:COMPUTERNAME-$timestamp.json"
[System.String]$outputFilePath       = join-path $scriptDirectoryPath "output-$env:COMPUTERNAME-$timestamp.txt"
[System.String]$logFilePath          = join-path $scriptDirectoryPath "logs-$env:COMPUTERNAME-$timestamp.txt"

$global:LogFile = $logFilePath

If ([System.IO.File]::Exists($logFilePath)) {

    Clear-Content $logFilePath

} Else {

    New-Item $logFilePath -ItemType File

}

If ([System.IO.File]::Exists($outputFilePath)) {

    Clear-Content $outputFilePath

} Else {

    New-Item $outputFilePath -ItemType File

}

Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)][ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
    [String]
    $level="INFO"
    )
    <#
        .SYNOPSIS
            Writes information in a log file.

        .DESCRIPTION
            This function writes the output information in a log file and it has an option
        to display the information as the audit progress.

        .PARAMETER message
            Displays the message.
        
        .PARAMETER level
            Displays the debugging level of the message.

        .PARAMETER
            Display the audit information as it gets executed.

        .NOTES
            This function contains a global variable DisplayAuditProgress to output a pretty display.
        If not set, no display will be shown on the terminal. 
    #>
    
    # Display INFO
    If ($global:verbose -eq "1") {

        If ($level -eq "INFO") {

            If ($message -Match "\[\?\]") {

                Write-Host $message -ForegroundColor Black -BackgroundColor White

            } Else {

                Write-Host $message

            }

        }
    }

    # Display INFO WARN ERROR CRITICAL
    If ($global:verbose -eq "2") {

        If ($level -ne "DEBUG") {

            If ($message -Match "\[\?\]") {

                Write-Host $message -ForegroundColor Black -BackgroundColor White

            } Else {

                Write-Host $message
                
            }

        }

    }

    # Display DEBUG INFO WARN ERROR CRITICAL
    If ($global:verbose -eq "3") {

        If ($message -Match "\[\?\]") {

            Write-Host $message -ForegroundColor Black -BackgroundColor White

        } Else {

            Write-Host $message
                
        }

    }

    If ($global:LogFile) {
        
        $level = $level.ToUpper()

        $stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
        $Line = "$stamp $level $message"

        Add-Content $LogFile -Value $Line

    }
}

function Log($exception) {
    <#
        .SYNOPSIS
            Handles log of exception.

        .DESCRIPTION
            This function writes the exception by calling Write-Log function using
        ERROR level and displayRealTime sets to false.

        .PARAMETER exception
            Sets the exception object. It will be interpreted as a string.
    #>

    Write-Log -level ERROR "[-] Exception : "

    Write-Log -level ERROR "[!] Error Message : `n $exception"

}

function Check-Administrative-Privilege() {
    <#
        .SYNOPSIS
            Checks administrative privilege

        .DESCRIPTION
            This function checks If the script can run with administrative privilege.
        It stops the execution of the script If no escalated privilege is given.
    #>

    Write-Log -level INFO "[?] Checking for administrative privileges ..`n"

    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    If ($isAdmin) {
	
        Write-Log -level INFO "        [+] ----->  Administrator`n"
            
    } Else {

        Write-Log -level WARNING "[-] Some of the operations need administrative privileges.`n"
            
        Write-Log -level WARNING "[*] Please run the script using an administrative account."

	    exit 

    }

}

function Check-PSDefault-Version() {
    <#
        .SYNOPSIS
            Checks PowerShell version

        .DESCRIPTION
            This function checks the version of the powershell installed.

        .NOTES
            It stops the script If PowerShell v1.0 is found.
        It warns the user If PowerShell v2.0 is found and continue.
    #>

    $PSVersion = $PSVersionTable.PSVersion.Major

    Write-Log -level INFO "[?] Checking for default PowerShell version ..`n"
   
    If ($PSVersion -lt 2) {
       
        Write-Log -level WARNING "[-] You have PowerShell v1.0.`n"
        
        Write-Log -level WARNING "[*] This script only supports Powershell version 2 or above."
        
        exit
        
    } ElseIf ($PSVersion -eq 2) {

        Write-Log -level WARNING "[-] The script will run, but consider this system outdated.`n`n"

    }
   
    Write-Log -level INFO "        [+] ----->  PowerShell v$PSVersion `n" 
}

function Parse-SystemInformation {
    <#
        .SYNOPSIS
            Parses system information about the computer and operating system.

        .DESCRIPTION
            This function parses the information about the domain role and create
        a custom object regrouping popular properties about the operating system.
        It saves the data in the report object. It uses Win32_ComputerSystem and
        Win32_OperatingSystem to extract operating system information (CSName, Caption,
        OSArchitecture, Organization, InstallDate, Version, SerialNumber, BootDevice,
        WindowsDirectory, CountryCode) and DomainRole with the version of PowerShell.

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-computersystem
        https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-operatingsystem
    #>

    Write-Log -level INFO "[?] Collecting OS information ..`n"

    $systemRoles = @{
        0x0 = "Standalone Workstation";
        0x1 = "Member Workstation";
        0x2 = "Standalone Server";
        0x3 = "Member Server";
        0x4 = "Backup  Domain Controller";
        0x5 = "Primary Domain Controller"       
    }

    $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
    $systemRole = $systemRoles[[int]$systemRoleID]
    $culture = (Get-Culture).Name

    $PSVersion = $PSVersionTable.PSVersion.Major

    $operatingSystem = Get-WmiObject Win32_OperatingSystem | Select-Object -Property CSName, Caption, OSArchitecture, Organization, InstallDate, Version, SerialNumber, BootDevice, WindowsDirectory, CountryCode

    $SystemInformation = New-Object -Type PSObject
    $SystemInformation | Add-Member -MemberType NoteProperty -Name PSVersion -Value $PSVersion
    $SystemInformation | Add-Member -MemberType NoteProperty -Name SystemRole -Value $SystemRole
    $SystemInformation | Add-Member -MemberType NoteProperty -Name Culture -Value $culture
    $SystemInformation | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $operatingSystem

    $caption = $operatingSystem.Caption

    Write-Log -level DEBUG "        [+] Auditing on $caption `n"
    
    Write-Log -level DEBUG "        [?] Detecting system role ..`n"

    Write-Log -level DEBUG "            [+] -----> $systemRole `n"

    Write-Log -level DEBUG "[!] Add SystemInformation object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name SystemInformation -Value $SystemInformation

}

function Display-SystemInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays the system information.

        .DESCRIPTION
            This function displays the systemrole from the report object parsed
        within the function Parse-SystemInformation.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
            
    #>

    Add-Content $output -Value "[?] System information ..`n"

    $caption = $report.SystemInformation.OperatingSystem.Caption
        
    Add-Content $output -Value "        [+] Auditing on $caption`n"

    Add-Content $output -Value "        [?] Detecting system role ..`n"
    
    $systemRole = $report.SystemInformation.SystemRole

    Add-Content $output -Value "            [+] -----> $SystemRole `n"

}

function Parse-Hotfix {
    <#
        .SYNOPSIS
            Parses system hotfixes about the computer and operating system.

        .DESCRIPTION
            This functions gets the hotfixes that have been applied to the local
        and remote computes. It adds (CSName, Description, HotFixID, InstalledBy,
        InstalledOn) in the report object.

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-5.1
    #>

    Write-Log -level INFO "[?] Collecting OS Updates ..`n"

    $hotFix = Get-Hotfix | Select-Object -Property CSName,Description,HotFixID,InstalledBy,InstalledOn

    Write-Log -level DEBUG "[!] Add HotFix object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name HotFix -Value $hotFix

}

function Display-Hotfix {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays system hotfix about the computer and operating system.

        .DESCRIPTION
            This functions displays only HotFixID of the hotfixes that have been applied 
        to the local and remote computes.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] OS Updates ..`n"

    ForEach ($hotFix in $report.Hotfix) {

        $hotFixID = $hotFix.HotFixID

        Add-Content $output -Value "        [+] -----> $hotFixID `n"

    }

}

function Parse-BIOSInformation {
    <#
        .SYNOPSIS
            Parses basic input/output services (BIOS) about the computer.

        .DESCRIPTION
            This function parses the basic input/output services (BIOS) about the
        computer and creates a custom object regrouping popular properties about
        the BIOS system. It saves the data in the report object. It uses Win32_BIOS
        to extract operating system information (Status, Version, PrimaryBIOS,
        Manufacturer, ReleaseDate, SerialNumber).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-bios
    #>

    Write-Log -level INFO "[?] Collecting BIOS information ..`n"

    $BIOSInformation = Get-WmiObject Win32_BIOS | Select-Object -Property Status, Version, PrimaryBIOS, Manufacturer, ReleaseDate, SerialNumber

    Write-Log -level DEBUG "[!] Add BIOSInformation object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name BIOSInformation -Value $BIOSInformation

}

function Display-BIOSInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays the basic input/output services (BIOS) information.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-BIOSInformation. It outputs the version, the manufacturer and the status.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] BIOS information ..`n"

    $manufacturer = $report.BIOSInformation.Manufacturer
    $version = $report.BIOSInformation.Version
    $status = $report.BIOSInformation.Status

    Add-Content $output -Value "        [+] Manufacturer: $manufacturer"
    Add-Content $output -Value "                 Version: $version"
    Add-Content $output -Value "                  Status: $status`n"

}

function Parse-DiskInformation {
    <#
        .SYNOPSIS
            Parses information about the physical disk drive.

        .DESCRIPTION
            This function parses information about the disk information and creates
        a custom object regrouping popular properties about physical disk drive. It
        saves the data in the report object. It uses Win32_DiskDrive to extract disk
        drive information (Model, SerialNumber, Description, MediaType,
        FirmwareRevision, Size).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-diskdriver
    #>

    Write-Log -level INFO "[?] Collecting disk information ..`n"

    $DiskInformation = Get-WmiObject Win32_DiskDrive | Select Model, SerialNumber, Description, MediaType, FirmwareRevision, Size

    Write-Log -level DEBUG "[!] Add DiskInformation object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name DiskInformation -Value $DiskInformation

}

function Display-DiskInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about the physical disk drive.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-DiskInformation. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Disk information ..`n"

    ForEach ($drive in $report.DiskInformation) {

        $model = $drive.Model
        $serialNumber = $drive.SerialNumber
        $description = $drive.Description
        $mediaType = $drive.MediaType
        $firmware = $drive.FirmwareRevision
        $size = $drive.Size / 1GB
        
        Add-Content $output -Value "        [+] Model            : $model `n"
        Add-Content $output -Value "            SerialNumber     : $serialNumber `n"
        Add-Content $output -Value "            Description      : $description `n"
        Add-Content $output -Value "            MediaType        : $mediaType `n"
        Add-Content $output -Value "            FirmwareRevision : $firmware `n"
        Add-Content $output -Value "            Size             : $size `n"
        Add-Content $output -Value ""

    }

}

function Parse-LogicalDiskInformation {
    <#
        .SYNOPSIS
            Parses information about the actual storage device.

        .DESCRIPTION
            This function parses information about the actual storage device and creates
        a custom object regrouping popular properties about logical disk. It saves the
        data in the report object. It uses Win32_LogicalDisk to extract storage device
        information (DeviceID, VolumneName, Size, FreeSpace).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-logicaldisk
    #>

    Write-Log -level INFO "[?] Collecting logical disk information ..`n"

    $LogicalDiskInformation = Get-WmiObject Win32_LogicalDisk | Select-Object -Property DeviceID, VolumeName, Size, FreeSpace

    Write-Log -level DEBUG "[!] Add LogicalDiskInformation object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name LogicalDiskInformation -Value $LogicalDiskInformation
    
}

function Display-LogicalDiskInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about the actual storage device.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-LogicalDiskInformation. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Logical disk information ..`n"

    ForEach ($disk in $report.LogicalDiskInformation) {

        $deviceID = $disk.DeviceID
        $volumeName = $disk.VolumeName
        $size = $disk.Size / 1Gb
        $freeSpace = $disk.FreeSpace / 1Gb
        
        Add-Content $output -Value "        [+] DeviceID       : $deviceID `n"
        Add-Content $output -Value "            VolumeName     : $volumeName `n"
        Add-Content $output -Value "            Total Size(GB) : $size `n"
        Add-Content $output -Value "            Free Size (GB) : $FreeSpace `n"
        Add-Content $output -Value ""

    }

}

function Parse-PhysicalNetworkInformation {
    <#
        .SYNOPSIS
            Parses information about the physical network.

        .DESCRIPTION
            This function parses information about the physical network and creates
        a custom object regrouping popular properties about physical network. It saves the
        data in the report object. It uses Win32_NetworkAdapter to physical network adapter
        information (Name, Manufacturer, Description, AdapterType, Speed, MACAddress and
        NetConnectionID).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-networkadapter
    #>

    Write-Log -level INFO "[?] Collecting physical netowrk information ..`n"

    $PhysicalNetworkInformation = Get-WmiObject Win32_NetworkAdapter | Select-Object -Property Name, Manufacturer, Description, AdapterType, Speed, MACAddress, NetConnectionID

    Write-Log -level DEBUG "[!] Add PhysicalNetworkInformation object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name PhysicalNetworkInformation -Value $PhysicalNetworkInformation

}

function Display-PhysicalNetworkInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about the physical network.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-PhysicalNetworkInformation. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Physical network information ..`n"

    ForEach ($adapter in $report.PhysicalNetworkInformation) {

        $name = $adapter.Name
        $manufacturer = $adapter.Manufacturer
        $description = $adapter.Description
        $adapterType = $adapter.AdapterType
        $speed = $adapter.Speed
        $macAddress = $adapter.MACAddress
        $netConnectionID = $adapter.NetConnectionID
        
        Add-Content $output -Value "        [+] Name            : $name `n"
        Add-Content $output -Value "            Manufacturer    : $manufacturer `n"
        Add-Content $output -Value "            Description     : $description `n"
        Add-Content $output -Value "            AdapterType     : $adapterType `n"
        Add-Content $output -Value "            Speed           : $speed `n"
        Add-Content $output -Value "            MACAddress      : $macAddress `n"
        Add-Content $output -Value "            NetConnectionID : $netConnectionID `n"
        Add-Content $output -Value ""

    }

}

function Parse-NetworkAdapterInformation {
    <#
        .SYNOPSIS
            Parses information about the attributes and behaviors of a network adapter.

        .DESCRIPTION
            This function parses information about the attributes and behaviors of a network
        adapter and creates a custom object regrouping popular properties about network adapter. 
        It saves the data in the report object. It uses Win32_NetworkAdapterConfiguration to get
        network adapter information (Description, DHCPServer, IpAddress, SubnetMask,
        DefaultIPGateway, IpSubnet, DNSServerSearchOrder, IsDHCPEnabled, MACAddress).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-networkadapterconfiguration
    #>

    Write-Log -level INFO "[?] Collecting network adapter information ..`n"

    try {

        $NetworkAdapterInformation = Get-WmiObject Win32_NetworkAdapterConfiguration | # -EA Stop | ? {$_.IPEnabled} |
            Select-Object Description, DHCPServer, 
            @{Name='IpAddress';Expression={$_.IpAddress -join '; '}},
            @{Name='SubnetMask';Expression={$_.SubnetMask -join '; '}},
            @{Name='DefaultIPGateway';Expression={$_.DefaultIPGateway -join '; '}},
            @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}},
            @{Name='DNSServerSearchOrder';Expression={$_.DNSServerSearchOrder -join '; '}},
            @{Name='IsDHCPEnabled';Expression={If ($_.DHCPEnabled) {$true} Else {$false} }},
            @{Name='MACAddress';Expression={$_.MACAddress -join '; '}},
            WinsPrimaryServer,
            WINSSecondaryServer

    } catch { 
        
        Write-Log -level DEBUG "[?] Exception in Parse-NetworkAdapterInformation ..`n"

        Log $_

    }

    Write-Log -level DEBUG "[!] Add NetworkAdapterInformation object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name NetworkAdapterInformation -Value $NetworkAdapterInformation

}

function Display-NetworkAdapterInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about the attributes and behaviors of a network adapter.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-NetworkAdapterInformation. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Network adapter information ..`n"

    ForEach ($adapter in $report.NetworkAdapterInformation) {

        $description = $adapter.Description
        $dhcpServer = $adapter.DHCPServer
        $ipAddress = $adapter.IpAddress
        $subnetMask = $adapter.SubnetMask
        $defaultIPGateway = $adapter.DefaultIPGateway
        $ipSubnet = $adapter.IpSubnet
        $dnsServerSearchOrder = $adapter.DNSServerSearchOrder
        $isDHCPEnabled = $adapter.IsDHCPEnabled
        $macAddress = $adapter.MACAddress
        $winsPrimaryServer = $adapter.WinsPrimaryServer
        $wINSSecondaryServer = $adapter.WINSSecondaryServer
        
        Add-Content $output -Value "        [+] Description          : $description `n"
        Add-Content $output -Value "            DHCPServer           : $dhcpServer `n"
        Add-Content $output -Value "            IpAddress            : $ipAddress `n"
        Add-Content $output -Value "            SubnetMask           : $subnetMask `n"
        Add-Content $output -Value "            DefaultIPGateway     : $defaultIPGateway `n"
        Add-Content $output -Value "            IpSubnet             : $ipSubnet `n"
        Add-Content $output -Value "            DNSServerSearchOrder : $dnsServerSearchOrder `n"
        Add-Content $output -Value "            IsDHCPEnabled        : $isDHCPEnabled `n"
        Add-Content $output -Value "            MACAddress           : $macAddress `n"
        Add-Content $output -Value "            WinsPrimaryServer    : $winsPrimaryServer `n"
        Add-Content $output -Value "            WINSSecondaryServer  : $wINSSecondaryServer `n"
        Add-Content $output -Value ""

    }

}

function Parse-WorldExposedLocalShares {
    <#
        .SYNOPSIS
            Gets informations about local shares and their associated DACLs.

        .DESCRIPTION
            This function checks local file system shares and collects informations about each 
        Access Control Entry (ACE) looking for those targeting the Everyone(Tout le monde) group.
            
        .NOTES
            This function can be modIfied in a way that for each share we
        return its corresponding ace objects for further processing.

        .LINK
            https://msdn.microsoft.com/en-us/library/windows/desktop/aa374862(v=vs.85).aspx
    #>

    Write-Log -level INFO "[?] Checking for world exposed local shares ..`n"

    $permissionFlags = @{
        0x1     = "Read-List";
        0x2     = "Write-Create";
        0x4     = "Append-Create Subdirectory";
        0x20    = "Execute file-Traverse directory";
        0x40    = "Delete child"
        0x10000 = "Delete";                     
        0x40000 = "Write access to DACL";
        0x80000 = "Write Onwer"
    }

    $aceTypes = @{ 
        0x0 = "Allow";
        0x1 = "Deny"
    }

    $WorldExposedLocalShares = @()
    
    try {

        Get-WmiObject -class Win32_share -Filter "type=0" | % {
            
            $shareName = $_.Name
            $sharePath = $_.Path
            $shareSecurityObj = Get-WmiObject -class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'"
            $securityDescriptor = $shareSecurityObj.GetSecurityDescriptor().Descriptor
            
            Write-Log -level DEBUG "        [+] -----> $shareName `n"
            Write-Log -level DEBUG "            [+] SharePath : $sharePath `n"

            $aceObj = @()

            ForEach($ace in $securityDescriptor.DACL) {
                
                # Looking for Everyone group (SID="S-1-1-0") permissions 
                $trusteeSID = (New-Object System.Security.Principal.SecurityIdentIfier($ace.trustee.SID, 0)).Value.ToString()
                
                $permissions = @()

                If ($trusteeSID -eq "S-1-1-0" -and $aceTypes[[int]$ace.aceType] -eq "Allow") {
                    $accessMask  = $ace.accessmask
                    
                    ForEach ($flag in $permissionFlags.Keys) {

                            If($flag -band $accessMask) {
                                
                                $permissions += $permissionFlags[$flag]
                            }
                    }
                    
                    Write-Log -level DEBUG "                Trustee   : $Trustee"
                    
                    $debugMessage = "                Permission: "
                    $debugMessage += ($permissions[0..($permissions.length)] -join "`n                            ")

                    Write-Log -level DEBUG $debugMessage


                    $rule = New-Object  PSObject
                    $rule | Add-Member -MemberType NoteProperty -Name Trustee -Value $ace.trustee.Name
                    $rule | Add-Member -MemberType NoteProperty -Name Permissions -Value $permissions

                    $aceObj += $rule

                }

            }

            Write-Log -level DEBUG " "

            $DACL = New-Object -Type PSObject
            $DACL | Add-Member -MemberType NoteProperty -Name ShareName -Value $shareName
            $DACL | Add-Member -MemberType NoteProperty -Name SharePath -Value $sharePath
            $DACL | Add-Member -MemberType NoteProperty -Name ACE -Value $aceObj

            $WorldExposedLocalShares += $DACL;

        }

    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-WorldExposedLocalShares ..`n"

        Log $_

        Write-Log -level ERROR "[-] Error : Unable to inspect local shares.`n"
    	
    }

    Write-Log -level DEBUG "[!] Add WorldExposedLocalShares object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name WorldExposedLocalShares -Value $WorldExposedLocalShares

}

function Display-WorldExposedLocalShares {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about the attributes and behaviors of a network adapter.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-WorldExposedLocalShares (ShareName, SharePath, ACE permissions, ACE Trustee).

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] World exposed local shares information ..`n"

    If ($report.WorldExposedLocalShares.Count -gt 0 ) {

        ForEach ($Share in $report.WorldExposedLocalShares) {

            $ShareName = $Share.ShareName
            $SharePath = $Share.SharePath
        
            Add-Content $output -Value "        [+] -----> $ShareName `n"
            Add-Content $output -Value "            [+] SharePath : $SharePath `n"

            ForEach ($ACE in $Share.ACE) {
            
                $permissions = $ACE.permissions

                If ($permissions.Count -gt 0) {
                
                    $Trustee = $ACE.Trustee

                    Add-Content $output -Value "                Trustee   : $Trustee"

                    $out = "                Permission: "
                    $out += ($permissions[0..($permissions.length)] -join "`n                            ")
                
                    Add-Content $output -Value $out 

                }

            }
        
            Add-Content $output -Value " "

        }

    } Else {
        
        Add-Content $output -Value "        [-] No local world exposed shares were found.`n"

    }

}		

function Parse-StartupSoftwares {
    <#
        .SYNOPSIS
            Parses information about startup command.

        .DESCRIPTION
            This function parses information about startup command that runs automatically
        when a user logs onto the computer system and creates a custom object regrouping
        popular properties about network adapter. It saves the data in the report object.
        It uses Win32_StartupCommand to get startup commands (Name, Location, Command,
        User, Caption).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-startupcommand
    #>

    Write-Log -level INFO "[?] Collecting list of startup softwares ..`n"

    $StartupSoftwares = Get-WmiObject Win32_StartupCommand | Select-Object -Property Name, Location, Command, User, Caption

    Write-Log -level DEBUG "[!] Add StartupSoftwares object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name StartupSoftwares -Value $StartupSoftwares

}

function Display-StartupSoftwares {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about startup command.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-StartupSoftwares. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Startup softwares information ..`n"

    ForEach ($startup in $report.StartupSoftwares) {

        $name = $startup.Name
        $location = $startup.Location
        $command = $startup.Command
        $user = $startup.User
        $caption = $startup.Caption
        
        Add-Content $output -Value "        [+] Name     : $name `n"
        Add-Content $output -Value "            Location : $location `n"
        Add-Content $output -Value "            Command  : $command `n"
        Add-Content $output -Value "            User     : $user `n"
        Add-Content $output -Value "            Caption  : $caption `n"
        Add-Content $output -Value ""

    }

}

function Parse-RunningProcess {
    <#
        .SYNOPSIS
            Parses information about running process.

        .DESCRIPTION
            This function parses information about running process and creates a custom 
        object regrouping running process information. It saves the data in the report object.
        It uses Win32_Process to get running processing information (Caption, ProcessID, Vm
        and Ws).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-process
    #>

    Write-Log -level INFO "[?] Collecting running process ..`n"

    $RunningProcess = Get-WmiObject Win32_Process | Select-Object -Property Caption, ProcessId, Vm, Ws | sort Vm -Descending

    Write-Log -level DEBUG "[!] Add RunningProcess object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name RunningProcess -Value $RunningProcess

}

function Display-RunningProcess {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about running process.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-RunningProcess. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output "[?] Running process information ..`n"

    ForEach ($process in $report.RunningProcess) {

        $caption = $process.Caption
        $processId = $process.ProcessId
        $vm = $process.Vm /1mb -as [Int]
        $ws = $process.Ws /1Mb -as [Int]
        
        Add-Content $output -Value "        [+] Caption   : $caption `n"
        Add-Content $output -Value "            ProcessId : $processId `n"
        Add-Content $output -Value "            Vm (MB)   : $vm `n"
        Add-Content $output -Value "            WS (MB)   : $ws `n"
        Add-Content $output -Value ""

    }
    
}

function Parse-RunningServices {
    <#
        .SYNOPSIS
            Parses information about running services.

        .DESCRIPTION
            This function parses information about running services and creates a custom 
        object regrouping running services information. It saves the data in the report object.
        It uses Win32_Service to get running services properties (Name, StartMode and State).

        .LINK
            https://docs.microsoft.com/en-us/desktop/cimwin32prov/win32-service
    #>

    Write-Log -level INFO "[?] Collecting running services ..`n"

    $RunningServices = Get-WmiObject Win32_Service | where {$_.State -eq "running"} | Select-Object -Property Name, StartMode, State

    Write-Log -level DEBUG "[!] Add RunningProcess object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name RunningServices -Value $RunningServices

}

function Display-RunningServices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about running process.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-RunningServices. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output "[?] Running services information ..`n"

    ForEach ($service in $report.RunningServices) {

        $name = $service.Name
        $startMode = $service.StartMode
        $state = $service.State
        
        Add-Content $output -Value "        [+] Name      : $name `n"
        Add-Content $output -Value "            StartMode : $startMode `n"
        Add-Content $output -Value "            State     : $state `n"
        Add-Content $output -Value ""

    }

}

function Parse-ApplicationsInstalled {
    <#
        .SYNOPSIS
            Parses information about applications installed on the system.

        .DESCRIPTION
            This function parses information about applications installed on the system and 
        creates a custom object regrouping the information. It saves the data in the report object.
        It uses a registery key stored in "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        to get the properties (DisplayName, DisplayVersion, Publisher, InstallDate).

        .NOTES
            There is an alternative considered more "dangerous" and slower, but it may 
        have more results: $ApplicationsInstalled = Get-WmiObject -Class Win32_Product | 
        Select-Object -Property PSComputerName, Caption, InstallDate, Vendor
    #>

    Write-Log -level INFO "[?] Collecting applications installed ..`n"

    $ApplicationsInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSPath
    
    ForEach ($application in $ApplicationsInstalled ) {
        
        $displayName = $application.DisplayName
        $displayVersion = $application.DisplayVersion
        $publisher = $application.Publisher
        $installDate = $application.InstallDate
        $pspath = $application.PSPath
        
        Write-Log -level DEBUG "        [+] DisplayName    : $DisplayName"
        Write-Log -level DEBUG "            DisplayVersion : $DisplayVersion"
        Write-Log -level DEBUG "            Publisher      : $Publisher"
        Write-Log -level DEBUG "            InstallDate    : $InstallDate"
        Write-Log -level DEBUG "            PSPath         : $PSPath`n"

    }

    Write-Log -level DEBUG "[!] Add ApplicationsInstalled object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name ApplicationsInstalled -Value $ApplicationsInstalled

}

function Display-ApplicationsInstalled {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays information about running process.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-ApplicationsInstalled. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collecting applications installed ..`n"
    
    ForEach ($application in $report.ApplicationsInstalled) {
        
        $displayName = $application.DisplayName
        $displayVersion = $application.DisplayVersion
        $publisher = $application.Publisher
        $installDate = $application.InstallDate
        
        Add-Content $output -Value "        [+] DisplayName    : $DisplayName `n"
        Add-Content $output -Value "            DisplayVersion : $DisplayVersion `n"
        Add-Content $output -Value "            Publisher      : $Publisher `n"
        Add-Content $output -Value "            InstallDate    : $InstallDate `n"
        Add-Content $output -Value "            PSPath         : $PSPath `n"
        Add-Content $output -Value ""

    }

}

function Run-LocalSecurityProducts {
    <#    
        .SYNOPSIS		
            Gets Windows Firewall Profile status and checks for installed third party security products.
			
        .DESCRIPTION
            This function operates by examining registry keys specIfic to the Windows Firewall and by using the 
        Windows Security Center to get information regarding installed security products. 
	            
        .NOTES
            The documentation in the msdn is not very clear regarding the productState property provided by
        the SecurityCenter2 namespace. For this reason, this function only uses available informations that were obtained by testing 
        dIfferent security products against the Windows API.
                            
        .LINK
            http://neophob.com/2010/03/wmi-query-windows-securitycenter2
    #>

    Write-Log -level INFO "[?] Collecting Local Security Products ..`n"

    If (Get-WmiObject -Namespace root -class __NAMESPACE -filter "name='SecurityCenter2'") {

        $securityCenterNS="root\SecurityCenter2"

    } Else {

        $securityCenterNS="root\SecurityCenter"

    }

    $SecurityProvider = @{         
        "00"    =   "None";
        "01"    =   "Firewall";
        "02"    =   "AutoUpdate_Settings";
        "04"    =   "AntiVirus";           
        "08"    =   "AntiSpyware";
        "10"    =   "Internet_Settings";
        "20"    =   "User_Account_Control";
        "40"    =   "Service"
    }

    $RealTimeBehavior = @{                              
        "00"    =    "Off";
        "01"    =    "Expired";
        "10"    =    "ON";
        "11"    =    "Snoozed"
    }
 
    $DefinitionStatus = @{
        "00"     =     "Up-to-date";
        "10"     =     "Out-of-date"
    }

    Parse-FirewallConfig
    Display-FirewallConfig $report $outputFilePath

    Parse-FirewallInformation
    Display-FirewallInformation $report $outputFilePath

    Parse-FirewallRegistryInformation
    Display-FirewallRegistryInformation $report $outputFilePath

    $role = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole

    If($role -eq 0 -or $role -eq 1) {
        
        Parse-FirewallProducts
        Display-FirewallProducts $report $outputFilePath

        Parse-AntivirusProducts
        Display-AntivirusProducts $report $outputFilePath
        
        Parse-AntispywareProducts
        Display-AntispywareProducts $report $outputFilePath

    }

}

Function Convert-FWProfileType {
    Param ($ProfileCode)
    <#
        .SYNOPSIS
            Gets Windows firewall profile type.

        .DESCRIPTION
            This function convert the Windows firewall profile type keys and
        returns an array of the descriptions found in profile code.
    #>

    $FWprofileTypes.keys | 
        ForEach –begin {

            [String[]]$descriptions= @()

        } -process { 

            If ($profileCode -bAND $_) {

                $descriptions += $FWProfileTypes[$_]

            }

        } –end {

            $descriptions

        }
}

function Parse-FirewallConfig {
    <#
        .SYNOPSIS
            Parses firewall configuration.

        .DESCRIPTION
            This function parses the firewall configuration of the system
        and saves the data in the report object. The information regroup
        firewall properties (NetworkType, FirewallEnabled, BlockAllInboundTraffic,
        DefaultInboundAction, DefaultOutboundAction).
    #>

    Write-Log -level INFO "[?] Collecting firewall configuration ..`n"

    $fw = New-object –comObject HNetCfg.FwPolicy2
    
    $activeProfiles = Convert-fwprofileType $fw.CurrentProfileTypes
    
    $fw = @(1,2,4) | select @{Name=“Network Type”     ;expression={$fwProfileTypes[$_]}},
                            @{Name=“Firewall Enabled” ;expression={$fw.FireWallEnabled($_)}},
                            @{Name=“Block All Inbound”;expression={$fw.BlockAllInboundTraffic($_)}},
                            @{name=“Default In”       ;expression={$FwAction[$fw.DefaultInboundAction($_)]}},
                            @{Name=“Default Out”      ;expression={$FwAction[$fw.DefaultOutboundAction($_)]}}|
                            Format-Table -auto

    $FireWallConfig = New-Object -Type PSObject

    $FireWallConfig | Add-Member -MemberType NoteProperty -Name FireWall -Value $fw
    $FireWallConfig | Add-Member -MemberType NoteProperty -Name ActiveProfiles -Value $activeProfiles

    Write-Log -level DEBUG "[!] Add firewall configuration object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name FireWallConfig -Value $FireWallConfig

}

function Display-FirewallConfig {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays firewall configuration.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-FirewallConfig. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collecting firewall configuration ..`n"
    
    ForEach ($firewallConfig in $report.FireWallConfig) {
        
        $firewall = $firewallConfig.Firewall
        $ActiveProfiles = $firewallConfig.ActiveProfiles
        
        Add-Content $output -Value "        [+] Firewall       : $firewall `n"
        Add-Content $output -Value "            ActiveProfiles : $ActiveProfiles `n"
        Add-Content $output -Value ""

    }

}

function Get-FireWallRule {
    <#
        .SYNOPSIS
            Gets the rules of the firewall.

        .DESCRIPTION
            This function parses firewall's rules and return the rules.
        It contains the name, direction, enabled, protocol, profile, action
        and grouping.
    #>

    Param ($name, $direction, $enabled, $protocol, $profile, $action, $grouping)
    
    $rules = (New-object –comObject HNetCfg.FwPolicy2).rules
    
    If ($name)      {$rules = $rules | Where-Object {$_.name –like $name}}
    If ($direction) {$rules = $rules | Where-Object {$_.direction –eq $direction}}
    If ($enabled)   {$rules = $rules | Where-Object {$_.Enabled –eq $enabled}}
    If ($protocol)  {$rules = $rules | Where-Object {$_.protocol -eq $protocol}}
    If ($profile)   {$rules = $rules | Where-Object {$_.Profiles -bAND $profile}}
    If ($action)    {$rules = $rules | Where-Object {$_.Action -eq $action}}
    If ($grouping)  {$rules = $rules | Where-Object {$_.Grouping -Like $grouping}}
    
    $rules
}

function Parse-FirewallInformation {
    <#
        .SYNOPSIS
            Parses firewall information.

        .DESCRIPTION
            This function parses the firewall information of the system
        and saves the data in the report object. The information regroup
        firewall properties (Name, Action, Direction, Protocol, Profiles,
        localPorts, ApplicationName) sorted by Direction and Name.
    #>

    Write-Log -level INFO "[?] Collecting firewall information ..`n"

    $fw = New-object –comObject HNetCfg.FwPolicy2 ; Convert-fwprofileType $fw.CurrentProfileTypes  

    $FWprofileTypes = @{1GB=”All”;1=”Domain”; 2=”Private” ; 4=”Public”}
    $FwAction       = @{1=”Allow”; 0=”Block”}
    $FwProtocols    = @{1=”ICMPv4”;2=”IGMP”;6=”TCP”;17=”UDP”;41=”IPv6”;43=”IPv6Route”; 44=”IPv6Frag”;
                      47=”GRE”; 58=”ICMPv6”;59=”IPv6NoNxt”;60=”IPv6Opts”;112=”VRRP”; 113=”PGM”;115=”L2TP”;
                      ”ICMPv4”=1;”IGMP”=2;”TCP”=6;”UDP”=17;”IPv6”=41;”IPv6Route”=43;”IPv6Frag”=44;”GRE”=47;
                      ”ICMPv6”=48;”IPv6NoNxt”=59;”IPv6Opts”=60;”VRRP”=112; ”PGM”=113;”L2TP”=115}
    $FWDirection    = @{1=”Inbound”; 2=”outbound”;} 
 
    $firewallInformation = Get-FirewallRule -enabled $true | select Name, @{Label=”Action”; expression={$Fwaction[$_.action]}},
                                                                          @{label="Direction";expression={ $fwdirection[$_.direction]}},
                                                                          @{Label=”Protocol”; expression={$FwProtocols[$_.protocol]}} , localPorts,
                                                                          @{Label=”Profiles”; expression={$FWprofileTypes[$_.profiles]}},applicationname |
                                                                          sort Direction, Name
    
    Write-Log -level DEBUG "[!] Add firewall information object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name FireWallInformation -Value $firewallInformation

}

function Display-FirewallInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays firewall information.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-FirewallInformation. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collecting firewall information ..`n"

}

function Parse-FirewallRegistryInformation {
    <#
        .SYNOPSIS
            Parses firewall registry information.

        .DESCRIPTION
            This function parses the firewall registry information and saves
        the data in the report object. The information regroup the firewall policies.

        .LINK
            https://technet.microsoft.com/pt-pt/library/cc755604(v=ws.10).aspx
    #>

    Write-Log -level INFO "[?] Collecting firewall registry information ..`n"

    $FirewallPolicySubkey = @(
        "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
    )

    $FirewallRegistryInformation = @()
      
    try {
        
        ForEach ($path in $FirewallPolicySubkey) {

            $policyName = $path.Split('\')[7]
            $policyName = $policyName.Replace("Profile", "") + " Profile"

            $policy = New-Object -Type PSObject
            $policy | Add-Member -MemberType NoteProperty -Name PolicyName -Value $policyName

            If (Test-Path -Path $($path)) {
                $enabled = $(Get-ItemProperty -Path $($path) -Name EnableFirewall).EnableFirewall  
            
                If($enabled -eq 1) { 
                    $state = "Enabled"
                } Else { 
                    $state = "Disabled"
                }

                $policy | Add-Member -MemberType NoteProperty -Name PolicyState -Value $state

            }

            $FirewallRegistryInformation += $policy
        }
             
    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-FirewallRegistryInformation ..`n"

        Log $_

        Write-Log -level ERROR "[-] Error : Unable to check Windows Firewall registry informations.`n"

    }

    Write-Log -level DEBUG "[!] Add firewall registry information object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name FirewallRegistryInformation -Value $FirewallRegistryInformation
}

function Display-FirewallRegistryInformation {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays firewall registry information.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-FirewallRegistryInformation. It outputs the name and the state
        for each firewall policy found.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collecting firewall registry information ..`n"

    Add-Content $output -value "[?] Checking If Windows Firewall is enabled ..`n"
              
    ForEach ($policy in $report.FirewallRegistryInformation) {
        
        $policyName = $policy.PolicyName
        $policyState = $policy.PolicyState

        If ($policyState) {

            $policy_output = "                [+] {0} Firewall : {1}" -f $policyName, $policyState

            Add-Content $output -value $policy_output

        } Else {

            Add-Content $output -value "        [-] Could not find $policyName Registry Subkey.`n"

        }

    }

    Add-Content $output -value " "

}

function Parse-FirewallProducts {
    <#
        .SYNOPSIS
            Parses third party firewall products.

        .DESCRIPTION
            This function parses third party firewall products and saves
        the data in the report object.
    #>

    Write-Log -level INFO "[?] Collecting third party firewall products ..`n"

    $firewalls = @(Get-WmiObject -Namespace $securityCenterNS -class FirewallProduct)
    
    Write-Log -level DEBUG "[!] Add firewall products object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name FirewallProducts -Value $firewalls
}

function Display-FirewallProducts {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays third party firewall products.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-FirewallProducts. It outputs the service type, the product name
        and the state of company.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collection third party firewall products .. `n"

    Add-Content $output -value "        [?] Collecting Firewall Profiles ..`n"

    $firewalls = $report.FirewallProducts

    If ($firewalls.Count -eq 0) {

        Add-Content $output -value "        [-] No other firewall installed.`n"

    } Else {

        $firewallsCount = $firewalls.Count

        Add-Content $output -value "        [+] Found $firewallsCount third party firewall products.`n"    
        Add-Content $output -value "            [?] Checking for product configuration ...`n"
            
        $firewalls | %{
            
            # The structure of the API is dIfferent depending on the version of the SecurityCenter Namespace
            
            If ($securityCenterNS.endswith("2")) {

                $version = "SecurityCenter2"

                [int]$productState = $_.ProductState
                    
                $hexString = [System.Convert]::toString($productState,16).padleft(6,'0')
                          	
                $provider=$hexString.substring(0,2)
                    
                $realTimeProtec=$hexString.substring(2,2)
                    
                $definition=$hexString.substring(4,2)
                
                $serviceType = $SecurityProvider[[String]$provider]
                $displayName = $_.displayName
                $state = $RealTimeBehavior[[String]$realTimeProtec]

                Add-Content $output -value "                [+] Service Type          : $serviceType."
                Add-Content $output -value "                [+] Product Name          : $displayName."
                Add-Content $output -value "                [+] State                 : $state.`n"
                
            } Else {
                
                $companyName = $_.CompanyName
                $productName = $_.displayName
                $state = $_.enabled

                Add-Content $output -value "                [+] Company Name           : $companyName."
                Add-Content $output -value "                [+] Product Name           : $productName."
                Add-Content $output -value "                [+] State                  : $state.`n"

            }
        }
    }

}

function Parse-AntivirusProducts {
    <#
        .SYNOPSIS
            Parses antivirus products.

        .DESCRIPTION
            This function parses the antivirus products and saves
        the data in the report object.
    #>

    Write-Log -level INFO "[?] Collecting antivirus products ..`n"

    $antivirus = @(Get-WmiObject -Namespace $securityCenterNS -class AntiVirusProduct)

    Write-Log -level DEBUG "[!] Add antivirus products object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name AntivirusProducts -Value $antivirus

}

function Display-AntivirusProducts {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays antivirus products.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-AntivirusProducts. It outputs the product name, the service type,
        the real time protection and the signature definitions If securityCenterNS
        matches "root\SecurityCenter2". If it matches "root\SecurityCenter",
        it outputs the company name, the product name, the real time protection
        and the product up-to-date.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Checking for installed antivirus products ..`n"

    Add-Content $output -value "[?] Collecting Antivirus information ..`n"

    $antivirus = $report.AntivirusProducts

    $antivirusCount = $antivirus.Count

    If ($antivirusCount -eq 0) {

        Add-Content $output -value "        [-] No antivirus product installed.`n"

    } Else {

        Add-Content $output -value "        [+] Found $antivirusCount AntiVirus solutions.`n"

        Add-Content $output -value "            [?] Checking for product configuration ..`n"

        $report.AntivirusProducts | %{

            If ( $securityCenterNS.endswith("2") ) {

                [int]$productState=$_.ProductState
                                       
                $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                                       
                $provider=$hexString.substring(0,2)
                                       
                $realTimeProtec=$hexString.substring(2,2)
                                       
                $definition=$hexString.substring(4,2)

                $displayName = $_.displayName
                $serviceType = $SecurityProvider[[String]$provider]
                $realTimeProtection = $RealTimeBehavior[[String]$realTimeProtec]
                $signatureDefinition = $DefinitionStatus[[String]$definition]

                Add-Content $output -value "                [+] Product Name          : $displayName."
                Add-Content $output -value "                [+] Service Type          : $serviceType."
                Add-Content $output -value "                [+] Real Time Protection  : $realTimeProtection."
                Add-Content $output -value "                [+] Signature Definitions : $signatureDefinition.`n"
                    
            } Else {
                
                $companyName = $_.CompanyName
                $displayName = $_.displayName
                $onAccessScanningEnabled = $_.onAccessScanningEnabled
                $productUpToDate = $_.productUpToDate
                   
                Add-Content $output -value "                [+] Company Name           : $companyName."
                Add-Content $output -value "                [+] Product Name           : $displayName."
                Add-Content $output -value "                [+] Real Time Protection   : $onAccessScanningEnabled."
                Add-Content $output -value "                [+] Product up-to-date     : $productUpToDate.`n"

            }

        }
            
    }

}

function Parse-AntispywareProducts {
    <#
        .SYNOPSIS
            Parses antispyware products.

        .DESCRIPTION
            This function parses the antispywares products and saves
        the data in the report object.
    #>

    Write-Log -level INFO "[?] Collecting antispyware products ..`n"

    $antispyware = @(Get-WmiObject -Namespace $securityCenterNS -class AntiSpywareProduct)

    Write-Log -level DEBUG "[!] Add antispyware products object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name AntispywareProducts -Value $antispyware

}

function Display-AntiSpywareProducts {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays antispyware products.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-AntiSpywareProducts. It outputs the product name, the service type,
        the real time protection and the signature definitions If securityCenterNS
        matches "root\SecurityCenter2". If it matches "root\SecurityCenter",
        it outputs the company name, the product name, the real time protection
        and the product up-to-date.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collecting antispyware products ..`n"

    $antispyware = $report.AntispywareProducts

    $antiSpywareCount = $antispyware.Count
    
    If ($antiSpywareCount -eq 0) {

        Add-Content $output -value "        [-] No antiSpyware product installed.`n"

    } Else {

        Add-Content $output -value "        [+] Found $antiSpywareCount antiSpyware solutions.`n"
        
        Add-Content $output -value "            [?] Checking for product configuration ..`n"
          
        $antispyware | %{

            If ( $securityCenterNS.endswith("2") ) {
                                            
                [int]$productState=$_.ProductState
                                         
                $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                                         
                $provider=$hexString.substring(0,2)
                                         
                $realTimeProtec=$hexString.substring(2,2)
                                         
                $definition=$hexString.substring(4,2)

                $displayName = $_.displayName
                $serviceType = $SecurityProvider[[String]$provider]
                $realTimeProtection = $RealTimeBehavior[[String]$realTimeProtec]
                $signatureDefinition = $DefinitionStatus[[String]$definition]
                                         
                Add-Content $output -value "                [+] Product Name          : $displayName."
                Add-Content $output -value "                [+] Service Type          : $serviceType."
                Add-Content $output -value "                [+] Real Time Protection  : $realTimeProtection."
                Add-Content $output -value "                [+] Signature Definitions : $signatureDefinition.`n"
 
            } Else {
                
                $companyName = $_.CompanyName
                $displayName = $_.displayName
                $onAccessScanningEnabled = $_.onAccessScanningEnabled
                $productUpToDate = $_.productUpToDate

                Add-Content $output -value "                [+] Company Name           : $companyName."
                Add-Content $output -value "                [+] Product Name           : $displayName."
                Add-Content $output -value "                [+] Real Time Protection   : $onAccessScanningEnabled."
                Add-Content $output -value "                [+] Product up-to-date     : $productUpToDate.`n"

            }
        }
    }

}

function Parse-SecurityEvents {
    <#
        .SYNOPSIS
            Parses the security events.

        .DESCRIPTION
            This function parses the newest security events from Get-EventLog Security.
        It collects the ten newest successful events and the twenty newest failure events.
        It saves the result in the report object.
    #>

    Write-Log -level INFO "[?] Collecting security events ..`n"

    $successAudit = Get-EventLog Security -newest 10 | where {$_.entrytype -eq "successaudit"} | Select-Object -Property TimeGenerated, Message
    
    $failureAudit = Get-EventLog Security -newest 20 | where {$_.entrytype -eq "failureaudit"} | Select-Object -Property TimeGenerated, Message
        
    $securityEvents = New-Object -Type PSObject
    $securityEvents | Add-Member -MemberType NoteProperty -Name SuccessAudit -Value $successAudit
    $securityEvents | Add-Member -MemberType NoteProperty -Name FailureAudit -Value $failureAudit

    Write-Log -level DEBUG "[!] Add SecurityEvents object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name SecurityEvents -Value $securityEvents

}

function Display-SecurityEvents {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays security events.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-SecurityEvents. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Security events information ..`n"

    Add-Content $output -value "[?] Successful events ..`n"

    ForEach ($successAudit in $report.SecurityEvents.SuccessAudit) {
        
        $timeGenerated = $successAudit.TimeGenerated
        $message = $successAudit.Message
        
        Add-Content $output -Value "        [+] timeGenerated : $timeGenerated `n"
        Add-Content $output -Value "            message       : $message `n"
        Add-Content $output -Value ""

    }

    Add-Content $output -value "[?] Failure events ..`n"

    ForEach ($failureAudit in $report.SecurityEvents.FailureAudit) {
        
        $timeGenerated = $failureAudit.TimeGenerated
        $message = $failureAudit.Message
        
        Add-Content $output -Value "        [+] timeGenerated : $timeGenerated `n"
        Add-Content $output -Value "            message       : $message `n"
        Add-Content $output -Value ""

    }

}

function Parse-DLLHijackability { 
    <#
        .SYNOPSIS
            Checks DLL Search mode and inspects permissions for directories in system %PATH%
        and checks write access for Authenticated Users group on these directories.
            
        .DESCRIPTION
            This functions tries to identIfy if DLL Safe Search is used and inspects 
        write access to directories in the path environment variable.       
    #>
    
    Write-Log -level INFO "[?] Checking for DLL hijackability ..`n"
    
    $DLLHijackability = New-Object -Type PSObject

    $items = @()

    try {

        Write-Log -level DEBUG "        [?] Checking for Safe DLL Search mode ..`n"
        
        $SafeDLLRegValue = Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\' -Name SafeDllSearchMode -ErrorAction SilentlyContinue
        
        $SafeDLLRegValue = [int]$SafeDLLRegValue.SafeDllSearchMode

        $DLLHijackability | Add-Member -MemberType NoteProperty -Name SafeDllSearchMode -Value $SafeDLLRegValue
        
        If ( $SafeDLLRegValue -and ( $SafeDLLRegValue -eq 0 ) ) {

            Write-Log -level DEBUG "                [+] DLL Safe Search is disabled !`n"

        } Else {

            Write-Log -level DEBUG "                [+] DLL Safe Search is enabled !`n"
        
        }

        Write-Log -level DEBUG "        [?] Checking directories in PATH environment variable ..`n"

        # Checking directories in PATH environment variable
        $systemPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
        
        $systemPath.split(";")| %{
  
            $directory = $_

            If ($directory) { # Can be emtpy
                 
                $writable = $false   

                # We are inspecting write access for the Authenticated Users group
                 
                $sid = "S-1-5-11"
                           
                $dirAcl = Get-Acl $($directory.trim('"'))            		

                ForEach ($rule in $dirAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentIfier])) {
                
                    If ($rule.IdentityReference -eq $sid) {
                        $accessMask = $rule.FileSystemRights.value__
                    
                        # Here we are checking directory write access in UNIX sense (write/delete/modIfy permissions)
                        # We use a combination of flags 
                                   
                        If ($accessMask -BAND 0xd0046) {
                                    
                            $writable = $true
                        }
                    }
                }
              
                $item = New-Object psobject -Property @{
        
                    "Directory"   =  $directory        
                    "Writable"    =  $writable           
        
                }

                Write-Log -level DEBUG "                [+] Directory: $directory"
                Write-Log -level DEBUG "                    Writable : $writable`n"

                $items += $item
            }
        }
        
    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-DLLHijackability ..`n"

        Log $_

    }

    $DLLHijackability | Add-Member -MemberType NoteProperty -Name Directories -Value $items

    Write-Log -level DEBUG "[!] Add DLLHijackability object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name DLLHijackability -Value $DLLHijackability

}

function Display-DLLHijackability {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays DLL Search mode and directories in PATH environment with write acccess.
            
        .DESCRIPTION
            This functions displays If DLL Safe Search is used and outputs
        the directories in PATH environment that have write access.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Checking for DLL hijackability ..`n"

    Add-Content $output -value "        [?] Checking for Safe DLL Search mode ..`n"

    If ( $report.DLLHijackability.SafeDllSearchMode -and ( $report.DLLHijackability.SafeDllSearchMode -eq 0 ) ) {

        Add-Content $output -value "                [+] DLL Safe Search is disabled !`n"

    } Else {

        Add-Content $output -value "                [+] DLL Safe Search is enabled !`n"
        
    }

    Add-Content $output -value "        [?] Checking directories in PATH environment variable ..`n"

    ForEach ($directory in $report.DLLHijackability.Directories) {
        
        $path = $directory.Directory
        $writable = $directory.Writable

        Add-Content $output -value "                [+] Directory: $path"
        Add-Content $output -value "                    Writable : $writable`n"

    }

}

function Parse-LocalGroupMembership {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [bool] $LocalAccount=$true
    )
    <#
        .SYNOPSIS
            Parse domain users and groups with local group membership.
                        
        .DESCRIPTION
            This function checks local groups on the machine for domain users/groups who are members in a local group.
        It uses Win32_Group and Win32_GroupUser classes of WMI to access user and group objects.
        
        .PARAMETER LocalAccount
            SpecIfies filtering LocalAccount to filter LocalAccount only. By default, it sets to True.
        It will parse only local group. If sets to False, it will parse only on the domain controller.
        
        .LINK
            https://docs.microsoft.com/en-us/windows/desktop/CIMWin32Prov/win32-groupuser     
    #>

    Write-Log "[?] Collection local group membership ..`n"

    $Win32Group = Get-WmiObject -Class Win32_Group -Filter "LocalAccount=$LocalAccount"|

        ForEach {
            
            $groupName = $_.Name
            $hostname = $_.Domain
            $wmi = Get-WmiObject -Class Win32_GroupUser -Filter "GroupComponent = `"Win32_Group.Domain='$hostname',Name='$groupName'`""

            If ($wmi -ne $null)  
            {  
                ForEach ($item in $wmi)  
                {
                    $data = $item.PartComponent -split "\,"

                    $CustomGroup = New-Object -Type PSObject
                    $CustomGroup | Add-Member -MemberType NoteProperty -Name Computer -Value $hostname
                    $CustomGroup | Add-Member -MemberType NoteProperty -Name Group -Value $groupName
                    $CustomGroup | Add-Member -MemberType NoteProperty -Name MemberDomain -Value ($data[0] -split "=")[1].Replace("""","")
                    $CustomGroup | Add-Member -MemberType NoteProperty -Name Member -Value ($data[1] -split "=")[1].Replace("""","").Replace('$', '') 

                    $CustomGroup
                }
                
                 
            }
        } | Select-Object Computer, Group, MemberDomain, Member

    
    $groupUser = $Win32Group

    If ( $groupUser.Count -gt 0 ) {

        $groups = @()

        ForEach ($group in $groupUser) {
            
            If (-Not ($groups -contains $group.Group) ) {

                $groups += $group.Group

            }
            
        }

        ForEach ($group in $groups) {
            
            Write-Log -level DEBUG "        [+] Group : $group "

            ForEach($item in $groupUser) {

                If ($item.Group -eq $group) {

                    $member = $item.Member

                    Write-Log -level DEBUG "            Member: $member"

                }

            }

            Write-Log -level DEBUG " "

        }

    } Else {
    
        Write-Log -level DEBUG "        [-] There are no local users on the specIfied scope.`n"

    }

    Write-Log -level DEBUG "[!] Add LocalGroupMembership object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name LocalGroupMembership -Value $Win32Group

}

function Display-LocalGroupMembership {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays domain users and groups with local group membership.
                        
        .DESCRIPTION
            This function displays group membership on the machine for domain users/groups who are members in a group.
        It will parse the output inserted in the report object under GroupUser from Parse-Group function.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Collection group account ..`n"

    $groupUser = $report.LocalGroupMembership

    If ( $groupUser.Count -gt 0 ) {

        $groups = @()

        ForEach ($group in $groupUser) {
            
            If (-Not ($groups -contains $group.Group) ) {

                $groups += $group.Group

            }
            
        }

        ForEach ($group in $groups) {
            
            Add-Content $output -value "        [+] Group : $group "

            ForEach($item in $groupUser) {

                If ($item.Group -eq $group) {

                    $member = $item.Member

                    Add-Content $output -value "            Member: $member"

                }

            }

            Add-Content $output -value " "

        }

    } Else {
    
        Add-Content $output -value "        [-] There are no local users on the specIfied scope.`n"

    }

}

function Parse-BinaryWritableServices {
    <#
        .SYNOPSIS
            Parses services whose binaries are writable by Authenticated Users and Everyone group members.
                    
        .DESCRIPTION
            This function checks services that have writable binaries and returns an array 
        containing service objects.
    #>

    Write-Log -level INFO "[?] Collecting binary writable services ..`n"

    [array]$BinaryWritableServices = @()

    # We are inspecting write access for Authenticated Users group members (SID = "S-1-5-11") and Everyone (SID = "S-1-1-0")
    $sids = @("S-1-5-11", "S-1-1-0")
    
    # Services to be ignored are those in system32 subtree
    $services = Get-WmiObject -Class Win32_Service | ? {$_.pathname -ne $null -and $_.pathname -notmatch ".*system32.*"}
         
    try {
 
        If ($services) {
	 	
            $services | % {
		  
                $service = $_

                $pathname = $($service.pathname.subString(0, $service.pathname.toLower().IndexOf(".exe")+4)).trim('"')

                Write-Log -level DEBUG "        [+] Name: $_" 
                Write-Log -level DEBUG "            Path: $pathname`n"
  
                $binaryAcl = Get-Acl $pathname -ErrorAction SilentlyContinue  
                                 
                If ($binaryAcl) {    		

                    ForEach ($rule in $binaryAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentIfier])) {
                                        
                        $sids | %{
             
                            $sid  = $_

                            If ($rule.IdentityReference -eq $sid) {

                                $accessMask = $rule.FileSystemRights.value__

                                If ($accessMask -band 0xd0006) {

                                    $BinaryWritableServices += $service

                                }

                            }

                        }

                    } 
                                
                }
         
            }

        }

    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-BinaryWritableServices ..`n"
    
        Log $_
        
    }

    Write-Log -level DEBUG "[!] Add BinaryWritableServices object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name BinaryWritableServices -Value $BinaryWritableServices 

}

function Display-BinaryWritableServices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays services whose binaries are writable by Authenticated Users and Everyone group members.
                    
        .DESCRIPTION
            This function displays services that have writable binaries and output the name and the path.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Binary writable services information ..`n"

    If ($report.WritableServices.Count -gt 0) {

        ForEach ($service in $report.BinaryWritableServices ) {

            $name = $service.name
            $pathname = $service.pathname

            Add-Content $output -value "        [+] Name: $name" 
            Add-Content $output -value "            Path: $pathname`n" 

        }
                
    } Else {

        Add-Content $output -value "        [-] Found no binary writable service.`n"

    }

}

function Parse-UnquotedPathServices {
    <#
        .SYNOPSIS
            Looks for services with unquoted path vulnerability.

        .DESCRIPTION
            This function gets all non-system32 services with unquotted pathnames.
        If display switch is used, it displays the name, state, start mode and pathname information,            
        otherwise it returns a array of the vulnerable services.
    #>

    Write-Log -level INFO "[?] Collecting unquoted path services ..`n"

    [array]$UnquotedPathServices = Get-WmiObject -Class Win32_Service| ? {
        $_.pathname.trim() -ne "" -and
        $_.pathname.trim() -notmatch '^"' -and
        $_.pathname.subString(0, $_.pathname.IndexOf(".exe")+4) -match ".* .*"
    } | Select-Object -Property PathName, StartMode

    Write-Log -level DEBUG "[!] Add UnquotedPathServices object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name UnquotedPathServices -Value $UnquotedPathServices.PathName

}

function Display-UnquotedPathServices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays services with unquoted path vulnerability.

        .DESCRIPTION
            This function gets all non-system32 services with unquotted pathnames.
        If display switch is used, it displays the name, state, start mode and pathname information,            
        otherwise it returns a array of the vulnerable services.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Unquoted path services information..`n"

    If ($report.UnquotedPathServices.Count -gt 0) {

        ForEach ($element in $report.UnquotedPathServices) {

            Add-Content $output -value "        [+] -----> $element .."

        }
        
        Add-Content $output -value " "

    } Else {

        Add-Content $output -value "        [-] Found no service with unquoted pathname.`n"

    }

}

function Parse-ConfigurableServices {
    <#
        .SYNOPSYS
            Parse all services that the current user can configure

        .DESCRIPTION
            This function tries to enumerate services for which configuration
        properties can be modIfied by the Authenticated Users group members.
        It uses the sc utility with the sdshow command to inspect the security 
        descriptor of the service object.
    #>
    
    Write-Log -level INFO "[?] Checking for configurable services ..`n"

    $configurables = @()

    try { 

        Get-WmiObject -Class Win32_Service | ? { $_.pathname -notmatch ".*system32.*"} | % {

            # get the security descriptor of the service in SDDL format

            $sddl = [String]$(sc.exe sdshow $($_.Name))

            If ($sddl -match "S:") {

                $dacl = $sddl.substring(0,$sddl.IndexOf("S:"))

            } Else {

                $dacl = $sddl

            }

            # We are interested in permissions related to Authenticated Users and Everyone group which are assigned
            # well known aliases ("AU", "WD" respectively) in the security descriptor sddl string.

            $permissions = [regex]::match($dacl, '\(A;;[A-Z]+;;;(AU|WD)\)')

            If ($permissions) {

                If ($permissions.value.split(';')[2] -match "CR|RP|WP|DT|DC|SD|WD|WO") {

                    $name = $_.Name
                    $pathName = $_.PathName

                    $configurable = New-Object -Type PSObject
                    $configurable | Add-Member -MemberType NoteProperty -Name Name -Value $name
                    $configurable | Add-Member -MemberType NoteProperty -Name Path -Value $pathName

                    $configurables += $configurable
                }

            }

        }

    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-ConfigurableServices ..`n"

        Log $_

    }
    
    Write-Log -level DEBUG "[!] Add ConfigurableServices object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name ConfigurableServices -Value $configurables
    
}

function Display-ConfigurableServices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSYS
            Displays all services that the current user can configure

        .DESCRIPTION
            This function displays the service for which configuration
        properties can be modIfied by the Authenticated Users group members.
        It outputs the name and path of the service.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -value "[?] Checking for configurable services ..`n"

    If ($report.ConfigurableServices.Count -gt 0) {

        ForEach ( $configurableService in $report.ConfigurableServices) {
            
            $name = $configurableService.Name
            $path = $configurableService.Path

            Add-Content $output -value "        [+] Name: $name"
            Add-Content $output -value "            Path: $path"
            
        }

        Add-Content $output -value " "

    } Else {
        
        Add-Content $output -value "        [-] Found no configurable services.`n"
        
    }
}

function Parse-UACLevel {
    <#
        .SYNOPSIS
            Parses current configuration of User Account Control.

        .DESCRIPTION
            This functions inspects registry informations related to UAC configuration 
        and checks whether UAC is enabled and which level of operation is used.
    #>

    Write-Log -level INFO "[?] Checking for UAC configuration ..`n"

    $UACLevel = New-Object -Type PSObject

    try {

        $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        
        $UACEnableLUA = [int]$UACRegValues.EnableLUA

        If ($UACEnableLUA -eq 1) {

            Write-Log -level DEBUG "        [+] UAC is enabled.`n"

        } Else {

            Write-Log -level DEBUG "        [-] UAC is enabled.`n"

        }

        $consentPrompt = $UACregValues.ConsentPromptBehaviorAdmin
        $secureDesktop = $UACregValues.PromptOnSecureDesktop

        $UACLevel | Add-Member -MemberType NoteProperty -Name EnableLUA -Value $UACEnableLUA
        $UACLevel | Add-Member -MemberType NoteProperty -Name ConsentPromptBehaviorAdmin -Value $consentPrompt
        $UACLevel | Add-Member -MemberType NoteProperty -Name PromptOnSecureDesktop -Value $secureDesktop

        Write-Log -level DEBUG "        [?] Checking for UAC level ..`n"

        If ($consentPrompt -eq 0 -and $secureDesktop -eq 0) {

            Write-Log -level DEBUG "                [+] UAC Level : Never NotIfy.`n"

        } ElseIf ($consentPrompt -eq 5 -and $secureDesktop -eq 0) {

            Write-Log -level DEBUG "                [+] UAC Level : NotIfy only when apps try to make changes (No secure desktop).`n"

        } ElseIf ($consentPrompt -eq 5 -and $secureDesktop -eq 1) {

            Write-Log -level DEBUG "                [+] UAC Level : NotIfy only when apps try to make changes (secure desktop on).`n"

        } ElseIf($consentPrompt -eq 5 -and $secureDesktop -eq 2) {

            Write-Log -level DEBUG "                [+] UAC Level : Always NotIfy with secure desktop.`n"

        }


    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-UACLevel ..`n"

        Log $_

    }

    Write-Log -level DEBUG "[!] Add UACLevel object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name UACLevel -Value $UACLevel

}

function Display-UACLevel {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays current configuration of User Account Control.

        .DESCRIPTION
            This functions inspects registry informations related to UAC configuration 
        and outputs whether UAC is enabled and which level of operation is used.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

   Add-Content $output -value "[?] Checking for UAC configuration ..`n"

    If ($report.UACLevel.EnableLUA -eq 1) {

        Add-Content $output -value "        [+] UAC is enabled.`n"

    } Else {

        Add-Content $output -value "        [-] UAC is enabled.`n"

    }

    Add-Content $output -value "        [?] Checking for UAC level ..`n" 

    $consentPrompt = $report.UACLevel.ConsentPromptBehaviorAdmin
    $secureDesktop = $report.UACLevel.PromptOnSecureDesktop

    If ($consentPrompt -eq 0 -and $secureDesktop -eq 0) {

        Add-Content $output -value "                [+] UAC Level : Never NotIfy.`n"

    } ElseIf ($consentPrompt -eq 5 -and $secureDesktop -eq 0) {

        Add-Content $output -value "                [+] UAC Level : NotIfy only when apps try to make changes (No secure desktop).`n"

    } ElseIf ($consentPrompt -eq 5 -and $secureDesktop -eq 1) {

        Add-Content $output -value "                [+] UAC Level : NotIfy only when apps try to make changes (secure desktop on).`n"

    } ElseIf($consentPrompt -eq 5 -and $secureDesktop -eq 2) {

        Add-Content $output -value "                [+] UAC Level : Always NotIfy with secure desktop.`n"

    }

}

function Parse-Services {
    <#
        .SYNOPSIS
            Parses the services on the computer.
            
        .DESCRIPTION
            This functions parses the services on the computer and create a custom PSObject
        that contains the name, displayname and status of the services.
        
        .NOTES
            See Get-WmiObject Win32_Service in Parse-RunningServices.

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-6
    #>

    Write-Log -level INFO "[?] Collecting services ..`n"

    $services = @()

    ForEach($service in Get-Service | Sort-Object status | Select-Object -Property Name, DisplayName, Status) {

        $services += New-Object PSObject -Property @{
            Name = $service.Name
            DisplayName = $service.DisplayName
            Status = $service.Status.toString()
        }

    }

    Write-Log -level DEBUG "[!] Add Services object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name Services -Value $services

}

function Display-Services {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays services.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-Services. It outputs a generic message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Services ..`n"

    ForEach ($service in $report.Services) {
        
        $name = $service.Name
        $displayName = $service.DisplayName
        $status = $service.Status
        
        Add-Content $output -Value "        [+] Name        : $name `n"
        Add-Content $output -Value "            DisplayName : $displayName `n"
        Add-Content $output -Value "            Status      : $status `n"
        Add-Content $output -Value ""

    }

}

function Parse-HostedServices {
    <#
        .SYNOPSIS
            Parses hosted services running DLLs not located in the system32 subtree.

        .DESCRIPTION
            This functions tries to identIfy whether there are any configured hosted 
        services based on DLLs not in system32.
    #>

    Write-Log -level INFO "[?] Checking hosted services not in system32 (svchost.exe) ..`n"

    $svcs = @()
     
    try {   
        
        $services = Get-WmiObject -Class Win32_service | ?{ $_.pathname -match "svchost\.exe" -and $(Test-Path $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$_.Name+"\Parameters")) -eq $true}

        If ($services) {
        
            ForEach ($service in $services) {
            
                $serviceName  = $service.Name 
                $serviceGroup = $service.pathname.split(" ")[2]

                $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name+"\Parameters"
                $serviceDLLPath=$(Get-ItemProperty $($reg) -Name ServiceDLL).ServiceDLL
                        
                If ($serviceDLLPath -ne $null -and $serviceDLLPath -notmatch ".*system32.*") {
                    $svcs += New-Object psobject -Property @{
                        serviceName    = $serviceName
                        serviceGroup   = $serviceGroup
                        serviceDLLPath = $serviceDLLPath
                    }
                }
            
            }

        }

    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-HostedServices ..`n"

        Log $_

    }

    Write-Log -level DEBUG "[!] Add HostedServices object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name HostedServices -Value $svcs
    
}

function Display-HostedServices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
     <#
        .SYNOPSIS
            Displays hosted services running DLLs not located in the system32 subtree.

        .DESCRIPTION
            This functions displays hosted services running DLLs not located in the
        system32 subtree by ServiceName, DLLPath and Group.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Hosted services not in system32 (svchost.exe) ..`n"

    If ( $report.HostedServices.Count -gt 0 ) {
        
        ForEach ($service in $report.HostedServices) {
            
            $serviceName = $service.serviceName
            $path = $service.serviceDLLPath
            $group = $service.serviceGroup

            Add-Content $output -Value "        [+] ServiceName: $serviceName"
            Add-Content $output -Value "            DLLPath    : $path"
            Add-Content $output -Value "            Group      : $group"
            Add-Content $output -Value " "

        }

    } Else {

        Add-Content $output -Value "        [-] Found no user hosted services.`n"

    }

}

function Parse-Autoruns {
    <#
        .SYNOPSIS
            Looks for autoruns specIfied in different places in the registry.
                         
        .DESCRIPTION
            This function inspects common registry keys used for autoruns.
        It examines the properties of these keys and report any found executables
        along with their pathnames.    
    #>

    $RegistryKeys = @(

        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\NotIfy",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"   # DLLs specIfied in this entry can hijack any process that uses user32.dll 
                            
        # not sure If it is all we need to check! maybe be more ;)
    )

    Write-Log -level INFO "[?] Checking registry keys for autoruns ..`n"

    $autoruns = @()

    try {
         
        $RegistryKeys | %{

            $key = $_
            
            $autorun = New-Object -Type PSObject
            $autorun | Add-Member -MemberType NoteProperty -Name Key -Value $key
            
            If (Test-Path -Path $key) {

                $executables = @()

                [array]$properties = Get-Item $key | Select-Object -ExpandProperty Property

                If ($properties.Count -gt 0) {

                    ForEach ($exe in $properties) {
                        
                        $name = $exe
                        $path = $($($(Get-ItemProperty $key).$exe)).replace('"','')

                        $executable = New-Object -Type PSObject
                        $executable | Add-Member -MemberType NoteProperty -Name Name -Value $name
                        $executable | Add-Member -MemberType NoteProperty -Name Path -Value $path

                        $executables += $executable
                    }
                    
                    $autorun | Add-Member -MemberType NoteProperty -Name Executables -Value $executables

                }

            }

            $autoruns += $autorun

        }
    
    } catch {
      
        Write-Log -level DEBUG "[?] Exception in Parse-Autoruns ..`n"

        Log $_

    }

    Write-Log -level DEBUG "[!] Add Autoruns object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name Autoruns -Value $autoruns

 }

function Display-Autoruns {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays autoruns specIfied in different places in the registry.
                         
        .DESCRIPTION
            This function displays common registry keys used for autoruns
        with the key and the name and the path of the executable.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Checking registry keys for autoruns ..`n"

    If ($report.Autoruns.Count -gt 0) {

        ForEach ($autorun in $report.Autoruns) {
            
            $key = $autorun.Key
            
            If ($autorun.Executables.count -gt 0) {

                Add-Content $output -Value "        [+] $key : "

                ForEach ($executable in $autorun.Executables) {
                
                    $name = $executable.Name
                    $path = $executable.Path

                    Add-Content $output -Value "            Name: $name"
                    Add-Content $output -Value "            Path: $path`n"
                
                }
            }

        }

        Add-Content $output -Value " "

    } Else {

        Add-Content $output -Value "        [-] Found no autoruns.`n"

    }

 }

function Parse-UnattendedInstallFiles {
    <#  
        .SYNOPSIS
            Checks for remaining files used by unattended installs.

        .DESCRIPTION
            This functions checks for remaining files used during Windows deployment
        by searching for specIfic files.
    #>

    $targetFilesList = @(
        "C:\unattended.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\System32\sysprep.inf",
        "C:\Windows\System32\sysprep\sysprep.xml"
    )

    Write-Log -level INFO "[?] Checking for unattended install leftovers ..`n"

    $targetFiles = @()

    try {

        $targetFilesList | ? { $(Test-Path $_) -eq $true } | %{ $targetFiles += $_ }

    } catch {
        
        Write-Log -level DEBUG "[?] Exception in Parse-UnattendedInstallFiles ..`n"

        Log $_

    }

    Write-Log -level DEBUG "[!] Add UnattendedInstallFiles object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name UnattendedInstallFiles -Value $targetFiles

}

function Display-UnattendedInstallFiles {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays unattented install files.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-UnattendedInstallFiles. It outputs the target files.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Unattended install leftovers information ..`n"

    If ($report.TargetFiles.Count -gt 0 ) {

        ForEach ($TargetFile in $report.UnattendedInstallFiles) {
            
            Add-Content $output -Value "        [+] Found: $TargetFile"

        }

        Add-Content $output -Value " "

    } Else {

        Add-Content $output -Value "        [-] No unattended install files were found.`n"

    }

}

function Parse-ScheduledTasks {
    <#
        .SYNOPSIS
            Checks for scheduled tasks.

        .DESCRIPTION
            This function looks for scheduled tasks.

        .NOTES
            This functions uses the schtasks.exe utility compatible with Powershell v2.0
        and then tries to parse the results. Here, only Folder, TaskName and Status have
        been extracted, because it was considered relevant information.
    #>

    Write-Log -level INFO "[?] Collecting scheduled tasks ..`n"

    $tasks = schtasks /query /fo LIST

    $ScheduledTasks = ForEach ($line in $tasks) {
	    $data = $line.split(':')
	
	    If ($data.Count -lt 2) {
	
		    $CustomTaskObject = New-Object -Type PSObject

		    $CustomTaskObject | Add-Member -MemberType NoteProperty -Name TaskPath -Value $taskPath
		    $CustomTaskObject | Add-Member -MemberType NoteProperty -Name TaskName -Value $taskName
		    $CustomTaskObject | Add-Member -MemberType NoteProperty -Name State -Value $state

		    $CustomTaskObject
		
		    $taskPath = ""
		    $taskName = ""
		    $state = ""
		
	    } Else {
	
		    $tag = $data[0]
		    $value = $data[1]

		    If ( $tag -eq 'Folder' ) {
			    $taskPath = $value.Trim()
		    } ElseIf ( $tag -eq 'TaskName' ) {
			    $taskName = $value.Trim()
		    } ElseIf ( $tag -eq 'Status' ) {
			    $state = $value.Trim()
		    }	
	    }
    }

    Write-Log -level DEBUG "[!] Add ScheduledTasks object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name ScheduledTasks -Value $ScheduledTasks

}

function Display-ScheduledTasks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays scheduled tasks.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-ScheduledTasks. It outputs the target files.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Scheduled tasks ..`n"
    

    ForEach($task in $report.ScheduledTasks) {

        $taskPath = $task.taskPath
        $taskName = $task.taskName
        $state = $task.state

        Add-Content $output -Value "        [+] TaskName : $taskPath "
        Add-Content $output -Value "            TaskPath : $taskName "
        Add-Content $output -Value "            State    : $state "

    }

}

function Parse-ScheduledTasksNotInSystem32 {
    <#
        .SYNOPSIS
            Checks for scheduled tasks whose binaries are not in *.system32.*

        .DESCRIPTION
            This function looks for scheduled tasks invoking non-system executables.

        .NOTES
            This functions uses the schtasks.exe utility to get informations about
        scheduled task and then tries to parse the results. Here I choose to parse XML output from the command.
        Another approach would be using the ScheduledTask Powershell module that was introduced starting from version 3.0.
    #>

    Write-Log -level INFO "[?] Collecting scheduled tasks that are not in system 32 ..`n"

    $ScheduledTasks = @()

    try {
        
        [xml]$tasksXMLobj = $(schtasks.exe /query /xml ONE) # ONE MIGHT NOT BE IMPLEMENTED UNDER MICROSOFT SERVER 2008 R2

        $tasksXMLobj.Tasks.Task | % {

            $taskCommandPath = [System.Environment]::ExpandEnvironmentVariables($_.actions.exec.command).trim()

            If ($taskCommandPath -ne $null -and $taskCommandPath -notmatch ".*system32.*") {
            
                If ($_.Principals.Principal.UserID) {

                    $sid = New-Object System.Security.Principal.SecurityIdentIfier($_.Principals.Principal.UserID)

                    $taskSecurityContext = $sid.Translate([System.Security.Principal.NTAccount])

                }

                $task = New-Object PSObject -Property @{

                    TaskCommand = $taskCommandPath

                    SecurityContext  = $taskSecurityContext

                }

                $ScheduledTasks += $task

            }

        }
         
    } catch {

        Write-Log -level DEBUG "[?] Exception in Parse-ScheduledTasksNotInSystem32 ..`n"

        Log $_

    }

    Write-Log -level DEBUG "[!] Add ScheduledTasksNotInSystem32 object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name ScheduledTasksNotInSystem32 -Value $ScheduledTasks
    
}

function Display-ScheduledTasksNotInSystem32 {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays scheduled tasks.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-ScheduledTasks. It outputs a general message at the moment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Collecting scheduled tasks that are not in system 32 ..`n"

    If ($report.ScheduledTasks.Count -gt 0 ) {

        ForEach ($scheduledTask in $report.ScheduledTasksNotInSystem32) {
            
            $out = "        [+] {0}`n            {1}`n" -f $scheduledTask.TaskCommand, $scheduledTask.SecurityContext

            Add-Content $output -Value $out

        }

    } Else {

        Add-Content $output -Value "        [-] No suspicious scheduled tasks were found.`n"

    }

}

function Parse-HostsFile {
    <#
        .SYNOPSIS
            Parses the hosts file in system32.

        .DESCRIPTION
            This function parses the hosts file in system32 and retrieves
        the IP and the hostname. If the line starts with a comment, it's
        ignored. If there is a comment at the end of a line, it will be parsed.
        It saves the data in the report object.

        .LINK
            https://www.sapien.com/blog/2009/03/02/parse-hosts-file-with-powershell/
    #>

    Write-Log -level INFO "[?] Checking hosts file ..`n"

    $hosts = @()

	$filepath = "C:\Windows\System32\drivers\etc\hosts"
		
	If ( (Get-Item $filepath -ea "SilentlyContinue").Exists ) {

		# define a regex to return first NON-whitespace character

		[regex]$r="\S"

		#strip out any lines beginning with # and blank lines

		$HostsData = Get-Content $filepath | where {
                
			(($r.Match($_)).value -ne "#") -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0)
				
		}

		If ($HostsData) {

			$HostsData | ForEach {

				$data = $_.trim() -replace '\s+', ' '
					
				$data = $data.Split(" ")
					
				$ip = $data[0]
				$hostname = $data[1]
					
				If ($_.contains("#")) {

					$comment = $_.substring($_.indexof("#")+1).trim()

				} Else {

					$comment = $null

				}

				$obj = New-Object PSObject

				$obj | Add-Member Noteproperty -name "IP" -Value $ip

				$obj | Add-Member Noteproperty -name "Hostname" -Value $hostname

				$obj | Add-Member Noteproperty -name "Comment" -Value $comment

				$hosts += $obj

				}

		}
    
	} Else {
        
        Write-Log -level DEBUG "[?] Exception in Parse-ScheduledTasksNotInSystem32 ..`n"

        Write-Log -level ERROR "[?] Failed to find $filename ..`n"

	}

    Write-Log -level DEBUG "[!] Add HostsFile object to report object `n"

    $report | Add-Member -MemberType NoteProperty -Name HostsFile -Value $hosts

}

function Display-HostsFile {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays hosts file information.

        .DESCRIPTION
            This function displays the information parsed by the function
        Parse-HostsFile. It outputs the hostname, the IP and the comment.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Add-Content $output -Value "[?] Checking hosts file ..`n"

    If ($report.HostsFile.Count -gt 0) {
        
        ForEach ($element in $report.HostsFile) {

            $hostname = $element.Hostname
            $ip = $element.IP
            $comment = $element.Comment

            Add-Content $output -Value "        [+] hostname: $hostname"
            Add-Content $output -Value "            ip      : $ip"

            If ($comment) {

                Add-Content $output -Value "            comment : $comment"
            }

        }

        Add-Content $output -Value " "

    } Else {

        Add-Content $output -Value "        [-] It has no entries in its HOSTS file.`n"

    }

}

function Parse-FullAccessDirectoriesOnDriveC {
    <#
        .SYNOPSIS
            Look for directories with full access on drive C:\.

        .DESCRIPTION
            This function parses the directories with full access on drive C:\.
        It saves the data in the report object.

        .NOTES
            It uses Get-ChildItem to iterate through the C:\ drive recursively.
        Then, it checks the full permission (F) with icacls.exe and redirects
        error message like "Access is denied" to standard error "2> null".
    #>

    Write-Log -level INFO "[?] Checking full access directories on drive C:\ ..`n"

	$paths = Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | Select-Object FullName

    $items = @()	

	ForEach ($element in $paths) {

		$icc = icacls $element.FullName 2> null
		
		If ($icc -like '*BUILTIN\Users:*(F)*') {

			$items += $element.FullName
			
		}
		
	}

    $report | Add-Member -MemberType NoteProperty -Name FullAccessDirectoriesOnDriveC -Value $items

}

function Display-FullAccessDirectoriesOnDriveC {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $report,

    [Parameter(Mandatory=$True)]
    [String]
    $output
    )
    <#
        .SYNOPSIS
            Displays directories with full access on drive C:\.

        .DESCRIPTION
            This function displays directories with full access on drive C:\
        parsed by the function Parse-FullAccessDirectoriesOnDriveC. It outputs
        the path If there are any.

        .PARAMETER report
            Extract the data from the report.

        .PARAMETER output
            The file to append the information.
    #>

    Write-Log "[?] Checking full access directories on drive C:\ ..`n"

    If ( $report.FullAccessDirectoriesOnDriveC.Count -gt 0) {

        ForEach ( $path in $report.FullAccessDirectoriesOnDriveC ) {

            Add-Content $output -Value "        [+] $path`n"

        }

    } Else {

        Add-Content $output -Value "        [-] Found no full access directory on drive C:\`n"

    }

}

function Escape-JSONString($str) {
    <#
        .SYNOPSIS
            Escape JSON string.

        .DESCRIPTION
            This function escapes JSON string and return the string escaped.

        .LINK
            https://gist.github.com/mdnmdn/6936714
    #>

	If ($str -eq $null) {
        return ""
    }
	
    $str = $str.ToString().Replace('\','\\').Replace('"','\"').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
	
    return $str;

}

function ConvertTo-JSON($maxDepth = 4,$forceArray = $false) {
    <#
        .SYNOPSIS
            Convert to JSON

        .DESCRIPTION
            This function converts an object to JSON string and return
        the result.

        .LINK
            https://gist.github.com/mdnmdn/6936714
    #>

	begin {

		$data = @()

	}

	process {

		$data += $_

	}
	
	end {
	
		If ($data.length -eq 1 -and $forceArray -eq $false) {

			$value = $data[0]

		} Else {

			$value = $data

		}

		If ($value -eq $null) {

			return "null"

		}

		$dataType = $value.GetType().Name

		If ($value.GetType().Name -eq 'Boolean') {

            return "$value".ToLower()

        }

        If ($value.GetType().IsPrimitive) {

            return "$value"
            
        }

		switch -regex ($dataType) {
            'String' {

					return  "`"{0}`"" -f (Escape-JSONString $value )

            }

	        '(System\.)?DateTime' {

                return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value
                
            }

	        '(System\.)?Object\[\]' {
					
				If ($maxDepth -le 0) { 
                    
                    return "`"$value`""
                
                }
					
				$jsonResult = ''

				ForEach ($elem in $value) {

					
					If ($jsonResult.Length -gt 0) {

                        $jsonResult +=', '

                    }				
					
                    $jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth -1))

				}

				return "[" + $jsonResult + "]"

	        }

			'(System\.)?Hashtable' {

				$jsonResult = ''

                ForEach ($key in $value.Keys) {

				    If ($jsonResult.Length -gt 0) {

                        $jsonResult +=', '

                    }

					$jsonResult += 
@"
"{0}": {1}
"@ -f $key , ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth -1) )

				}

				return "{" + $jsonResult + "}"

			}
	        
            default { #object

				If ($maxDepth -le 0) {

                    return  "`"{0}`"" -f (Escape-JSONString $value)

                }
					
				return "{" +
					(($value | Get-Member -MemberType *property | % { 
@"
"{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth -1) )			
					
				}) -join ', ') + "}"

            }

        }

	}

}

function Test-Ping() {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $address
    )
    <#
        .SYNOPSIS
            Tests the address of a computer.

        .DESCRIPTION
            This function tests the ping status code using Win32_PingStatus.
        Return true If the address exists, false otherwise.

        .PARAMETER address
            Sets the address.

        .LINK
            https://docs.microsoft.com/en-us/previous-version/windows/desktop/wmipicmp/win32_pingstatus
    #>

    $wmi = Get-WmiObject -query "SELECT * FROM Win32_PingStatus WHERE Address = '$address'"

    If ($wmi.statuscode -eq 0) {

	    $true

    } Else {

	    $false

    }

}

function Initialize-Audit {

    Clear-Host

    $start = Get-Date

    Write-Log "Starting Audit at $start"
    Write-Log "-------------------------------------`n"
    
    SecEdit.exe /export /cfg $secpolFilePath /quiet
    Write-Log "[?] Collecting Local GPO (SecEdit.exe) ..`n"

    $report = New-Object -Type PSObject
    
    Check-Administrative-Privilege
    Check-PSDefault-Version
    
    Parse-SystemInformation
    Display-SystemInformation $report $outputFilePath
    
    Parse-Hotfix
    Display-Hotfix $report $outputFilePath

    Parse-BIOSInformation
    Display-BIOSInformation $report $outputFilePath

    Parse-DiskInformation
    Display-DiskInformation $report $outputFilePath
    
    Parse-LogicalDiskInformation
    Display-LogicalDiskInformation $report $outputFilePath

    Parse-PhysicalNetworkInformation
    Display-PhysicalNetworkInformation $report $outputFilePath

    Parse-NetworkAdapterInformation
    Display-NetworkAdapterInformation $report $outputFilePath

    Parse-WorldExposedLocalShares
    Display-WorldExposedLocalShares $report $outputFilePath

    Parse-StartupSoftwares
    Display-StartupSoftwares $report $outputFilePath

    Parse-RunningProcess
    Display-RunningProcess $report $outputFilePath

    Parse-RunningServices
    Display-RunningServices $report $outputFilePath

    Parse-ApplicationsInstalled
    Display-ApplicationsInstalled $report $outputFilePath
    
    Run-LocalSecurityProducts

    Parse-SecurityEvents
    Display-SecurityEvents $report $outputFilePath

    Parse-DLLHijackability
    Display-DLLHijackability $report $outputFilePath

    Parse-LocalGroupMembership
    Display-LocalGroupMembership $report $outputFilePath
    
    Parse-BinaryWritableServices
    Display-BinaryWritableServices $report $outputFilePath

    Parse-UnquotedPathServices
    Display-UnquotedPathServices $report $outputFilePath

    Parse-ConfigurableServices
    Display-ConfigurableServices $report $outputFilePath

    Parse-UACLevel
    Display-UACLevel $report $outputFilePath

    Parse-Services
    Display-Services $report $outputFilePath

    Parse-HostedServices
    Display-HostedServices $report $outputFilePath
    
    Parse-Autoruns
    Display-Autoruns $report $outputFilePath

    Parse-UnattendedInstallFiles
    Display-UnattendedInstallFiles $report $outputFilePath

    Parse-ScheduledTasks
    Display-ScheduledTasks $report $outputFilePath

    Parse-ScheduledTasksNotInSystem32
    Display-ScheduledTasksNotInSystem32 $report $outputFilePath
    
    Parse-HostsFile
    Display-HostsFile $report $outputFilePath
    
    # Can work, but take some time ;)
    #Parse-FullAccessDirectoriesOnDriveC
    #Display-FullAccessDirectoriesOnDriveC $report $outputFilePath

    If ([System.IO.File]::Exists($jsonFilePath)) {

        Clear-Content $jsonFilePath

    } Else {

        New-Item $jsonFilePath -ItemType File

    }

    $report | ConvertTo-JSON | Out-File $jsonFilePath

    $end = Get-Date
    $CompletionTimeInSeconds = $(New-TimeSpan -Start $start -End $end).TotalSeconds

    Write-Log -level INFO "[!!] Done`n"
    Write-Log -level INFO "Audit completed in $CompletionTimeInSeconds seconds. `n"
    
    Write-Log -level INFO  "End Audit at $end"
    Write-Log -level INFO  "-------------------------------------`n"
}

Initialize-Audit
