Param([string]$verbosity, [string]$range)

if ([string]::IsNullOrEmpty($verbosity)) {

    $verbosity = "1"

}

function Get-AddressesFromRange($range) {

    $listAddresses = @()

    # Parse the range
    $from, $to = $range.Split("-")

	try {
		
        # Convert from IP to integer
		$from_parsed = [system.net.ipaddress]::Parse($from).GetAddressBytes()
		[array]::Reverse($from_parsed)
		$from_uint32 = [system.BitConverter]::ToUInt32($from_parsed, 0)
		
        # Convert to IP to integer
		$to_parsed = [system.net.ipaddress]::Parse($to).GetAddressBytes()
		[array]::Reverse($to_parsed)
		$to_uint32 = [system.BitConverter]::ToUInt32($to_parsed, 0)

	} catch {
		
		Write-Output "The range contains an invalid IP address."
		Write-Output "-range <from_ip>-<to_ip>"
        
	}

	$ipv4 = $from.Split(".") | % {iex $_}
	
	$i = 3
	
	while ($from_uint32 -le $to_uint32 -and $i -ge 0) {
	
		# Test IP
		# $from
		$listAddresses += $from

		while ($i -ge 0) {
		
			if ( ( $ipv4[$i] + 1 ) -gt 255) {
			
				$ipv4[$i] = 0
				$i = $i - 1;
				
			} else {
				
				$ipv4[$i] = $ipv4[$i] + 1
				
				if ($i -ne 3) {
						
					$i = $i + 1
				
				}
				
				break
			
			}
			
		}
		
		$from = $ipv4 -join "."

		$from_parsed = [system.net.ipaddress]::Parse($from).GetAddressBytes()
		[array]::Reverse($from_parsed)
		$from_uint32 = [system.BitConverter]::ToUInt32($from_parsed, 0)
		
	}

    $listAddresses

}

if ( [string]::IsNullOrEmpty($range) ) {

    .\waps.ps1 -verbosity $verbosity

} else {

    $ips = Get-AddressesFromRange($range)

    foreach($ip in $ips) {
        
        try {
            
            if (-not (Test-Connection -Count 1 $ip -quiet) ) {

                Write-Output "Error: No connectivity on $ip"

            } else {
                
                Write-Output "Found: Connectivity on $ip"
                
                $hostName = [system.net.dns]::gethostentry($ip).HostName
                $hostName

                if([bool](Test-WSMan -ComputerName $hostName -ErrorAction SilentlyContinue)) {

                    Invoke-Command -ComputerName $hostName -FilePath .\waps.ps1 -ArgumentList $verbosity

                    $pwd = Invoke-Command -ComputerName $hostName -ScriptBlock {pwd}
                    $path_remote = $pwd.Path.Replace('C:', 'C$')

                    $COMPUTERNAME = Invoke-Command -ComputerName $hostName -ScriptBlock {$env:COMPUTERNAME}
                    
                    Copy-Item -Path "\\$COMPUTERNAME\$path_remote\secedit-$COMPUTERNAME*" -Destination .
                    Copy-Item -Path "\\$COMPUTERNAME\$path_remote\logs-$COMPUTERNAME*" -Destination .
                    Copy-Item -Path "\\$COMPUTERNAME\$path_remote\output-$COMPUTERNAME*" -Destination .
                    Copy-Item -Path "\\$COMPUTERNAME\$path_remote\json-$COMPUTERNAME*" -Destination .

                    Remove-Item -Path "\\$COMPUTERNAME\$path_remote\secedit-$COMPUTERNAME*"
                    Remove-Item -Path "\\$COMPUTERNAME\$path_remote\logs-$COMPUTERNAME*"
                    Remove-Item -Path "\\$COMPUTERNAME\$path_remote\output-$COMPUTERNAME*"
                    Remove-Item -Path "\\$COMPUTERNAME\$path_remote\json-$COMPUTERNAME*"

                } else {

                    Write-Output "Error: WinRM is not activated on $hostName ($ip)"

                } 
            }

        } catch {

            $_

        }
    }

}