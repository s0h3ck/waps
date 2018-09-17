# Windows Audit PowerShell (WAPS)

This script was created to encourage the community to better audit Windows system. It uses a lot of concepts designed in [WINspect](https://github.com/A-mIn3/WINspect). WAPS enchances modularity on top of it so modules can be inserted or removed with the auditor preferences.

This tool has been tested on:
- Microsoft Windows Server 2008 R2 Standard
- Microsoft Windows Server 2008 R2 Enterprise
- Microsoft Windows Server 2012 R2 Enterprise
- Microsoft Windows 7 Enterprise
- Microsoft Windows 10 Enterprise
- Microsoft Windows Server 2016 Datacenter

Trial Enterprise Windows versions were used to test the script.

## TL;DR

Quoted from WINspect:

> It focuses on enumerating different parts of a Windows machine to identify security weaknesses and point to components that need further hardening.

In addition, it parses other interesting information about the system to further enchance the output with a baseline defined by your organisation. It aims to run on multiple machines and output the results. It's basically just a collector of interesting information about the Windows machine.

You will benefit from this tool if you have a baseline of authorized applications, services and your configuration is strict and minimal. Whitelisting is good too.

## Features (28 modules)
Module-X implies Parse-X and Display-X functions. Display-X is a plaintext version of the results of one function and steps produced during execution.

Module-SystemInformation - Collecting information about the system such as PowerShell version, domain role and operating system.

Module-HotFix - Collecting the hotfixes installed on the system

Module-BIOSInformation - Collecting information about the BIOS

Module-DiskInformation - Collecting information about the disk

Module-LogicalDiskInformation - Collecting information about the logical disk

Module-PhysicalNetworkInformation - Collecting information about the physical network adapter

Module-NetworkAdapterInformation - Collecting information about network adapter

Module-WorldExposedLocalShares - Collecting information about the local shares and their associated DACLs

Module-StartupSoftwares - Collecting the startup softwares (the programs)

Module-RunningProcess - Collecting the running processes

Module-RunningServices - Collecting the services

Module-ApplicationsInstalled - Collecting the applications installed

Module-LocalSecurityProducts - Collecting the firewall configuration and third party products such as antivirus and antispyware.

Module-SecurityEvents - Collecting newest eventlog that succeed and failed (respectively 10 and 20 events by default)

Module-DLLHijackability - Collecting DLL Hijackability

Module-LocalGroupMembership - Collecting domain users and groups with local group membership

Module-BinaryWritableServices - Collecting local services that are configurable by Authenticated Users group members

Module-UnquotedPathServices - Collecting services with unquoted path vulnerability

Module-ConfigurableServices - Collecting configurable services

Module-UACLevel - Collecting User Account Control (UAC) settings

Module-Services - Collecting local services 

Module-HostedServices - Non-system32 Windows Hosted Services and their associated DLLs

Module-Autoruns - Registry autoruns

Module-UnattendedInstallFiles - Collecting remaining files used by unattended installs

Module-ScheduledTasks - Collecting local scheduled tasks

Module-ScheduledTasksNotInSystem32 - Collecting non-system32 Windows Hosted Services

Module-HostsFile - Collecting hosts in the hosts file in system32

Module-FullAccessDirectoriesOnDriveC - Collecting directories with full access on drive C:

ConvertTo-Json - A version to be compatible with PowerShell v2.0

## How to use it locally?
To run it locally, use waps.ps1.
To run it remotely, use waps.ps1 and waps\_agent.ps1.

```text
powershell .\waps.ps1 -verbosity 3
powershell .\waps\_agent.ps1 -verbosity 3 -range "192.168.0.1-192.168.0.255"
```

To convert the Json format v2 to something more readable, run the following:

```text
Get-Content -Raw -Path .\json-DESKTOP-1337-1337133742.json | ConvertFrom-Json | ConvertTo-Json > json-DESKTOP-1337-1337133742-readable.json
```

To list all properties of PowerShell object, add `| Format-List *` after the command.

## How to use it remotely?
### Option 1: Target a computer locally
```text
powershell .\waps.ps1 -verbosity 3
```

### Option 2: Target a computer range by IP
```text
powershell .\waps\_agent.ps1 -verbosity 3 -range "192.168.0.1-192.168.0.255"
```

## WorkFlow
It will create four files where the script is started if there are no errors:

1) secedit-$timestamp.log = secedit-1337133742.log
2) logs-$env:computername:$unixEpochTime.txt = logs-DESKTOP-1337-1337133742.txt
3) output-$env:COMPUTERNAME-$timestamp.txt = output-DESKTOP-1337-1337133742.txt
4) json-$env:COMPUTERNAME-$timestamp.txt = json-DESKTOP-1337-1337133742.txt

If there are errors such as administrator permission needed, only 2 and 3 will be created.

## Problem running the script?
Error such as waps.ps1 cannot be loaded because running scripts is disabled on this system. Execute as administrator:
```text
Set-ExecutionPolicy Bypass
```
Be sure to return to the default state once your done.

## Contributions
Please contribute and suggest any improvements. Spelling, design modeling, exchanging ideas, etc. If you want to point an issue, please [file an issue](https://github.com/s0h3ck/waps/issues).

### TODO
- [ ] Improve the documentation (how to use it, options, plan of customization, etc.)
- [ ] Improve compatibility between version (more tests)
- [ ] More stuff about active directory? Yes, always.

## Direct contributions
Please make sure you respect the code style of [Powershell](https://github.com/PoshCode/PowerShellPracticeAndStyle). Please indent your code with 4 spaces. You feel ready to push a new module?

Fork the repository.
Fill a pull request.
Poke me and it will be approved a few days later ;)

## Need Help
If you have questions or need further guidance on using the tool, please [file an issue](https://github.com/s0h3ck/waps/issues) or contact me.

## License
This project is licensed under The GPL terms.
