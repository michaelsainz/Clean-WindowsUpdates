#Requires -Version 3
<#
.Synopsis
   Removes Windows Updates using the Microsoft supported functions.
.DESCRIPTION
   This script will use Microsoft supported methods to safely remove superseded
   updates from the system. Once removed, these updates cannot be uninstalled.
   The primary benefit is recoverying disk space.
.EXAMPLE
   Clear-WindowsUpdateCache -ComputerName <string>
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   Michael Sainz
   mike@iamdigerati.com
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
[CmdLetBinding()]
Param (        
    [Parameter(
        Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true, 
        ValueFromRemainingArguments=$false, 
        HelpMessage="Enter one or more computer names seperated by commas.")]
    [Alias("MachineName","CN")] 
    [String[]]$ComputerName = $env:COMPUTERNAME
)

function Test-Hotfix {
    [CmdletBinding()]
    Param (
        # Accept a single or multiple computers from the pipeline
        [Parameter(
            Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            HelpMessage="Enter one or more computer names seperated by commas.")]
        [Alias("MachineName","CN")]
        [String[]]$ComputerName = $env:COMPUTERNAME
    )
    Begin {
        ForEach($C in $ComputerName) {
        Write-Debug -Message "Entering Test-Hotfix function for $C."
        }
    }
    Process {
        ForEach($C in $ComputerName) {
            Try {
                Write-Debug -Message "Checking $C for Windows Update KB2852386."
                Write-Verbose -Message "Checking for Windows 7 Hotfix on $C."
                Get-HotFix -ComputerName $C -Id KB2852386 -ErrorAction Stop | Out-Null
                Write-Verbose -Message "Hotfix is installed on $C."
            }
	        Catch [System.UnauthorizedAccessException] {
		        Write-Verbose -Message "Unable to access the remote computer- Access is denied. Exiting."
            }
            Catch [System.Management.Automation.RuntimeException] {
                Write-Verbose -Message "Hotfix not installed. Exiting."
            }
        }
    }
    End {
        Write-Debug -Message "Exiting Get-Hotfix function."
    }
}

function Clear-Windows7UpdateCache {
    [CmdletBinding()]
    Param (
        # Accept a single or multiple computers from the pipeline
        [Parameter(
            Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            HelpMessage="Enter one or more computer names seperated by commas.")]
        [Alias("MachineName","CN")] 
        [String[]]$ComputerName = $env:COMPUTERNAME
    )

    Begin {
        $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup"
        ForEach($C in $ComputerName) {
            Write-Debug -Message "Entering Clear-Windows7UpdateCache function."
        }
    }
    Process {
	    ForEach($C in $ComputerName) {
            Try {
                Write-Verbose -Message "Executing the Windows Cleanup Manager on $C."
                
                Invoke-Command -ComputerName $C -ErrorAction Stop -ScriptBlock {
                    New-ItemProperty -Path $Args[0] -Name StateFlags0128 -PropertyType DWord -Value 2 -ErrorAction Stop | Out-Null} -ArgumentList $Key
		        Invoke-Command -ComputerName $C -ErrorAction Stop -ScriptBlock {
                Start-Process CleanMgr.exe -ArgumentList "/sagerun:128" -NoNewWindow -Wait}
	            
                Write-Verbose -Message "Successfully removed superseded updates on $C."
            }
            Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                Write-Debug -Message "PSRemoting exception. WinRM is not configured."
                Write-Verbose -Message "PSRemoting (WinRM) needs to be enabled on $C."
            }
        }
    }
    End {
        Invoke-Command -ComputerName $C -ErrorAction Stop -ScriptBlock {
                Remove-ItemProperty -Path $Args[0] -Name StateFlags0128} -ArgumentList $Key
        
        Write-Debug -Message "Exiting Clear-Windows7UpdateCache function."
    }
}

function Clear-Win81UpdateCache {
    [CmdletBinding()]
    [OutputType([int])]
    Param (
        # Accept a single or multiple computers from the pipeline
        [Parameter(
            Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            HelpMessage="Enter one or more computer names seperated by commas.")]
        [Alias("MachineName","CN")] 
        [String[]]$ComputerName = $env:COMPUTERNAME
    )

    Begin {
        Write-Debug -Message "Entering Clear-Win81UpdateCache function."
        Write-Verbose -Message "Clearing Windows 8.1 Updates on $ComputerName."
    }
    Process {
        Try {
            Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
                Start-Process DISM.exe -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait}
            Write-Verbose -Message "Successfully cleaned Windows Updates out of the Windows Component Store on $ComputerName."
        }
        Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Debug -Message "PSRemoting exception. WinRM is not configured."
            Write-Verbose -Message "PSRemoting (WinRM) needs to be enabled on $ComputerName."
        }
    }
    End {
        Write-Debug -Message "Exiting Clear-Win81UpdateCache function."
    }
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal $Identity
If ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $False) {
	Write-Verbose -Message "Please run this script with Administrator rights. Exiting."
    Exit
}

ForEach ($C in $ComputerName) {
    If($C -eq $env:COMPUTERNAME) {
        Write-Debug -Message "Running locally on this system."
        If([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2)) {
            Write-Verbose -Message "Currently running Windows 7. Calling the Windows Cleanup Wizard."
            Test-Hotfix -ComputerName $C
            Clear-Windows7UpdateCache -ComputerName $C
        }

        ElseIf([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,2)) {
            Write-Verbose -Message "Currently running Windows 8.1 or higher. Calling the DISM tool."
            Clear-Win81UpdateCache -ComputerName $C
        }
    }
    Else {
        Try {
            Write-Verbose -Message "Connecting to $C..."
            Write-Debug -Message "Getting the WMI Class for $C."
            $OS = Get-WmiObject -ClassName Win32_OperatingSystem -ComputerName $C -ErrorAction Stop
        }
        Catch [System.Runtime.InteropServices.COMException] {
            Write-Verbose -Message "Could not connect to $C. Ensure that the system is online and that WinRM is configured correctly."
        }
        
        If($OS.Version -like '6.1.*') {
        Write-Verbose -Message "Currently running Windows 7. Calling the Windows Cleanup Wizard."
        Test-Hotfix -ComputerName $C
        Clear-Windows7UpdateCache -ComputerName $C
        }

        ElseIf($OS.Version -like '6.3.*') {
        Write-Debug -Message "I got Windows 8.1."
        Write-Verbose -Message "Currently Running Windows 8.1 or higher. Calling the DISM tool."
        Clear-Win81UpdateCache -ComputerName $C
        }
    }
}