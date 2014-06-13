<#
.SYNOPSIS 
Removes Windows Updates using the Microsoft supported functions.

.DESCRIPTION
This script will use Microsoft supported methods to safely remove superseded
updates from the system. Once removed, these updates cannot be uninstalled.
The primary benefit is recoverying disk space.

.NOTES
Michael Sainz
mike@iamdigerati.com

.LINK
http://www.iamdigerati.com/

#>

[CmdletBinding()]
Param()

$DebugPreference = "Continue"

Write-Debug "Checking for Administrator rights."
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal $Identity
If ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $False) {
	Write-Debug "Script isn't running with Administrator rights. Exiting."
    Write-Verbose "Please run this script with Administrator rights. Exiting."
    Exit
    }

function Check-Hotfix {
	Write-Debug "Entered function Check-Hotfix."
	Try {
		Get-HotFix -Id KB2852386 -ErrorAction Stop
		Write-Debug "Hotfix KB2852386 is installed."
	}
	Catch {
		Write-Debug "The Get-Hotfix cmdlet returned an error."
        Write-Verbose "Missing needed hotfix."
    }
	Finally {
		Write-Debug "Exiting function Check-Hotfix."
	}
}

Function Clean-Windows7Updates {
Write-Debug "Entered function Clean-Windows7Updates."
If (Check-Hotfix -eq True) {
	Write-Debug "Writing a registry key to variable."
	$Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup"
	Try {
		Write-Debug "Writing the registry configuration for the Cleanup function."
        New-ItemProperty -Path $Key -Name StateFlags0128 -PropertyType DWord -Value 2 -ErrorAction Stop | Out-Null
        Write-Debug "Successfully set registry key for the Cleanup function."
	}
	Catch [System.Management.Automation.ActionPreferenceStopException] {
		Write-Debug "Couldn't write the registry key needed for the Cleanup function."
	}
	Catch {
		Write-Debug "A general error occured, exiting."
	}
	Finally {}
	
    Write-Debug "Executing the Cleanup Manager process."
    Write-Verbose "Executing the Windows Cleanup Manager."
	Start-Process CleanMgr.exe -ArgumentList "/sagerun:128" -NoNewWindow -Wait
	Write-Debug "Cleaning up registry configuration for the Cleanup function."
	Remove-ItemProperty -Path $Key -Name StateFlags0128
    Write-Verbose "Successfully cleaned Windows Updates out of the Windows Component Store."
}
Else{
	Write-Verbose "Hotfix KB2852386 is not installed on this machine. Exiting."
    }
}
Function Clean-Windows81Updates {
    Write-Debug "Entered function Clean-Windows81Updates."
    Try {
    Write-Debug "Executing DISM tool."
    Start-Process DISM.exe -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait
    Write-Debug "DISM completed successfully."
    Write-Verbose "Successfully cleaned Windows Updates out of the Windows Component Store."
    }
    Catch {
    Write-Debug "Caught an unknown error while executing DISM process."
    Write-Verbose "An unknown error occurred while attempting to execute the DISM tool. Exiting"
    Exit
    }
    Finally {}
}
If([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2)) {
    Write-Verbose "Currently running Windows 7. Calling Windows Cleanup Wizard."
    Clean-Windows7Updates
}
ElseIf([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,2)) {
    Write-Verbose "Currently running Windows 8.1 or higher. Calling the DISM tool."
    Clean-Windows81Updates
}