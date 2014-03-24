<#
.SYNOPSIS 
Removes Windows Updates using the Microsoft supported Disk Cleanup Wizard
functions.

.DESCRIPTION
This script will use the Microsoft supported Disk Cleanup Wizard plugin to
safely remove applied Windows updates from the system. Once removed, these
updates cannot be uninstalled. The primary benefit is recovering disk space.

.NOTES
Michael Sainz
mike@iamdigerati.com

.LINK
http://www.iamdigerati.com/

#>

[CmdletBinding()]
Param()

Write-Verbose "Checking for Administrator rights."

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = new-object Security.Principal.WindowsPrincipal $Identity
If ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $False)
    {
    Write-Verbose "Script isn't running with Administrator rights. Exiting."
    Exit
    }

Write-Verbose "Check if the required registry key exists."
$Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup"

Write-Verbose "Writing the registry configuration for the Cleanup function."
Try{
    New-ItemProperty -Path $Key -Name StateFlags0128 -PropertyType DWord -Value 2 -ErrorAction Stop | Out-Null
    }
Catch [System.Management.Automation.ActionPreferenceStopException]{
    Write-Verbose "Couldn't write the registry key needed for the Cleanup function."
    }
Catch{
    Write-Verbose "A general error occured, exiting."
    }
Finally{
    Write-Verbose "Exiting."
    Exit
    }

Write-Verbose "Executing the Cleanup Manager."
Start-Process CleanMgr.exe -ArgumentList "/sagerun:128" -NoNewWindow -Wait

Write-Verbose "Cleaning up registry configuration for the Cleanup function."
Remove-ItemProperty -Path $Key -Name StateFlags0128