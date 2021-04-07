#
# EducateITServerVersions.ps1
# ===========================================================================
# (c)2020 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Get the Versions from the executables
# History:
#   V1.0 - 18.11.2019 - M.Trojahn - Initial creation
#   
#
#	
# ===========================================================================


		
function Get-EitRaptorServerVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\RaptorServer\RaptorServer.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}


		
function Get-EitAssistantServerVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\AssistantServer\AssistantServer.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}


	
function Get-EitActionsServerVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\ActionsServer\ActionsServer.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}


function Get-EitProcessMonitorCollectorVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\ProcessMonitorCollector\ProcessMonitorCollector.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}


function Get-EitPowerShellServiceVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files (x86)\EducateIT\PowerShellService\PowerShellService.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}



function Get-EitStatisticServerVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\StatisticServer\StatisticServer.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}


function Get-EitSessionMonitorVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\SessionMonitor\SessionMonitor.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}

function Get-EitDirectoryScannerServiceVersion {
	param([string]$ComputerName=$env:ComputerName)
	$ExePath = "C:\Program Files\EducateIT\DirectoryScannerService\DirectoryScannerService.exe"
	$Version = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		if (Test-Path $args[0]) {
			(Get-Item -Path  $args[0]).VersionInfo
		}
		else {
			"0"
		}
	} -ArgumentList $ExePath
	return ([pscustomobject]@{ComputerName=$ComputerName;Version=$Version.ProductVersion})
}








