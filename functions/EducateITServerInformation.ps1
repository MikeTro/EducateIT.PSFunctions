#
# EducateITServerInformation.ps1
# ===========================================================================
# (c)2021 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.1
#
# Get the Versions from the executables
# History:
#   V1.0 - 18.11.2019 - M.Trojahn - Initial creation
#	V1.1 - 07.11.2021 - M.Trojahn - renamed from EducateITServerVersions.ps1 to EducateITServerInformation.ps1
#   								add Get-EitServerServiceInfo
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



function Get-EitServerServiceInfo
{
<#
 .Synopsis
		Get info about an EducateIT Srever Service
    .Description
		Use this function to get the Versin & License Information from a EducateIT Server Service
	
	.Parameter ComputerName
		the computer name
		
	.Parameter ServerExePath
		the path to the server executable, for example "C:\Program Files\EducateIT\RaptorServer\RaptorServer.exe"	
		
	.EXAMPLE
		Get-EitServerInfo -ServerExePath "C:\Program Files\EducateIT\RaptorServer\RaptorServer.exe"
		
	.OUTPUTS
		ComputerName   : RAPTOR19
		ProductName    : Raptor
		ProductVersion : 4.10.2
		LicensedTo     : n/a
		ValidLicense   : True
		Status         : valid
		IsTrial        : False
		ExpiresInDays  : 165

	.NOTES  
		Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History:
            V1.0 - 07.11.2021 - M.Trojahn - Initial creation
			
    #>	
	param(
		[string]$ComputerName=$env:ComputerName,
		[parameter(Mandatory = $true)][string]$ServerExePath
	)
	
	$ServerInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		$ServerExePath = $args[0]
		if (Test-Path $ServerExePath)
		{
			$tmpOutPut = New-TemporaryFile
			$dummy = Start-Process -FilePath $ServerExePath -ArgumentList "--license-status" -RedirectStandardOutput $tmpOutPut -PassThru -Wait
			$LicData = Get-Content $tmpOutPut
			If ($LicData.Contains("Licensed to:"))
			{
				$tmp = $LicData[0] -split ': '
				$LicensedTo = $tmp[1]
				
			}
			else {
				$LicensedTo = "n/a"
			}
			Remove-Item $tmpOutPut
			
			$tmpOutPut = New-TemporaryFile
			$dummy = Start-Process -FilePath $ServerExePath -ArgumentList "--license-status-json" -RedirectStandardOutput $tmpOutPut -PassThru -Wait
				
			$LicData = try { Get-Content $tmpOutPut | ConvertFrom-Json } catch { $null }
			if ($LicData -eq $null)
			{
				$LicData = ([pscustomobject]@{LicensedTo="n/a";valid_license="n/a";Status="n/a";is_trial="n/a";expires_in_days="n/a"})
			}
			Remove-Item $tmpOutPut
			$VersionInfo = $(Get-Item -Path $ServerExePath).VersionInfo
			$ServerInfo += ([pscustomobject]@{ComputerName=$env:ComputerName;ProductName=$VersionInfo.ProductName;ProductVersion=$VersionInfo.ProductVersion;LicensedTo=$LicensedTo;ValidLicense=$LicData.valid_license;Status=$LicData.status;IsTrial=$LicData.is_trial;ExpiresInDays=$LicData.expires_in_days})
		}
		else
		{
			"0"
		}
		$ServerInfo
	} -ArgumentList $ServerExePath
		
	return ([pscustomobject]@{ComputerName=$ServerInfo.ComputerName;ProductName=$ServerInfo.ProductName;ProductVersion=$ServerInfo.ProductVersion;LicensedTo=$ServerInfo.LicensedTo;ValidLicense=$ServerInfo.ValidLicense;Status=$ServerInfo.Status;IsTrial=$ServerInfo.IsTrial;ExpiresInDays=$ServerInfo.ExpiresInDays})
}



