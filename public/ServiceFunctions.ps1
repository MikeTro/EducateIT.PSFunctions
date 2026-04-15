#
#
# ServiceFunctions.ps1
# ===========================================================================
# (c)2026 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Service Functions for Raptor Scripts
#
# History:
#   V1.0 - 15.04.2026 - M.Trojahn - Initial creation
#                                       


function Update-EitServiceAccount 
{
	<#
		.Synopsis
			Update Account for a Windows Service 
		.Description
			Update Account for a Windows Service 
		
		.Parameter ServiceName
			the service to configure
			
		.Parameter Username
			the username to configure
			
		.Parameter Password
			the password to configure
			
		
		.NOTES  
			Copyright: (c) 2026 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
						V1.0 - 15.04.2026 - M.Trojahn - Initial creation
				
				
	#>	
	
	Param(
		[Parameter(Mandatory=$true)] [string] $ServiceName,
		[Parameter(Mandatory=$false)] [string] $ComputerName="localhost",
		[Parameter(Mandatory=$true)] [string] $Username,
		[Parameter(Mandatory=$true)] [string] $Password
	)
	

	$myService = Get-CimInstance -ComputerName $ComputerName -Query "SELECT * FROM Win32_Service WHERE Name = '$ServiceName'"
	$myService | Invoke-CimMethod -MethodName Change -Arguments @{StartName=$UserName;StartPassword=$Password}
	
	$myService | Invoke-CimMethod -MethodName StopService | Out-Null
	while ($myService.Started) 
	{
		sleep 1
		$myService = Get-CimInstance -ComputerName $ComputerName -Query "SELECT * FROM Win32_Service WHERE Name = '$ServiceName'"
	}
}
