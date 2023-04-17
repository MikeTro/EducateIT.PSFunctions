#
# CitrixFunctions.ps1
# ===========================================================================
# (c)2023 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.12
#
# Citrix Functions for Raptor Scripts
#
# History:
#   V1.0 - 01.09.2016 - M.Trojahn - Initial creation
#   V1.1 - 06.09.2017 - M.Trojahn - Add Get-EitFarmSessions
#   V1.2 - 18.11.2019 - M.Trojahn - Get-EitCitrixLicenseInformation, Get-EitCitrixLicenseServer, Get-EitSiteInfo
#	V1.3 - 11.11.2019 - M.Trojahn - Get-EitCitrixMachineInfo, Remove-EitProvVM, New-EitProvVM
#	V1.4 - 11.02.2020 - M.Trojahn - Add-EitBrokerTag, Remove-EitBrokerTag, Add Tag in Get-EitCitrixMachineInfo
#	V1.5 - 26.02.2020 - M.Trojahn - Updates in New-EitProvVM
#	V1.6 - 20.08.2020 - M.Trojahn - Resume-EitCitrixBrokerMachine, Reset-EitCitrixBrokerMachine, Start-EitCitrixBrokerMachine, Stop-EitCitrixBrokerMachine,
#									Restart-EitCitrixBrokerMachine, Suspend-EitCitrixBrokerMachine, Invoke-EitCitrixBrokerMachineShutdown
#	V1.7 - 26.10.2020 - M.Trojahn - Invoke-EitUserSessionLogoff, Stop-BrokerSession
#	V1.8 - 08.03.2021 - M.Trojahn - Use -MaxRecordCount 10000 in function Get-EitFarmServers 
#	V1.9 - 03.05.2021 - M.Trojahn - Don't stop in Invoke-EitUserSessionsLogoff if a broker is not reachable
#  V1.10 - 21.12.2022 - M.Trojahn - Remove MaxRecordCount from Stop-EitBrokerSession 
#  V1.11 - 20.03.2023 - M.Trojahn - add Get-EitBrokerMachines
#  V1.12 - 12.04.2023 - M.Trojahn - add Get-EitBrokerSessions, Stop-EitAllBrokerSessionOnMachine
#
#
#
#


function Get-EitFarmServers {
	<#
	 .Synopsis
			Get citrix farm servers 
		.Description
			List Citrix farm servers
		
		.Parameter FarmEntryPoints
			the farm entry point, XenDesktop Controller / XenApp Server
			
		.EXAMPLE
			Get-EitFarmServers -FarmEntryPoint xd01
			List all farmserver from FarmEntryPoint XD01
	
		.EXAMPLE
			Get-EitFarmServers -FarmEntryPoint xd01, xd02
			List all farmserver from the FarmEntryPoints XD01 & XD02
	
			
			
		.NOTES  
			Copyright: (c)2016 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 01.09.2016 - M.Trojahn - Initial creation
	 #>	
	Param 
		(	[Parameter(Mandatory=$true)]  [string[]]$FarmEntryPoints
		) 
		
	$FarmType = "XenDesktop"
	$MachineList = @()
	$bSuccess = $false
	$StatusMessage = "Error while reading machine list!"
	
	$DSNfile = "C:\Program Files (x86)\Citrix\Independent Management Architecture\MF20.dsn"
	try {
		if (Test-Path $DSNfile) { $FarmType = "XenApp" }
	
		foreach ($item in $FarmEntryPoints) {
			if (Test-EitPort -server $item -port 5985 -timeout "1000") {
				$Session = New-PSSession -ComputerName $item -ErrorAction stop 
				$DSNCheck = Invoke-Command -Session $Session -ScriptBlock {Test-Path $args[0]} -ArgumentList $DSNfile
				If ($DSNCheck -eq $true) { $FarmType = "XenApp" }
				if ($FarmType -eq "XenApp") {
					Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix.xenapp.commands} -ErrorAction stop
					$XAServers = Invoke-Command -Session $Session -ScriptBlock {Get-XAServer | Select Servername}
					Remove-PSSession -Session $Session
					foreach ($XAServer in $XAServers) {
						$MachineList += $XAServers.Servername
					}
					$StatusMessage = "Successfully read machine list..."
					$bSuccess = $true
				}
				else {
					Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
					$XDMachines = Invoke-Command -Session $Session -ScriptBlock {Get-BrokerMachine -MaxRecordCount 10000 | Select DNSName} 
					Remove-PSSession -Session $Session
					foreach ($XDMachine in $XDMachines) {
						$MachineList += $XDMachine.DNSName
					}
					$StatusMessage = "Successfully read machine list..."
					$bSuccess = $true
				}
			}
			else {
				throw "ERROR, server $item is not reachable"
			}
		}
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$MachineList = $MachineList | select -uniq
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;MachineList=$MachineList})
	return $ReturnObject
}
	

function Get-EitBrokerMachines {
	<#
	 .Synopsis
			Get citrix machines
		.Description
			List Citrix machines
		
		.Parameter Brokers
			the XenDesktop Controllers
			
		.EXAMPLE
			Get-EitBrokerMachines -Brokers xd01
			List all machines from Broker XD01
	
		.EXAMPLE
			Get-EitBrokerMachines -Brokers xd01, xd02
			List all machines from the brokers XD01 & XD02
	
			
			
		.NOTES  
			Copyright	:	(c)2023 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 20.03.2023 - M.Trojahn - Initial creation
	 #>	
	Param 
		(	[Parameter(Mandatory=$true)]  [string[]]$Brokers
		) 
		
	$MachineList = @()
	$bSuccess = $false
	$StatusMessage = "Error while reading machine list!"
	
	function Make-EITSBrokerMachineData($DNSName, $MachineName, $SessionSupport, $OSType) {
		$out = New-Object psobject
		$out | add-member -type noteproperty -name DNSName $DNSName.ToLower()
		$out | add-member -type noteproperty -name MachineName $MachineName.ToLower()
		$out | add-member -type noteproperty -name SessionSupport $SessionSupport.ToString().ToLower()
		$out | add-member -type noteproperty -name OSType $OSType.ToLower()
		$out
	}

	try 
	{
		foreach ($Broker in $Brokers) 
		{
			if (Test-EitPort -server $Broker -port 5985 -timeout "1000") 
			{
				$Session = New-PSSession -ComputerName $Broker -ErrorAction stop 
				Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
				$BrokerMachines = Invoke-Command -Session $Session -ScriptBlock {Get-BrokerMachine -MaxRecordCount 10000 | Select DNSName, MachineName, SessionSupport, OSType} 
				foreach ($BrokerMachine in $BrokerMachines) 
				{
					$MachineList += Make-EITSBrokerMachineData -DNSName $BrokerMachine.DNSName -MachineName $BrokerMachine.MachineName -SessionSupport $BrokerMachine.SessionSupport -OSType $BrokerMachine.OSType
				}	
				Remove-PSSession -Session $Session
				$StatusMessage = "Successfully read machine list..."
				$bSuccess = $true
				
			}
			else 
			{
				throw "ERROR, broker $Broker is not reachable via WinRM!"
			}
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$UniqueMachineList = $MachineList | Get-EitPSUnique | Sort DNSName
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;MachineList=$UniqueMachineList})
	return $ReturnObject
}

	
function Get-EitFarmSessions {
	<#
	.Synopsis
			Get citrix farm sessions 
		.Description
			List Citrix farm sessions
		
		.Parameter FarmEntryPoints
			the farm entry point, XenDesktop Controller / XenApp Server
			
		.EXAMPLE
			Get-EitFarmSessions -FarmEntryPoint xd01
			List all session from FarmEntryPoint XD01

		.EXAMPLE
			Get-EitFarmSessions -FarmEntryPoint xd01, xd02
			List all sessions from the FarmEntryPoints XD01 & XD02

			
			
		.NOTES  
			Copyright: (c)2017 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 06.09.2017 - M.Trojahn - Initial creation
	#>	
	Param (	[Parameter(Mandatory=$true)]  [string[]]$FarmEntryPoints
	) 
	
	
	function Make-EITSessionDataData($UserName, $ServerName) {
		$out = New-Object psobject
		$out | add-member -type noteproperty -name UserName $UserName
		$out | add-member -type noteproperty -name ServerName $ServerName
		$out
	}
		
	
	$FarmType = "XenDesktop"
	$SessionList = @()
	$bSuccess = $false
	$StatusMessage = "Error while session machine list!"
	
	$DSNfile = "C:\Program Files (x86)\Citrix\Independent Management Architecture\MF20.dsn"
	try {
		if (Test-Path $DSNfile) { $FarmType = "XenApp" }
		foreach ($item in $FarmEntryPoints) {
			if (Test-EitPort -server $item -port 5985 -timeout "1000") {
				$Session = New-PSSession -ComputerName $item -ErrorAction stop 
				$DSNCheck = Invoke-Command -Session $Session -ScriptBlock {Test-Path $args[0]} -ArgumentList $DSNfile
				If ($DSNCheck -eq $true) { $FarmType = "XenApp" }
				if ($FarmType -eq "XenApp") {
					Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix.xenapp.commands} -ErrorAction stop
					$XASessions = Invoke-Command -Session $Session -ScriptBlock {Get-XASession -Farm | select accountname, servername}
					Remove-PSSession -Session $Session
					foreach ($XASession in $XASessions) {
						$SessionList += (Make-EITSessionDataData -UserName $XASession.AccountName -ServerName $XASession.ServerName)
					}
					
					$StatusMessage = "Successfully read session list..."
					$bSuccess = $true
				}
				else {
					Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
					$XDSessions = Invoke-Command -Session $Session -ScriptBlock {Get-BrokerSession -MaxRecordCount 100000 | Select DNSName, UserName} 
					Remove-PSSession -Session $Session
					foreach ($XDSession in $XDSessions) {
						$SessionList += (Make-EITSessionDataData -UserName $XDSession.UserName -ServerName $XDSession.DNSName)
					}
					$StatusMessage = "Successfully read session list..."
					$bSuccess = $true
				}
			}
			else {
				throw "Server $item is not reachable"
			}
		}
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;SessionList=$SessionList})
	return $ReturnObject
}
	

function Get-EitCitrixLicenseInformation {
	<#
		.Synopsis
		get license informations form the citrix license server
		.Description
			get license informations form the citrix license server
		
		.Parameter LicenseServer
			the license server
			
		.Parameter LicenseServerPort
			the port of the license server
		
			
			
		.EXAMPLE
			Get-EitCitrixLicenseInformation -LicenseServer MyLicenseServer
			List all licenses from the license server MyLicenseServer


			
		.NOTES  
			Copyright: (c)2017 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 20.12.2017 - M.Trojahn - Initial creation
	#>	
	Param(
		[Parameter(Mandatory=$True)] [string] $LicenseServer,
		[Parameter(Mandatory=$false)] [string] $LicenseServerPort = "8083"

	)
	
	
	function Make-EITLicenseData($LicenseServer, $LicenseProductName, $Available, $InUse) {
		$out = New-Object psobject
		$out | add-member -type noteproperty -name LicenseServer $LicenseServer
		$out | add-member -type noteproperty -name LicenseProductName $LicenseProductName
		$out | add-member -type noteproperty -name Available $Available
		$out | add-member -type noteproperty -name InUse $InUse
		$out
	}
	
	try {
		$Session = New-PSSession -ComputerName $LicenseServer -ErrorAction stop 
		Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin Citrix.Licensing.Admin.V1} -ErrorAction stop
		
		$AllLicense = Invoke-Command -Session $Session -ScriptBlock {
			
			
			
			$AdminAddress = "https://" + $args[0] + ":" + $args[1]
			$LicCert = Get-LicCertificate -AdminAddress $AdminAddress
			$AllLicense = Get-LicInventory -AdminAddress $AdminAddress -CertHash $LicCert.CertHash
			$AllLicense

			
		} -ArgumentList $LicenseServer, $LicenseServerPort
		
		Remove-PSSession -Session $Session	
		$LicAll = @{}
		$LicInUse = @{}
		$LicAvailable = @{}
		$LicenseInfo = @()
		$bSuccess = $true
		$StatusMessage = "Successfully get license info!"
		foreach ($License in $AllLicense) {
			$LicenseProductName = $License.LocalizedLicenseProductName
			$InUse = $License.licensesinuse
			$Available = $License.LicensesAvailable
			
			if ($LicInUse.ContainsKey($LicenseProductName)) {
				if ($LicInUse.Get_Item($LicenseProductName) -le $InUse) {
					$LicInUse.Set_Item($LicenseProductName, $InUse)
				}
			}
			else {
				$LicInUse.add($LicenseProductName, $InUse)
			}
			if ($LicAvailable.ContainsKey($LicenseProductName)) {
				if ($LicAvailable.Get_Item($LicenseProductName) -le $Available) {
					$LicAvailable.Set_Item($LicenseProductName, $Available)
				}
			}
			else {
					$LicAvailable.add($LicenseProductName, $Available)
			}
		}	

		
		
		#Output license usage for each type.
		$LicenseTypeOutput = $LicInUse.Keys
		Foreach ($Type in $LicenseTypeOutput) {
			$OutPutLicInUse = $LicInUse.Get_Item($Type)
			$OutPutAvail = $LicAvailable.Get_Item($Type)
			$LicenseInfo += (Make-EITLicenseData -LicenseServer $LicenseServer -LicenseProductName $Type -Available $OutPutAvail -InUse $OutPutLicInUse)
		} 
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;LicenseInfo=$LicenseInfo})
	return $ReturnObject
}

function Get-EitCitrixLicenseServer {
	<#
		.Synopsis
			get the license server from the site config
		.Description
			get license informations form the citrix license server
		
		.Parameter FarmEntryPoints
			the farm entry point, XenDesktop Controller / XenApp Server
			
		.EXAMPLE
			Get-EitCitrixLicenseInformation -FarmEntryPoint xd01
			List the license server from FarmEntryPoint XD01

		.EXAMPLE
			Get-EitCitrixLicenseInformation -FarmEntryPoint xd01, xd02
			List the license server from FarmEntryPoint XD01 & XD02


			
		.NOTES  
			Copyright: (c)2017 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 20.12.2017 - M.Trojahn - Initial creation
	#>
	Param (
		[Parameter(Mandatory=$true)]  [string[]]$FarmEntryPoints
	) 

	$LicenseServer = @()
	$bSuccess = $true
	$StatusMessage = "Successfuly get license server!"
	
	try {
		foreach ($item in $FarmEntryPoints) {
			$Session = New-PSSession -ComputerName $item -ErrorAction stop 
			Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
			$SiteConfig = Invoke-Command -Session $Session -ScriptBlock {Get-ConfigSite}
			Remove-PSSession -Session $Session
			$LicenseServer += $SiteConfig.LicenseServerName
		}
	}	
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;LicenseServer=$LicenseServer})
	return $ReturnObject
}

function Get-EitSiteInfo {
	<#
		.Synopsis
			get information about a citrix site
		.Description
			get information about a citrix site
		
		.Parameter DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		.EXAMPLE
			Get-EitSiteInfo -DDCAddress MyDDC
			List the site info from MYDDC


			
		.NOTES  
			Copyright: (c)2019 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 18.11.2019 - M.Trojahn - Initial creation
	#>
	Param (	
		[Parameter(Mandatory=$true)]  [string[]]$DDCAddress
    ) 

	$SiteInfos = @()
	$ControllerInfo = @()
	$bSuccess = $true
	$StatusMessage = "Successfuly get site info!"
	
	try {
		foreach ($item in $DDCAddress) {
			$Session = New-PSSession -ComputerName $item -ErrorAction stop 
			Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
			$SiteName = (Invoke-Command -Session $Session -ScriptBlock {Get-BrokerSite}).Name
			$Controllers = Invoke-Command -Session $Session -ScriptBlock {Get-BrokerController}
			foreach ($Controller in $Controllers) {
				$ControllerInfo += ([pscustomobject]@{Controller=$Controller.DNSName;ControllerVersion=$Controller.ControllerVersion})
			}
			
			$SiteInfo = ([pscustomobject]@{SiteName=$SiteName;Controller=$ControllerInfo})
			$SiteInfos += $SiteInfo
			$SiteInfo = $null
			Remove-PSSession -Session $Session
		}
		
	}	
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;SiteInfos=$SiteInfos})
	return $ReturnObject
}

function Get-EitCitrixMachineInfo {
	<#
	.Synopsis
			Get infos about a citrix machine 
		.Description
			Get infos about a citrix machine 
		
		.Parameter MachineName
			the machine name to get the infos
			has to be in the format 'DomainName\ComputerName
			
		.Parameter DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
		
		.EXAMPLE
			Get-EitCitrixMachineInfo -MachineName MyDomain\MyComputerName -DDCAddress MyDDC
			
		.NOTES  
			Copyright	:	(c)2019 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 11.11.2019 - M.Trojahn - Initial creation
				V1.0 - 11.02.2020 - M.Trojahn - Add Tags
	#>	
	Param ( 
			[Parameter(Mandatory=$true)] [string] $MachineName, 
			[Parameter(Mandatory=$true)] [string] $DDCAddress
		) 
	If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {	
		$tmp = $MachineName.Split("\")
		$DomainName = $tmp[0]
		$MachineName = $tmp[1]	
		$bSuccess = $true
		$StatusMessage = "Successfuly get machine info"
		$MyBrokerMachine = $Null
		$bActivePersonalVDisk = $false
		Add-pssnapin citrix.*
		$MyBrokerMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress -ErrorAction SilentlyContinue
		If ($MyBrokerMachine -eq $Null) {
			$bSuccess = $false
			$StatusMessage =  "ERROR: Machine $MachineName does not exists!"
		}
		$MyProvVM = $Null
		$MyProvVM = Get-ProvVM -VMName $MachineName -AdminAddress $DDCAddress -ErrorAction SilentlyContinue
		If ($MyProvVM -eq $Null) {
			$bSuccess = $false
			$StatusMessage =  "ERROR: ProvVm $MachineName does not exists!"
		}
		else {
			If ($MyProvVM.PersonalVDiskIndex -ne $Null) {
				$bActivePersonalVDisk = $True
			}
			else {
				$bActivePersonalVDisk = $false
			}	
		}
	}	
	else {
		throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
	}	
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;MachineName=$MyBrokerMachine.MachineName;DDC=$DDCAddress;CatalogName=$MyBrokerMachine.CatalogName;DesktopGroupName=$MyBrokerMachine.DesktopGroupName;AssociatedUserNames=$MyBrokerMachine.AssociatedUserNames;ProvisioningType=$MyBrokerMachine.ProvisioningType;ActivePersonalVDisk=$bActivePersonalVDisk;Tags=$MyBrokerMachine.Tags})
	return $ReturnObject
}

function Remove-EitProvVM {
	<#
	.Synopsis
			Removes a VM that was created using Citrix XenDesktop Machine Creation Services.
			
		.Description
			Removes a VM that was created using Citrix XenDesktop Machine Creation Services.
		
		.Parameter MachineName
			The machine name to remove
			has to be in the format 'DomainName\ComputerName
			
		.Parameter DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		.Parameter CatalogName
			The name of the catalog
		
		.Parameter Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.Parameter Debug
			Enables the debug log
		
		.EXAMPLE
			Remove-EitProvVM -MachineName MyDomain\MyComputerName -CatalogName MyCatalogName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Copyright	:	(c)2019 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 11.11.2019 - M.Trojahn - Initial creation
	#>	


	Param ( 
			[Parameter(Mandatory=$true)] [string]  $MachineName, 
			[Parameter(Mandatory=$true)] [string]  $CatalogName,
			[Parameter(Mandatory=$true)] [string]  $DDCAddress,
			[Parameter(Mandatory=$true)] [Object[]] $Logger,
			[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
			$Logger.Debug("Command: New-EitProvVM -MachineName " + $MachineName + " -CatalogName " + $CatalogName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
		$succeeded = $false
		$tmp = $MachineName.Split("\")
		$DomainName = $tmp[0]
		$MachineName = $tmp[1]
		
		$TestVM = $Null
		$Logger.Info("Testing machine $MachineName in Catalog $CatalogName")
		$TestVM = Get-BrokerMachine -CatalogName $CatalogName -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress -ErrorAction SilentlyContinue
		If ($TestVM -ne $Null) {
			try {
				Add-PSSnapin citrix.*
				
				$svcStatus = Get-ConfigServiceStatus  -AdminAddress $DDCAddress
				if ($svcStatus -ne "OK") {
					$Logger.Error("Problem with $DDCAddress, ConfigServiceStatus is $svcStatus")
					throw "Problem with $DDCAddress, ConfigServiceStatus is $svcStatus"
				}

				# Query availability of logging
				# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/get-logsite-xd75.html
				# TODO: exit if logging is not available
				$logState = Get-LogSite  -AdminAddress $ddcAddress 
				if ($logState.State -ne "Enabled") {
					$Logger.Error("Problem with $DDCAddress, Logging state is $($logState.State)")
					throw "Problem with $DDCAddress, Logging state is $($logState.State)"
				}
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				
				$HighLevelOp =  Start-LogHighLevelOperation  -AdminAddress $DDCAddress -Source "Remove-EitProvVM" -Text "Remove Machine $MachineName from Catalog $MyMachine.CatalogName "
				Set-BrokerCatalogMetadata  -AdminAddress $DDCAddress -CatalogName $MyMachine.CatalogName  -LoggingId $HighLevelOp.Id -Name 'Remove-EitProvVM_Status' -Value "Getting Machine"
				
				$Logger.Info("Testing MaintMode")
				IF (!$MyMachine.InMaintenanceMode) {
					$Logger.Info("Machine is not in MaintMode, enableing MaintMode...")
					Set-BrokerMachine $MyMachine -InMaintenanceMode $true -AdminAddress $DDCAddress
				}
				else {
					$Logger.Info("Machine is in MaintMode, nothing to do, continue...")
				}

				$Logger.Info("Checking PowerState...")
				if ($MyMachine.Powerstate -eq "On") {
					$Logger.Info("Machine is ON, stopping Machine")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action TurnOff -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$TimeOut = 600
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					
					if ($BrokerHostingPowerActionState -eq "Completed") {
						$return = 0
					}
					else {
						$Logger.Error("TimeOut reached, while turning off VDI!")
						Throw "TimeOut reached, while turning off VDI!"
					}
				}
				else {
					$Logger.Info("Machine is Off, nothing to do, continue...")
				}
				$Logger.Info("Getting ProvVM")
				Set-BrokerCatalogMetadata  -AdminAddress $DDCAddress -CatalogName $MyMachine.CatalogName  -LoggingId $HighLevelOp.Id -Name 'EducateIT_RemoveVDI_Status' -Value "Getting ProvVM"
				$MyProvVM = Get-ProvVM  -AdminAddress $DDCAddress -ProvisioningSchemeName $MyMachine.CatalogName  -VMName $MachineName
				
				$Logger.Info("Unlock VM")
				Unlock-ProvVM  -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -ProvisioningSchemeName $MyMachine.CatalogName  -VMID $MyProvVM.VMId
				
				
				Set-BrokerCatalogMetadata  -AdminAddress $DDCAddress -CatalogName $MyMachine.CatalogName  -LoggingId $HighLevelOp.Id -Name 'EducateIT_RemoveVDI_Status' -Value "Remove ProvVM"
				$Logger.Info("Remove ProvVM - Deleting from Hypervisor")
				$rc = Remove-ProvVM  -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -ProvisioningSchemeName $MyMachine.CatalogName  -VMName $MachineName -RunAsynchronously
				$ProvTask = Get-ProvTask -TaskId $rc.Guid
				$i = 0
				$TimeOut = 600
				while (($ProvTask.Status -ne "Finished") -and ($i -lt $TimeOut)) {
						$ProvTask = Get-ProvTask -TaskId $rc.Guid
						$Logger.Info("Status of Task Remove-ProvVM for machine " + $MyMachine.MachineName + " is " + $ProvTask.Status + ", waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
				}
				
				$ProvTask = Get-ProvTask -TaskId $rc.Guid
				if ($ProvTask.Status -ne "Finished") {
					$Logger.Error("TimeOut reached, while while waiting for vm removal!")
					Throw "TimeOut reached, while waiting for for vm removal!"
				}
				
				
				# to do error check
				$Logger.Info("Remove BrokerMachine from DesktopGroup " + $MyMachine.DesktopGroupName + "(" + $MyMachine.DesktopGroupUid + ")")
				$rc = Remove-BrokerMachine -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -DesktopGroup $MyMachine.DesktopGroupUid -Force -InputObject $MyMachine
				# to do error check
				
				$Logger.Info("Remove BrokerMachine from Catalog " + $MyMachine.CatalogName + "(" + $MyMachine.CatalogUid + ")")
				Remove-BrokerMachine -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -Force -InputObject $MyMachine
				
				$succeeded = $true
				Stop-LogHighLevelOperation -AdminAddress $DDCAddress -HighLevelOperationId $HighLevelOp.Id -IsSuccessful $succeeded
				$Logger.Info("Seccessfuly removed machine $MachineName")
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while removing machine " + $MachineName + ": " + $_ )
				throw $_
			}
			finally {
				# Log high level operation stop, and indicate its success
				# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/start-loghighleveloperation-xd75.html
				<# Stop-LogHighLevelOperation  -AdminAddress $DDCAddress -HighLevelOperationId $HighLevelOp.Id -IsSuccessful $succeeded #>
			}
		}
		else {
			$Logger.Error("Machine $MachineName does not exists! Cannot remove this machine!")
			throw "ERROR: Machine $MachineName does not exists! Cannot remove this machine!"
		}
	}	
	else {
		$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
		throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
	}
}

function New-EitProvVM {
	<#
	.Synopsis
			Creates a new virtual machine using Citrix XenDesktop Machine Creation Services.
			
		.Description
			Creates a new virtual machine using Citrix XenDesktop Machine Creation Services.
		
		.Parameter MachineName
			The machine name to create
			has to be in the format 'DomainName\ComputerName
			
		.Parameter DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		.Parameter CatalogName
			The name of the catalog in which the virtual machine is created
		
		.Parameter DesktopGroupName
			The name of the DeleiveryGroup in which the virtual machine is assigned
		
		.Parameter AssociatedUserNames
			the broker users to add to this private desktop
		
		.Parameter Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.Parameter Debug
			Enables the debug log
		
		.EXAMPLE
			New-EitProvVM -MachineName MyDomain\MyComputerName -CatalogName MyCatalogName -DDCAddress MyDDC -AssociatedUserNames MyDomain\MyUser -Logger MyLogger
			
		.NOTES  
			Copyright	:	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.2
			
			History:
				V1.0 - 11.11.2019 - M.Trojahn - Initial creation
				V1.1 - 26.02.2020 - M.Trojahn - Testing AD Account, Add Account to catalog if it not exists
				V1.2 - 28.02.2020 - M.Trojahn - Updates in AD Account testing
	#>	
	Param ( 
			[Parameter(Mandatory=$true)] [string] $MachineName, 
			[Parameter(Mandatory=$true)] [string] $DDCAddress,
			[Parameter(Mandatory=$true)] [string] $CatalogName,
			[Parameter(Mandatory=$true)] [string] $DesktopGroupName,
			[Parameter(Mandatory=$true)] [string[]] $AssociatedUserNames,
			[Parameter(Mandatory=$true)] [Object[]] $Logger,
			[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("DebugMode is enabled")
	}
	If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
		if ($EnableDebug) {		
			$Logger.Debug("Command: New-EitProvVM -MachineName " + $MachineName + " -CatalogName " + $CatalogName + " -DesktopGroupName " + $DesktopGroupName + " -DDCAddress " + $DDCAddress + " -AssociatedUserNames " + ($AssociatedUserNames -Join (", ")) + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
		}
		$TestVM = $Null
		Add-PSSnapin citrix.*
		$TestVM = Get-BrokerMachine -CatalogName $CatalogName -AdminAddress $DDCAddress -MachineName $MachineName -ErrorAction SilentlyContinue
		If ($TestVM -eq $Null) {
			try {

				$succeeded = $false
				$svcStatus = Get-ConfigServiceStatus  -AdminAddress $ddcAddress
				if ($svcStatus -ne "OK") {
					$Logger.Error("Problem with $DDCAddress, ConfigServiceStatus is $svcStatus")
					throw "Problem with $DDCAddress, ConfigServiceStatus is $svcStatus"
				}

				# Query availability of logging
				# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/get-logsite-xd75.html
				# TODO: exit if logging is not available
				$logState = Get-LogSite  -AdminAddress $ddcAddress 
				if ($logState.State -ne "Enabled") {
					$Logger.Error("Problem with $DDCAddress, Logging state is $($logState.State)")
					throw "Problem with $DDCAddress, Logging state is $($logState.State)"
				}
			
				$Logger.Info("Initializing FullClone for machine $MachineName")
				$HighLevelOp = Start-LogHighLevelOperation -AdminAddress $DDCAddress -Source "New-EitProvVM" -Text "Adding Machine $MachineName to Catalog $CatalogName"
				if ($EnableDebug) {		
					$Logger.Debug("$MyCatalog =  Get-BrokerCatalog -Name $catalogName")
				}
				$MyCatalog =  Get-BrokerCatalog -Name $CatalogName -AdminAddress $DDCAddress
				if ($EnableDebug) {
					$Logger.Debug("Obtained broker catalog UID $($MyCatalog.Uid)")
				}
				Set-BrokerCatalogMetadata -AdminAddress $DDCAddress -CatalogName $CatalogName -LoggingId $HighLevelOp.Id -Name 'New-EitProvVM_Status' -Value "Adding Machine Accounts"

				# http://support.citrix.com/proddocs/topic/citrix-adidentity-admin-v2-xd75/get-acctadaccount-xd75.html
				# check to see if there are already account for the account pool able satisfy this request
				if ($EnableDebug) {
					$Logger.Debug("Get-AcctIdentityPool -AdminAddress $DDCAddress -IdentityPoolName $CatalogName -MaxRecordCount 2147483647")
				}
				$AcctIdPool = Get-AcctIdentityPool -AdminAddress $DDCAddress -IdentityPoolName $CatalogName -MaxRecordCount 2147483647
				if ($EnableDebug) {
					$Logger.Debug("Obtained identity pool for $CatalogName, which has UID $($AcctIdPool.IdentityPoolUid) Full variable is $($AcctIdPool)")
				}
				# http://support.citrix.com/proddocs/topic/citrix-adidentity-admin-v2-xd75/get-acctadaccount-xd75.html
				# check to see if there are already account for the account pool able satisfy this request
				# Get-AcctADAccount  -AdminAddress $ddcAddress -IdentityPoolUid $acctIdPool.IdentityPoolUid -Lock $False -MaxRecordCount 2147483647 -State 'Available'


				# http://support.citrix.com/proddocs/topic/citrix-adidentity-admin-v2-xd75/new-acctadaccount-xd75.html
				#LogDebug("calling $NewMachineAccts = New-AcctADAccount  -AdminAddress $DDCAddress -Count $NewDesktopCount -IdentityPoolUid $($AcctIdPool.IdentityPoolUid) -LoggingId $HighLevelOp.Id")
				# $NewMachineAccts = New-AcctADAccount -AdminAddress $DDCAddress -Count $NewDesktopCount -IdentityPoolUid $AcctIdPool.IdentityPoolUid -LoggingId $HighLevelOp.Id
				
				$Logger.Info("Check if AD Account for machine $MachineName exists in Domain...")
				$tmp = $MachineName.Split("\")
				$EitADComputer = Get-EitADComputer -ComputerName $tmp[1]
				if ($EnableDebug) {
					$Logger.Debug($EitADComputer)
				}
				If ($EitADComputer.Success -ne "True") {
					throw "AD Account for machine $MachineName does not exists, please create it first..."
				}     
				$Logger.Info("Check if AD Account for machine $MachineName in Catalog $CatalogName already exists...")
				$MyADAccount = Get-AcctADAccount -IdentityPoolUid $acctIdPool.IdentityPoolUid -AdminAddress $DDCAddress | where {$_.ADAccountName -eq ($MachineName + "$")}
				
				if ($EnableDebug) {
					$Logger.Debug($MyADAccount)
				}
				
				If ($MyADAccount -eq $Null) {
					$Logger.Info("AD Account for machine $MachineName does not exists in catalog $CatalogName, try to adding it...")
					$rc = Add-AcctADAccount -ADAccountName ($MachineName + "$") -AdminAddress $DDCAddress -IdentityPoolName $CatalogName
					if ($rc.FailedAccountsCount -gt 1) {
						$Logger.Info("Account creation in catalog $CatalogName failed. Check permissions")
						throw "Account creation in catalog $CatalogName failed. Check permissions"
					}  
					
				}	
						
				If ($MyADAccount.State -eq "Tainted") {
					$Logger.Info("State of AD Account for machine $MachineName is Tainted, repairing it...")
					$rc = Repair-AcctADAccount -ADAccountName ($MachineName + "$") -AdminAddress $DDCAddress
				}	
				
				if ($EnableDebug) {
					$Logger.Debug("SuccessfulAccountsCount: " + $rc.SuccessfulAccountsCount)
					$Logger.Debug("FailedAccountsCount: " + $rc.FailedAccountsCount)
				}
				
				
				$Logger.Info("Recheck if AD Account for machine $MachineName in Catalog $CatalogName already exists...")
				$MyADAccount = Get-AcctADAccount -IdentityPoolUid $acctIdPool.IdentityPoolUid -AdminAddress $DDCAddress | where {$_.ADAccountName -eq ($MachineName + "$")}	
				
				if ($EnableDebug) {
					$Logger.Debug($($MyADAccount))
				}
				if ([string]::IsNullOrEmpty($MyADAccount)) {
					$Logger.Error("Error with AcctADAccount, result is null!")
					throw "Error with AcctADAccount, result is null!"
				} 

				Set-BrokerCatalogMetadata -AdminAddress $DDCAddress -CatalogName $CatalogName -LoggingId $HighLevelOp.Id -Name 'New-EitProvVM_Status' -Value "Creating new desktop"

				# http://support.citrix.com/proddocs/topic/citrix-machinecreation-admin-v2-xd75/new-provvm-xd75.html
				if ($EnableDebug) {
					$Logger.Debug("Calling New-ProvVM  -ADAccountName $($MyADAccount.SuccessfulAccounts) -AdminAddress $DDCAddress -LoggingId $($HighLevelOp.Id)  -MaxAssistants 5 -ProvisioningSchemeName $CatalogName")
				}
				$Logger.Info("Start cloning machine $MachineName")
				#$newVMs = New-ProvVM  -ADAccountName $NewMachineAccts.SuccessfulAccounts -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id  -MaxAssistants 5 -ProvisioningSchemeName $CatalogName
				$rc = New-ProvVM  -ADAccountName $MyADAccount -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id  -MaxAssistants 5 -ProvisioningSchemeName $CatalogName -RunAsynchronously

				$ProvTask = Get-ProvTask -TaskId $rc.Guid -AdminAddress $DDCAddress
				$i = 0
				$TimeOut = 600
				while (($ProvTask.Status -ne "Finished") -and ($i -lt $TimeOut)) {
					$ProvTask = Get-ProvTask -TaskId $rc.Guid -AdminAddress $DDCAddress
					$Logger.Info("Status of Task New-ProvVM for machine " + $MachineName + " is " + $ProvTask.Status + ", waiting for completion... ($i / $TimeOut) ")
					Start-Sleep -Milliseconds 10000
					$i++
				}
				if ($EnableDebug) {
					$Logger.Debug($(Get-ProvTask -TaskId $rc.Guid -AdminAddress $DDCAddress))
				}
				
				if ($ProvTask.VirtualMachinesCreationFailedCount -ne 0) {
					$Logger.Error("Problem occurred while creating new vm " + $MachineName + ": " + $ProvTask.TerminatingError)
					throw ("Problem occurred while creating new vm " + $MachineName + ": " + $ProvTask.TerminatingError)
				}
				
				
				if ($ProvTask.WorkflowStatus -ne "Completed") {
					$Logger.Error("Problem occurred while creating new vm " + $MachineName + ": " + $ProvTask.TerminatingError)
					throw ("Problem occurred while creating new vm " + $MachineName + ": " + $ProvTask.TerminatingError)
				}
				if ($EnableDebug) {
					$Logger.Debug("New-ProvVM reported $($ProvTask)")
				}
				foreach ($newVM in $ProvTask.CreatedVirtualMachines) {	
					# Lock-ProvVM http://support.citrix.com/proddocs/topic/citrix-machinecreation-admin-v2-xd75/lock-provvm-xd75.html
					if ($EnableDebug) {
						$Logger.Debug("Lock-ProvVM  -AdminAddress $DDCAddress -LoggingId $($HighLevelOp.Id) -ProvisioningSchemeName $CatalogName -Tag 'Brokered' -VMID @($newVM.VMId)")
					}
					$Logger.Info("Locking VM")
					Lock-ProvVM  -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -ProvisioningSchemeName $CatalogName -Tag 'Brokered' -VMID @($newVM.VMId)

					# New-BrokerMachine http://support.citrix.com/proddocs/topic/citrix-broker-admin-v2-xd75/new-brokermachine-xd75.html
					if ($EnableDebug) {
						$Logger.Debug("New-BrokerMachine  -AdminAddress $DDCAddress -CatalogUid $newCatalog.Uid -LoggingId $($highLevelOp.Id) -MachineName $newVM.ADAccountSid")
					}
					$NewBrokeredMachine = New-BrokerMachine  -AdminAddress $DDCAddress -CatalogUid $MyCatalog.Uid -LoggingId $HighLevelOp.Id -MachineName $newVM.ADAccountSid
					if ($EnableDebug) {
						$Logger.Debug("Result from New-BrokerMachine was $newBrokeredMachine")
					}	
				}
				$succeeded = $true
			}
			catch [System.Exception] {
				Set-BrokerCatalogMetadata -AdminAddress $DDCAddress -CatalogName $CatalogName -LoggingId $HighLevelOp.Id -Name 'MyScriptS_Status' -Value "Add new Desktops failed"
				$Logger.Error("Problem with catalog creation / update: " + $_ )
				throw $_
			}
			finally {
				# Log high level operation stop, and indicate its success
				# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/start-loghighleveloperation-xd75.html
				Stop-LogHighLevelOperation -AdminAddress $DDCAddress -HighLevelOperationId $HighLevelOp.Id -IsSuccessful $succeeded
			}
			#------------------END CatalogAddMachine -------------------------------

			#------------------START DesktopGroupAddMachine -------------------------------

			
			# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/start-loghighleveloperation-xd75.html
			$succeeded = $false #indicates if high level operation succeeded.
			$HighLevelOp = Start-LogHighLevelOperation -AdminAddress $DDCAddress -Source "New-EitProvVM" -Text "Adding machines to DeliveryGroup $DesktopGroupName"

			try {
				if ($EnableDebug) {
					$Logger.Debug("Add-BrokerMachinesToDesktopGroup  -AdminAddress $DDCAddress -Catalog $CatalogName -Count 1 -DesktopGroup $DesktopGroupName -LoggingId $HighLevelOp.Id")
				}
				$Logger.Info("Add machine to DesktopGroup $DesktopGroupName")
				$rc = Add-BrokerMachinesToDesktopGroup -AdminAddress $DDCAddress -Catalog $CatalogName -Count 1 -DesktopGroup $DesktopGroupName -LoggingId $HighLevelOp.Id
				
				<# if ($rc.SuccessfulAccountsCount -ne 1) {
					throw "Error while adding machine $MachineName to DesktopGroup $DesktopGroupName, $_"
				} #>
				Set-BrokerCatalogMetadata -AdminAddress $DDCAddress -CatalogName $CatalogName -LoggingId $HighLevelOp.Id -Name 'New-EitProvVM_Status' -Value "Ready"
				$succeeded = $true
				$Logger.Info("Succeeded in creating catalog $catalogName with 1 machine" )
			}
			catch [System.Exception] {
				Set-BrokerCatalogMetadata -AdminAddress $DDCAddress -CatalogName $CatalogName -LoggingId $HighLevelOp.Id -Name 'New-EitProvVM_Status' -Value "Add machine to desktop group failed"
				$Logger.Error("Problem with desktop delivery group creation " + $_ )
				throw $_
			}
			finally	{
				# Log high level operation stop, and indicate its success
				# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/start-loghighleveloperation-xd75.html
				Stop-LogHighLevelOperation -AdminAddress $DDCAddress -HighLevelOperationId $HighLevelOp.Id -IsSuccessful $succeeded
			}
			
			# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/start-loghighleveloperation-xd75.html
			$succeeded = $false #indicates if high level operation succeeded.
			$HighLevelOp =  Start-LogHighLevelOperation -AdminAddress $DDCAddress -Source "New-EitProvVM" -Text "Adding users to machine $MachineName"

			try {
				foreach ($AssociatedUserName in $AssociatedUserNames) {
					if ($EnableDebug) {
						$Logger.Debug("Add-BrokerUser -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -Name $AssociatedUserName -PrivateDesktop $MachineName")
					}
					$Logger.Info("Add user $AssociatedUserName to machine $MachineName")
					Add-BrokerUser -AdminAddress $DDCAddress -LoggingId $HighLevelOp.Id -Name $AssociatedUserName -PrivateDesktop $MachineName
				}
				$succeeded = $true
				$Logger.Info("Succeeded in adding users..." )
							
			}
			catch [System.Exception] {
				Set-BrokerCatalogMetadata -AdminAddress $DDCAddress -CatalogName $CatalogName -LoggingId $HighLevelOp.Id -Name 'New-EitProvVM_Status' -Value "Adding users to machine $MachineName failed"
				$Logger.Error("Problem with adding users " + $_ )
				throw $_
			}
			finally	{
				# Log high level operation stop, and indicate its success
				# http://support.citrix.com/proddocs/topic/citrix-configurationlogging-admin-v1-xd75/start-loghighleveloperation-xd75.html
				Stop-LogHighLevelOperation -AdminAddress $DDCAddress -HighLevelOperationId $HighLevelOp.Id -IsSuccessful $succeeded
			}
			
			try {
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName $MachineName -AdminAddress $DDCAddress
				$Logger.Info("Testing MaintMode")
				If ($MyMachine.InMaintenanceMode) {
					$Logger.Info("Machine is in MaintMode, disable MaintMode...")
					Set-BrokerMachine $MyMachine -InMaintenanceMode $false -AdminAddress $DDCAddress
				}
				else {
					$Logger.Info("Machine is NOT in MaintMode, nothing to do, continue...")
				}
			
				$Logger.Info("Checking PowerState...")
				if ($EnableDebug) {
					$Logger.Debug($($MyMachine))
					$Logger.Debug("Powerstate: " + $MyMachine.Powerstate)
				}
				
				if ($MyMachine.Powerstate -ne "On") {
					$Logger.Info("Machine is OFF, starting Machine")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action TurnOn -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$TimeOut = 600
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					
					if ($BrokerHostingPowerActionState -eq "Completed") {
						$return = 0
					}
					else {
						$Logger.Error("TimeOut reached, while turning on VDI!")
						Throw "TimeOut reached, while turning on VDI!"
					}
				}
				else {
					$Logger.Info("Machine is On, nothing to do, continue...")
				}
				
				$Logger.Info("Checking Registration state...")
				$RegistrationState = $(Get-BrokerMachine -MachineName $MachineName -AdminAddress $DDCAddress).RegistrationState
				if ($RegistrationState -ne "Registered") {
					$i = 0
					$TimeOut = 600
					$RegistrationState = $(Get-BrokerMachine -MachineName $MachineName -AdminAddress $DDCAddress).RegistrationState
					while (($RegistrationState -ne "Registered") -and ($i -lt $TimeOut)) {
						$RegistrationState = $(Get-BrokerMachine -MachineName $MachineName -AdminAddress $DDCAddress).RegistrationState
						$Logger.Info("RegistrationState of Machine " +  $MyMachine.MachineName + " is " + $RegistrationState + ", waiting for registration... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
						if ($EnableDebug) {
							$Logger.Debug($i)
						}
					}
					$RegistrationState = $(Get-BrokerMachine -MachineName $MachineName -AdminAddress $DDCAddress).RegistrationState
					if ($RegistrationState -ne "Registered") {
						$Logger.Error("TimeOut reached, while waiting for registration!")
						Throw "TimeOut reached, while waiting for registration!"
					}
				}
				else {
					$Logger.Info("Machine is Registered, nothing to do, continue...")
				}
				
			}
			catch [System.Exception] {
				$Logger.Error("Problem occurred while turning machine on " + $_ )
				throw $_
			}
			if ($EnableDebug) {
				$Logger.Debug("Machine created successfully!")
			}
		}
		else {
			$Logger.Error("Machine $MachineName already exists! Cannot clone this machine!")
			throw "ERROR: machine $MachineName already exists! Cannot clone this machine!"
		}
	}
	else {
		$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
		throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
	}
}

function Remove-EitBrokerTag {
	<#
		.Synopsis
			Removes a tag from am vm
			
		.Description
			Removes a tag from am vm
		
		.Parameter MachineName
			The machine name to remove the tag
			has to be in the format 'DomainName\ComputerName
			
		.Parameter DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		.Parameter TagName
			The name of the tag to remove
		
		.Parameter Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.Parameter Debug
			Enables the debug log
		
		.EXAMPLE
			Remove-EitBrokerTag -MachineName MyDomain\MyComputerName -TagName MyTag -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Copyright	:	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 11.02.2020 - M.Trojahn - Initial creation
	#>	


	Param ( 
			[Parameter(Mandatory=$true)] [string]  $MachineName, 
			[Parameter(Mandatory=$true)] [string]  $TagName, 
			[Parameter(Mandatory=$true)] [string]  $DDCAddress,
			[Parameter(Mandatory=$true)] [Object[]] $Logger,
			[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
			$Logger.Debug("Command: Remove-EitBrokerTag -MachineName " + $MachineName + " -TagName " + $TagName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
		$succeeded = $false
		$tmp = $MachineName.Split("\")
		$DomainName = $tmp[0]
		$MachineName = $tmp[1]
		
		$TestVM = $Null
		$Logger.Info("Testing machine $MachineName")
		$TestVM = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress -ErrorAction SilentlyContinue
		If ($TestVM -ne $Null) {
			try {
				if ((Get-PSSnapin -Name "Citrix.Broker.Admin.V2" -ErrorAction SilentlyContinue) -eq $null) {
					Add-PSSnapin citrix* -ErrorAction SilentlyContinue
				}
								
				$Logger.Info("Get tags from machine $DomainName\$MachineName")
				<# $MachineTags = $(Get-BrokerMachine -MachineName  $MachineName -AdminAddress $DDCAddress -ErrorAction SilentlyContinue).Tags #>
				$MachineTags = $TestVM.Tags
				$Logger.Info("Testing if tag $TagName exists on machine $DomainName\$MachineName")
				if ($EnableDebug) {		
					$Logger.Debug("MachineTags =  " + $MachineTags)
				}
				if ($MachineTags.contains($TagName)) {
					$Logger.Info("Tag exists, removing it from machine $DomainName\$MachineName")
					if ($EnableDebug) {		
						$Logger.Debug("Command: Remove-BrokerTag -Machine " + $MachineName + " -Name " + $TagName + " -AdminAddress " + $DDCAddress)
					}
					Remove-BrokerTag -Machine ($DomainName + "\" + $MachineName) -Name $TagName -AdminAddress $DDCAddress
				}
				else {
					$msg = "Tag $TagName does not exists on machine $MachineName! Cannot remove tag from this machine!"
					$Logger.Error($msg)
					throw ("ERROR: " + $msg)
				}
				
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while removing tag on machine " + $MachineName + ": " + $_ )
				throw $_
			}
		}
		else {
			$Logger.Error("Machine $MachineName does not exists! Cannot remove tag from this machine!")
			throw "ERROR: Machine $MachineName does not exists! Cannot remove tag from this machine!"
		}
	}	
	else {
		$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
		throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
	}
}

function Add-EitBrokerTag {
	<#
	.Synopsis
			Adds a tag from am vm
			
		.Description
			Adds a tag from am vm
		
		.Parameter MachineName
			The machine name to add the tag
			has to be in the format 'DomainName\ComputerName
			
		.Parameter DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		.Parameter TagName
			The name of the tag to add
		
		.Parameter Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.Parameter Debug
			Enables the debug log
		
		.EXAMPLE
			Add-EitBrokerTag -MachineName MyDomain\MyComputerName -TagName MyTag -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Copyright	:	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 11.02.2020 - M.Trojahn - Initial creation
	#>	


	Param ( 
			[Parameter(Mandatory=$true)] [string]  $MachineName, 
			[Parameter(Mandatory=$true)] [string]  $TagName, 
			[Parameter(Mandatory=$true)] [string]  $DDCAddress,
			[Parameter(Mandatory=$true)] [Object[]] $Logger,
			[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
			$Logger.Debug("Command: Add-EitBrokerTag -MachineName " + $MachineName + " -TagName " + $TagName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
		$succeeded = $false
		$tmp = $MachineName.Split("\")
		$DomainName = $tmp[0]
		$MachineName = $tmp[1]
		
		$TestVM = $Null
		$Logger.Info("Testing machine $MachineName")
		$TestVM = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress -ErrorAction SilentlyContinue
		If ($TestVM -ne $Null) {
			try {
				if ((Get-PSSnapin -Name "Citrix.Broker.Admin.V2" -ErrorAction SilentlyContinue) -eq $null) {
					Add-PSSnapin citrix* -ErrorAction SilentlyContinue
				}
				$Logger.Info("Test if tag $TagName exists...")
				$TestBrokerTag = $null
				$TestBrokerTag = Get-BrokerTag -Name $TagName -AdminAddress $DDCAddress -ErrorAction SilentlyContinue
				
				if ($TestBrokerTag -ne $null) {
					$MachineTags = $TestVM.Tags
					$Logger.Info("Testing if tag $TagName already exists on machine $DomainName\$MachineName")
					if ($EnableDebug) {		
						$Logger.Debug("MachineTags =  " + $MachineTags)
					}
					if (!($MachineTags.contains($TagName))) {
						$Logger.Info("Tag does not exists, adding it to machine $DomainName\$MachineName")
						if ($EnableDebug) {		
							$Logger.Debug("Command: Add-BrokerTag -Machine " + $MachineName + " -Name " + $TagName + " -AdminAddress " + $DDCAddress)
						}
						Add-BrokerTag -Machine ($DomainName + "\" + $MachineName) -Name $TagName -AdminAddress $DDCAddress
					}
					else {
						$msg = "Tag $TagName does already exists on machine $MachineName! Cannot add tag to this machine!"
						$Logger.Error($msg)
						throw ("ERROR: " + $msg)
					}
				}
				else {
					$msg = "Tag $TagName does not exists in this environment, please create it first! Cannot add tag to this machine!"
					$Logger.Error($msg)
					throw ("ERROR: " + $msg)
				}
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while adding tag on machine " + $MachineName + ": " + $_ )
				throw $_
			}
		}
		else {
			$Logger.Error("Machine $MachineName does not exists! Cannot add tag to this machine!")
			throw "ERROR: Machine $MachineName does not exists! Cannot add tag to this machine!"
		}
	}	
	else {
		$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
		throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
	}
}

function Stop-EitCitrixBrokerMachine {
	<#
		.SYNOPSIS
			This functions turns off a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to turn off a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to stop
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Stop-EitCitrixBrokerMachine -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Stop-EitBrokerMachine -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "On") {
					$Logger.Info("Trying to turn off machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action TurnOff -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly turned off!")
					}
					else {
						$Logger.Error("TimeOut reached, while turning off machine $MachineName!")
						Throw "TimeOut reached, while turning off machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to turn off machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Start-EitCitrixBrokerMachine {
	<#
		.SYNOPSIS
			This functions turns on a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to turn on a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to start
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Start-EitCitrixBrokerMachine -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Start-EitBrokerMachine -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "Off") {
					$Logger.Info("Trying to turn on machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action TurnOn -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly turned on!")
					}
					else {
						$Logger.Error("TimeOut reached, while turning on machine $MachineName!")
						Throw "TimeOut reached, while turning on machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to turn on machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Suspend-EitCitrixBrokerMachine {
	<#
		.SYNOPSIS
			This functions suspends a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to suspend a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to suspend
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Suspend-EitCitrixBrokerMachine -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Suspend-EitBrokerMachine -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "On") {
					$Logger.Info("Trying to suspend machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action Suspend -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly suspended!")
					}
					else {
						$Logger.Error("TimeOut reached, while suspending machine $MachineName!")
						Throw "TimeOut reached, while suspending machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to suspend machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Resume-EitCitrixBrokerMachine {
	<#
		.SYNOPSIS
			This functions resumes a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to resume a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to resume
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Resume-EitCitrixBrokerMachine -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Resume-EitBrokerMachine -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "Suspended") {
					$Logger.Info("Trying to resume machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action Resume -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly resumed!")
					}
					else {
						$Logger.Error("TimeOut reached, while resuming machine $MachineName!")
						Throw "TimeOut reached, while resuming machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to resume machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Reset-EitCitrixBrokerMachine {
	<#
		.SYNOPSIS
			This functions resets a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to reset a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to reset
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Reset-EitCitrixBrokerMachine -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Resete-EitBrokerMachine -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "On") {
					$Logger.Info("Trying to reset machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action Reset -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly reseted!")
					}
					else {
						$Logger.Error("TimeOut reached, while reseting machine $MachineName!")
						Throw "TimeOut reached, while reseting machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to reset machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Invoke-EitCitrixBrokerMachineShutdown {
	<#
		.SYNOPSIS
			This functions shutdowns a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to shutdown a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to shutdown
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Invoke-EitCitrixBrokerMachineShutdown -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Invoke-EitBrokerMachineShutdown -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "On") {
					$Logger.Info("Trying to shutdown machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action Shutdown -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly shutdown!")
					}
					else {
						$Logger.Error("TimeOut reached, while shutdown machine $MachineName!")
						Throw "TimeOut reached, while shutdown machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to shutdown machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Restart-EitCitrixBrokerMachine {
	<#
		.SYNOPSIS
			This functions restarts a citrix broker machine (vdi).

		.DESCRIPTION
			Use this function to restart a citrix broker machine (vdi).

		.PARAMETER MachineName
			The machine name to restart
			has to be in the format 'DomainName\ComputerName
		
		.PARAMETER DDCAddress
			Specifies the address of a XenDesktop controller to which the PowerShell snap-in connects.
			
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitFileLogger command
			
		.PARAMETER Debug
			Enables the debug log
		
		.EXAMPLE
			Restart-EitCitrixBrokerMachine -MachineName MyDomain\MyComputerName -DDCAddress MyDDC -Logger MyLogger
			
		.NOTES  
			Requirements : Broker_PowerShellSnapIn_x64.msi

			Copyright	 :	(c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		 :	1.0
			
			History:
				V1.0 - 20.08.2020 - M.Trojahn - Initial creation
	#>	
	<# # Requires -PSSnapin Citrix.Broker.Admin.V2 #>

    param (
	    [Parameter(Mandatory=$True)] [string] $MachineName,
		[Parameter(Mandatory=$true)] [string] $DDCAddress,
		[Parameter(Mandatory=$true)] [Object[]] $Logger,
		[Parameter(Mandatory=$false)] [boolean] $EnableDebug
	) 
	if ($EnableDebug) {		
		$Logger.Debug("Command: Restart-EitBrokerMachine -MachineName " + $MachineName + " -DDCAddress " + $DDCAddress + " -Logger " +  $Logger + " -EnableDebug " + $EnableDebug)
	}
	$SnapinTest = $null
	$SnapinName = "Citrix.Broker.Admin.V2"
	if ((Get-PSSnapin | ? { $_.Name -eq $SnapinName }) -eq $null) {
    	Add-PSSnapin $SnapinName -ErrorAction SilentlyContinue
	}
	$SnapinTest = Get-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue
	if ($SnapinTest -ne $null) {
		If ([Regex]::Matches($MachineName, "\\").Count -ne 0) {
			$succeeded = $false
			$tmp = $MachineName.Split("\")
			$DomainName = $tmp[0]
			$MachineName = $tmp[1]
			$TimeOut = 600 
			try {
				if ($EnableDebug) {
					$Logger.Debug("Get Broker Machine $DomainName\$MachineName -AdminAddress $DDCAddress")
				}	
				$Logger.Info("Get machine info for machine $DomainName\$MachineName")
				$MyMachine = Get-BrokerMachine -MachineName ($DomainName + "\" + $MachineName) -AdminAddress $DDCAddress
				if ($MyMachine.Powerstate -eq "On") {
					$Logger.Info("Trying to restart machine $MachineName ...")
					$BrokerHostingPowerAction = New-BrokerHostingPowerAction -Action Restart -MachineName $MyMachine.MachineName -AdminAddress $DDCAddress
					if ($EnableDebug) {
						$Logger.Debug("BrokerHostingPowerAction UID: " + $BrokerHostingPowerAction.UID)
					}
					$i = 0
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
					while (($BrokerHostingPowerActionState -ne "Completed") -and ($i -lt $TimeOut)) {
						$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State
						$Logger.Info("BrokerHostingPowerAction state of machine " + $MyMachine.MachineName + " is $BrokerHostingPowerActionState, waiting for completion... ($i / $TimeOut)")
						Start-Sleep -Milliseconds 5000
						$i++
					}
					$BrokerHostingPowerActionState = $(Get-BrokerHostingPowerAction -UID $BrokerHostingPowerAction.UID -AdminAddress $DDCAddress).State

					if ($BrokerHostingPowerActionState -eq "Completed") {
						$MyLogger.Info("Machine $MachineName successfuly restarted!")
					}
					else {
						$Logger.Error("TimeOut reached, while restarting machine $MachineName!")
						Throw "TimeOut reached, while restarting machine $MachineName!"
					}
				}
				else {
					Throw ("Unable to restart machine $MachineName, Powerstate is " + $MyMachine.Powerstate)
				}	
			}
			catch [System.Exception] {
				$succeeded = $false
				$Logger.Error("Problem while performing power action for machine " + $MachineName + ": " + $_ )
				throw $_
			}	
		}	
		else {
			$Logger.Error("MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'")
			throw "MachineName $MachineName is not in the correct format! MachineName has to be 'DomainName\ComputerName'"
		}	
	}
	else {
		$Logger.Error("Required PSSnapin Citrix.Broker.Admin.V2 is not installed!")
		throw "Required PSSnapin Citrix.Broker.Admin.V2 is not installed!"
	}				
}

function Invoke-EitUserSessionsLogoff {
<#
 .Synopsis
		Logoff all session for a specified user 
    .Description
		Logoff all session for a specified user 
	
    .Parameter FarmEntryPoints
		the farm entry point, XenDesktop Controller / XenApp Server
	.Parameter UserName
		the username to logoff
	.EXAMPLE
		Invoke-EitUserSessionsLogoff -FarmEntryPoint MyBroker -UserName MyUser
		Logoff all sessions from user MyUser

			
		
	.NOTES  
		Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.2
		
		History:
            V1.0 - 01.03.2019 - M.Trojahn - Initial creation
			V1.1 - 26.10.2020 - M.Trojahn - Rename from Logoff-EitUserSesseions to Invoke-EitUserSessionLogoff
			V1.2 - 03.05.2021 - M.Trojahn - Don't stop if a server is DDC not reachable
 #>	
Param (	
	[Parameter(Mandatory=$true)]  [string[]]$FarmEntryPoints,
	[Parameter(Mandatory=$true)]  $UserName
) 
	
	
	
	$FarmType = "XenDesktop"
	$SessionList = @()
	$bSuccess = $false
	$StatusMessage = "Error while session machine list!"
	
	$DSNfile = "C:\Program Files (x86)\Citrix\Independent Management Architecture\MF20.dsn"
	try {
		if (Test-Path $DSNfile) { $FarmType = "XenApp" }
		foreach ($item in $FarmEntryPoints) {
			if (Test-EitPort -server $item -port 5985 -timeout "1000") {
				$PSSession = New-PSSession -ComputerName $item -ErrorAction stop 
				$DSNCheck = Invoke-Command -Session $PSSession -ScriptBlock {Test-Path $args[0]} -ArgumentList $DSNfile
				If ($DSNCheck -eq $true) { $FarmType = "XenApp" }
				if ($FarmType -eq "XenApp") {
					Invoke-Command -Session $PSSession -ScriptBlock {Add-PSSnapin citrix.xenapp.commands} -ErrorAction stop
					$XASessions = Invoke-Command -Session $PSSession -ScriptBlock {Get-XASession -Farm | select accountname, servername}
					Remove-PSSession -Session $PSSession
					foreach ($XASession in $XASessions) {
						#$SessionList += (Make-EITSessionDataData -UserName $XASession.AccountName -ServerName $XASession.ServerName)
					}
					
					$StatusMessage = "Successfully read session list..."
					$bSuccess = $true
				}
				else {
					Invoke-Command -Session $PSSession -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
					$BrokerSessions = Invoke-Command -Session $PSSession -ScriptBlock {param($Username) Get-BrokerSession -MaxRecordCount 100000 | Where {$_.UserName -eq $Username}} -ArgumentList $UserName
					foreach ($BrokerSession in $BrokerSessions) {
						Write-Host "   Stopping session $($BrokerSession.SessionKey) from Server $($BrokerSession.MachineName)..."
						Invoke-Command -Session $PSSession -ScriptBlock {param($BrokerSession) Stop-BrokerSession $BrokerSession } -ArgumentList $BrokerSession
					}
					Remove-PSSession -Session $PSSession
					$StatusMessage = "Successfully logged of sessions..."
					$bSuccess = $true
				}
			}
			else {
				Write-Host "Server $item is not reachable"
			}
		}
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
	return $ReturnObject
}

function Stop-EitBrokerSession {
<#
       .SYNOPSIS
             This functions stops a sesion.

       .DESCRIPTION
             Use this function to stop a session

       .PARAMETER  DDC
             The DDC where you wish to execute the action

       .PARAMETER  UID
             The UID of the session

       .EXAMPLE
             Stop-EitBrokerSession -DDC MyBroker -UID MyUID
       
       .NOTES  
			Copyright	: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch 
			Version		: 1.1
			History:
				V1.0 - 14.08.2019 - M.Trojahn - Initial creation  
				V1.1 - 21.12.2022 - M.Trojahn - Remove MaxRecordCount 

#>

    param (
		[Parameter(Mandatory=$True)][string]$DDC,
		[Parameter(Mandatory=$True)][string]$UID
	)
       
	try {
		$startTime = Get-Date
		Write-Host "connecting to Citrix DDC $DDC"
		$PSSession = New-PSSession -ComputerName $DDC
		Write-Host "loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $PSSession -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "reading session infomation for session $uid..."
		
		$TimeOut = 600
		$i = 0
		$UserSession = Invoke-Command -Session $PSSession -ScriptBlock {param($UID) Get-BrokerSession -UID $UID -ErrorAction SilentlyContinue} -ArgumentList $UID 
		If ($UserSession -ne $null) {
			Write-Host "stopping session..."
			$rc = Invoke-Command -Session $PSSession -ScriptBlock {param($UID) Get-BrokerSession -UID $UID | Stop-BrokerSession -ErrorAction SilentlyContinue} -ArgumentList $UID
			while (($(Invoke-Command -Session $PSSession -ScriptBlock {param($UID) Get-BrokerSession -UID $UID -ErrorAction SilentlyContinue} -ArgumentList $UID) -ne $null) -and ($i -lt $TimeOut)) {
				Start-Sleep -Milliseconds 1000
				Write-Host "   Session is still alive, waiting for session to stop ($i / $TimeOut)..." 
				$i++
			}
			$UserSession = Invoke-Command -Session $PSSession -ScriptBlock {param($UID) Get-BrokerSession -UID $UID -ErrorAction SilentlyContinue} -ArgumentList $UID
			$endTime = get-Date
			if ($UserSession -eq $null) {
					$LogoffTime = $endTime - $startTime
					$message = "Session successfully stopped in " + $LogoffTime.Minutes + "m " + $LogoffTime.Seconds + "s"
					Write-Host $message
			}
			else {
				Throw "ERROR: TimeOut ($TimeOut s) reached, while stopping session!"
			}
		}	
		else {
			Throw "ERROR, no session found with UID $UID"
	    }
	}
	catch {
	    Throw $_.Exception.Message
	}
	finally {
		Remove-PSSession -Session $PSSession
	}
}


function Get-EitBrokerSessions {
	<#
	 .Synopsis
			Get citrix sessions
		.Description
			List Citrix sessions
		
		.Parameter Brokers
			the XenDesktop Controllers
			
		.EXAMPLE
			Get-EitBrokerSessions -Brokers xd01
			List all sessions from Broker XD01
	
		.EXAMPLE
			Get-EitBrokerSessions -Brokers xd01, xd02
			List all sessions from brokers XD01 & XD02
	
			
			
		.NOTES  
			Copyright	:	(c)2023 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 12.04.2023 - M.Trojahn - Initial creation
	 #>	
	Param 
		(	
			[Parameter(Mandatory=$true)]  [string[]]$Brokers,
			[Parameter(Mandatory=$false)]  [string[]]$MachineName
		) 
		
	$SessionList = @()
	$bSuccess = $false
	$StatusMessage = "Error while reading session list!"
	
	function Make-EITSBrokerSessionData($UserName, $MachineName, $SessionState, $UserUPN, $Uid) {
		$out = New-Object psobject
		$out | add-member -type noteproperty -name UserName $UserName
		$out | add-member -type noteproperty -name UserUPN $UserUPN
		$out | add-member -type noteproperty -name Uid $Uid
		$out | add-member -type noteproperty -name MachineName $MachineName
		$out | add-member -type noteproperty -name SessionState $SessionState
		
		$out
	}

	try 
	{
		foreach ($Broker in $Brokers) 
		{
			if (Test-EitPort -server $Broker -port 5985 -timeout "1000") 
			{
				$Session = New-PSSession -ComputerName $Broker -ErrorAction stop 
				Invoke-Command -Session $Session -ScriptBlock {Add-PSSnapin citrix*} -ErrorAction stop
				if ($MachineName -ne $null) 
				{
					$BrokerSessions = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerSession -MachineName $MachineName -MaxRecordCount 10000 | Select UserName, Uid, UserUPN, MachineName, SessionState} -ArgumentList $MachineName
				}	
				else
				{
					$BrokerSessions = Invoke-Command -Session $Session -ScriptBlock {Get-BrokerSession -MaxRecordCount 10000 | Select UserName, Uid, UserUPN, MachineName, SessionState} 
				}
				
				foreach ($BrokerSession in $BrokerSessions) 
				{
					$SessionList += Make-EITSBrokerSessionData -UserName $BrokerSession.UserName -MachineName $BrokerSession.MachineName -SessionState $BrokerSession.SessionState -Uid $BrokerSession.Uid -UserUPN $BrokerSession.UserUPN
				}	
				Remove-PSSession -Session $Session
				$StatusMessage = "Successfully read session list..."
				$bSuccess = $true
				
			}
			else 
			{
				throw "ERROR, broker $Broker is not reachable via WinRM!"
			}
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$UniqueSessionList = $SessionList | Get-EitPSUnique | Sort UserUPN
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;SessionList=$UniqueSessionList})
	return $ReturnObject
}





function Stop-EitAllBrokerSessionOnMachine {
<#
       .SYNOPSIS
            This functions stops all sesions on a given machine.

       .DESCRIPTION
            Use this function to stop all sesions on a given machine.

       .PARAMETER  Broker
            The broker where you wish to execute the action

       .PARAMETER  MachineName
            The machine name, must be in format MyDomain\MyMachineName
		
		.PARAMETER Logger
			The EducateIT FileLogger object
			Has to be created before with the New-EitLogger command
			
		.PARAMETER EnableDebug
			Enables the debug log
			Only available if logging is activated via Logger paramter

       .EXAMPLE
            Stop-EitAllBrokerSessionOnMachine -Broker MyBroker -MachineName MyDomain\MyMachineName
			 
		.EXAMPLE
            Stop-EitAllBrokerSessionOnMachine -Broker MyBroker -MachineName MyDomain\MyMachineName -Logger MyEitLogger
			 	 
		.OUTPUTS
			Success	: True
			Message	: Successfully stopped machine sessions
       
       .NOTES  
			Copyright	: (c)2023 by EducateIT GmbH - http://educateit.ch - info@educateit.ch 
			Version		: 1.0
			History		:
							V1.0 - 12.04.2023 - M.Trojahn - Initial creation  
#>

    param (
		[Parameter(Mandatory=$True)] 	[string]$Broker,
		[Parameter(Mandatory=$True)] 	[string]$MachineName,
		[Parameter(Mandatory=$false)] 	[Object[]] $Logger,
		[Parameter(Mandatory=$false)] 	[Switch] $EnableDebug
	)
       
	try {
		$PSSession = $null
		$EnableLog = $false
		$bSuccess = $false
		$StatusMessage = "Error while stopping machine sessions!"
		
		if ($Logger -ne $null)
		{
			$EnableLog = $true
		}
			
		if (($EnableLog -eq $false) -And ($EnableDebug)) 
		{
			$EnableDebug = $false
			throw "Logger parameter is missing!"
		}
		
		if ($EnableDebug) 
		{ 
			$Logger.Debug("Start function Stop-EitAllBrokerSessionOnMachine") 
			$Logger.Debug("Broker: $Broker") 
			$Logger.Debug("MachineName: $MachineName") 
			$Logger.Debug("EnableDebug: EnableDebug") 
			$Logger.Debug($Logger) 
			
		}
		if ($MachineName.Contains("\"))
		{
			if ($EnableLog) {$Logger.Info("connecting to Citrix broker $Broker")}
			$PSSession = New-PSSession -ComputerName $Broker
			if ($EnableLog) {$Logger.Info("loading Citrix Broker Snapins...")}
			$rc = Invoke-Command -Session $PSSession -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
			if ($EnableLog) {$Logger.Info("reading sessions on machine $MachineName...")}
			
			$MachineSessions = Invoke-Command -Session $PSSession -ScriptBlock {param($MachineName) Get-BrokerSession -MachineName $MachineName -MaxRecordCount 10000 -ErrorAction SilentlyContinue} -ArgumentList $MachineName 
			if ($EnableDebug) { $Logger.Debug($MachineSessions) }
			if ($MachineSessions -ne $null) 
			{
				if ($EnableLog) {$Logger.Info("   stopping sessions...")}
				foreach ($MachineSession in $MachineSessions) 
				{
					if ($EnableLog) {$Logger.Info("      stopping session for user $($MachineSession.UserName)")}
					if ($EnableDebug) { $Logger.Debug($MachineSession) }
					$rc = Invoke-Command -Session $PSSession -ScriptBlock {param($MachineSession) Stop-BrokerSession -InputObject $MachineSession -ErrorAction SilentlyContinue} -ArgumentList $MachineSession
					if ($EnableDebug) { $Logger.Debug($rc) }
				}
				$bSuccess = $true
				$StatusMessage = "Successfully stopped machine sessions"
			}	
			else {
				Throw "ERROR, no session found on machine  $MachineName"
			}
		}	
		else {
			Throw "MachineName must be in the format DomainName\MachineName"
		}	
	}
	catch {
	    $bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	finally {
		if ($PSSession -ne $null) 
		{
			if (Get-PSSession -Id $PSSession.Id -ErrorAction SilentlyContinue) 
			{
				Remove-PSSession -Session $PSSession
			}
		}	
		if ($EnableDebug) { $Logger.Debug("End function Stop-EitAllBrokerSessionOnMachine") }
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
	return $ReturnObject
}
