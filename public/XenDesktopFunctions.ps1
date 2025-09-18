<#
       .SYNOPSIS
             function library for Citrix XenDesktop VDI actions

       .DESCRIPTION
             This is a function library for Citrix XenDesktop VDI actions like start, shutdown, restart, reset

       .NOTES  
			Author		: EducateIT GmbH - info@educateit.ch 
			Version		: 1.2
			
			History		: 
						V1.0	-	16.06.2014	-	created
						V1.1	-	04.09.2014	-	Add-EitVDIUser, Get-EitVDIUser, Remove-EitVDIUser, Show-CustomInputBox, Show-UserListBox
													Load-ListBox, Query-EitMaintMode, Set-EitMaintMode added
						V1.2	-	23.03.2020	-	Show-CustomInputBox, Show-UserListBox & Load-ListBox removed
													Rename function to Verb-EitAction
													Renamed Query-EitMaintMode to Request-EitMaintMode
													Renamed Shutdown-EitVDI to Start-EitVDIShutdown
													Renamed TurnOn-EitVDI to Start-EitVDI
													Renamed TurnOff-EitVDI to Stop-EitVDI

#>


function Resume-EitVDI {
	<#
		.SYNOPSIS
				This functions resumes a VDI.

		.DESCRIPTION
				Use this function to resume a suspended VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to resume, has to be Domainname\Comuptername

		.EXAMPLE
				Resume-EitVDI -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

	param (
	[Parameter(Mandatory=$True)][string]$Broker,
	[Parameter(Mandatory=$True)][string]$MachineName)

	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Borker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
			if ($VDI.Powerstate -eq "Suspended") {
				Write-Host "   trying to resume vdi..."
				$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action Resume -MachineName $MachineName} -ArgumentList $VDI.MachineName
				while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
					Start-Sleep -Milliseconds 100
					$i++
				}
				$State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
				if ($State -eq "Completed") {
					$return = 0
				}
				else {
					Throw "TimeOut reached, while resuming VDI!"
				}
			}
			else {
				Throw ("VDI could not be resumed, Powerstate is " + $VDI.Powerstate)
			}
		}
		else {
			Throw "Error while getting VDI $MachineName"
		}
		return $return
	}
	catch {
		Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Suspend-EitVDI {
	<#
		.SYNOPSIS
				This functions suspends a VDI.

		.DESCRIPTION
				Use this function to suspend a running VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to supsend, has to be Domainname\Comuptername

		.EXAMPLE
				Suspend-EitVDI -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Borker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
	        if ($VDI.Powerstate -eq "On") {
				Write-Host "   trying to suspend vdi..."
	           	$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action Suspend -MachineName $MachineName} -ArgumentList $VDI.MachineName
	            while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
	                Start-Sleep -Milliseconds 100
					$i++
	            }
                $State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
                if ($State -eq "Completed") {
                    $return = 0
                }
                else {
                    Throw "TimeOut reached, while suspending VDI!"
                }
            }
            else {
                Throw ("VDI could not be suspended, Powerstate is " + $VDI.Powerstate)
			}
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Start-EitVDI {
	<#
		.SYNOPSIS
				This functions turns a VDI on.

		.DESCRIPTION
				Use this function to turn on a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to start, has to be Domainname\Comuptername

		.EXAMPLE
				Start-EitVDI -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author		: 	EducateIT GmbH - info@educateit.ch 
			Version		:	1.1
			
			History:
				V1.1 - 23.03.2020 - M.Trojahn - Renamed from TurnOn-EitVDI to Start-EitVDI

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Borker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
	        if ($VDI.Powerstate -ne "On") {
				Write-Host "   trying to turn on vdi..."
	           	$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action TurnOn -MachineName $MachineName} -ArgumentList $VDI.MachineName
	            while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
	                Start-Sleep -Milliseconds 100
					$i++
	            }
                $State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
                if ($State -eq "Completed") {
                    $return = 0
                }
                else {
                    Throw "TimeOut reached, while turning on VDI!"
                }
            }
            else {
                Throw ("VDI could not be turned on, Powerstate is " + $VDI.Powerstate)
			}
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	   
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Stop-EitVDI {
	<#
		.SYNOPSIS
				This functions turns off a VDI.

		.DESCRIPTION
				Use this function to turn off a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to turn off, has to be Domainname\Comuptername

		.EXAMPLE
				Stop-EitVDI -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author		: 	EducateIT GmbH - info@educateit.ch 
			Version		:	1.1
			
			History:
				V1.1 - 23.03.2020 - M.Trojahn - Renamed from TurnOff-EitVDI to Stop-EitVDI

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Borker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
	        if ($VDI.Powerstate -eq "On") {
				Write-Host "   trying to turn off vdi..."
	           	$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action TurnOff -MachineName $MachineName} -ArgumentList $VDI.MachineName
	            while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
	                Start-Sleep -Milliseconds 100
					$i++
	            }
                $State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
                if ($State -eq "Completed") {
                    $return = 0
                }
                else {
                    Throw "TimeOut reached, while turning off VDI!"
                }
            }
            else {
                Throw ("VDI could not be turned off, Powerstate is " + $VDI.Powerstate)
			}
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Start-EitVDIShutdown {
	<#
		.SYNOPSIS
				This functions shutdown a VDI.

		.DESCRIPTION
				Use this function to shutdown a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to shutdown, has to be Domainname\Comuptername

		.EXAMPLE
				Start-EitVDIShutdown -Broker MyBroker -MachineName MyDomain\MyVDI
		
			Author		: 	EducateIT GmbH - info@educateit.ch 
			Version		:	1.1
			
			History:
				V1.0 - 23.03.2020 - M.Trojahn - Renamed from Shutdown-EitVDI to Start-EitVDIShutdown

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Borker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
	        if ($VDI.Powerstate -eq "On") {
				Write-Host "   trying to shutdown vdi..."
	           	$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action Shutdown -MachineName $MachineName} -ArgumentList $VDI.MachineName
	            while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
	                Start-Sleep -Milliseconds 100
					$i++
	            }
                $State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
                if ($State -eq "Completed") {
                    $return = 0
                }
                else {
                    Throw "TimeOut reached, while shutdown VDI!"
                }
            }
            else {
                Throw ("VDI could not shutdown, Powerstate is " + $VDI.Powerstate)
			}
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Reset-EitVDI {
	<#
		.SYNOPSIS
				This functions resets a VDI.

		.DESCRIPTION
				Use this function to reset a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to reset, has to be Domainname\Comuptername

		.EXAMPLE
				Reset-EitVDI -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Borker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
	        if ($VDI.Powerstate -ne "Off") {
	           	Write-Host "   trying to reset vdi..."
				$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action Reset -MachineName $MachineName} -ArgumentList $VDI.MachineName
	            while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
	                Start-Sleep -Milliseconds 100
					$i++
	            }
                $State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
                if ($State -eq "Completed") {
                    $return = 0
                }
                else {
                    Throw "TimeOut reached, while reseting VDI!"
                }
            }
            else {
                Throw ("VDI could not be reseted, Powerstate is " + $VDI.Powerstate)
			}
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Restart-EitVDI {
	<#
		.SYNOPSIS
				This functions restarts a VDI.

		.DESCRIPTION
				Use this function to restart a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to restart, has to be Domainname\Comuptername

		.EXAMPLE
				Restart-EitVDI -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading vdi infos..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
	        if ($VDI.Powerstate -ne "Off") {
				Write-Host "   trying to restart vdi..."
	           	$BrokerHostingPowerAction = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) New-BrokerHostingPowerAction -Action Restart -MachineName $MachineName} -ArgumentList $VDI.MachineName
	            while (($(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State -ne "Completed") -or ($i -lt 600)) {
	                Start-Sleep -Milliseconds 100
					$i++
	            }
                $State = $(Invoke-Command -Session $Session -ScriptBlock {param($UID) Get-BrokerHostingPowerAction -UID $UID} -ArgumentList $BrokerHostingPowerAction.UID).State
                if ($State -eq "Completed") {
                    $return = 0
                }
                else {
                    Throw "TimeOut reached, while restarting VDI!"
                }
            }
            else {
                Throw ("VDI could not be restarted, Powerstate is " + $VDI.Powerstate)
			}
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Add-EitVDIUser {
	<#
		.SYNOPSIS
				This functions adds a user to a VDI.

		.DESCRIPTION
				Use this function to add a User to a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name, has to be Domainname\Comuptername
				
			.PARAMETER  UserName
				The user name, has to be Domainname\UserName	 

		.EXAMPLE
				Add-EitVDIUser -Broker MyBroker -MachineName MyDomain\MyVDI -UserName MyDomain\MyUser
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName,
	[Parameter(Mandatory=$True)][string]$UserName)
       
	try {
		$return = 0
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   Add User $UserName to vdi $MachineName..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerMachine -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
		
			Invoke-Command -Session $Session -ScriptBlock {param($VDI, $UserName) Add-BrokerUser -Machine $VDI -Name $UserName} -ArgumentList $VDI, $UserName
			        
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Get-EitVDIUser {
	<#
		.SYNOPSIS
				This functions get the assigned user from a vdi.

		.DESCRIPTION
				Use this function to read the assigned Users

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name, has to be Domainname\Comuptername
				
		.EXAMPLE
				Get-EitVDIUser -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   Get User from vdi $MachineName..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerMachine -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
			$VDIUser = Invoke-Command -Session $Session -ScriptBlock {param($VDI) Get-BrokerUser -MachineUID $VDI.UID} -ArgumentList $VDI
			        
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $VDIUser
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}


function Remove-EitVDIUser {
	<#
		.SYNOPSIS
				This functions removes a user from a VDI.

		.DESCRIPTION
				Use this function to remove a User from a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name, has to be Domainname\Comuptername
				
			.PARAMETER  UserName
				The user name, has to be Domainname\UserName	 

		.EXAMPLE
				Remove-EitVDIUser -Broker MyBroker -MachineName MyDomain\MyVDI -UserName MyDomain\MyUser
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName,
	[Parameter(Mandatory=$True)][string]$UserName)
       
	try {
		$return = 0
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   Remove User $UserName from vdi $MachineName..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerMachine -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
		
			Invoke-Command -Session $Session -ScriptBlock {param($VDI, $UserName) Remove-BrokerUser -Machine $VDI -Name $UserName} -ArgumentList $VDI, $UserName
			        
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $return
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Request-EitMaintMode {
	<#
		.SYNOPSIS
				This functions queries the maintmode of a VDI.

		.DESCRIPTION
				Use this function to query the maintmode of a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to restart, has to be Domainname\Comuptername

		.EXAMPLE
				Request-EitMaintMode -Broker MyBroker -MachineName MyDomain\MyVDI
		
		.NOTES  
			Author		: 	EducateIT GmbH - info@educateit.ch 
			Version		:	1.1

			
			History:
				V1.0 - 23.03.2020 - M.Trojahn - Renamed from Query-EitMaintMode to Request-EitMaintMode

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   reading MaintMode for vdi $MachineName..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
			If ($VDI.DesktopKind -eq "Private") {
				$MaintMode = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerPrivateDesktop -MachineName $MachineName | Select-Object InMaintenanceMode} -ArgumentList $MachineName
			}
			else {
				$MaintMode = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerSharedDesktop -MachineName $MachineName | Select-Object InMaintenanceMode} -ArgumentList $MachineName
			}
		
	        
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $MaintMode.InMaintenanceMode
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}

function Set-EitMaintMode {
	<#
		.SYNOPSIS
				This functions sets the maintmode of a VDI.

		.DESCRIPTION
				Use this function to set the maintmode of a VDI

		.PARAMETER  Broker
				The Broker where you wish to execute the action

		.PARAMETER  MachineName
				The machine name to restart, has to be Domainname\Comuptername
				
			.PARAMETER  MaintMode
				The maintmode to set (true or flase)

		.EXAMPLE
				Set-EitMaintMode -Broker MyBroker -MachineName MyDomain\MyVDI -MaintMode $true
				Set-EitMaintMode -Broker MyBroker -MachineName MyDomain\MyVDI -MaintMode $false
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

    param (
    [Parameter(Mandatory=$True)][string]$Broker,
    [Parameter(Mandatory=$True)][string]$MachineName,
	[Parameter(Mandatory=$True)][boolean]$MaintMode)
       
	try {
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   setting MaintMode = $MaintMode for vdi $MachineName..."
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
			If ($VDI.DesktopKind -eq "Private") {
				$MaintMode = Invoke-Command -Session $Session -ScriptBlock {param($MachineName, $MaintMode) Set-BrokerPrivateDesktop -MachineName $MachineName -InMaintenanceMode $MaintMode} -ArgumentList $MachineName, $MaintMode
			}
			else {
				$MaintMode = Invoke-Command -Session $Session -ScriptBlock {param($MachineName, $MaintMode) Set-BrokerSharedDesktop -MachineName $MachineName -InMaintenanceMode $MaintMode} -ArgumentList $MachineName, $MaintMode
			}
		
	        
	    }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	    return $MaintMode
	}
	catch {
	    Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}


function Reset-EitPersonalvDisk {
	<#
		.SYNOPSIS
				This functions resets a Personal vDisk.

		.DESCRIPTION
				Use this function to reset a Personal vDisk

		.PARAMETER  MachineName
				The machine name whre the perosnla vDisk is connetced to
			
			.PARAMETER  Broker
				The Broker to check machine powerstate

		.EXAMPLE
				Reset-EitPersonalvDisk -MachineName MyDomain\MyVDI -Broker MyBroker
		
		.NOTES  
			Author     : EducateIT GmbH - info@educateit.ch 

	#>

	param (
	[Parameter(Mandatory=$True)][string]$Broker,
	[Parameter(Mandatory=$True)][string]$MachineName)

	
	$arrMachineName = $MachineName.Split("\")
	
	
	try {
		Write-Host "   connecting to machine $MachineName..."
		$Session = New-PSSession -ComputerName $arrMachineName[1]
		Write-Host "   reseting personal vDisk..."
		Invoke-Command -Session $Session -ScriptBlock {Invoke-Expression "& 'C:\Program Files\citrix\personal vdisk\bin\ctxpvd.exe' -s reset"}
		Remove-PSSession -Session $Session
		Write-Host "   connecting to Broker $Broker..."
		$Session = New-PSSession -ComputerName $Broker
		Write-Host "   loading Citrix Broker Snapins..."
		$rc = Invoke-Command -Session $Session -ScriptBlock { Add-PSSnapin Citrix.Broker.*}
		Write-Host "   testing PowerState..."
		$i = 0
		$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
		If ($VDI -ne $null) {
			Write-Host "      PowerState is " $VDI.Powerstate ", call shutdown command..."
			TurnOff-EitVDI -Broker $Broker -MachineName $MachineName
			Write-Host "      waiting for machine shutdown, PowerState is" $VDI.Powerstate
			 while(($VDI.Powerstate -ne "Off") -and ($i -gt 300)) {
				Write-Host "   waiting for machine shutdown, PowerState is" $VDI.Powerstate
                <# Write-Host $i #>
				Start-Sleep -Seconds 1
				$i++
				$VDI = Invoke-Command -Session $Session -ScriptBlock {param($MachineName) Get-BrokerDesktop -MachineName $MachineName -ErrorAction SilentlyContinue} -ArgumentList $MachineName
			}
	        if ($VDI.Powerstate -eq "Off") {
                Write-Host "      machine is off, starting it again..."
				TurnOn-EitVDI -Broker $Broker -MachineName $MachineName
				
			}
			else {
                    Throw "TimeOut reached, while stopping VDI!"
            }	
				
		 }
	    else {
			Throw "Error while getting VDI $MachineName"
	    }
	}
	catch {
		Throw $error[0]
	}
	finally {
		Remove-PSSession -Session $Session
	}
}


