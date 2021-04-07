#
# ScriptFunctions.ps1
# ===========================================================================
# (c)2020 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.5
#
# Useful Script functions
# History:
#   V1.0 - 01.09.2016 - M.Trojahn - Initial creation
#   V1.1 - 20.12.2017 - M.Trojahn - Get-EitRemoteComputersFromXenDataConf
#   V1.2 - 14.08.2019 - M.Trojahn - Update in Get-EitRemoteComputersFromXenDataConf
#   V1.3 - 21.10.2019 - M.Trojahn - Add New-EitFileLogger
#	V1.4 - 16.03.2020 - M.Trojahn - Remove function test-port
#	V1.5 - 14.12.2020 - M.Trojahn - Move New-EitFileLogger to newly created LogFunctions.ps1
#	
# ===========================================================================


function Test-EitTranscribing {
	$externalHost = $Host.gettype().getproperty("ExternalHost", [reflection.bindingflags]"NonPublic,Instance").getvalue($Host, @())

	try {
		$externalHost.gettype().getproperty("IsTranscribing", [reflection.bindingflags]"NonPublic,Instance").getvalue($externalHost, @())
	} 
	catch {
		write-warning "This host does not support transcription."
	}
}



function Write-EitLog { 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()] [Alias("LogContent")] [string]$Message, 
        [Parameter(Mandatory=$true)] [Alias('LogPath')] [string]$Path, 
		[Parameter(Mandatory=$true)] [boolean]$logEnabled, 
        [Parameter(Mandatory=$false)] [ValidateSet("Error","Warn","Info")] [string]$Level="Info",
		[Parameter(Mandatory=$false)] [boolean] $SuppressOutput = $false
        
    ) 
 
            
	# If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
	if (!(Test-Path $Path)) { 
		Write-Verbose "Creating $Path." 
		$NewLogFile = New-Item $Path -Force -ItemType File 
	} 

	
	# Format Date for our Log File 
	$FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 

	# Write message to error, warning, or verbose pipeline and specify $LevelText 
	switch ($Level) { 
		'Error' { 
			Write-Error $Message 
			$LevelText = 'ERROR:' 
			} 
		'Warn' { 
			Write-Warning $Message 
			$LevelText = 'WARNING:' 
			} 
		'Info' { 
			Write-Verbose $Message 
			$LevelText = 'INFO:' 
			} 
		} 
	 
	if ($logEnabled -eq $true) {
		# Write log entry to $Path 
		"$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
	}
	if ($SuppressOutput -ne $true) {
		Write-Host "$FormattedDate $LevelText $Message"
	}	
    
}

function Test-EitPort {
<#
	.Synopsis
			Test if a port is reachable
		.Description
			Tests if a port is reachable
		
		.Parameter ComputerName
			the coumputer to test
			
		.Parameter Port
			the port to test
		
		.Parameter Timeout
			defines how long the tcp client waits for answer, default 10ms
			
		.EXAMPLE
			Test-EitPort -ComputerName MyServer -Port MyPort
		
		.NOTES  
		Copyright: (c)2018 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.1
		
		History:
			V1.0 - 01.09.2016 - M.Trojahn - Initial creation
			V1.1 - 08.01.2018 - M.Trojahn - Add default timeout of 10ms
#>	


    param(
		[Alias("Server")] [parameter(Mandatory = $true)][string]$ComputerName,
		[parameter(Mandatory = $true)][int]$Port,
		[parameter(Mandatory = $false)][int]$Timeout=10
	)
    $ErrorActionPreference = "SilentlyContinue"
	try 	{
		$tcpclient = new-Object system.Net.Sockets.TcpClient
		$iar = $tcpclient.BeginConnect($ComputerName,$Port,$null,$null)
		$wait = $iar.AsyncWaitHandle.WaitOne($Timeout,$false)
		if(!$wait) 		{
			$tcpclient.Close()
			return $false
		}
		else {
			$Error.Clear()
			$tcpclient.EndConnect($iar) | out-Null
			if($Error[0]) 			{
				$failed = $true
			}
			else {
				$failed = $false
			}
			$tcpclient.Close()
		}   
		if($failed){return $false}else{return $true}
	}
	catch [System.SystemException] {
		Write-Host $($Error[0])
	}
}


function Get-EitRemoteComputersFromXenDataConf {
	<#
	.	Synopsis
			Get the remote computers from the XenData.conf_b.xml
		.Description
			Get the remote computers from the XenData.conf_b.xml
		
		.Parameter XenDataConfPath
			path to the XenData.conf_b.xml
			
		.Parameter LinkName	
			Filter for the LinkName
		
		.EXAMPLE
			Get-EitRemoteComputersFromXenDataConf 
			List all the RemoteComputers from the XenData config file
			
		.EXAMPLE
			Get-EitRemoteComputersFromXenDataConf -LinkName MyLinkName
			Lists only RemoteComupters for the Link MyLinkName
		
		.EXAMPLE
			Get-EitRemoteComputersFromXenDataConf -XenDataConfPath "C:\Program Files\EducateIT\RaptorServer\conf\XenData2.conf_b.xml"
			With path to the XenData config file
			
		.OUTPUTS
			Success        : True
			Message        : Successfully get remote computers from XenData.conf_b.xml
			RemoteComputers : [String[]] RemoteComputer


		.NOTES  
			Copyright: (c)2019 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 20.12.2017 - M.Trojahn - Initial creation
				V1.1 - 14.08.2019 - M.Trojahn - LinkName Parameter added
		#>	
	Param(
        [string] $XenDataConfPath="C:\Program Files\EducateIT\RaptorServer\conf\XenData2.conf_b.xml",
		[string] $LinkName="All"
    )
    
    [boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully get remote computers from XenData.conf_b.xml"
    $ComputerList = @()
	try { 
		if (Test-Path $XenDataConfPath) { 
			[XML] $XenDataConf  = Get-Content $XenDataConfPath
			
		}
		else {
			throw ($XenDataConfPath + " does not exists!")
		}

		$ns = New-Object System.Xml.XmlNamespaceManager($XenDataConf.NameTable)
		$ns.AddNamespace("ns", $XenDataConf.DocumentElement.NamespaceURI)

		
		
		If ($LinkName.toUpper() -eq "ALL") {
			$RemoteComputerList = $XenDataConf.SelectNodes("//ns:Value[@name='RemoteComputerList']", $ns)
		}
		else {
			$Lists = $XenDataConf.Configuration.Module.List
			foreach ($List in $Lists) {
				if ($List.name -eq "Links") {
					$Links = $List
					break
				}
			}
			foreach ($ListEntry in $Links.ListEntry) {
				if ($ListEntry.Value.name -eq "Name") {
					if ($ListEntry.Value.innerText -eq $LinkName) {
						$Link = $ListEntry
						$RemoteComputerList = $Link.SelectNodes("ns:Value[@name='RemoteComputerList']", $ns)
						break
					}
				}
			}
			
		}
		
		if ($RemoteComputerList -ne $null) {
			foreach ($item in $RemoteComputerList) {
				$aRemoteComputers = $item.InnerText.split("`r`n|`r|`n")
				foreach ($RemoteComputer in $aRemoteComputers) {
					$RemoteComputer = $RemoteComputer.Trim()
					if ($RemoteComputer.Length -ne 0) {
						$ComputerList += $RemoteComputer
					}
				}
			}
		}
		else {
			Throw "Error, no RemoteComputers found for Link $LinkName!"
		}
	}
    
    catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
  
    $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;RemoteComputers=$ComputerList})
    return $ReturnObject
}

function Get-EitScriptDirectory { 
<#
	.Synopsis
			Get the current script directory
		.Description
			Get the current script directory when $PSScriptRoot is not available
		
		.EXAMPLE
			Get-EitScriptDirectory
		
		.NOTES  
		Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History:
			V1.0 - 14.12.2020 - M.Trojahn - Initial creation
			
#>	

	if (-not $PSScriptRoot) {
			Split-Path -Parent (Convert-Path ([environment]::GetCommandLineArgs()[0])) 
	} 
	else { 
		$PSScriptRoot 
	}
}
