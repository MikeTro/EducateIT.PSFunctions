#
# ScriptFunctions.ps1
# ===========================================================================
# (c)2023 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.9
#
# Useful Script functions
# History:
#   V1.0 - 01.09.2016 - M.Trojahn - Initial creation
#   V1.1 - 20.12.2017 - M.Trojahn - Get-EitRemoteComputersFromXenDataConf
#   V1.2 - 14.08.2019 - M.Trojahn - Update in Get-EitRemoteComputersFromXenDataConf
#   V1.3 - 21.10.2019 - M.Trojahn - Add New-EitFileLogger
#	V1.4 - 16.03.2020 - M.Trojahn - Remove function test-port
#	V1.5 - 14.12.2020 - M.Trojahn - Move New-EitFileLogger to newly created LogFunctions.ps1
#	V1.6 - 28.04.2021 - M.Trojahn - Add Test-EitIsDriveWritable, Get-EitFirstWritableDrive & Get-EitLastWritableDrive
#	V1.7 - 30.06.2021 - M.Trojahn - Add New-EitSecret
#	V1.8 - 03.08.2022 - M.Trojahn - New-EitEncryptedPassword
#	V1.9 - 20.03.2023 - M.Trojahn - Get-EitPSUnique
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
			the computer to test
			
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

function Test-EitIsDriveWritable {
<#
	.Synopsis
			Test if a drive ist writable
		.Description
			Test if a drive ist writable
		
		.Parameter DriveName
			the drive to test
			
		.EXAMPLE
			Test-EitIsDriveWritable -DriveName D
		
		.NOTES  
		Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History:
			V1.0 - 28.04.2021 - M.Trojahn - Initial creation
			
#>	
    param(
		[parameter(Mandatory = $true)][string]$DriveName
	)
	try {
        $MyDrive = Get-PSDrive $DriveName -ErrorAction SilentlyContinue
        if ($MyDrive) {
            $test_tmp_filename = "writetest-"+[guid]::NewGuid()
            $test_filename = (Join-Path $MyDrive.root $test_tmp_filename)
            [io.file]::OpenWrite($test_filename).close()
            return $true
        }
        else {
            throw "drive $DriveName does not exists!"
        }
    }    
    catch	{
        return $false

    }
}	


function Get-EitLastWritableDrive {
<#
	.Synopsis
			Get the last writable drive
    .Description
        Get the last writable drive
            
    .EXAMPLE
        Get-EitLastWritableDrive
    
    .NOTES  
        Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
        Version		:	1.0
        
        History:
            V1.0 - 28.04.2021 - M.Trojahn - Initial creation
        
#>	
    $MyDrives = Get-PSDrive -PSProvider FileSystem
    foreach ($Drive in $MyDrives.Name | Sort-Object -Descending) {
        if (Test-EitIsDriveWritable $Drive) {
            return $Drive
            break
        }    
    }    
}	


function Get-EitFirstWritableDrive {
<#
	.Synopsis
			Get the first writable drive
    .Description
        Get the first writable drive
            
    .EXAMPLE
        Get-EitFirstWritableDrive
    
    .NOTES  
        Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
        Version		:	1.0
        
        History:
            V1.0 - 28.04.2021 - M.Trojahn - Initial creation
        
#>	
    $MyDrives = Get-PSDrive -PSProvider FileSystem
    foreach ($Drive in $MyDrives.Name | Sort-Object) {
        if (Test-EitIsDriveWritable $Drive) {
            return $Drive
            break
        }    
    }    
}	


function New-EitSecret
{
	<#
	.Synopsis
			Creates a new secret
		.Description
			Creates a new secret key par for the raptor system
		
		.Parameter Label
			The label of the secret
	
		.Parameter Version
			The secret version to use. Use this option if you need to create secrets for old software versions. By default, the latest version is used.
		
		.Parameter LimitForWeb
    		Limit the characters in the generated secrets to a set suitable for web basic authentication. Use this option if you like to authenticate using a HTTP/JSON network interface.	
	
		.EXAMPLE
			 New-EitSecret -Label MyLabel
		
		.NOTES  
			Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 30.06.2021 - M.Trojahn - Initial creation
			
	#>	
	param (
		[parameter(Mandatory = $true)]
		[string]$Label,
		[parameter(Mandatory = $false)]
		[int]$Version = 2,
		[parameter(Mandatory = $false)]
		[switch]$LimitForWeb
	)
	try
	{
		$bSuccess = $true
		$StatusMessage = "New secret successfully created "
		$SecretInfo = New-TemporaryFile
		$NewSecret = $Null
		$exe = "$env:ProgramFiles\EducateIT\SecretGeneratorCommand\SecretGeneratorCommand.exe"
		if ($LimitForWeb)
		{
			$arguments = "--label=$Label --version=$Version --file=$SecretInfo --limit-for-web"
		}
		else
		{
			$arguments = "--label=$Label --version=$Version --file=$SecretInfo"
		}
		if (Test-Path $exe)
		{
			Start-Process -FilePath $exe -ArgumentList $arguments -Wait
			$NewSecret = Get-Content -Path $SecretInfo | ConvertFrom-Json
			Remove-Item $SecretInfo -Force
		}
		else
		{
			throw "Error: $exe does not exists"
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$ReturnObject = ([pscustomobject]@{ Success = $bSuccess; Message = $StatusMessage; Secret = $NewSecret })
	return $ReturnObject
}

function New-EitEncryptedPassword
{
	<#
	.Synopsis
			Creates a encrypted password
		.Description
			Creates a encrypted password for the raptor system
		
		.Parameter Server
			The server 
	
		.Parameter Password
			The password
		
		
		.EXAMPLE
			 New-EitEncryptedPassword -Server ActionsServer -Password MyPassword
		
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.08.2022 - M.Trojahn - Initial creation
			
	#>	
	param (
		[Parameter(Mandatory=$true)] [ValidateSet("ActionsServer","RaptorServer", "ProcessMonitorCollector")] [string]$Server,
		[Parameter(Mandatory=$true)] [string]$Password
	)
	try
	{
		$bSuccess = $true
		$StatusMessage = "Password successfully created "
		$PWFile = New-TemporaryFile
		$MyErrorFile = New-TemporaryFile
		$exe = "$env:ProgramFiles\EducateIT\" + $Server + "\" + $Server + ".exe"
		$arguments = "--pe-encode-password=" + $Password
		$EncryptedPassword = $null
		if (Test-Path $exe)
		{
			Start-Process -FilePath $exe -ArgumentList $arguments -Wait -RedirectStandardOutput $PWFile -RedirectStandardError $MyErrorFile
			if (Test-Path $MyErrorFile)
			{
				$EncryptedPassword = Get-Content -Path $PWFile
				<# Remove-Item $PWFile -Force #>
				if ($EncryptedPassword -eq $null) 
				{
					if (Test-Path $MyErrorFile)
					{
						$ErrorMessage = Get-Content -Path $MyErrorFile
						<# Remove-Item $MyErrorFile -Force  #>
						if ($ErrorMessage -ne $null) 
						{
							throw $ErrorMessage
						}
						else
						{
							throw "Unknown error occurred!"
							
						}
					}
				}
			}	
		}
		else
		{
			throw "Error: $exe does not exists"
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$ReturnObject = ([pscustomobject]@{ Success = $bSuccess; Message = $StatusMessage; EncryptedPassword = $EncryptedPassword})
	return $ReturnObject
}



function Get-EitPSUnique 
{
	<#
	.Synopsis
			Filtering for Unique Objects
		.Description
			Filtering for Unique Objects
		
		.Parameter InputObject
			The inputObject to filter 
	
		.EXAMPLE
			$Obj | Get-EitPSUnique
		
		.NOTES  
			Copyright: (c)2023 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 20.03.2023 - M.Trojahn - Initial creation based on https://github.com/jdhitsolutions/PSScriptTools/blob/master/functions/Get-PSUnique.ps1
			
	#>	
    [cmdletbinding()]
    [OutputType("object")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [object]$InputObject
    )

    begin 
	{
        Write-Verbose "[$((Get-Date).TimeOfDay) BEGIN  ] Starting $($MyInvocation.MyCommand)"
        Write-Debug "[$((Get-Date).TimeOfDay) BEGIN  ] Initializing list"
        $UniqueList = [System.Collections.Generic.list[object]]::new()
    } 

    process 
	{
        foreach ($item in $InputObject) 
		{
            if ($UniqueList.Exists( { -not(Compare-Object $args[0].PSObject.properties.value $item.PSObject.Properties.value) })) 
			{
                Write-Debug "[$((Get-Date).TimeOfDay) PROCESS] Skipping: $($item |Out-String)"
            }
            else 
			{
                Write-Debug "[$((Get-Date).TimeOfDay) PROCESS] Adding as unique: $($item | Out-String)"
                $UniqueList.add($item)
            }
        }
    } 

    end 
	{
        Write-Verbose "[$((Get-Date).TimeOfDay) END    ] Found $($UniqueList.count) unique objects"
        Write-Debug "[$((Get-Date).TimeOfDay) END    ] Writing results to the pipeline"
        $UniqueList
        Write-Verbose "[$((Get-Date).TimeOfDay) END    ] Ending $($MyInvocation.MyCommand)"
    } 
}




