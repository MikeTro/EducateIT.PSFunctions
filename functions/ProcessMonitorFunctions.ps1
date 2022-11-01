#
# ProcessMonitorFunctions.ps1
# ===========================================================================
# (c)2022 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Processmonitor functions for Raptor Scripts
#
# History:
#   V1.0 - 01.11.2022 - M.Trojahn - Initial creation from various functions
#									add Get-EitProcessMonitorListByUserName, Get-EitProcessMonitorListByProcessName, Get-EitProcessMonitorListByApplicationName
#										
#
#
#
# ===========================================================================



function Get-EitProcessMonitorListByUserName {
<# 
 .SYNOPSIS  
        Query the ProcessMonitor Collector Api for running prcesses by user name       
    .DESCRIPTION  
        Use this function to query the ProcessMonitor Collector Api for running prcesses by user name
    .PARAMETER apiKey
        The apiKey for the Rest Api
	.PARAMETER apiSecret
        The apiSecretfor the Rest Api
	.PARAMETER URI
			The URI of the API
	.PARAMETER DomainName
			The Processname to search for
	.PARAMETER UserName
			The username to search for			
	.PARAMETER DisableCertificateCheck
			Disables the ssl certificate check		
			
			
    .EXAMPLE  
        Get-EitProcessMonitorListByUserName -apiKey $apiKey -apiSecret $apiSecret -URI ProcessMonitorURI -DomainName MyDomain -UserName MyUserName
        Returns all the running process for user MyUserName
		
		Get-EitProcessMonitorListByProcessName -apiKey $apiKey -apiSecret $apiSecret -URI ProcessMonitorURI -DomainName MyDomain -UserName MyUserName -DisableCertificateCheck
        The check for certificate is disabled, trusting all ssl certificates
        
    .NOTES  
            Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0

            History:
                V1.0 - 01.11.2022 - M.Trojahn - Initial creation   
#>

    param(
        [Parameter(Mandatory=$True)] [string]$apiKey,
		[Parameter(Mandatory=$True)] [string]$apiSecret,
		[Parameter(Mandatory=$True)] [string]$URI,
		[Parameter(Mandatory=$True)] [string]$DomainName,
		[Parameter(Mandatory=$True)] [string]$UserName,
		[Parameter(Mandatory=$False)] [switch]$DisableCertificateCheck
		
    )

	# Creating the authorization header
	$auth = $apiKey + ':' + $apiSecret
	$Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
	$EncodedPassword = [System.Convert]::ToBase64String($Encoded)
	$headers = @{"Authorization"="Basic $($EncodedPassword)"}
	
	# Creating the PSCredential object
	$pwd = ConvertTo-SecureString $apiSecret -AsPlainText -Force
	$cred = New-Object Management.Automation.PSCredential ($apiKey, $pwd)

	# Creating the filter
	$Filter = @"
{
	"filter": "<Value name=\"owner\"><Matches>$DomainName\\$UserName</Matches></Value>",
	"limit": -1
}
"@ 

	if ($DisableCertificateCheck) {
		#Write-Host "Turning off certificate validation..."
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	}	
	
	# Use TLS1.2 otherwise there is no connection
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	$StatusMessage = "Successfully read process monitor api..."
	try {
		# call the rest api
		$rc = Invoke-RestMethod -Headers $headers -Method Post -Uri $URI -Body $Filter -ContentType "application/json; charset=utf-8" -Credential $cred
		
		# Clean up web session
		$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
		#Make the REST API Call using Invoke-RestMethod
		$ServicePoint.CloseConnectionGroup("")
		
		if ($DisableCertificateCheck) {
			#Write-Host "Turning back certificate validation..."
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$false}
		}
		
		if ($rc.processlist -ne $Null) {
			$bSuccess = $true
		}
		else {
			$bSuccess = $false
			$StatusMessage = "No runnig process for user $UserName found!"
		}
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
		
	}
	
	if ($bSuccess) {
		if ($rc.status -eq "success") {
			$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ProcessList=$rc.processlist})
		}
		else {
			$ReturnObject = ([pscustomobject]@{Success=$false;Message=$rc.errorMessage;ProcessList=""})
		}
	}
	else {
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ProcessList=""})
	}
	return $ReturnObject
}	

function Get-EitProcessMonitorListByProcessName {
<# 
 .SYNOPSIS  
        Query the ProcessMonitor Collector Api for running prcesses        
    .DESCRIPTION  
        Use this function to query the ProcessMonitor Collector Api for running prcesses
    .PARAMETER apiKey
        The apiKey for the Rest Api
	.PARAMETER apiSecret
        The apiSecretfor the Rest Api
	.PARAMETER URI
			The URI of the API
	.PARAMETER Processname
			The Processname to search for
	.PARAMETER DisableCertificateCheck
			Disables the ssl certificate check		
			
			
    .EXAMPLE  
        Get-EitProcessMonitorListByProcessName -apiKey $apiKey -apiSecret $apiSecret -URI ProcessMonitorURI -ProcessName wordpad
        Returns al the running wordpad process
		
		Get-EitProcessMonitorListByProcessName -apiKey $apiKey -apiSecret $apiSecret -URI ProcessMonitorURI -ProcessName wordpad -DisableCertificateCheck
        The check for certificate is disabled, trusting all ssl certificates
        
    .NOTES  
            Copyright: (c)2017 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.1

            History:
                V1.0 - 17.05.2017 - M.Trojahn - Initial creation   
				V1.1 - 08.08.2017 - M.Trojahn - Add switch parameter DisableCertificateCheck
#>

    param(
        [Parameter(Mandatory=$True)] [string]$apiKey,
		[Parameter(Mandatory=$True)] [string]$apiSecret,
		[Parameter(Mandatory=$True)] [string]$URI,
		[Parameter(Mandatory=$True)] [string]$ProcessName,
		[Parameter(Mandatory=$False)] [switch]$DisableCertificateCheck
		
    )

	# Creating the authorization header
	$auth = $apiKey + ':' + $apiSecret
	$Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
	$EncodedPassword = [System.Convert]::ToBase64String($Encoded)
	$headers = @{"Authorization"="Basic $($EncodedPassword)"}
	
	# Creating the PSCredential object
	$pwd = ConvertTo-SecureString $apiSecret -AsPlainText -Force
	$cred = New-Object Management.Automation.PSCredential ($apiKey, $pwd)

	# Creating the filter
	$Filter = @"
{
	"filter": "<Value name=\"name\"><Matches>$ProcessName</Matches></Value>",
	"limit": -1
}
"@ 
	
	if ($DisableCertificateCheck) {
		#Write-Host "Turning off certificate validation..."
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	}	
	
	# Use TLS1.2 otherwise there is no connection
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	
	$StatusMessage = "Successfully read process monitor api..."
	try {
		# call the rest api
		$rc = Invoke-RestMethod -Headers $headers -Method Post -Uri $URI -Body $Filter -ContentType "application/json; charset=utf-8" -Credential $cred
		
		# Clean up web session
		$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
		#Make the REST API Call using Invoke-RestMethod
		$ServicePoint.CloseConnectionGroup("")
		
		if ($DisableCertificateCheck) {
			#Write-Host "Turning back certificate validation..."
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$false}
		}
		
		if ($rc.processlist -ne $Null) {
			$bSuccess = $true
		}
		else {
			$bSuccess = $false
			$StatusMessage = "No runnig process $ProcessName found!"
		}
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
		
	}
	
	if ($bSuccess) {
		if ($rc.status -eq "success") {
			$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ProcessList=$rc.processlist})
		}
		else {
			$ReturnObject = ([pscustomobject]@{Success=$false;Message=$rc.errorMessage;ProcessList=""})
		}
	}
	else {
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ProcessList=""})
	}
	return $ReturnObject
}	

function Get-EitProcessMonitorListByApplicationName {
<# 
 .SYNOPSIS  
        Query the ProcessMonitor Collector Api for running prcesses        
    .DESCRIPTION  
        Use this function to query the ProcessMonitor Collector Api for running prcesses
    .PARAMETER apiKey
        The apiKey for the Rest Api
	.PARAMETER apiSecret
        The apiSecretfor the Rest Api
	.PARAMETER URI
			The URI of the API
	.PARAMETER PApplicationName
			The Processname to search for
	.PARAMETER DisableCertificateCheck
			Disables the ssl certificate check		
			
			
    .EXAMPLE  
        Get-EitProcessMonitorListByApplicationName -apiKey $apiKey -apiSecret $apiSecret -URI ProcessMonitorURI -ApplicationName Wordpad
        Returns all the running wordpad process
		
		Get-EitProcessMonitorListByApplicationName -apiKey $apiKey -apiSecret $apiSecret -URI ProcessMonitorURI -ApplicationName wordpad -DisableCertificateCheck
        The check for certificate is disabled, trusting all ssl certificates
        
    .NOTES  
            Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0

            History:
                V1.0 - 01.02.2022 - M.Trojahn - Initial creation   
				
#>

    param(
        [Parameter(Mandatory=$True)] [string]$apiKey,
		[Parameter(Mandatory=$True)] [string]$apiSecret,
		[Parameter(Mandatory=$True)] [string]$URI,
		[Parameter(Mandatory=$True)] [string]$ApplicationName,
		[Parameter(Mandatory=$False)] [switch]$DisableCertificateCheck
		
    )

	# Creating the authorization header
	$auth = $apiKey + ':' + $apiSecret
	$Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
	$EncodedPassword = [System.Convert]::ToBase64String($Encoded)
	$headers = @{"Authorization"="Basic $($EncodedPassword)"}
	
	# Creating the PSCredential object
	$pwd = ConvertTo-SecureString $apiSecret -AsPlainText -Force
	$cred = New-Object Management.Automation.PSCredential ($apiKey, $pwd)

	# Creating the filter
	$Filter = @"
{
	"filter": "<Value name=\"applicationName\"><Matches>$ApplicationName</Matches></Value>",
	"limit": -1
}
"@ 
	
	if ($DisableCertificateCheck) {
		#Write-Host "Turning off certificate validation..."
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	}	
	
	# Use TLS1.2 otherwise there is no connection
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	
	$StatusMessage = "Successfully read process monitor api..."
	try {
		# call the rest api
		$rc = Invoke-RestMethod -Headers $headers -Method Post -Uri $URI -Body $Filter -ContentType "application/json; charset=utf-8" -Credential $cred
		
		# Clean up web session
		$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
		#Make the REST API Call using Invoke-RestMethod
		$ServicePoint.CloseConnectionGroup("")
		
		if ($DisableCertificateCheck) {
			#Write-Host "Turning back certificate validation..."
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$false}
		}
		
		if ($rc.processlist -ne $Null) {
			$bSuccess = $true
		}
		else {
			$bSuccess = $false
			$StatusMessage = "No runnig application $ApplicationName found!"
		}
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
		
	}
	
	if ($bSuccess) {
		if ($rc.status -eq "success") {
			$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ProcessList=$rc.processlist})
		}
		else {
			$ReturnObject = ([pscustomobject]@{Success=$false;Message=$rc.errorMessage;ProcessList=""})
		}
	}
	else {
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ProcessList=""})
	}
	return $ReturnObject
}	

