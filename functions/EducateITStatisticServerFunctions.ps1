#
# EducateITStatisticServerFunctions.ps1
# ===========================================================================
# (c)2021 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# StatisticServer Functions for Raptor Scripts
#
# History:
#   V1.0 - 06.04.2021 - M.Trojahn - Initial creation
#                                        Write-EitStatisticServerEntry
#   
#######################################################################################################

function Write-EitStatisticServerEntry {
<# 
	.SYNOPSIS  
        Write an entry to the EducateIT Statistic Server       
		
    .DESCRIPTION  
         Use this function to write an entry to the EducateIT Statistic Server      
		 
    .PARAMETER apiKey
        The apiKey for the Rest Api
	.PARAMETER apiSecret
        The apiSecretfor the Rest Api
		
	.PARAMETER StatisticServer
		The name or ip address of the statistic server
			
	.PARAMETER StatisticServerPort
		The port of the Statisticserver, deafult 17696
			
	.PARAMETER DisableCertificateCheck
		Disables the ssl certificate check		
			
	.PARAMETER beginTime
		The startime of the task in UTC
	
	.PARAMETER endTime
		The endtime of the task in UTC
	
	.PARAMETER sourceUserName
		The source user name
		
	.PARAMETER sourceHost
		the source host
		
	.PARAMETER sourceDomain
		the source domain
		
	.PARAMETER  taskName
		the task name
		
	.PARAMETER taskHost
		the task host
		
	.PARAMETER taskStatus
		the status of the task
		
	.PARAMETER targetType
		the target type
		valid values are "no_target","process","session", "profile", "user", "computer", "user_and_computer", "repository_channel", "user_message"
		
	.PARAMETER targetUserName
		the target user name
	
	.PARAMETER targetHost
		the target host
		
	.PARAMETER  targetDomain
		the target domain
		
	.PARAMETER targetValue
		the target value
	
	.PARAMETER targetDetail 
		the target detail
	
	.PARAMETER applicationName
		the name of the application which send the entry
	
	.PARAMETER applicationCompany
		the company name
	
	.PARAMETER applicationVersion
		the version of the application
		has to be in format "1.0.0"
	
    .EXAMPLE  
		Write-EitStatisticServerEntry -apiKey myApiKey -apiSecret myAiSecret -StatisticServer myStatisticServer -beginTime ((get-date).ToUniversalTime().tostring("o")) -endTime ((get-date).ToUniversalTime().tostring("o")) -targetType "Computer" -sourceUserName $env:UserName -sourceHost $env:ComputerName -sourceDomain $env:Domain -taskName "MyTask" -taskHost $env:ComputerName -taskStatus "success" -targetUserName $env:UserName -targetHost $env:ComputerName -targetDomain $env:Domain -targetValue "MyValue" -targetDetail "MyDetail" -applicationName "MyScricpt" -applicationCompany "EducateIT" -applicationVersion "1.0.0" -DisableCertificateCheck
		
    .NOTES  
            Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0

            History:
                V1.0 - 01.04.2021 - M.Trojahn - Initial creation   
				
#>

    param(
        [Parameter(Mandatory=$true)] [string]$apiKey,
		[Parameter(Mandatory=$true)] [string]$apiSecret,
		[Parameter(Mandatory=$true)] [string]$StatisticServer,
		[Parameter(Mandatory=$false)] [int]$StatisticServerPort = 17696,
		[Parameter(Mandatory=$true)] [string]$beginTime,
		[Parameter(Mandatory=$true)] [string]$endTime,
		[Parameter(Mandatory=$true)] [string]$sourceUserName,
		[Parameter(Mandatory=$true)] [string]$sourceHost,
		[Parameter(Mandatory=$true)] [string]$sourceDomain,
		[Parameter(Mandatory=$true)] [string]$taskName,
		[Parameter(Mandatory=$true)] [string]$taskHost,
		[Parameter(Mandatory=$true)] [string]$taskStatus,
		[Parameter(Mandatory=$true)] [ValidateSet("no_target","process","session", "profile", "user", "computer", "user_and_computer", "repository_channel", "user_message")] [string]$targetType,
		[Parameter(Mandatory=$true)] [string]$targetUserName,
		[Parameter(Mandatory=$true)] [string]$targetHost,
		[Parameter(Mandatory=$true)] [string]$targetDomain,
		[Parameter(Mandatory=$true)] [string]$targetValue,
		[Parameter(Mandatory=$true)] [string]$targetDetail,
		[Parameter(Mandatory=$true)] [string]$applicationName,
		[Parameter(Mandatory=$true)] [string]$applicationCompany,
		[Parameter(Mandatory=$true)] [string]$applicationVersion,
		[Parameter(Mandatory=$False)] [switch]$DisableCertificateCheck
    )

	$bSuccess = $true
	$StatusMessage = "Successfully wrote statistic server entry..."
	
	# Creating the authorization header
	$auth = $apiKey + ':' + $apiSecret
	$Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
	$EncodedPassword = [System.Convert]::ToBase64String($Encoded)
	$headers = @{"Authorization"="Basic $($EncodedPassword)"}
	
	# Creating the PSCredential object
	$pwd = ConvertTo-SecureString $apiSecret -AsPlainText -Force
	$cred = New-Object Management.Automation.PSCredential ($apiKey, $pwd)
	
	# Creating the URI
	$URI = "https://" + $StatisticServer + ":" + $StatisticServerPort + "/writeEntry"
	
	# Creating the custom object for building the json body
	$entry = ([pscustomobject]@{
				beginTime=$beginTime;
				endTime=$endTime;
				sourceUserName=$sourceUserName;
				sourceHost=$sourceHost;
				sourceDomain=$sourceDomain;
				taskName=$taskName;
				taskHost=$taskHost;
				taskStatus=$taskStatus;
				targetType=$targetType;
				targetUserName=$targetUserName;
				targetHost=$targetHost;
				targetDomain=$targetDomain;
				targetValue=$targetValue;
				targetDetail=$targetDetail;
				applicationName=$applicationName;
				applicationCompany=$applicationCompany;
				applicationVersion=$applicationVersion}
	)
	$body = (ConvertTo-Json $entry)
	
	if ($DisableCertificateCheck) {
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	}	

	# Use TLS1.2 otherwise there is no connection
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	try {
		
		if (!(Test-EitPort -ComputerName $StatisticServer -Port $StatisticServerPort)) {
			throw "Statisticserver $StatisticServer is not listening on Port $StatisticServerPort!"
		}
	
		# call the rest api
		$rc = Invoke-RestMethod -Headers $headers -Method Post -Uri $URI -Body $body -ContentType "application/json; charset=utf-8" -Credential $cred
	
		if ($rc.status -ne "success") {
			throw $rc.reason
		}
		
	}
	catch {
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	if ($bSuccess) {
			if ($rc.status -eq "success") {
				$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
			}
			else {
				$ReturnObject = ([pscustomobject]@{Success=$false;Message=$rc.errorMessage})
			}
	}
	else {
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
	}
	return $ReturnObject
	
	finally {
		# Clean up web session
		$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
		$ServicePoint.CloseConnectionGroup("") | Out-Null
		if ($DisableCertificateCheck) {
			# Turning back certificate validation...
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$false}
		}
	}
}	
