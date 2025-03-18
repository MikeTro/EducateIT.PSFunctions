#
# CitrixCVADFunctions.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.1
#
# Citrix CVAD  (Citrix Virtual Apps and Desktops REST API) functions for Raptor Scripts
#
# History:
#   V1.0 - 24.02.2005 - M.Trojahn - Initial creation, add Get-EitCitrixCVADMe, Get-EitCitrixCVADSessionsInSite, Get-EitCitrixCVADSMachinesInSite, Get-EitCitrixCVADbearerToken
#	V1.1 - 06.03.2005 - M.Trojahn - Add UserName & MachineName parameter in function Get-EitCitrixCVADSessions 			
#
#
# ===========================================================================

function Get-EitCitrixCVADMe 
{
	<#
		.SYNOPSIS
			get information about the logged on citrix CVAD user
		
		.DESCRIPTION
			get information about the logged on citrix CVAD user
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId (CitrixOnPremises)
			
		.PARAMETER DDC
			the delivery controller (aka broker) for the request
			
		.EXAMPLE
			Get-EitCitrixCVADMe -bearerToken MybearerToken 
			List information about the logged on citrix CVAD user

		.NOTES  
			Copyright	: 	(c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 25.02.2025 - M.Trojahn - Initial creation
	#>
    param (
        [Parameter(Mandatory=$true)]  [string] $DDC,
		[Parameter(Mandatory=$true)]  [string] $bearerToken,
        [Parameter(Mandatory=$false)] [string] $customerId = "CitrixOnPremises"
    )
	
	$bSuccess = $true
	$StatusMessage = "Successfuly get my info!"
	$response = ""
	try 
	{
		$requestUri = "https://$DDC/cvad/manage/me"

		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerId;
		}
		
		if (Test-EitPort -server $DDC -port 443 -timeout 1000) 
		{
			# Invoke REST API
			$responseData = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
		}
		else
		{
			throw "DDC $DDC is not reachable via HTTPS!"
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = "Error: $($_.Exception.Message)"
	}
	# Return structured output
    [pscustomobject]@{
        Success = $bSuccess
        Message = $StatusMessage
        MyInfo  = $responseData
    }	
}

function Get-EitCitrixCVADSessionsInSite 
{
<#
		.SYNOPSIS
			List sessions in Citrix CVAD site
		.DESCRIPTION
			List sessions in Citrix CVAD site
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId (CitrixOnPremises)
		
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER DDC
			the delivery controller (aka broker) for the request
			
		.EXAMPLE
			Get-EitCitrixCVADSessionsInSite -DDC myBroker -bearerToken MybearerToken -siteId MySiteID
			List all sessions in site MySite 

		.NOTES  
			Copyright	: 	(c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 25.02.2025 - M.Trojahn - Initial creation
				
	#>		
    param (
		[Parameter(Mandatory=$true)]  [string] $DDC,
		[Parameter(Mandatory=$true)]  [string] $siteId,
        [Parameter(Mandatory=$true)]  [string] $bearerToken,
        [Parameter(Mandatory=$false)] [string] $customerId = "CitrixOnPremises"
    )

    $bSuccess = $true
	$StatusMessage = "Successfuly get sessions!"
	$response = ""
	try 
	{
		
		if (Test-EitPort -server $DDC -port 443 -timeout 1000) 
		{
			$SessionsData = Get-EitCitrixDaasSessionsInSite -customerId $customerId -bearerToken $bearerToken -siteId $siteId -endpoint "https://$DDC"
		}
		else
		{
			throw "DDC $DDC is not reachable via HTTPS!"
		}
		
		# Ensure the function call was successful
		if ($SessionsData.Success -ne "True")
		{
			throw $SessionsData.Message
		}	
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
		$SessionsData = @{ Sessions = @() }  
	}
	# Return structured output
    [pscustomobject]@{
        Success  = $bSuccess
        Message  = $StatusMessage
        Sessions = $SessionsData.Sessions
    }
}



function Get-EitCitrixCVADSMachinesInSite 
{
<#
		.SYNOPSIS
			List machines in Citrix CVAD site
			
		.DESCRIPTION
			List machines in Citrix CVAD site
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId (CitrixOnPremises)
		
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER DDC
			the delivery controller (aka broker) for the request
		
		.EXAMPLE
			Get-EitCitrixCVADMachinesInSite -DDC myDDC -bearerToken myBearerToken -siteId MySiteID
			List all machines in site MySite 
			
		.NOTES  
			Copyright	: 	(c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 25.02.2025 - M.Trojahn - Initial creation
				
	#>		
    param (
		[Parameter(Mandatory=$true)]  [string] $DDC,
		[Parameter(Mandatory=$true)]  [string] $siteId,
        [Parameter(Mandatory=$true)]  [string] $bearerToken,
        [Parameter(Mandatory=$false)] [string] $customerId = "CitrixOnPremises"
    )
    
	$bSuccess = $true
	$StatusMessage = "Successfuly get machines!"
	$response = ""
	try 
	{	
		if (Test-EitPort -server $DDC -port 443 -timeout 1000) 
		{
			$MachinesData = Get-EitCitrixDaaSMachinesInSite -customerId $customerId -bearerToken $bearerToken -siteId $siteId -endpoint "https://$DDC"
		}
		else
		{
			throw "DDC $DDC is not reachable via HTTPS!"
		}
	
		# Ensure the function call was successful
		if ($MachinesData.Success -ne "True")
		{
			$StatusMessage = "Error: $($_.Exception.Message)"
			$MachinesData = @{ Machines = @() }
		}	
    }
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	# Return structured output
    [pscustomobject]@{
        Success  = $bSuccess
        Message  = $StatusMessage
        Machines = $MachinesData.Machines
    }
}


function Get-EitCitrixCVADbearerToken 
{
	<#
		.SYNOPSIS
			get a citrix CVAD api bearerToken
			
		.DESCRIPTION
			get a citrix CVAD api bearerToken
		
		.PARAMETER EncodedAdminCredential
			the Encoded Admin Credentials 
			see https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops/citrix-cvad-rest-apis/citrix-virtual-apps-and-desktops-apis#prerequisites for more information
			
		.PARAMETER DDC
			the delivery controller (aka broker) for the request
			
		.EXAMPLE
			Get-EitCitrixCVADbearerToken -DDC myDDC -EncodedAdminCredential myEncodedAdminCredential
			
		.NOTES  
			Copyright	: 	(c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 24.02.2025 - M.Trojahn - Initial creation
				
	#>
    param (
        [Parameter(Mandatory=$true)] [string] $DDC,
		[Parameter(Mandatory=$true)] [string] $EncodedAdminCredential
    )
	
	$bSuccess = $true
	$StatusMessage = "Successfuly get bearerToken!"
	$response = ""
	$bearerToken = ""
	try {
		if (-not("TrustAllCertsPolicy" -as [type])) {
		add-type -TypeDefinition @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;

			public static class TrustAllCertsPolicy {
				public static bool ReturnTrue(object sender,
					X509Certificate certificate,
					X509Chain chain,
					SslPolicyErrors sslPolicyErrors) { return true; }

				public static RemoteCertificateValidationCallback GetDelegate() {
					return new RemoteCertificateValidationCallback(TrustAllCertsPolicy.ReturnTrue);
				}
			}
"@
		}

		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TrustAllCertsPolicy]::GetDelegate()

		# Set Tls versions
		$allProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
		[System.Net.ServicePointManager]::SecurityProtocol = $allProtocols

		$tokenUrl = "https://$DDC/cvad/manage/Tokens"
		$Headers = @{
			Accept = "application/json"
			Authorization = "Basic $EncodedAdminCredential"
		}
		
		if (Test-EitPort -server $DDC -port 443 -timeout 1000) 
		{
			$response = Invoke-WebRequest -Uri $tokenUrl -Method POST -Headers $Headers -UseBasicParsing -ErrorAction Stop
			$responseJson = $response.Content | ConvertFrom-Json
			$bearerToken = $responseJson.token
		}
		else
		{
			throw "DDC $DDC is not reachable via HTTPS!"
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = "Error: $($_.Exception.Message)"
	}
	# Return structured output
    [pscustomobject]@{
        Success     = $bSuccess
        Message     = $StatusMessage
        BearerToken = $bearerToken
    }
}


function Get-EitCitrixCVADSessions 
{
	<#
		.SYNOPSIS
			Get a list of all Citrix sessions via the CVAD API on multiple delivery controllers.
			
		.DESCRIPTION
			Get a list of all Citrix sessions via the CVAD API on multiple delivery controllers.
		
		.PARAMETER DDCs
			The list of delivery controllers (aka brokers)
			
		.PARAMETER EncodedAdminCredential
			the Encoded Admin Credentials 
			see https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops/citrix-cvad-rest-apis/citrix-virtual-apps-and-desktops-apis#prerequisites for more information
			
		.PARAMETER MachineName
			The machine name(s) to filter sessions
			
		.PARAMETER UserName
			The user name(s) to filter sessions		

				
		.EXAMPLE
			Get-EitCitrixCVADSessions  -DDCs myDDC1, myDDC2 -EncodedAdminCredential myEncodedAdminCredential
			
		.NOTES  
			Copyright	: 	(c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 24.02.2025 - M.Trojahn - Initial creation
				V1.1 - 06.03.2025 - M.Trojahn - Add UserName & MachineName parameter
				
	#>
	Param (
        [Parameter(Mandatory = $true)]  [string[]]$DDCs,
		[Parameter(Mandatory = $true)] [string]$EncodedAdminCredential,
		[Parameter(Mandatory = $false)] [string[]]$MachineName,
        [Parameter(Mandatory = $false)] [string[]]$UserName
		
    )
	
	
	$SessionList = @()
    $SessionHash = @{}
    $bSuccess = $false
    $StatusMessage = "Error while reading session list!"
    
    function Make-EitSessionData {
        Param (
            [string]$UserName,
            [string]$MachineName,
            [string]$SessionState,
            [string]$UserUPN,
            [string]$Uid
        )
        [PSCustomObject]@{
            UserName     = $UserName
            UserUPN      = $UserUPN
            Uid          = $Uid
            MachineName  = $MachineName
            SessionState = $SessionState
        }
    }
	
	try {
        foreach ($DDC in $DDCs) {
            if (-not (Test-EitPort -server $DDC -port 443 -timeout 1000)) 
			{
                Write-Warning "ERROR: DDC $DDC is not reachable via HTTPS!"
                continue
            }
				
			$myAccessToken = Get-EitCitrixCVADbearerToken -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
			if ($myAccessToken.Success -eq "true")
			{
				$MyInfo = Get-EitCitrixCVADMe -DDC $DDC -bearerToken $myAccessToken.bearerToken
				if ($MyInfo.Success -eq "true")
				{
					$SessionsData = Get-EitCitrixCVADSessionsInSite -DDC $DDC -bearerToken $myAccessToken.bearerToken -siteid $MyInfo.MyInfo.Customers.Sites.Id
					if ($SessionsData.Success -eq "true")
					{
						foreach ($Session in $SessionsData.Sessions) 
						{
							$EitSessionData = Make-EitSessionData -UserName $Session.User.Name -MachineName $Session.Machine.Name -SessionState $Session.State -Uid $Session.Uid -UserUPN $Session.User.PrincipalName
							if (-not $SessionHash.ContainsKey($EitSessionData.Uid)) 
							{
								$SessionHash[$EitSessionData.Uid] = $EitSessionData
							}
						}
						$StatusMessage = "Successfully read session list..."
						$bSuccess = $true
					} 
					else
					{
						throw $SessionsData.Message
					}
				} 
				else
				{
					throw $MyInfo.Message
				} 
			} 
			else
			{
				throw $myAccessToken.Message
			}
        }
    } 
	catch 
	{
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }
    
	$SessionList = $SessionHash.Values | Sort-Object UserUPN
	$SessionList = $SessionList | Where-Object {
		(-not $MachineName -or $_.MachineName -in $MachineName) -and
		(-not $UserName -or $_.UserName -in $UserName)
	} | Select-Object UserName, Uid, UserUPN, MachineName, SessionState
    [PSCustomObject]@{
        Success     = $bSuccess
        Message     = $StatusMessage
        SessionList = $SessionList
    }
}
