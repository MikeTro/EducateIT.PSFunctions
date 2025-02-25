#
# CitrixCVADFunctions.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Citrix CVAD  (Citrix Virtual Apps and Desktops REST API) functions for Raptor Scripts
#
# History:
#   V1.0 - 24.02.2005 - M.Trojahn - Initial creation, add Get-EitCitrixCVADMe, Get-EitCitrixCVADSessionsInSite, Get-EitCitrixCVADSMachinesInSite, Get-EitCitrixCVADbearerToken
#									
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
			the DDC, aka Broker
			
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
		$requestUri = [string]::Format("https://$DDC/cvad/manage/me")

		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
		}
		$response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;MyInfo=$response})
	return $ReturnObject	
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
			the DDC
			
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
		[Parameter(Mandatory=$true)]  [string] $siteid,
        [Parameter(Mandatory=$true)]  [string] $bearerToken,
        [Parameter(Mandatory=$false)] [string] $customerid = "CitrixOnPremises"
    )

    $bSuccess = $true
	$StatusMessage = "Successfuly get sessions!"
	$response = ""
	try 
	{
		$SessionsData = Get-EitCitrixDaasSessionsInSite -customerId $customerid -bearerToken $bearerToken -siteId $siteid -endpoint "https://$DDC"
		if ($SessionsData.Success -ne "True")
		{
			throw $SessionsData.Message
		}	
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Sessions=$SessionsData.Sessions})
	return $ReturnObject
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
			the DDC, aka Broker
		
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
		[Parameter(Mandatory=$true)]  [string] $siteid,
        [Parameter(Mandatory=$true)]  [string] $bearerToken,
        [Parameter(Mandatory=$false)] [string] $customerid = "CitrixOnPremises"
    )
    
	$bSuccess = $true
	$StatusMessage = "Successfuly get machines!"
	$response = ""
	try 
	{	
		$MachinesData = Get-EitCitrixDaaSMachinesSite -customerId $customerid -bearerToken $bearerToken -siteId $siteid -endpoint "https://$DDC"
		if ($MachinesData.Success -ne "True")
		{
			throw $MachinesData.Message
		}	
    }
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Machines=$MachinesData.Machines})
	return $ReturnObject
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
			the DDC, aka Broker
			
		.EXAMPLE
			Get-EitCitrixCVADbearerToken -DDC myDDC -Credential MyCredentials
			
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
		
		$response = Invoke-WebRequest -Uri $tokenUrl -Method POST -Headers $Headers -UseBasicParsing -ErrorAction Stop
		
		$content  = $response.Content | ConvertFrom-Json
		$bearerToken = $content.token
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;bearerToken=$bearerToken})
	return $ReturnObject	
}
