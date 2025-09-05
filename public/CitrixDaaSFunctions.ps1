#
# CitrixDaaSFunctions.ps1
# ===========================================================================
# (c)2024 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.3
#
# Citrix Daas (Citrix Cloud) functions for Raptor Scripts
#
# History:
#   V1.0 - 27.10.2022 - M.Trojahn - Initial creation
#									add Get-EitCitrixDaaSMe, Get-EitCitrixDaaSSessionsInSite, Get-EitCitrixDaaSSession, 
#										Stop-EitCitrixDaaSSession, Get-EitCitrixDaaSMachinesInSite, Get-EitCitrixDaaSbearerToken
#										Get-EitCitrixDaaSMachine, Restart-EitCitrixDaaSMachine, Stop-EitCitrixDaaSMachine, Start-EitCitrixDaaSMachine
#   V1.1 - 11.09.2023 - M.Trojahn - Add UseBasicParsing in function Get-EitCitrixDaaSbearerToken
#	V1.2 - 19.04.2024 - M.Trojahn - fix wrong client_id & client_secret variable declaration in function Get-EitCitrixDaaSbearerToken
#	V1.3 - 13.08.2024 - M.Trojahn - Use paging Get-EitCitrixDaaSSessionsInSite & Get-EitCitrixDaaSMachinesInSite
#
#
# ===========================================================================

function Get-EitCitrixDaaSMe {
	<#
		.SYNOPSIS
			get information about the logged on citrix DaaS user
		.DESCRIPTION
			get information about the logged on citrix DaaS user
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSMe -customerId MycustomerId -bearerToken MybearerToken 
			List information about the logged on citrix DaaS user


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
	#>
    param (
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
        [Parameter(Mandatory=$true)]
        [string] $customerId,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
	
	$bSuccess = $true
	$StatusMessage = "Successfuly get my info!"
	$response = ""
	try {
		$requestUri = [string]::Format($endPoint + "/cvad/manage/me")

		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
		}
		$response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -ContentType "application/json" -UseBasicParsing
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;MyInfo=$response})
	return $ReturnObject	
}

function Get-EitCitrixDaaSSessionsInSite {
<#
		.SYNOPSIS
			List sessions in Citrix DaaS site
		.DESCRIPTION
			List sessions in Citrix DaaS site
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
		
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.PARAMETER maxRecordCountLimit
			The maximum record count, should not be greater than 1000
			
		.EXAMPLE
			Get-EitCitrixDaaSSessionsInSite -customerId MycustomerId -bearerToken MybearerToken -siteId MySiteID
			List all sessions in site MySite 


			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
				V1.1 - 13.08.2024 - M.Trojahn - Use paging for querying more than 1000 objects
												https://developer-docs.citrix.com/en-us/citrix-daas-service-apis/citrix-daas-rest-apis/how-to-use-paging-to-query-many-objects-through-multiple-api-calls.html
	#>		
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com",
		[Parameter(Mandatory=$false)]
		[ValidateRange(1,1000)]
		[string] $maxRecordCountLimit="1000"	
    )
    $requestUri = $endPoint + "/cvad/manage/Sessions?limit=$maxRecordCountLimit"
	$headers = @{
        "Accept" = "application/json";
        "Authorization" = "CWSAuth Bearer=$bearerToken";
        "Citrix-CustomerId" = $customerid;
        "Citrix-InstanceId" = $siteid;
    }
	$bSuccess = $true
	$StatusMessage = "Successfuly get sessions!"
	$response = ""
	try 
	{
		$response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -UseBasicParsing
	    while ($response.ContinuationToken -ne $null)
		{
			$requestUriContinue = $requestUri + "&continuationtoken=" + $response.ContinuationToken
			$responsePage = Invoke-RestMethod -Uri $requestUriContinue -Method GET -Headers $headers
			$response.Items += $responsePage.Items
			$response.ContinuationToken = $responsePage.ContinuationToken
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Sessions=$response.items})
	return $ReturnObject
}

function Get-EitCitrixDaaSSession {
<#
		.SYNOPSIS
			gets a Citrix DaaS Session object 
		.DESCRIPTION
			get a Citrix DaaS Session object 
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
		
		.PARAMETER siteId
			the siteId				
			
		.PARAMETER sessionId
			the sessionId		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSSession -customerId MycustomerId -bearerToken MybearerToken -siteId MySiteID -sessionId MySessionId
			Get a Citrix DaaS Session object 


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
	#>	
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$true)]
        [string] $sessionId,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
	
	$bSuccess = $true
	$StatusMessage = "Successfuly get session!"
	$response = ""
	try 
	{
		$requestUri =  $endPoint + "/cvad/manage/Sessions/$sessionId"
		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
			"Citrix-InstanceId" = $siteid;
		}

		$response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -UseBasicParsing
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Session=$response})
	return $ReturnObject
}

function Stop-EitCitrixDaaSSession {
<#
		.SYNOPSIS
			logoffs a session
			
		.DESCRIPTION
			Use this function to logoff a Citrix DaaS session
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
			
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER sessionId
			the sessionId		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Stop-EitCitrixDaaSSession -customerId MycustomerId -bearerToken MybearerToken -sessionId MySessionId
			Logoff session with sessionID MySessionId


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
	#>		
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $sessionId,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
   
    $headers = @{
        "Accept" = "application/json";
        "Authorization" = "CWSAuth Bearer=$bearerToken";
        "Citrix-CustomerId" = $customerid;
        "Citrix-InstanceId" = $siteid;
    }
	
	$bSuccess = $true
	$StatusMessage = "Successfuly stopped the session!"
	$response = ""
	try 
	{
		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
			"Citrix-InstanceId" = $siteid;
		}
		$requestUri = [string]::Format(($endPoint + "/cvad/manage/Sessions/{0}/`$logoff"), $sessionid)
		$response = Invoke-RestMethod -Uri $requestUri -Method POST -Headers $headers -ContentType "application/json" -UseBasicParsing
		
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Response=$response})
	return $ReturnObject
}

function Get-EitCitrixDaaSMachinesInSite {
<#
		.SYNOPSIS
			List machines in Citrix DaaS site
			
		.DESCRIPTION
			List machines in Citrix DaaS site
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
		
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
		
		.PARAMETER maxRecordCountLimit
			The maximum record count, should not be greater than 1000
			
		.EXAMPLE
			Get-EitCitrixDaaSMachinesInSite -customerId MycustomerId -bearerToken MybearerToken -siteId MySiteID
			List all machines in site MySite 
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
				V1.1 - 13.08.2024 - M.Trojahn - Use paging for querying more than 1000 objects
												https://developer-docs.citrix.com/en-us/citrix-daas-service-apis/citrix-daas-rest-apis/how-to-use-paging-to-query-many-objects-through-multiple-api-calls.html
	
	#>		
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com",
		[Parameter(Mandatory=$false)]
		[ValidateRange(1,1000)]
		[string] $maxRecordCountLimit="1000"	

    )
    $requestUri = $endPoint + "/cvad/manage/Machines?limit=$maxRecordCountLimit"
    $headers = @{
        "Accept" = "application/json";
        "Authorization" = "CWSAuth Bearer=$bearerToken";
        "Citrix-CustomerId" = $customerid;
        "Citrix-InstanceId" = $siteid;
    }
	$bSuccess = $true
	$StatusMessage = "Successfuly get machines!"
	$response = ""
	try 
	{	
		$response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -UseBasicParsing
		while ($response.ContinuationToken -ne $null)
		{
			$requestUriContinue = $requestUri + "&continuationtoken=" + $response.ContinuationToken
			$responsePage = Invoke-RestMethod -Uri $requestUriContinue -Method GET -Headers $headers
			$response.Items += $responsePage.Items
			$response.ContinuationToken = $responsePage.ContinuationToken
		}
    }
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Machines=$response.items})
	return $ReturnObject
}

function Get-EitCitrixDaaSbearerToken {
	<#
		.SYNOPSIS
			get a citrix DaaS api bearerToken
			
		.DESCRIPTION
			get a citrix DaaS api bearerToken
		
		.PARAMETER clientId
			the client id	
			
		.PARAMETER clientSecret
			the client secret		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSbearerToken -clientId MyClientID -clientSecret MyClientSecret
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.2
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
				V1.1 - 11.09.2023 - M.Trojahn - add -UseBasicParsing
				V1.2 - 19.04.2024 - M.Trojahn - fix wrong client_id & client_secret variable declaration
	#>
    param (
        [Parameter(Mandatory=$true)]
        [string] $clientId,
		 [Parameter(Mandatory=$true)]
        [string] $clientSecret,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
	
	$bSuccess = $true
	$StatusMessage = "Successfuly get bearerToken!"
	$response = ""
	$bearerToken = ""
	try {
		$tokenUrl =  $endPoint + "/cctrustoauth2/root/tokens/clients"

		$body = @{
			grant_type = "client_credentials"
			client_id = $clientId
			client_secret = $clientSecret
		}
		
		# Obtain bearer token from authorization server
		$response = Invoke-WebRequest $tokenUrl -Method POST -Body $Body -UseBasicParsing
		
		$token  = $response.Content | ConvertFrom-Json
		$bearerToken = $token.access_token
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;bearerToken=$bearerToken})
	return $ReturnObject	
}

function Get-EitCitrixDaaSMachine {
<#
		.SYNOPSIS
			gets a Citrix DaaS machine object 
			
		.DESCRIPTION
			get a Citrix DaaS machine object 
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
		
		.PARAMETER siteId
			the siteId				
			
		.PARAMETER machineId
			the sessionId		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSMachine -customerId MycustomerId -bearerToken MybearerToken -siteId MySiteID -machineId MyMachineId
			Get a Citrix DaaS machine object 


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 24.10.2022 - M.Trojahn - Initial creation
	#>	
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$true)]
        [string] $machineId,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
	
	$bSuccess = $true
	$StatusMessage = "Successfuly get machine!"
	$response = ""
	try 
	{
		$requestUri =  $endPoint + "/cvad/manage/Machines/$machineId"
		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
			"Citrix-InstanceId" = $siteid;
		}
		$response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -UseBasicParsing
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Machine=$response})
	return $ReturnObject
}

function Restart-EitCitrixDaaSMachine {
<#
		.SYNOPSIS
			Restart a Citrix DaaS machine
			
		.DESCRIPTION
			Use this function to restart a Citrix DaaS machine
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
			
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER machineId
			the machineId		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Restart-EitCitrixDaaSMachine -customerId MycustomerId -bearerToken MybearerToken -sessionId MyMachineId
			Restart machine with machineID MyMachineId


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
	#>		
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $machineId,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
   
    $headers = @{
        "Accept" = "application/json";
        "Authorization" = "CWSAuth Bearer=$bearerToken";
        "Citrix-CustomerId" = $customerid;
        "Citrix-InstanceId" = $siteid;
    }
	
	$bSuccess = $true
	$StatusMessage = "Successfuly restarted the machine!"
	$response = ""
	try 
	{
		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
			"Citrix-InstanceId" = $siteid;
		}
		$requestUri = [string]::Format(($endPoint + "/cvad/manage/Machines/{0}/`$reboot"), $machineId)
		$response = Invoke-RestMethod -Uri $requestUri -Method POST -Headers $headers -ContentType "application/json" -UseBasicParsing
		
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Response=$response})
	return $ReturnObject
}

function Stop-EitCitrixDaaSMachine {
<#
		.SYNOPSIS
			Stop a Citrix DaaS machine
			
		.DESCRIPTION
			Use this function to shutdwon a Citrix DaaS machine
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
			
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER machineId
			the machineId		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Stop-EitCitrixDaaSMachine -customerId MycustomerId -bearerToken MybearerToken -sessionId MyMachineId
			Shutdown machine with machineID MyMachineId


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
	#>		
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $machineId,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
   
    $headers = @{
        "Accept" = "application/json";
        "Authorization" = "CWSAuth Bearer=$bearerToken";
        "Citrix-CustomerId" = $customerid;
        "Citrix-InstanceId" = $siteid;
    }
	
	$bSuccess = $true
	$StatusMessage = "Successfuly stopped the machine!"
	$response = ""
	try 
	{
		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
			"Citrix-InstanceId" = $siteid;
		}
		$requestUri = [string]::Format(($endPoint + "/cvad/manage/Machines/{0}/`$shutdown"), $machineId)
		$response = Invoke-RestMethod -Uri $requestUri -Method POST -Headers $headers -ContentType "application/json" -UseBasicParsing
		
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Response=$response})
	return $ReturnObject
}

function Start-EitCitrixDaaSMachine {
<#
		.SYNOPSIS
			Start a Citrix DaaS machine
			
		.DESCRIPTION
			Use this function to start a Citrix DaaS machine
		
		.PARAMETER bearerToken
			the bearerToken
			
		.PARAMETER customerId
			the customerId	
			
		.PARAMETER siteId
			the siteId			
			
		.PARAMETER machineId
			the machineId		
			
		.PARAMETER endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Start-EitCitrixDaaSMachine -customerId MycustomerId -bearerToken MybearerToken -sessionId MyMachineId
			Start machine with machineID MyMachineId


			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
	#>		
    param (
        [Parameter(Mandatory=$true)]
        [string] $customerid,
        [Parameter(Mandatory=$true)]
        [string] $siteid,
        [Parameter(Mandatory=$true)]
        [string] $machineId,
        [Parameter(Mandatory=$true)]
        [string] $bearerToken,
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"
    )
   
    $headers = @{
        "Accept" = "application/json";
        "Authorization" = "CWSAuth Bearer=$bearerToken";
        "Citrix-CustomerId" = $customerid;
        "Citrix-InstanceId" = $siteid;
    }
	
	$bSuccess = $true
	$StatusMessage = "Successfuly started the machine!"
	$response = ""
	try 
	{
		$headers = @{
			"Accept" = "application/json";
			"Authorization" = "CWSAuth Bearer=$bearerToken";
			"Citrix-CustomerId" = $customerid;
			"Citrix-InstanceId" = $siteid;
		}
		$requestUri = [string]::Format(($endPoint + "/cvad/manage/Machines/{0}/`$start"), $machineId)
		$response = Invoke-RestMethod -Uri $requestUri -Method POST -Headers $headers -ContentType "application/json" -UseBasicParsing
		
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Response=$response})
	return $ReturnObject
}

