#
# CitrixDaaSFunctions.ps1
# ===========================================================================
# (c)2022 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Citrix Daas (Citrix Cloud) functions for Raptor Scripts
#
# History:
#   V1.0 - 27.10.2022 - M.Trojahn - Initial creation
#									add Get-EitCitrixDaaSMe, Get-EitCitrixDaaSSessionsInSite, Get-EitCitrixDaaSSession, 
#										Stop-EitCitrixDaaSSession, Get-EitCitrixDaaSMachinesInSite, Get-EitCitrixDaaSbearerToken
#										Get-EitCitrixDaaSMachine, Restart-EitCitrixDaaSMachine, Stop-EitCitrixDaaSMachine, Start-EitCitrixDaaSMachine
#
#
#
# ===========================================================================

function Get-EitCitrixDaaSMe {
	<#
		.Synopsis
			get information about the logged on citrix DaaS user
		.Description
			get information about the logged on citrix DaaS user
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
			
		.Parameter endPoint
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
		.Synopsis
			List sessions in Citrix DaaS site
		.Description
			List sessions in Citrix DaaS site
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
		
		.Parameter siteId
			the siteId			
			
		.Parameter endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSSessionsInSite -customerId MycustomerId -bearerToken MybearerToken -siteId MySiteID
			List all sessions in site MySite 


			
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
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"	
    )
    $requestUri = $endPoint + "/cvad/manage/Sessions"
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
		.Synopsis
			gets a Citrix DaaS Session object 
		.Description
			get a Citrix DaaS Session object 
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
		
		.Parameter siteId
			the siteId				
			
		.Parameter sessionId
			the sessionId		
			
		.Parameter endPoint
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
		.Synopsis
			logoffs a session
		.Description
			Use this function to logoff a Citrix DaaS session
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
			
		.Parameter siteId
			the siteId			
			
		.Parameter sessionId
			the sessionId		
			
		.Parameter endPoint
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
		.Synopsis
			List machines in Citrix DaaS site
		.Description
			List machines in Citrix DaaS site
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
		
		.Parameter siteId
			the siteId			
			
		.Parameter endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSMachinesInSite -customerId MycustomerId -bearerToken MybearerToken -siteId MySiteID
			List all machines in site MySite 


			
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
		[Parameter(Mandatory=$false)]
		[string] $endPoint="https://api-us.cloud.com"	
    )
    $requestUri = $endPoint + "/cvad/manage/Machines"
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
		.Synopsis
			get a citrix DaaS api bearerToken
		.Description
			get a citrix DaaS api bearerToken
		
		.Parameter clientId
			the client id	
			
		.Parameter clientSecret
			the client secret		
			
		.Parameter endPoint
			the endPoint, aka https://api-us.cloud.com
			
		.EXAMPLE
			Get-EitCitrixDaaSbearerToken -clientId MyClientID -clientSecret MyClientSecret
			
		.NOTES  
			Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.10.2022 - M.Trojahn - Initial creation
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
			client_id = $client_id
			client_secret = $client_secret
		}
		
		# Obtain bearer token from authorization server
		$response = Invoke-WebRequest $tokenUrl -Method POST -Body $Body
		
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
		.Synopsis
			gets a Citrix DaaS machine object 
		.Description
			get a Citrix DaaS machine object 
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
		
		.Parameter siteId
			the siteId				
			
		.Parameter machineId
			the sessionId		
			
		.Parameter endPoint
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
		.Synopsis
			Restart a Citrix DaaS machine
		.Description
			Use this function to restart a Citrix DaaS machine
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
			
		.Parameter siteId
			the siteId			
			
		.Parameter machineId
			the machineId		
			
		.Parameter endPoint
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
		.Synopsis
			Stop a Citrix DaaS machine
		.Description
			Use this function to shutdwon a Citrix DaaS machine
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
			
		.Parameter siteId
			the siteId			
			
		.Parameter machineId
			the machineId		
			
		.Parameter endPoint
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
		.Synopsis
			Start a Citrix DaaS machine
		.Description
			Use this function to start a Citrix DaaS machine
		
		.Parameter bearerToken
			the bearerToken
			
		.Parameter customerId
			the customerId	
			
		.Parameter siteId
			the siteId			
			
		.Parameter machineId
			the machineId		
			
		.Parameter endPoint
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

