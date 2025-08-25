#
# MSAvDFunctions.ps1
# ===========================================================================
# (c)2024 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Microsoft AvD functions for Raptor Scripts
#
# History:
#   V1.0 - 03.09.2024 - M.Trojahn - Initial creation
#									add Get-EitAzBearerToken, Get-EitAzHostPoolsBySubscription, 
#									Get-EitAzSessionHostsByHostPool, Get-EitAzUserSessionsByHostPool, Send-EitAzUserMessage, 
#									Disconnect-EitAzUserSession, Remove-EitAzUserSession, Get-EitAzUserSession
#
#
# ===========================================================================



function Get-EitAzBearerToken {
<#
		.SYNOPSIS
			Get a Azure Bearer token
		
		.DESCRIPTION
			Retrieve the Azure Bearer Token for an authentication session
		
		.PARAMETER AppId
			the AppId of the Azure service principal
			
		.PARAMETER AppSecret
			the AppSecret of the Azure service principal	
			
		.PARAMETER TenantId
			the id of the Azure tennant	
			
		.EXAMPLE
			Get-EitAzBearerToken -AppId MyAppID -AppSecret MyAppSecret -TenantId MyTenantId
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				
	#>
	param(
		[Parameter(Mandatory=$true)] 
		[string] $AppID,
		[Parameter(Mandatory=$true)]
		[string] $AppSecret,
		[Parameter(Mandatory=$true)]
		[string] $TenantID,
		[Parameter(Mandatory=$false)]
		[string] $baseURL = 'https://management.azure.com'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly got bearerToken!"
	$response = ""
	$bearerToken = ""
    try {
		## https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
		[string]$Uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

		[hashtable]$Body = @{
			grant_type    = 'client_credentials'
			client_Id     = $AppId
			client_Secret = $AppSecret
			scope         = "$baseURL/.default"
		}

		$response = Invoke-RestMethod -URI $Uri -Body $Body -Method 'POST' -ContentType 'application/x-www-form-urlencoded'  -UseBasicParsing -ErrorAction SilentlyContinue
		$bearerToken = $response | Select-Object -ExpandProperty access_token
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;bearerToken=$bearerToken})
	return $ReturnObject	
}

function Get-EitAzHostPoolsBySubscription {
<#
		.SYNOPSIS
			Get Azure hostpools by azure subscription
		
		.DESCRIPTION
			Get Azure hostpools by azure subscription
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER Subscription
			a valid Azure subscription	
			
		.EXAMPLE
			Get-EitAzHostPoolsBySubscription -BearerToken MyBearerToken -Subscription MySubscription
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				
	#>	
	param(
	[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$Subscription,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly got hostpools!"
	$result = ""
	try
	{
		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type',$contentType )
		$Uri = "$AzBaseURL/subscriptions/$Subscription/providers/$Provider/hostPools$APIVersion"; 

		$result = Invoke-WebRequest -Uri $Uri -Headers $header -UseBasicParsing
		$HostPools = $($result.content | ConvertFrom-Json).value
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;HostPools=$HostPools})
	return $ReturnObject
}

function Get-EitAzSessionHostsByHostPool {
	<#
		.SYNOPSIS
			Get Azure SessionHosts by HostPool
		
		.DESCRIPTION
			Get Azure SessionHosts by HostPool
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER Subscription
			a valid Azure subscription	
			
		.PARAMETER $HostPoolId
			a valid Azure HostPoolId
			
		.EXAMPLE
			Get-EitAzSessionHostsByHostPool -BearerToken MyBearerToken -Subscription MySubscription -HostPoolId MyHostPoolId
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				
	#>	
	param(
		[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$Subscription,
		[Parameter(Mandatory=$true)]
		[string]$HostPoolId,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly got SessionHosts!"
	$result = ""
	try
	{

		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type', $contentType )

		$ResourceGroupName = $($HostPoolId.Split("/")[4])
		$HostPoolName = $($HostPoolId.Split("/")[8])

		$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts$APIVersion"
		$result = Invoke-WebRequest -Uri $Uri -Headers $header -UseBasicParsing
		$SessionHosts = $($result.content | ConvertFrom-Json).value
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;SessionHosts=$SessionHosts})
	return $ReturnObject	
}

function Get-EitAzUserSessionsByHostPool {
	<#
		.SYNOPSIS
			Get Azure User Session by HostPool
		
		.DESCRIPTION
			Get Azure User Session by HostPool
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER Subscription
			a valid Azure subscription	
			
		.PARAMETER $HostPoolId
			a valid Azure HostPoolId
			
		.EXAMPLE
			Get-EitAzUserSessionsByHostPool -BearerToken MyBearerToken -Subscription MySubscription -HostPoolId MyHostPoolId
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				
	#>	
	param(
		[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$Subscription,
		[Parameter(Mandatory=$true)]
		[string]$HostPoolId,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly got user sessions!"
	$result = ""
	try
	{
		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type',$contentType )

		$ResourceGroupName = $($HostPoolId.Split("/")[4])
		$HostPoolName = $($HostPoolId.Split("/")[8])

		$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/userSessions$APIVersion"
		$result = Invoke-WebRequest -Uri $Uri -Headers $header -UseBasicParsing
		$UserSessionsByHostPool = $($result.content | ConvertFrom-Json).value
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;Sessions=$UserSessionsByHostPool})
	return $ReturnObject	
	
}

function Send-EitAzUserMessage {
	<#
		.SYNOPSIS
			Send a message to an Azure User Session
		
		.DESCRIPTION
			Send a message to an Azure User Session
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER SessionId
			a valid Azure session id	
			
		.PARAMETER MessageTitle
			the title of the message
			
		.PARAMETER MessageBody
			the body of the message	
			
		.EXAMPLE
			Send-EitAzUserMessage -BearerToken MyBearerToken -SessionId MySessionId -MessageTitle "A title example" -MessageBody "A example message"
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				
	#>	
	param(
		[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$SessionID,
		[Parameter(Mandatory = $true)]
		[string] $MessageTitle,
		[Parameter(Mandatory = $true)]
		[string] $MessageBody,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly send message!"
	$result = ""
	try
	{
		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type',$contentType )

		$Subscription = $($SessionID.Split("/")[2])
		$ResourceGroupName = $($SessionID.Split("/")[4])
		$HostPoolName = $($SessionID.Split("/")[8])
		$SessionHostName = $($SessionID.Split("/")[10])
		$SessionIdNumber = $($SessionID.Split("/")[12])

		$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber/sendMessage$APIVersion"
		$Body = @{'messageBody' = $MessageBody; 'messageTitle' = $MessageTitle }
		$JsonBody = $Body | ConvertTo-Json -Depth 20

		## convertto-json converts certain characters to codes so we convert back as Azure doesn't like them
		$JsonBody = $JsonBody  -replace '\\u003e' , '>' -replace '\\u003c' , '<' -replace '\\u0027' , '''' -replace '\\u0026' , '&'

		$Result = Invoke-WebRequest -Uri $Uri -Headers $header -Method 'POST' -Body $JsonBody -UseBasicParsing
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;StatusCode=$Result.StatusCode})
	return $ReturnObject	
}

function Disconnect-EitAzUserSession {
	<#
		.SYNOPSIS
			Disconnect a Azure User Session
		
		.DESCRIPTION
			Disconnect a Azure User Session
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER SessionId
			a valid Azure session id	
			
		.EXAMPLE
			Disconnect-EitAzUserSession -BearerToken MyBearerToken -SessionId MySessionId
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				
	#>	
	param(
		[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$SessionID,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly disconnected session!"
	$result = ""
	try
	{
		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type',$contentType )

		$Subscription = $($SessionID.Split("/")[2])
		$ResourceGroupName = $($SessionID.Split("/")[4])
		$HostPoolName = $($SessionID.Split("/")[8])
		$SessionHostName = $($SessionID.Split("/")[10])
		$SessionIdNumber = $($SessionID.Split("/")[12])

		$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber/disconnect$APIVersion"
		$Result = Invoke-WebRequest -Uri $Uri -Headers $header -Method 'POST' -UseBasicParsing
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;StatusCode=$Result.StatusCode})
	return $ReturnObject	
}

function Remove-EitAzUserSession {
	<#
		.SYNOPSIS
			Remove (logoff) a Azure User Session
		
		.DESCRIPTION
			Remove (logoff) a Azure User Session
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER SessionId
			a valid Azure session id	
			
		.PARAMETER SessionId
			use the force command	
			
		.EXAMPLE
			Remove-EitAzUserSession -BearerToken MyBearerToken -SessionId MySessionId
			
		.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				V1.1 - 18.08.2025 - M.Trojahn - adding Force Parameter
				
	#>	
	param(
		[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$SessionID,
		[switch]$Force,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	
	$response = ""
	try 
	{
		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type',$contentType )

		$Subscription = $($SessionID.Split("/")[2])
		$ResourceGroupName = $($SessionID.Split("/")[4])
		$HostPoolName = $($SessionID.Split("/")[8])
		$SessionHostName = $($SessionID.Split("/")[10])
		$SessionIdNumber = $($SessionID.Split("/")[12])
		
		if ($Force -eq $true) 
		{
			$StatusMessage = "The user was successfully forced to log out!"
			$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber$APIVersion&force={force}"
		}
		else
		{
			$StatusMessage = "User successfully logged off!"
			$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber$APIVersion"
		}
		
		$response = Invoke-WebRequest -Uri $Uri -Headers $header -Method 'DELETE' -UseBasicParsing
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;StatusCode=$response.StatusCode})
	return $ReturnObject	
}



function Get-EitAzUserSession {
	<#
		.SYNOPSIS
			Get Azure User Session 
		
		.DESCRIPTION
			Get Azure User Session 
		
		.PARAMETER BearerToken
			a Azure BearerToken created by Get-EitAzBearerToken
			
		.PARAMETER SessionId
			a valid Azure session Id
			
		.
			
		.EXAMPLE
			Get-EitAzUserSessionsByHostPool -BearerToken MyBearerToken -SessionId /my/session/id
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 02.09.2024 - M.Trojahn - Initial creation
				
	#>	
	param(
		[Parameter(Mandatory=$true)]
		[string]$BearerToken,
		[Parameter(Mandatory=$true)]
		[string]$SessionId,
		[Parameter(Mandatory = $false)]
		[string]$contentType = 'application/json',
		[Parameter(Mandatory = $false)]
		[string][string]$AzBaseURL = "https://management.azure.com",
		[Parameter(Mandatory = $false)]
		[string]$Provider = 'Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2024-04-03'
	)
	$bSuccess = $true
	$StatusMessage = "Successfuly got user session!"
	$result = ""
	$SessionState = $null
	try
	{
		[hashtable]$header = @{
			'Authorization' = "Bearer $BearerToken"
		}
		$header.Add('Content-Type',$contentType )

		
		
		$Subscription = $($SessionId.Split("/")[2])
		$ResourceGroupName = $($SessionId.Split("/")[4])
		$HostPoolName = $($SessionId.Split("/")[8])
		$SessionHostName = $($SessionId.Split("/")[10])
		$SessionIdNumber = $($SessionId.Split("/")[12])

		$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIdNumber$APIVersion"
		$result = Invoke-WebRequest -Uri $Uri -Headers $header -UseBasicParsing
		$SessionState = $($result.content | ConvertFrom-Json).properties.sessionState
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;SessionId=$SessionId;SessionState=$SessionState})
	return $ReturnObject	
}

