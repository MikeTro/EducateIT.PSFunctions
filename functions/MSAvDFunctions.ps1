#
# MSAvDFunctions.ps1
# ===========================================================================
# (c)2024 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Microsoft AvD functions for Raptor Scripts
#
# History:
#   V1.0 - 26.07.2024 - M.Trojahn - Initial creation
#									add Get-EitAzBearerToken, Get-EitAzHostPoolsBySubscription, 
#									Get-EitAzSessionHostsByHostPool, Get-EitAzUserSessionsByHostPool, Send-EitAzUserMessage, 
#									Disconnect-EitAzUserSession, Remove-EitAzUserSession
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
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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

    
	## https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
	[string]$Uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

	[hashtable]$Body = @{
		grant_type    = 'client_credentials'
		client_Id     = $AppId
		client_Secret = $AppSecret
		scope         = "$baseURL/.default"
	}


	Invoke-RestMethod -URI $Uri -Body $Body -Method 'POST' -ContentType 'application/x-www-form-urlencoded' | Select-Object -ExpandProperty access_token -ErrorAction SilentlyContinue
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
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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
		[string]$Provider = 'providers/Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2022-02-10-preview'
	)

	[hashtable]$header = @{
		'Authorization' = "Bearer $BearerToken"
	}
	$header.Add('Content-Type',$contentType )
	$Uri = "$AzBaseURL/subscriptions/$Subscription/$Provider/hostPools$APIVersion"; 

	$result = Invoke-WebRequest -Uri $Uri -Headers $header
	$HostPools = $($result.content | ConvertFrom-Json).value
	return $HostPools
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
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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
		[string]$Provider = 'providers/Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2022-02-10-preview'
	)

	[hashtable]$header = @{
		'Authorization' = "Bearer $BearerToken"
	}
	$header.Add('Content-Type', $contentType )

	$ResourceGroupName = $($HostPoolId.Split("/")[4])
	$HostPoolName = $($HostPoolId.Split("/")[8])

	$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/$Provider/hostPools/$HostPoolName/sessionHosts$APIVersion"
	$result = Invoke-WebRequest -Uri $Uri -Headers $header
	$SessionHosts = $($result.content | ConvertFrom-Json).value
	return $SessionHosts
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
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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
		[string]$Provider = 'providers/Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2022-02-10-preview'
	)

	[hashtable]$header = @{
		'Authorization' = "Bearer $BearerToken"
	}
	$header.Add('Content-Type',$contentType )

	$ResourceGroupName = $($HostPoolId.Split("/")[4])
	$HostPoolName = $($HostPoolId.Split("/")[8])

	$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/$Provider/hostPools/$HostPoolName/userSessions$APIVersion"
	$result = Invoke-WebRequest -Uri $Uri -Headers $header
	$UserSessionsByHostPool = $($result.content | ConvertFrom-Json).value
	return $UserSessionsByHostPool
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
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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
		[string]$Provider = 'providers/Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2022-02-10-preview'
	)

	[hashtable]$header = @{
		'Authorization' = "Bearer $BearerToken"
	}
	$header.Add('Content-Type',$contentType )

	$Subscription = $($SessionID.Split("/")[2])
	$ResourceGroupName = $($SessionID.Split("/")[4])
	$HostPoolName = $($SessionID.Split("/")[8])
	$SessionHostName = $($SessionID.Split("/")[10])
	$SessionIdNumber = $($SessionID.Split("/")[12])

	$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber/sendMessage$APIVersion"
	$Body = @{'messageBody' = $MessageBody; 'messageTitle' = $MessageTitle }
	$JsonBody = $Body | ConvertTo-Json -Depth 20

	## convertto-json converts certain characters to codes so we convert back as Azure doesn't like them
	$JsonBody = $JsonBody  -replace '\\u003e' , '>' -replace '\\u003c' , '<' -replace '\\u0027' , '''' -replace '\\u0026' , '&'

	$Result = Invoke-WebRequest -Uri $Uri -Headers $header -Method 'POST' -Body $JsonBody
	return $Result.StatusCode
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
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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
		[string]$Provider = 'providers/Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2022-02-10-preview'
	)

	[hashtable]$header = @{
		'Authorization' = "Bearer $BearerToken"
	}
	$header.Add('Content-Type',$contentType )

	$Subscription = $($SessionID.Split("/")[2])
	$ResourceGroupName = $($SessionID.Split("/")[4])
	$HostPoolName = $($SessionID.Split("/")[8])
	$SessionHostName = $($SessionID.Split("/")[10])
	$SessionIdNumber = $($SessionID.Split("/")[12])

	$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber/disconnect$APIVersion"
	
	$Result = Invoke-WebRequest -Uri $Uri -Headers $header -Method 'POST' 
	return $Result.StatusCode
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
			
		.EXAMPLE
			Remove-EitAzUserSession -BearerToken MyBearerToken -SessionId MySessionId
			
		.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 26.07.2024 - M.Trojahn - Initial creation
				
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
		[string]$Provider = 'providers/Microsoft.DesktopVirtualization',
		[Parameter(Mandatory = $false)]
		[string]$APIVersion = '?api-version=2022-02-10-preview'
	)

	[hashtable]$header = @{
		'Authorization' = "Bearer $BearerToken"
	}
	$header.Add('Content-Type',$contentType )

	$Subscription = $($SessionID.Split("/")[2])
	$ResourceGroupName = $($SessionID.Split("/")[4])
	$HostPoolName = $($SessionID.Split("/")[8])
	$SessionHostName = $($SessionID.Split("/")[10])
	$SessionIdNumber = $($SessionID.Split("/")[12])

	$Uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIDNumber$APIVersion"
	$Result = Invoke-WebRequest -Uri $Uri -Headers $header -Method 'DELETE' 
	return $Result.StatusCode
}

