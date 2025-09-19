# ===========================================================================
# MSAvDFunctions.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.2
#
# Microsoft AvD functions for Raptor Scripts
#
# History:
#   V1.0 - 03.09.2024 - M.Trojahn - Initial creation
#									add Get-EitAzBearerToken, Get-EitAzHostPoolsBySubscription, 
#									Get-EitAzSessionHostsByHostPool, Get-EitAzUserSessionsByHostPool, Send-EitAzUserMessage, 
#									Disconnect-EitAzUserSession, Remove-EitAzUserSession, Get-EitAzUserSession
#	V1.1 - 18.08.2025 - M.Trojahn - adding Force Parameter in Remove-EitAzUserSession
#	V1.2 - 16.09.2025 - M.Trojahn - add function Get-EitAzSessionHost & Set-EitAzSessionHostAllowNewSession
#
#
#
# ===========================================================================

function Get-EitAzBearerToken
{
    <#
		.SYNOPSIS
			Get an Azure Bearer token

		.DESCRIPTION
			Retrieves the Azure Bearer Token for an authentication session.

		.PARAMETER AppId
			The AppId of the Azure service principal

		.PARAMETER AppSecret
			The AppSecret of the Azure service principal	

		.PARAMETER TenantId
			The ID of the Azure tenant	

		.EXAMPLE
			Get-EitAzBearerToken -AppId MyAppID -AppSecret MyAppSecret -TenantId MyTenantId

		.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements

	#>
	
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $AppId,

        [Parameter(Mandatory = $true)]
        [string] $AppSecret,

        [Parameter(Mandatory = $true)]
        [string] $TenantId,

        [Parameter(Mandatory = $false)]
        [string] $BaseUrl = 'https://management.azure.com'
    )

    $success = $true
    $statusMessage = "Successfully retrieved bearer token."
    $bearerToken = $null

    try
    {
        # Ensure TLS 1.2 (older Windows defaults may lack it)
        try
        {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }
        catch
        {
            # ignore if not supported
        }

        $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $AppId
            client_secret = $AppSecret
            scope         = "$BaseUrl/.default"
        }

        Write-Verbose "Sending authentication request to $uri"

        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop

        if ($response -and $response.access_token)
        {
            $bearerToken = $response.access_token
        }
        else
        {
            throw "Authentication response did not contain a bearer token."
        }
    }
    catch
    {
        $success = $false
        $statusMessage = "Error retrieving token: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success     = $success
        Message     = $statusMessage
        BearerToken = $bearerToken
    }
}

function Get-EitAzHostPoolsBySubscription
{
    <#
		.SYNOPSIS
			Get Azure hostpools by azure subscription

		.DESCRIPTION
			Get Azure hostpools by azure subscription

		.PARAMETER BearerToken
			A valid Azure BearerToken created by Get-EitAzBearerToken

		.PARAMETER Subscription
			A valid Azure subscription ID

		.EXAMPLE
			Get-EitAzHostPoolsBySubscription -BearerToken MyBearerToken -Subscription MySubscription

		.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version : 1.1
			
			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements
	#>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [string]$Subscription,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess      = $true
    $StatusMessage = "Successfully retrieved hostpools."
    $HostPools     = $null

    try
    {
        $headers = @{
            Authorization = "Bearer $BearerToken"
            'Content-Type' = $ContentType
        }

        $uri = "$AzBaseURL/subscriptions/$Subscription/providers/$Provider/hostPools" + "?api-version=" + $APIVersion

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -ErrorAction Stop

        $HostPools = ($response.Content | ConvertFrom-Json).value
    }
    catch
    {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }

    return [pscustomobject]@{
        Success   = $bSuccess
        Message   = $StatusMessage
        HostPools = $HostPools
    }
}

function Get-EitAzSessionHostsByHostPool
{
    <#
        .SYNOPSIS
            Get Azure SessionHosts by HostPool
        
        .DESCRIPTION
            Get Azure SessionHosts by HostPool
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER Subscription
            A valid Azure subscription    
            
        .PARAMETER HostPoolId
            A valid Azure HostPoolId
            
        .EXAMPLE
            Get-EitAzSessionHostsByHostPool -BearerToken MyBearerToken -Subscription MySubscription -HostPoolId MyHostPoolId
            
        .NOTES  
            Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version     :   1.1
            
            History:
                V1.0 - 03.09.2024 - M.Trojahn - Initial creation
                V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements
    #>   
	
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [string]$Subscription,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolId,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $StatusMessage = "Successfully got SessionHosts!"
    $SessionHosts = @()

    try
    {
        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        if ($HostPoolId -notmatch "(?i)^/subscriptions/.+/resourceGroups/.+/providers/.+/hostPools/.+$")
        {
            throw "Invalid HostPoolId format: $HostPoolId"
        }

        $parts = $HostPoolId -split "/"
        $ResourceGroupName = $parts[4]
        $HostPoolName = $parts[8]

        $uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts?api-version=$APIVersion"

        # WebRequest + ConvertFrom-Json for PS 5.1
        $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -ErrorAction Stop
        $SessionHosts = ($response.Content | ConvertFrom-Json).value
    }
    catch
    {
        $bSuccess = $false
        $StatusMessage = "Error getting session hosts: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success      = $bSuccess
        Message      = $StatusMessage
        SessionHosts = $SessionHosts
    }
}

function Get-EitAzUserSessionsByHostPool
{
    <#
        .SYNOPSIS
            Get Azure User Sessions by HostPool
        
        .DESCRIPTION
            Retrieves all user sessions for a given HostPool in Azure Virtual Desktop.
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER Subscription
            A valid Azure subscription ID
            
        .PARAMETER HostPoolId
            A valid Azure HostPoolId
            
        .EXAMPLE
            Get-EitAzUserSessionsByHostPool -BearerToken MyToken -Subscription MySub -HostPoolId /subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.DesktopVirtualization/hostPools/zzz
            
        .NOTES  
            Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version     : 1.1
            
            History:
                V1.0 - 03.09.2024 - M.Trojahn - Initial creation
                V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [string]$Subscription,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolId,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $StatusMessage = "Successfully retrieved user sessions."
    $UserSessionsByHostPool = @()

    try
    {
        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        if ($HostPoolId -notmatch "^/subscriptions/.+/resourceGroups/.+/providers/.+/hostPools/.+$")
        {
            throw "Invalid HostPoolId format: $HostPoolId"
        }

        $parts = $HostPoolId -split "/"
        $ResourceGroupName = $parts[4]
        $HostPoolName = $parts[8]

        $uri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/userSessions" + "?api-version=" + $APIVersion

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -ErrorAction Stop
        $UserSessionsByHostPool = ($response.Content | ConvertFrom-Json).value
    }
    catch
    {
        $bSuccess = $false
        $StatusMessage = "Error retrieving user sessions: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success  = $bSuccess
        Message  = $StatusMessage
        Sessions = $UserSessionsByHostPool
    }
}

function Send-EitAzUserMessage
{
    <#
        .SYNOPSIS
            Send a message to an Azure User Session
        
        .DESCRIPTION
            Sends a custom message (title and body) to a specified Azure Virtual Desktop user session.
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER SessionId
            The full Azure resource ID of the user session
            
        .PARAMETER MessageTitle
            The title of the message to send
            
        .PARAMETER MessageBody
            The body content of the message
            
        .EXAMPLE
            Send-EitAzUserMessage -BearerToken $token -SessionId "/subscriptions/xxx/..." -MessageTitle "Warning" -MessageBody "Please save your work."
        
        .NOTES
            Copyright: (c)2025 by EducateIT GmbH
            Version     : 1.1

            History:
                V1.0 - 03.09.2024 - M.Trojahn - Initial creation
                V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [string]$SessionId,

        [Parameter(Mandatory = $true)]
        [string]$MessageTitle,

        [Parameter(Mandatory = $true)]
        [string]$MessageBody,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $StatusMessage = "Successfully sent message."
    $StatusCode = $null

    try
    {
        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        if ($SessionId -notmatch "(?i)^/subscriptions/.+/resourceGroups/.+/providers/.+/hostPools/.+/sessionHosts/.+/userSessions/.+$")
        {
            throw "Invalid SessionId format: $SessionId"
        }

        $parts = $SessionId -split "/"
        $subscriptionId   = $parts[2]
        $resourceGroup    = $parts[4]
        $hostPoolName     = $parts[8]
        $sessionHostName  = $parts[10]
        $userSessionId    = $parts[12]

        $uri = "$AzBaseURL/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/$Provider/hostPools/$hostPoolName/sessionHosts/$sessionHostName/userSessions/$userSessionId/sendMessage" + "?api-version=" + $APIVersion

        $body = @{
            messageTitle = $MessageTitle
            messageBody  = $MessageBody
        }

        $jsonBody = $body | ConvertTo-Json -Depth 5

        # Fix character encoding issues Azure doesn't like
        $jsonBody = $jsonBody `
            -replace '\\u003e', '>' `
            -replace '\\u003c', '<' `
            -replace '\\u0027', '''' `
            -replace '\\u0026', '&'

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -Body $jsonBody -UseBasicParsing -ErrorAction Stop
        $StatusCode = [int]$response.StatusCode
		        
        if ($StatusCode -eq 200)
        {
            $bSuccess = $true
        }
        else
        {
            throw "Unexpected status code: $StatusCode"
        }
		
		
    }
    catch
    {
        $bSuccess = $false
        try
        {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        catch
        {
            # ignore
        }
        $StatusMessage = "Failed to send message: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success     = $bSuccess
        Message     = $StatusMessage
        StatusCode  = $StatusCode
    }
}

function Disconnect-EitAzUserSession
{
    <#
        .SYNOPSIS
            Disconnect an Azure User Session
        
        .DESCRIPTION
            Disconnects a user session in Azure Virtual Desktop (AVD).
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER SessionId
            The full Azure resource ID of the user session to disconnect
            (/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DesktopVirtualization/hostPools/{hp}/sessionHosts/{sh}/userSessions/{id})
            
        .EXAMPLE
            Disconnect-EitAzUserSession -BearerToken $token -SessionId "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/hp/sessionHosts/sh.domain.tld/userSessions/1"
            
        .NOTES  
            Copyright: (c)2025 by EducateIT GmbH
            Version     : 1.1
            
            History:
                V1.0 - 03.09.2024 - M.Trojahn - Initial creation
                V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements
    #>       
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [string]$SessionId,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $StatusMessage = "Successfully disconnected session."
    $StatusCode = $null
    $OperationLocation = $null

    try
    {
        if ($SessionId -notmatch "(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/hostPools/[^/]+/sessionHosts/[^/]+/userSessions/[^/]+$")
        {
            throw "Invalid SessionId format: $SessionId"
        }

        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        $parts = $SessionId -split "/"
        $subscriptionId  = $parts[2]
        $resourceGroup   = $parts[4]
        $hostPoolName    = $parts[8]
        $sessionHostName = $parts[10]
        $userSessionId   = $parts[12]

        $uri = "$AzBaseURL/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/$Provider/hostPools/$hostPoolName/sessionHosts/$sessionHostName/userSessions/$userSessionId/disconnect" + "?api-version=" + $APIVersion

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -UseBasicParsing -ErrorAction Stop

        $StatusCode = [int]$response.StatusCode
        
        if ($StatusCode -eq 200)
        {
            $bSuccess = $true
        }
        else
        {
            throw "Unexpected status code: $StatusCode"
        }
    }
    catch
    {
        $bSuccess = $false
        try
        {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        catch
        {
            # ignore
        }
        $StatusMessage = "Failed to disconnect session: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success           = $bSuccess
        Message           = $StatusMessage
        StatusCode        = $StatusCode
        SessionId         = $SessionId
    }
}

function Remove-EitAzUserSession
{
    <#
		.SYNOPSIS
			Remove (log off) an Azure User Session

		.DESCRIPTION
			Remove (log off) an Azure User Session

		.PARAMETER BearerToken
			An Azure BearerToken created by Get-EitAzBearerToken

		.PARAMETER SessionId
			A valid Azure session ID

		.PARAMETER Force
			Use the force logoff option

		.EXAMPLE
			Remove-EitAzUserSession -BearerToken MyBearerToken -SessionId MySessionId

		.NOTES
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version     : 1.2

			History:
				V1.0 - 03.09.2024 - M.Trojahn - Initial creation
				V1.1 - 18.08.2025 - M.Trojahn - Added Force parameter
				V1.2 - 03.09.2025 - M.Trojahn - Optimized URI building and performance
	#>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [string]$SessionID,

        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [string]$AzBaseURL = 'https://management.azure.com',

        [Parameter(Mandatory = $false)]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $response = $null
    $StatusMessage = ""
	$StatusCode = $null

    try
    {
        if ($SessionID -notmatch "(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/hostPools/[^/]+/sessionHosts/[^/]+/userSessions/[^/]+$")
        {
            throw "Invalid SessionId format: $SessionID"
        }

        $header = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        $parts = $SessionID -Split "/"
        $Subscription       = $parts[2]
        $ResourceGroupName  = $parts[4]
        $HostPoolName       = $parts[8]
        $SessionHostName    = $parts[10]
        $SessionIdNumber    = $parts[12]

        $BaseUri = "$AzBaseURL/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/$Provider/hostPools/$HostPoolName/sessionHosts/$SessionHostName/userSessions/$SessionIdNumber"

        $forceValue = if ($Force.IsPresent) { "true" } else { "false" }
        $StatusMessage = if ($Force.IsPresent) { "The user was successfully forced to log out!" } else { "User successfully logged off!" }

        $Uri = $BaseUri + "?api-version=" + $APIVersion + "&force=$forceValue"

        $response = Invoke-WebRequest -Uri $Uri -Headers $header -Method Delete -UseBasicParsing -ErrorAction Stop
		$StatusCode = [int]$response.StatusCode
        
        if ($StatusCode -eq 200)
        {
            $bSuccess = $true
        }
        else
        {
            throw "Unexpected status code: $StatusCode"
        }
    }
    catch
    {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }

    $ReturnObject = [pscustomobject]@{
        Success    = $bSuccess
        Message    = $StatusMessage
        StatusCode = $StatusCode 
        SessionID  = $SessionID
        BaseUri    = $BaseUri
        URI        = $Uri
    }

    return $ReturnObject
}

function Get-EitAzUserSession
{
    <#
        .SYNOPSIS
            Get Azure User Session
        
        .DESCRIPTION
            Retrieves a single Azure Virtual Desktop (AVD) user session and returns its key properties, including session state.
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER SessionId
            The full Azure resource ID of the user session
            (/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DesktopVirtualization/hostPools/{hp}/sessionHosts/{sh}/userSessions/{id})
        
        .EXAMPLE
            Get-EitAzUserSession -BearerToken $token -SessionId "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/hp/sessionHosts/host.domain.tld/userSessions/1"
        
        .NOTES  
            Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version     : 1.1
            
            History:
                V1.0 - 02.09.2024 - M.Trojahn - Initial creation
                V1.1 - 03.09.2025 - M.Trojahn - Optimized version with improvements
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $StatusMessage = "Successfully retrieved user session."
    $StatusCode = $null
    $Session = $null
    $SessionState = $null

    try
    {
        # Validate resource ID before splitting
        if ($SessionId -notmatch "(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/hostPools/[^/]+/sessionHosts/[^/]+/userSessions/[^/]+$")
        {
            throw "Invalid SessionId format: $SessionId"
        }

        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        $parts = $SessionId -split "/"
        $subscriptionId  = $parts[2]
        $resourceGroup   = $parts[4]
        $hostPoolName    = $parts[8]
        $sessionHostName = $parts[10]
        $userSessionId   = $parts[12]

        $uri = "$AzBaseURL/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/$Provider/hostPools/$hostPoolName/sessionHosts/$sessionHostName/userSessions/$userSessionId" + "?api-version=" + $APIVersion

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop

        $StatusCode = [int]$response.StatusCode
		$StatusDescription = $response.StatusDescription
		
		if ($StatusCode -eq 200)
        {
            $bSuccess = $true
			
			if ($response.Content -ne $null)
			{
				$parsed = $response.Content | ConvertFrom-Json
				$Session = $parsed
				if ($parsed.properties)
				{
					$SessionState = $parsed.properties.sessionState
				}
			}
			else
			{
				throw "Dy not get any content!"
			}
        }
        else
        {
            throw "Unexpected status code: $StatusCode"
        }
		

       
    }
    catch
    {
        $bSuccess = $false
        try
        {
            # Try to extract HTTP status code if present
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        catch
        {
            # ignore if not an HTTP error
        }
        $StatusMessage = "Failed to retrieve user session: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success      = $bSuccess
        Message      = $StatusMessage
        StatusCode   = $StatusCode
		StatusDescription   = $StatusDescription
        SessionId    = $SessionId
        SessionState = $SessionState
        Session      = $Session
    }
}

function Get-EitAzSessionHost
{
    <#
        .SYNOPSIS
            Get Azure Session host
        
        .DESCRIPTION
            Retrieves a single Azure Virtual Desktop (AVD) session host and returns its key properties.
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER SessionHostId
            The full Azure resource ID of the session host
            (/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DesktopVirtualization/hostPools/{hp}/sessionHosts/{sh})
        
        .EXAMPLE
            Get-EitAzSessionHost -BearerToken $token -SessionHostId "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/hp/sessionHost"
        
        .NOTES  
            Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version     : 1.0
            
            History:
                V1.0 - 16.09.2025 - M.Trojahn - Initial creation
               
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionHostId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
    $StatusMessage = "Successfully retrieved sessionhost."
    $StatusCode = $null
    $SessionHost = $null
   

    try
    {
        # Validate resource ID before splitting
        if ($SessionHostId -notmatch "(?i)^/subscriptions/[0-9a-f-]+/resourcegroups/[a-z0-9_-]+/providers/Microsoft\.DesktopVirtualization/hostpools/[a-z0-9_-]+/sessionhosts/[a-z0-9.-]+$")
        {
            throw "Invalid SessionHostId format: $SessionHostId"
        } 

        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }

        $parts = $SessionHostId -split "/"
        $subscriptionId  = $parts[2]
        $resourceGroup   = $parts[4]
        $hostPoolName    = $parts[8]
        $sessionHostName = $parts[10]
       

        $uri = "$AzBaseURL/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/$Provider/hostPools/$hostPoolName/sessionHosts/$sessionHostName" + "?api-version=" + $APIVersion

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop

        $StatusCode = [int]$response.StatusCode
		$StatusDescription = $response.StatusDescription
		
		if ($StatusCode -eq 200)
        {
            $bSuccess = $true
			
			if ($response.Content -ne $null)
			{
				$parsed = $response.Content | ConvertFrom-Json
				$SessionHost = $parsed
			}
			else
			{
				throw "Did not get any content!"
			}
        }
        else
        {
            throw "Unexpected status code: $StatusCode"
        }
    }
    catch
    {
        $bSuccess = $false
        try
        {
            # Try to extract HTTP status code if present
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        catch
        {
            # ignore if not an HTTP error
        }
        $StatusMessage = "Failed to retrieve user session: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success      		= $bSuccess
        Message      		= $StatusMessage
        StatusCode   		= $StatusCode
		StatusDescription 	= $StatusDescription
        SessionHostId    	= $SessionHostId
        SessionHost      	= $SessionHost
    }
}

function Set-EitAzSessionHostAllowNewSession
{
    <#
        .SYNOPSIS
           Set the allowNewSession parameter on a SessionHost
        
        .DESCRIPTION
            Set the allowNewSession parameter on a SessionHost
        
        .PARAMETER BearerToken
            A valid Azure BearerToken created by Get-EitAzBearerToken
            
        .PARAMETER SessionHostId
            The full Azure resource ID of the session host
            (/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DesktopVirtualization/hostPools/{hp}/sessionHosts/{sh})
        
        .EXAMPLE
            Set-EitAzSessionHostAllowNewSession -BearerToken $myNearerToken -SessionId "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/hp/sessionHosts"
        
        .NOTES  
            Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version     : 1.0
            
            History:
                V1.0 - 16.09.2025 - M.Trojahn - Initial creation
                
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BearerToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionHostId,

		[Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
		[ValidateSet("Allow", "Disallow")]
        [string]$Mode="Allow",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$AzBaseURL = "https://management.azure.com",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Provider = 'Microsoft.DesktopVirtualization',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$APIVersion = '2024-04-03'
    )

    $bSuccess = $true
	$SessionHostProperties = $null
    $StatusMessage = "Successfully set allowNewSession parameter."
 
    try
    {
        if ($Mode -eq "Allow")  
		{
            $allowNewSession = $true
        }
		else
		{
            $allowNewSession = $false
        }
		
		# Validate resource ID before splitting
        if ($SessionHostId -notmatch "(?i)^/subscriptions/[0-9a-f-]+/resourcegroups/[a-z0-9_-]+/providers/Microsoft\.DesktopVirtualization/hostpools/[a-z0-9_-]+/sessionhosts/[a-z0-9.-]+$")
        {
            throw "Invalid SessionHostId format: $SessionHostId"
        } 

        $headers = @{
            'Authorization' = "Bearer $BearerToken"
            'Content-Type'  = $ContentType
        }
		$body = @{
			properties = @{
				allowNewSession = $allowNewSession
			}
		}
        $parts = $SessionHostId -split "/"
        $subscriptionId  = $parts[2]
        $resourceGroup   = $parts[4]
        $hostPoolName    = $parts[8]
        $sessionHostName = $parts[10]
       

        $uri = "$AzBaseURL/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/$Provider/hostPools/$hostPoolName/sessionHosts/$sessionHostName" + "?api-version=" + $APIVersion
     
        # $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
		$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Patch -Body ($body | ConvertTo-Json) -ContentType $ContentType -ErrorAction Stop
        if ($response -ne $null)
		{
			$bSuccess = $true
			$SessionHostProperties = $response.properties
		}
		else
		{
			throw "No response received."
		}
    }
    catch
    {
        $bSuccess = $false
        $StatusMessage = "Failed to set allowNewSession parameter: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Success      			= $bSuccess
        Message      			= $StatusMessage
        SessionHostId    		= $SessionHostId
		SessionHostProperties	= $SessionHostProperties
    }
}


