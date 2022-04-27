<#
       .SYNOPSIS
             function library for net send functions

       .DESCRIPTION
             This is a function library for net send functions

       .NOTES  
			Author		: EducateIT GmbH - info@educateit.ch 
			Version		: 1.2
			
			History		: 
                        V1.0	-	29.06.2015	-	created
                        V1.1    -   23.03.2020 	- 	M.Trojahn - Rename Send-NetMessage to Send-EitNetMessage
						V1.2 	- 	27.04.2022 	- 	M.Trojahn - Add debug log via EitFileLogger
						
#>



function Send-EitNetMessage
{
    <#  
        .SYNOPSIS  
            Sends a message to network computers
    
        .DESCRIPTION  
            Allows the administrator to send a message via a pop-up textbox to multiple computers
    
        .EXAMPLE  
            Send-EitNetMessage "This is a test of the emergency broadcast system.  This is only a test."
    
            Sends the message to all users on the local computer.
    
        .EXAMPLE  
            Send-EitNetMessage "Updates start in 15 minutes.  Please log off." -Computername testbox01 -Seconds 30 
    
            Sends a message to all users on Testbox01 asking them to log off.  
            The popup will appear for 30 seconds. 
        
        .EXAMPLE
            ".",$Env:Computername | Send-EitNetMessage "Fire in the hole!" 
            
            Pipes the computernames to Send-EitNetMessage and sends the message "Fire in the hole!" 
            
        .EXAMPLE
            Get-ADComputer -filter * | Send-EitNetMessage "Updates are being installed tonight. Please log off at EOD." -Seconds 60
            
            Queries Active Directory for all computers and then notifies all users on those computers of updates.  
            Notification stays for 60 seconds or until user clicks OK.


         .NOTES  
            Copyright	: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch 
            Version		: 1.2
            History:
                        V1.0 -            - M.Trojahn - Initial creation  
                        V1.1 - 23.03.2020 - M.Trojahn - Rename Send-NetMessage to Send-EitNetMessage
						V1.2 - 27.04.2022 - M.Trojahn - Add debug log via EitFileLogger
    #>

    Param(
        [Parameter(Mandatory=$True)]
        [String]$Message,
        
        [String]$SessionID="*",
        [Int]$Seconds="3600",
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias("Name")]
        [String[]]$Computername=$env:computername,
		[Object[]]$EitFileLogger=$null,
        [Switch]$VerboseMsg
    )
    
	$EnableDebug = $false
	if ($EitFileLogger -ne $null) 
	{
		$EnableDebug = $true
	}

	$MessageFile = [System.IO.Path]::GetTempFileName()
	
	# Convert the <NL> string into a real
	$message = $message.Replace("//","`r`n");
	
	# Save the message to a tmp file
	#$Message | Out-File $MessageFile -Encoding "ASCII"
	$Message | Out-File $MessageFile -Encoding "Default"
	
	foreach ($Computer in $ComputerName) 
	{
		Write-Host "Processing $Computer / $SessionID"
		
		$cmd = "/c msg.exe $SessionID /Time:$($Seconds)"
		if ($ComputerName){$cmd += " /SERVER:$($ComputerName)"}
		if ($VerboseMsg){$cmd += " /V"}
		$cmd += " <$($MessageFile)"
		
		if ($EnableDebug) {$EitFileLogger.Debug($cmd)}
		Start-Process "cmd.exe" -ArgumentList $cmd -Wait
	}
	Remove-Item $MessageFile
}


