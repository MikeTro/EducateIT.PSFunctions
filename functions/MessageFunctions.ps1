<#
       .SYNOPSIS
             function library for net send functions

       .DESCRIPTION
             This is a function library for net send functions

       .NOTES  
			Author		: EducateIT GmbH - info@educateit.ch 
			Version		: 1.1
			
			History		: 
                        V1.0	-	29.06.2015	-	created
                        V1.1    -   23.03.2020 - M.Trojahn - Rename Send-NetMessage to Send-EitNetMessage
						
#>



function Send-EitNetMessage{
    <#  
        .SYNOPSIS  
            Sends a message to network computers
    
        .DESCRIPTION  
            Allows the administrator to send a message via a pop-up textbox to multiple computers
    
        .EXAMPLE  
            Send-NetMessage "This is a test of the emergency broadcast system.  This is only a test."
    
            Sends the message to all users on the local computer.
    
        .EXAMPLE  
            Send-NetMessage "Updates start in 15 minutes.  Please log off." -Computername testbox01 -Seconds 30 -VerboseMsg -Wait
    
            Sends a message to all users on Testbox01 asking them to log off.  
            The popup will appear for 30 seconds and will write verbose messages to the console. 
        
        .EXAMPLE
            ".",$Env:Computername | Send-NetMessage "Fire in the hole!" -Verbose
            
            Pipes the computernames to Send-NetMessage and sends the message "Fire in the hole!" with verbose output
            
            VERBOSE: Sending the following message to computers with a 5 delay: Fire in the hole!
            VERBOSE: Processing .
            VERBOSE: Processing MyPC01
            VERBOSE: Message sent.
            
        .EXAMPLE
            Get-ADComputer -filter * | Send-NetMessage "Updates are being installed tonight. Please log off at EOD." -Seconds 60
            
            Queries Active Directory for all computers and then notifies all users on those computers of updates.  
            Notification stays for 60 seconds or until user clicks OK.


         .NOTES  
            Copyright	: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch 
            File Name 	: Create-RaptorReport.ps1
            Version		: 1.1
            History:
                        V1.0 -            - M.Trojahn - Initial creation  
                        V1.1 - 23.03.2020 - M.Trojahn - Rename Send-NetMessage to Send-EitNetMessage
	
            
    #>

    Param(
        [Parameter(Mandatory=$True)]
        [String]$Message,
        
        [String]$SessionID="*",
        [Int]$Seconds="3600",
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias("Name")]
        [String[]]$Computername=$env:computername,
        [Switch]$VerboseMsg
    )
    
	Begin {
    	Write-Verbose "Sending the following message to computers: $Message"
    }
    
	Process {
		
		$MessageFile = [System.IO.Path]::GetTempFileName()
		
		# Convert the <NL> string into a real
		$message = $message.Replace("//","`r`n");
		
		# Save the message to a tmp file
		#$Message | Out-File $MessageFile -Encoding "ASCII"
		
		$Message | Out-File $MessageFile -Encoding "Default"
		
		
    	ForEach ($Computer in $ComputerName) {
	        #Write-Verbose "Processing $Computer / $SessionID"
			
			Write-Host "Processing $Computer / $SessionID"
			
	        $cmd = "/c msg.exe $SessionID /Time:$($Seconds)"
	        if ($ComputerName){$cmd += " /SERVER:$($ComputerName)"}
	        if ($VerboseMsg){$cmd += " /V"}
	        #$cmd += " $($Message)"
			$cmd += " <$($MessageFile)"
			#Invoke-Expression $cmd
			
			$cmd | Out-File "C:\RaptorLog\Send-NetMessage.log" -Append
			
			Start-Process "cmd.exe" -ArgumentList $cmd
	

			
			
			
        }
		#Remove-Item $MessageFile
    }
	End {
    	Write-Verbose "Message sent."
    }
}


