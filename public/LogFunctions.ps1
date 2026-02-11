<#
       .SYNOPSIS
             function library for log functions

       .DESCRIPTION
             This is a function library for log functions

       .NOTES  
			Author		: EducateIT GmbH - info@educateit.ch 
			Version		: 1.4
			
			History		: 
							V1.0	-	14.12.2020	-	created from ScriptFunctions.ps1
							V1.1	-	13.04.2023	-	add New-EitLogger
							V1.2	-	17.10.2025	-	remove function New-FileEitLogger
														add alias New-FileEitLogger to New-EitLogger to ensure backwards compatibility
							V1.3	-	19.01.2026	-	Remove log4net.dll and use our own logging function.
							V1.4	-	11.02.2026	-	Create the log path if it does not exist in function New-EitLogger.					
#>

class EitLogger
{
    [bool]$LogToFile
    [string]$LogFilePath
    [int]$MaxFileSizeKB
    [int]$MaxArchiveFiles
    [System.Collections.Generic.List[string]]$MemoryLog

    <#
    .SYNOPSIS
        Initializes a new Logger instance.

    .DESCRIPTION
        Creates a new logger that writes log entries to memory and optionally to a file.
        Supports log level filtering, colorized console output, and rolling log files.

    .PARAMETER ToFile
        Enables writing log entries to a file.

    .PARAMETER LogFilePath
        The full path to the log file.

    .PARAMETER MaxFileSizeKB
        The maximum file size in kilobytes before a rolling log is triggered.

    .PARAMETER MaxArchiveFiles
        Number of archived log files to keep (e.g., .log.1, .log.2, etc.).
		
		
	.NOTES  
				Copyright: (c)2026 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
				Version		:	1.0
				
				History:
					V1.0 - 19.01.2026 - M.Trojahn - Initial creation			
		
    #>
    EitLogger([bool]$ToFile, [string]$LogFilePath, [int]$MaxFileSizeKB, [int]$MaxArchiveFiles)
    {
        $this.LogToFile = $ToFile
        $this.LogFilePath = $LogFilePath
        $this.MaxFileSizeKB = $MaxFileSizeKB
        $this.MaxArchiveFiles = $MaxArchiveFiles
        $this.MemoryLog = [System.Collections.Generic.List[string]]::new()
    }

    <#
    .SYNOPSIS
        Writes an informational log entry.

    .DESCRIPTION
        Logs a message with the INFO level. Also prints the message in white to the console.

    .PARAMETER Message
        The log message.
    #>
    [void] Info([string]$Message)  { $this.Write($Message, "INFO") }

    <#
    .SYNOPSIS
        Writes a warning log entry.

    .DESCRIPTION
        Logs a message with the WARN level. Also prints the message in yellow to the console.

    .PARAMETER Message
        The log message.
    #>
    [void] Warn([string]$Message)  { $this.Write($Message, "WARN") }

    <#
    .SYNOPSIS
        Writes an error log entry.

    .DESCRIPTION
        Logs a message with the ERROR level. Also prints the message in red to the console.

    .PARAMETER Message
        The log message.
    #>
    [void] Error([string]$Message) { $this.Write($Message, "ERROR") }

    <#
    .SYNOPSIS
        Writes a debug log entry.

    .DESCRIPTION
        Logs a message with the DEBUG level. This is not printed to the console.

    .PARAMETER Message
        The log message.
    #>
    [void] Debug([string]$Message) { $this.Write($Message, "DEBUG") }

    <#
    .SYNOPSIS
        Writes a log entry with the specified log level.

    .DESCRIPTION
        Core logging method. Writes the message to memory, optionally to a file,
        and to the console based on the level. Automatically handles rolling log files.

    .PARAMETER Message
        The log message.

    .PARAMETER Level
        The log level: INFO, DEBUG, ERROR, or WARN.
    #>
    [void] Write([string]$Message, [string]$Level = "INFO")
    {
        if ([string]::IsNullOrWhiteSpace($Message)) { return }

        $allowedLevels = @("INFO", "DEBUG", "ERROR", "WARN")
        if ($allowedLevels -notcontains $Level) { $Level = "INFO" }

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $logLine = "$timestamp [$Level] $Message"

        $this.MemoryLog.Add($logLine)

        switch ($Level)
        {
            "INFO"  { Write-Host $logLine -ForegroundColor White }
            "WARN"  { Write-Host $logLine -ForegroundColor Yellow }
            "ERROR" { Write-Host $logLine -ForegroundColor Red }
            default { } # DEBUG = no output
        }

        if ($this.LogToFile)
        {
            if (Test-Path $this.LogFilePath)
            {
                $sizeKB = (Get-Item $this.LogFilePath).Length / 1KB
                if ($sizeKB -ge $this.MaxFileSizeKB)
                {
                    for ($i = $this.MaxArchiveFiles - 1; $i -ge 1; $i--)
                    {
                        $old = "$($this.LogFilePath).$i"
                        $new = "$($this.LogFilePath)." + ($i + 1)
                        if (Test-Path $old)
                        {
                            Rename-Item -Path $old -NewName $new -Force
                        }
                    }
                    Rename-Item -Path $this.LogFilePath -NewName "$($this.LogFilePath).1" -Force
                }
            }
            Add-Content -Path $this.LogFilePath -Value $logLine
        }
    }

    <#
    .SYNOPSIS
        Returns all log entries stored in memory.

    .OUTPUTS
        string[] – An array of log messages.
    #>
    [string[]] Get()
    {
        return $this.MemoryLog.ToArray()
    }

    <#
    .SYNOPSIS
        Clears the in-memory log buffer.
    #>
    [void] Clear()
    {
        $this.MemoryLog.Clear()
    }
}


function New-EitLogger {
	<#
		.SYNOPSIS
			Creates and returns a new Logger object.

		.DESCRIPTION
			Initializes a new Logger instance for in-memory and optional file-based logging.
			Useful for logging in scripts and modules with support for log levels and rolling files.

		.PARAMETER ToMem
			If set, log only to memory

		.PARAMETER LogFilePath
			The full path to the log file.

		.PARAMETER MaxFileSizeKB
			Maximum size (in KB) of the log file before rolling over.

		.PARAMETER MaxArchiveFiles
			Maximum number of archived log files to retain.

		.EXAMPLE
			$logger = New-EitLogger -ToFile -LogFilePath "C:\Logs\mylog.txt"
			$logger.Write("Application started", "INFO")
			
		.NOTES  
			Copyright: (c)2026 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 19.01.2026 - M.Trojahn - Initial creation	
				V1.1 - 11.02.2026 - M.Trojahn - Create the log path if it does not exist.	
			
	#>

    [CmdletBinding()]
	[Alias("New-EitFileLogger")]
    param
    (
        [switch]$ToMem,

        [string]$LogFilePath = "$PSScriptRoot\logfile.log",

        [int]$MaxFileSizeKB = 10000,

        [int]$MaxArchiveFiles = 10
    )
	
	if (!(Test-Path $LogFilePath -PathType Leaf)) 
	{
		New-Item $LogFilePath -Force 
	}

    if ($ToMem.IsPresent)
    {
		 return [EitLogger]::new($false,$null,$null,$null)
	}
	else 
	{	
        # Add _yyyy-MM-dd to the log file name
        $dateStamp = (Get-Date).ToString("yyyy-MM-dd")

        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($LogFilePath)
        $extension = [System.IO.Path]::GetExtension($LogFilePath)
        $directory = [System.IO.Path]::GetDirectoryName($LogFilePath)

        if (-not $extension) { $extension = ".log" }

        $datedName = "${baseName}_$dateStamp$extension"

        $LogFilePath = Join-Path -Path $directory -ChildPath $datedName
    }

    return [EitLogger]::new($true, $LogFilePath, $MaxFileSizeKB, $MaxArchiveFiles)
}





Export-ModuleMember -Alias New-EitFileLogger -function New-EitLogger
