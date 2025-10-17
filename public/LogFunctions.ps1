<#
       .SYNOPSIS
             function library for log functions

       .DESCRIPTION
             This is a function library for log functions

       .NOTES  
			Author		: EducateIT GmbH - info@educateit.ch 
			Version		: 1.2
			
			History		: 
							V1.0	-	14.12.2020	-	created from ScriptFunctions.ps1
							V1.1	-	13.04.2023	-	add New-EitLogger
							V1.2	-	17.10.2025	-	remove function New-FileEitLogger
														add alias New-FileEitLogger to New-EitLogger to ensure backwards compatibility
#>

function New-EitLogger {
	<#
	.Synopsis
		Create a new logger
	.Description
		Create a new log4Net logger

	.Parameter LogFilePath
		path to logfile
		if omitted only a console logger will be created
	
	.Parameter log4netPath
		Path to the log4Net DLL, default $PSScriptRoot
		
	.Parameter logUTC
		Log also the UTC TimeStamp
		
	.Parameter enableRolling	
		enable rolling file logs
	
	.Parameter maxSize
		max size of file
		
	.EXAMPLE
		$MyLogger = New-EitLogger -LogFilePath MyLogFilePath 
		Create a file logger
		
	.EXAMPLE
		$MyLogger = New-EitLogger 
		Create a console logger	
		
	.EXAMPLE
		$MyLogger = New-EitLogger -LogFilePath MyLogFilePath -enableRolling $false
		Create a non rolling file logger
		
		
	.NOTES  
		Copyright	: 	(c) 2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.1
		
		History		:
						V1.0 - 13.04.2023 - M.Trojahn - Initial creation
						V1.1 - 17.10.2025 - M.Trojahn - add alias New-FileEitLogger to New-EitLogger to ensure backwards compatibility
			
	#>	
	[Alias("New-EitFileLogger")]
	Param ( 
        [Parameter(Mandatory=$false)] [string] $logFilePath,
		[Parameter(Mandatory=$false)] [string] $log4netPath = $PSScriptRoot + "\log4net.dll",
		[Parameter(Mandatory=$false)] [boolean] $logUTC = $false,
		[Parameter(Mandatory=$false)] [boolean] $enableRolling = $true,
		[Parameter(Mandatory=$false)] [string] $maxSize = "10MB"
    ) 
	
	[void][Reflection.Assembly]::LoadFile($log4netPath);
	[log4net.LogManager]::ResetConfiguration();
	
	if ($logUTC) 
	{
		$MyLayout = New-Object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff} (%utcdate{yyyy-MM-dd HH:mm:ss.fff})] [%level] [%message]%n')
	}	
	else 
	{
		$MyLayout = New-Object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff}] [%level] [%message]%n')
	}	

	if ($LogFilePath.length -ne 0) 
	{
		if ($enableRolling) 
		{
			$RollingFileAppender = New-Object log4net.Appender.RollingFileAppender
			$RollingFileAppender.Layout = $MyLayout
			$RollingFileAppender.file = $LogFilePath
			$RollingFileAppender.AppendToFile = $true
			$RollingFileAppender.Name = "filelog"
			$RollingFileAppender.StaticLogFileName = $false
			$RollingFileAppender.PreserveLogFileNameExtension = $true
			$RollingFileAppender.LockingModel = New-Object log4net.Appender.FileAppender+MinimalLock
			$RollingFileAppender.MaximumFileSize = $maxSize
			$RollingFileAppender.DatePattern = "_yyyy-MM-dd"
			$RollingFileAppender.RollingStyle = "Date"
			$RollingFileAppender.RollingStyle = "Size"
			$RollingFileAppender.RollingStyle = "Composite"
			$RollingFileAppender.MaxSizeRollBackups = "100"
			$RollingFileAppender.Threshold = [log4net.Core.Level]::All
			$RollingFileAppender.ActivateOptions()
			[log4net.Config.BasicConfigurator]::Configure($RollingFileAppender)
		}
		else 
		{
			$FileAppender = New-Object log4net.Appender.FileAppender
			$FileAppender.Layout = $MyLayout
			$FileAppender.Threshold = [log4net.Core.Level]::All
			$FileAppender.file = $LogFilePath
			$FileAppender.AppendToFile = $true
			$FileAppender.Name = "filelog"
			$FileAppender.LockingModel = New-Object log4net.Appender.FileAppender+MinimalLock
			$FileAppender.ActivateOptions()
			[log4net.Config.BasicConfigurator]::Configure($FileAppender)
		}
	}
	
	$ColorConsoleAppender = New-Object log4net.Appender.ColoredConsoleAppender
	$MyColorConsoleLayout = New-Object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff}] %message%n')
	$ColorConsoleAppender.Layout = $MyColorConsoleLayout
	
	# debug
	$ColorConsoleAppenderDebugCollorScheme 	= New-Object log4net.Appender.ColoredConsoleAppender+LevelColors
	$ColorConsoleAppenderDebugCollorScheme.Level = [log4net.Core.Level]::Debug
	$ColorConsoleAppenderDebugCollorScheme.ForeColor = [log4net.Appender.ColoredConsoleAppender+Colors]::Green
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderDebugCollorScheme)
	
	# info
	$ColorConsoleAppenderInfoCollorScheme = New-Object log4net.Appender.ColoredConsoleAppender+LevelColors
	$ColorConsoleAppenderInfoCollorScheme.level	= [log4net.Core.Level]::Info
	$ColorConsoleAppenderInfoCollorScheme.ForeColor = [log4net.Appender.ColoredConsoleAppender+Colors]::White
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderInfoCollorScheme)
	
	# warn
	$ColorConsoleAppenderWarnCollorScheme = New-Object log4net.Appender.ColoredConsoleAppender+LevelColors
	$ColorConsoleAppenderWarnCollorScheme.level		= [log4net.Core.Level]::Warn
	$ColorConsoleAppenderWarnCollorScheme.ForeColor	= ([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::Yellow)
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderWarnCollorScheme)
		
	# error
	$ColorConsoleAppenderErrorCollorScheme 	= New-Object log4net.Appender.ColoredConsoleAppender+LevelColors
	$ColorConsoleAppenderErrorCollorScheme.level		= [log4net.Core.Level]::Error
	$ColorConsoleAppenderErrorCollorScheme.ForeColor	= [log4net.Appender.ColoredConsoleAppender+Colors]::Red
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderErrorCollorScheme)
		
	# fatal
	$ColorConsoleAppenderFatalCollorScheme 	= New-Object log4net.Appender.ColoredConsoleAppender+LevelColors
	$ColorConsoleAppenderFatalCollorScheme.level		= [log4net.Core.Level]::Fatal
	$ColorConsoleAppenderFatalCollorScheme.ForeColor	= ([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::Red)
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderFatalCollorScheme)
	
	$ColorConsoleAppender.ActivateOptions()
	#Colored console appender initialization - > do not show Debug messages to the console (Threshold)
	$ColorConsoleAppender.Threshold = [log4net.Core.Level]::Info
	[log4net.Config.BasicConfigurator]::Configure($ColorConsoleAppender)

	$EitLogger = [log4net.LogManager]::GetLogger("root")
	return $EitLogger 
}

Export-ModuleMember -Alias New-EitFileLogger -Function New-EitLogger
