<#
       .SYNOPSIS
             function library for log functions

       .DESCRIPTION
             This is a function library for log functions

       .NOTES  
			Author		: EducateIT GmbH - info@educateit.ch 
			Version		: 1.1
			
			History		: 
							V1.0	-	14.12.2020	-	created from ScriptFunctions.ps1
							V1.1	-	13.04.2023	-	add New-EitLogger
						
#>

function New-EitFileLogger {
	<#
	.Synopsis
		Create a new rolling file logger
	.Description
		Create a new log4Net RollingFileAppender logger

	.Parameter LogFilePath
		path to logfile
		
	.Parameter log4netPath
		Path to the log4Net DLL, Default $Env:EducateITScripts
		
	.Parameter logUTC
		Log also the UTC TimeStamp

	.EXAMPLE
		$MyLogger = New-EitFileLogger -LogFilePath MyLogFilePath 
		
		
	
	.NOTES  
		Copyright	: 	(c) 2019 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History		:
						V1.0 - 21.10.2019 - M.Trojahn - Initial creation
			
	#>	
	Param ( 
        [Parameter(Mandatory=$true)] [string] $LogFilePath,
		[Parameter(Mandatory=$false)] [string] $log4netPath = $PSScriptRoot + "\log4net.dll",
		[Parameter(Mandatory=$false)] [boolean] $logUTC = $false
        
    ) 
	
	[void][Reflection.Assembly]::LoadFile($log4netPath);
	[log4net.LogManager]::ResetConfiguration();
	
	if ($logUTC)
	{
		$MyLayout = new-object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff} (%utcdate{yyyy-MM-dd HH:mm:ss.fff})] [%level] [%message]%n')
	}	
	else 
	{
		$MyLayout = new-object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff}] [%level] [%message]%n')
	}	
	$RollingFileAppender = new-object log4net.Appender.RollingFileAppender
	
	$RollingFileAppender.Layout = $MyLayout
	$RollingFileAppender.file = $LogFilePath
	$RollingFileAppender.MaximumFileSize = "10MB"
	$RollingFileAppender.AppendToFile = $true
	$RollingFileAppender.Name = "filelog"
	$RollingFileAppender.StaticLogFileName = $false
	$RollingFileAppender.PreserveLogFileNameExtension = $true
	$RollingFileAppender.LockingModel = new-object log4net.Appender.FileAppender+MinimalLock
	$RollingFileAppender.DatePattern = "_yyyy-MM-dd"
	$RollingFileAppender.RollingStyle = "Date"
	$RollingFileAppender.RollingStyle = "Size"
	$RollingFileAppender.RollingStyle = "Composite"
	$RollingFileAppender.MaxSizeRollBackups = "100"
	
	
	$RollingFileAppender.Threshold = [log4net.Core.Level]::All
	$RollingFileAppender.ActivateOptions()
	[log4net.Config.BasicConfigurator]::Configure($RollingFileAppender)
	
	
	#Colored console appender initialization - > do not show Debug messages to the console
	$ColorConsoleAppender = new-object log4net.Appender.ColoredConsoleAppender(([log4net.Layout.ILayout](new-object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff}] %message%n'))));
	$ColorConsoleAppenderDebugCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderDebugCollorScheme.Level=[log4net.Core.Level]::Debug; $ColorConsoleAppenderDebugCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::Green;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderDebugCollorScheme);
	$ColorConsoleAppenderInfoCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderInfoCollorScheme.level=[log4net.Core.Level]::Info; $ColorConsoleAppenderInfoCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::White;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderInfoCollorScheme);
	$ColorConsoleAppenderWarnCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderWarnCollorScheme.level=[log4net.Core.Level]::Warn; $ColorConsoleAppenderWarnCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::Yellow;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderWarnCollorScheme);
	$ColorConsoleAppenderErrorCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderErrorCollorScheme.level=[log4net.Core.Level]::Error; $ColorConsoleAppenderErrorCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::Red;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderErrorCollorScheme);
	$ColorConsoleAppenderFatalCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderFatalCollorScheme.level=[log4net.Core.Level]::Fatal; $ColorConsoleAppenderFatalCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::Red);
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderFatalCollorScheme);
	$ColorConsoleAppender.ActivateOptions();
	$ColorConsoleAppender.Threshold = [log4net.Core.Level]::Info;
	[log4net.Config.BasicConfigurator]::Configure($ColorConsoleAppender);
	
	$EitLogger = [log4net.LogManager]::GetLogger("root");
	return $EitLogger 
}



function New-EitLogger {
	<#
	.Synopsis
		Create a new logger
	.Description
		Create a new log4Net logger

	.Parameter LogFilePath
		path to logfile
		
	.Parameter log4netPath
		Path to the log4Net DLL, default $PSScriptRoot
		
	.Parameter logUTC
		Log also the UTC TimeStamp

	.EXAMPLE
		$MyLogger = New-EitLogger -LogFilePath MyLogFilePath 
		Create a file logger
		
	.EXAMPLE
		$MyLogger = New-EitLogger 
		Create a console logger	
		
	
	.NOTES  
		Copyright	: 	(c) 2023 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History		:
						V1.0 - 13.04.2023 - M.Trojahn - Initial creation
			
	#>	
	Param ( 
        [Parameter(Mandatory=$false)] [string] $LogFilePath,
		[Parameter(Mandatory=$false)] [string] $log4netPath = $PSScriptRoot + "\log4net.dll",
		[Parameter(Mandatory=$false)] [boolean] $logUTC = $false
        
    ) 
	
	[void][Reflection.Assembly]::LoadFile($log4netPath);
	[log4net.LogManager]::ResetConfiguration();
	
	if ($logUTC) 
	{
		$MyLayout = new-object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff} (%utcdate{yyyy-MM-dd HH:mm:ss.fff})] [%level] [%message]%n')
	}	
	else 
	{
		$MyLayout = new-object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff}] [%level] [%message]%n')
	}	

	if ($LogFilePath.length -ne 0) 
	{
		$RollingFileAppender = new-object log4net.Appender.RollingFileAppender
		$RollingFileAppender.Layout = $MyLayout
		$RollingFileAppender.file = $LogFilePath
		$RollingFileAppender.MaximumFileSize = "10MB"
		$RollingFileAppender.AppendToFile = $true
		$RollingFileAppender.Name = "filelog"
		$RollingFileAppender.StaticLogFileName = $false
		$RollingFileAppender.PreserveLogFileNameExtension = $true
		$RollingFileAppender.LockingModel = new-object log4net.Appender.FileAppender+MinimalLock
		$RollingFileAppender.DatePattern = "_yyyy-MM-dd"
		$RollingFileAppender.RollingStyle = "Date"
		$RollingFileAppender.RollingStyle = "Size"
		$RollingFileAppender.RollingStyle = "Composite"
		$RollingFileAppender.MaxSizeRollBackups = "100"
		
		
		$RollingFileAppender.Threshold = [log4net.Core.Level]::All
		$RollingFileAppender.ActivateOptions()
		[log4net.Config.BasicConfigurator]::Configure($RollingFileAppender)
	}
	
	#Colored console appender initialization - > do not show Debug messages to the console
	$ColorConsoleAppender = new-object log4net.Appender.ColoredConsoleAppender(([log4net.Layout.ILayout](new-object log4net.Layout.PatternLayout('[%date{yyyy-MM-dd HH:mm:ss.fff}] %message%n'))));
	$ColorConsoleAppenderDebugCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderDebugCollorScheme.Level=[log4net.Core.Level]::Debug; $ColorConsoleAppenderDebugCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::Green;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderDebugCollorScheme);
	$ColorConsoleAppenderInfoCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderInfoCollorScheme.level=[log4net.Core.Level]::Info; $ColorConsoleAppenderInfoCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::White;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderInfoCollorScheme);
	$ColorConsoleAppenderWarnCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderWarnCollorScheme.level=[log4net.Core.Level]::Warn; $ColorConsoleAppenderWarnCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::Yellow;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderWarnCollorScheme);
	$ColorConsoleAppenderErrorCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderErrorCollorScheme.level=[log4net.Core.Level]::Error; $ColorConsoleAppenderErrorCollorScheme.ForeColor=[log4net.Appender.ColoredConsoleAppender+Colors]::Red;
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderErrorCollorScheme);
	$ColorConsoleAppenderFatalCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors; $ColorConsoleAppenderFatalCollorScheme.level=[log4net.Core.Level]::Fatal; $ColorConsoleAppenderFatalCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::Red);
	$ColorConsoleAppender.AddMapping($ColorConsoleAppenderFatalCollorScheme);
	$ColorConsoleAppender.ActivateOptions();
	$ColorConsoleAppender.Threshold = [log4net.Core.Level]::Info;
	[log4net.Config.BasicConfigurator]::Configure($ColorConsoleAppender);
	
	$EitLogger = [log4net.LogManager]::GetLogger("root");
	return $EitLogger 
}

