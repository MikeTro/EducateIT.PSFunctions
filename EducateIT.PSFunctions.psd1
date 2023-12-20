###############################################################################################
# Module manifest for module 'EducateIT.PSFunctions'
#
# Generated by: EducateIT GmbH
# 
#
# Copyright	:	(c)2023 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
#
# History:
#           V1.3 	- 16.03.2020 - M. Trojahn - Remove Test-Port in ScriptFunctions.ps1
#           V1.4 	- 17.06.2020 - M. Trojahn - Add VHDFunctions
#                     12.08.2020 - M. Trojahn - AddDriveFunctions, FSLogixFunctions
#           V1.5 	- 14.12.2020 - M. Trojahn - Add LogFunctions, fix error in MessageFunctions & ADFunctiions
#           V1.6 	- 06.04.2021 - M. Trojahn - Add EducateITStatisticServerFunctions
#          		   	  07.04.2021 - M. Trojahn - Update ADFunctions (Get-EitBitlockerPasswords)
#           V1.7 	- 07.11.2021 - M. Trojahn - rename EducateITServerVersions.ps1 to EducateITServerInformation.ps1
#											 add Get-EitServerServiceInfo
#           V1.7.3 	- 17.11.2021 - M. Trojahn - Add Name parameter, required for reporting in Get-EitServerServiceInfo
#           V1.8.0 	- 14.03.2022 - M. Trojahn - Rename Invoke-EitExecutable to Start-EitExecutable in SetupFunctions.ps1 because of Trend ApexOne Behavior Monitoring
#           V1.8.1 	- 27.04.2022 - M. Trojahn - Add log to Send-EitNetMessage function in MessageFunctions.ps1
#           V1.8.2 	- 03.08.2022 - M. Trojahn - Add New-EitEncryptedPassword function in ScriptFunctions.ps1
#           V1.9.0 	- 27.10.2022 - M. Trojahn - Add CitrixDaaSFunctions.ps1
#           V1.9.1 	- 01.11.2022 - M. Trojahn - ProcessMonitorFunctions.ps1
#			V1.9.2	- 21.12.2022 - M. Trojahn - Remove MaxRecordCount from Stop-EitBrokerSession in CitrixFunctions.ps1
#			V1.9.3	- 20.03.2023 - M. Trojahn - add Get-EitPSUnique in ScriptFunctions.ps1
#												add Get-EitBrokerMachine in CitrixFunctions.ps1	
#			V1.9.4	- 29.03.2023 - M. Trojahn - add Get-EitADUser in ADFunctions.ps1
#			V1.9.5	- 13.04.2023 - M. Trojahn - add Get-EitBrokerSessions, Stop-EitAllBrokerSessionOnMachine in CitrixFunctions.ps1
#												add New-EitLogger in LogFunctions.ps1
#												Test also for the new raptor server path in Get-EitRemoteComputersFromXenDataConf
#									 			Add Get-EitLinkNamesFromXenDataConf, Get-EitLinkNameForBrokerMachine in ScriptFunctions.ps1
#			V1.9.6	- 07.09.2023 - M. Trojahn - Add UTF8 Encoding in function New-EitEncryptedPassword in ScriptFunctions.ps1
#			V1.9.7	- 11.09.2023 - M. Trojahn - Add UseBasicParsing in function Get-EitCitrixDaaSbearerToken in CitrixDaaSFunctions.ps1
#			V1.9.8	- 12.12.2023 - M. Trojahn - Add logger to stop-eitbrokersession, only use remoting if it is required in Get-EitServerServiceInfo
#					  20.12.2023 - M. Trojahn - Add add full site data to Get-EitSiteInfo
#
###############################################################################################

@{

# Script module or binary module file associated with this manifest.
# RootModule = ''

# Version number of this module.
ModuleVersion = '1.9.8'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '8f46b42d-aec9-4b41-b8a3-f59ad56ee44e'

# Author of this module
Author = 'EducateIT GmbH'

# Company or vendor of this module
CompanyName = 'EducateIT GmbH'

# Copyright statement for this module
Copyright = '(c) 2023 EducateIT GmbH. All rights reserved.'

# Description of the functionality provided by this module
Description = 'EducateIT Powershell functions'


# Minimum version of the Windows PowerShell engine required by this module
# PowerShellVersion = ''

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @(
	'.\functions\ADFunctions.ps1', 
    '.\functions\CitrixFunctions.ps1', 
    '.\functions\MessageFunctions.ps1', 
    '.\functions\XenDesktopFunctions.ps1',
	'.\functions\ScriptFunctions.ps1',
    '.\functions\EducateITServerInformation.ps1',
    '.\functions\VHDFunctions.ps1',
    '.\functions\DriveFunctions.ps1',
    '.\functions\FSLogixFunctions.ps1',
    '.\functions\LogFunctions.ps1',
    '.\functions\SetupFunctions.ps1',
	'.\functions\EducateITStatisticServerFunctions.ps1'
	'.\functions\CitrixDaaSFunctions.ps1',
	'.\functions\ProcessMonitorFunctions.ps1'
)

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('*')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{
    PSData = @{
        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

 
}




