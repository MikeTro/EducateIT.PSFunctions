#
#
# DriveFunctions.ps1
# ===========================================================================
# (c)2020 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Drive Functions for Raptor Scripts
#
# History:
#   V1.0 - 10.08.2020 - M.Trojahn - Initial creation
#                                       Get-EitNextFreeDrive, Test-EitDriveExists


function Get-EitNextFreeDrive { 
    <#
        .Synopsis
            Finds a free drive letter 
        .Description
            Finds a free drive letter 

            .EXAMPLE
            Get-EitNextFreeDrive
            
        .NOTES  
            Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0
            
            History:
                V1.0 - 10.08.2020 - M.Trojahn - Initial creation
    #>	
	68..90 | ForEach-Object { "$([char]$_):" } |
	Where-Object { 'a:', 'b:' -notcontains $_ } |
	Where-Object {
		(new-object System.IO.DriveInfo $_).DriveType -eq 'noRootdirectory'
	} | select-object -last 1
}

function Test-EitDriveExists { 
    <#
        .Synopsis
            Tests if a drive exists
        .Description
            Use this functiuon to test if a file exists.

        .EXAMPLE
            Get-EitNextFreeDrive
            
        .NOTES  
            Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0
            
            History:
                V1.0 - 10.08.2020 - M.Trojahn - Initial creation
    #>	
	param($driveletter) 
	(New-Object System.IO.DriveInfo($driveletter)).DriveType -ne 'NoRootDirectory' 
} 










