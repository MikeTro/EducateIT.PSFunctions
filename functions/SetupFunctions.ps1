function Invoke-EitMsiExec {
<#
    .DESCRIPTION
        Install or uninstall a .msi or .msp file
    
    .PARAMETER FilePath
        Specify the path to the .msi (or .msp) file to be installed

    .PARAMETER Guid
        Specify the GUID of the MSI-based application to be uninstalled

    .PARAMETER Install
        Used to install a .msi file

    .PARAMETER Uninstall
        Used to uninstall a MSI-based application

    .PARAMETER Patch
        Used to install a .msp file

    .PARAMETER Arguments
        Specify additional arguments to pass to the .msi (or .msp) file (Comma seperated list)
	
    .PARAMETER ExitCodes
        Specify non-standard success exit codes (Comma seperated list)

    .EXAMPLE
        Install a .msi file
            Invoke-MsiExec -Install -FilePath "$PSScriptRoot\Setup.msi" -Arguments '/qn,/norestart,TRANSFORMS="$PSScriptRoot\Settings.mst"'

        Install a .msi file with non-standard exit codes 2 and 8
            Invoke-MsiExec -Install -FilePath "$PSScriptRoot\Setup.msi" -Arguments '/qn,/norestart' -ExitCodes '2,8'
        
        Install a .msp file
            Invoke-Msiexec -Patch -FilePath "$PSScriptRoot\Patch.msp" -Arguments '/qn,/norestart'

        Uninstall a .msi
            Invoke-MsiExec -Uninstall -Guid "{00000000-0000-0000-0000-000000000000}" -Arguments '/qn,/norestart'

    .NOTES  
        Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
        Version		:	1.0
        
        History:
            V1.0 - 14.12.2020 - M.Trojahn - Initial creation, adaptet from https://raw.githubusercontent.com/ConfigJon/Miscellaneous-Scripts/master/App%20Packaging/Invoke-MsiExec.ps1
				
#>
    param(
        [ValidateScript({
            if (!($_ | Test-Path)) {
                throw "The specified file does not exist"
            }
            if (!($_ | Test-Path -PathType Leaf)) {
                throw "The FilePath argument must be a file. Folder paths are not allowed."
            }
            if (($_ -notmatch "(\.msi)") -and ($_ -notmatch "(\.msp)")) {
                throw "The specified file must be a .msi or .msp file"
            }
            return $true 
        })]
        [System.IO.FileInfo]$FilePath,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$Arguments,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$ExitCodes,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][Switch]$Install,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][Switch]$Uninstall,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][Switch]$Patch,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$Guid
    )

    #Parameter validation
    if (!($Install) -and !($Uninstall) -and !($Patch)) {
        throw "One of the Install or Uninstall or Patch parameters must be specified"
    }
    if ($Install -and ($Uninstall -or $Patch)) {
        throw "Only one of the Install or Uninstall or Patch parameters can be specified"
    }
    if ($Uninstall -and ($Install -or $Patch)) {
        throw "Only one of the Install or Uninstall or Patch parameters can be specified"
    }
    if ($Patch -and ($Install -or $Uninstall)) {
        throw "Only one of the Install or Uninstall or Patch parameters can be specified"
    }
    if ($Install -and !($FilePath)) {
        throw "The FilePath parameter must be specified when using the Install parameter"
    }
    if ($Patch -and !($FilePath)) {
        throw "The FilePath parameter must be specified when using the Patch parameter"
    }
    if ($Install -and $Guid) {
        throw "The Guid parameter should not be specified when using the Install parameter"
    }
    if ($Patch -and $Guid) {
        throw "The Guid parameter should not be specified when using the Patch parameter"
    }

    #Create a list to store arguments
    $ArgumentList = New-Object 'System.Collections.Generic.List[string]'
	
    #Convert the exit codes to a list
    if ($ExitCodes) {
        $ExitSplit = $ExitCodes.Split(',')
    }

    #Add the install, uninstall, or patch argument to the list
    if ($Install) {
        $ArgumentList.Add('/i')
    }
    if ($Uninstall) {
        $ArgumentList.Add('/x')
    }
    if ($Patch) {
        $ArgumentList.Add('/p')
    }

    #Add the FilePath argument to the list
    if ($FilePath) {
        $StringFilePath = $FilePath.ToString() #Convert the FilePath argument to a string
        $StringFilePath = $StringFilePath.insert(0,'"') #Add a quote at the start of the path
        $StringFilePath+='"' #Add a quote at the end of the path
        $ArgumentList.Add($StringFilePath)
    }

    #Add the Guid argument to the list
    if ($Guid) {
        $ArgumentList.Add($Guid)
    }

    #Add any additional arguments to the list
    if($Arguments) {
        $Arguments = $ExecutionContext.InvokeCommand.ExpandString($Arguments) #Expand any variables passed in the arguments list
        $ArgumentsSplit = $Arguments.Split(',')
        $Count = 0

        while($Count -lt $ArgumentsSplit.Count) {
            $ArgumentList.Add($ArgumentsSplit[$Count].Trim())
            $Count++
        }
    }
    
    #Run MsiExec
    if ($FilePath) {
        Write-Output "Running Command: MsiExec.exe $ArgumentList"
    }
    if ($Guid) {
        Write-Output "Uninstalling $Guid"
    }
    $ExitCode = (Start-Process -FilePath "MsiExec.exe" -ArgumentList $ArgumentList -Wait -PassThru).ExitCode

    #Report the Exit Code
    Write-Output "The exit code is $ExitCode"

    #Terminate the script if an error occurs
    if (($ExitCode -ne 0) -and ($ExitCode -ne 3010) -and !($ExitSplit -contains $ExitCode)) {
        throw "MsiExec terminated with error code $ExitCode"
    }
}


function Start-EitExecutable {
<#
    .DESCRIPTION
        Install a .exe file
    
    .PARAMETER FilePath
        Specify the path to the .exe file to be installed

    .PARAMETER Arguments
        Specify additional arguments to pass to the .exe file (Comma seperated list)

    .PARAMETER ExitCodes
        Specify non-standard success exit codes (Comma seperated list)

    .EXAMPLE
        Install a .exe file
            Start-EitExecutable -FilePath "$PSScriptRoot\Setup.exe" -Arguments '/S,/v"/qn REBOOT=reallysuppress"'

        Install a .exe file with non-standard exit codes 2 and 8
            Start-EitExecutable -FilePath "$PSScriptRoot\Setup.exe" -Arguments '/S' -ExitCodes '2,8'

    .NOTES  
        Copyright: (c)2022 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
        Version		:	1.1
        
        History:
            V1.0 - 14.12.2020 - M. Trojahn - Initial creation, adaptet from https://raw.githubusercontent.com/ConfigJon/Miscellaneous-Scripts/master/App%20Packaging/
			V1.1 - 14.03.2022 - M. Trojahn - Rename to Start-EitExecutable because of Trend ApexOne Behavior Monitoring
            
#>
    param(
        [ValidateScript({
            if (!($_ | Test-Path)) {
                throw "The specified file does not exist"
            }
            if (!($_ | Test-Path -PathType Leaf)) {
                throw "The FilePath argument must be a file. Folder paths are not allowed."
            }
            if ($_ -notmatch "(\.exe)") {
                throw "The specified file must be a .exe file"
            }
            return $true 
        })]
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$FilePath,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$Arguments,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][String]$ExitCodes
    )

    #Create a list to store arguments
    $ArgumentList = New-Object 'System.Collections.Generic.List[string]'

    #Convert the exit codes to a list
    if ($ExitCodes) {
        $ExitSplit = $ExitCodes.Split(',')
    }

    #Add any additional arguments to the list
    if ($Arguments) {
        $Arguments = $ExecutionContext.InvokeCommand.ExpandString($Arguments) #Expand any variables passed in the arguments list
        $ArgumentsSplit = $Arguments.Split(',')
        $Count = 0

        while($Count -lt $ArgumentsSplit.Count) {
            $ArgumentList.Add($ArgumentsSplit[$Count].Trim())
            $Count++
        }
    }

    #Add quotes to the FilePath
    $StringFilePath = $FilePath.ToString() #Convert the FilePath argument to a string
    $StringFilePath = $StringFilePath.insert(0,'"') #Add a quote at the start of the path
    $StringFilePath+='"' #Add a quote at the end of the path
    
    #Run the executable
    Write-Output "Running Command: $StringFilePath $ArgumentList"
    if ($Arguments) {
        $ExitCode = (Start-Process -FilePath $StringFilePath -ArgumentList $ArgumentList -Wait -PassThru).ExitCode
    }
    else {
        $ExitCode = (Start-Process -FilePath $StringFilePath -Wait -PassThru).ExitCode
    }

    #Report the Exit Code
    Write-Output "The exit code is $ExitCode"

    #Terminate the script if an error occurs
    if (($ExitCode -ne 0) -and ($ExitCode -ne 3010) -and !($ExitSplit -contains $ExitCode)) {
        throw "The executable terminated with error code $ExitCode"
    }
}

