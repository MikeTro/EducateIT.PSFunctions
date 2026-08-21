#
# LicenseFunctions.ps1
# ===========================================================================
# (c)2026 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Useful Script functions
# History:
#   V1.00 -19.08.2026 - M.Trojahn - Initial creation, add Register-EitLicense
#	
# ===========================================================================


function Register-EitLicense
{
    <#
        .SYNOPSIS
            Activates or reactivates an EducateIT application.

        .DESCRIPTION
            Activates or reactivates an EducateIT application by starting the
            specified executable with the appropriate licensing arguments.

            The function uses separate parameter sets for activation and
            reactivation.

            When activating an application, the License parameter is mandatory.

            When reactivating an application, no license is required.

            Standard output, standard error, and the process exit code are
            captured and returned as part of the result object.

            An exit code other than 0 is considered an error. Standard error
            output alone does not cause the operation to fail if the process
            returns exit code 0.

        .PARAMETER Activate
            Activates the specified EducateIT application.

        .PARAMETER Reactivate
            Reactivates the specified EducateIT application.

        .PARAMETER Application
            Specifies the full path to the EducateIT application executable.

        .PARAMETER License
            Specifies the license used to activate the application.

        .EXAMPLE
            Register-EitLicense `
                -Application "C:\Program Files\EducateIT\ActionsServer\ActionsServer.exe" `
                -Activate `
                -License "XXXXX-XXXXX-XXXXX"

        .EXAMPLE
            Register-EitLicense `
                -Application "C:\Program Files\EducateIT\ActionsServer\ActionsServer.exe" `
                -Reactivate

        .OUTPUTS
            PSCustomObject

        .NOTES
            Copyright: (c)2026 by EducateIT GmbH
            Version  : 1.0

            Compatibility:
                Windows PowerShell 5.1 or later.
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Activate'
        )]
        [switch]$Activate,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Reactivate'
        )]
        [switch]$Reactivate,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Application,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Activate'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$License
    )

    $success = $false
    $statusMessage = $null
    $successMessage = $null
    $exitCode = $null
    $standardOutput = $null
    $standardError = $null
    $argumentList = $null
    $mode = $null
    $process = $null
    $tmpStandardOutput = $null
    $tmpStandardError = $null

    try
    {
        if (-not (Test-Path -LiteralPath $Application -PathType Leaf))
        {
            throw "Application '$Application' does not exist."
        }

        switch ($PSCmdlet.ParameterSetName)
        {
            'Activate'
            {
                $mode = 'Activate'
                $argumentList = "--license-activate=$License"
                $successMessage = 'Successfully activated application.'
            }

            'Reactivate'
            {
                $mode = 'Reactivate'
                $argumentList = '--license-reactivate'
                $successMessage = 'Successfully reactivated application.'
            }

            default
            {
                throw "Unsupported parameter set '$($PSCmdlet.ParameterSetName)'."
            }
        }

        $tmpStandardOutput = New-TemporaryFile -ErrorAction Stop
        $tmpStandardError = New-TemporaryFile -ErrorAction Stop
        $process = Start-Process -FilePath $Application -ArgumentList $argumentList -Wait -PassThru -RedirectStandardOutput $tmpStandardOutput.FullName -RedirectStandardError $tmpStandardError.FullName -ErrorAction Stop
        $exitCode = $process.ExitCode

        if (
            Test-Path -LiteralPath $tmpStandardOutput.FullName -PathType Leaf
        )
        {
            $standardOutput = Get-Content -LiteralPath $tmpStandardOutput.FullName -Raw -ErrorAction Stop
        }

        if (
            Test-Path -LiteralPath $tmpStandardError.FullName -PathType Leaf
        )
        {
            $standardError = Get-Content -LiteralPath $tmpStandardError.FullName -Raw -ErrorAction Stop
        }

        if ($exitCode -ne 0)
        {
            if ([string]::IsNullOrWhiteSpace($standardError))
            {
                throw "Error occurred while registering '$Application'. Exit code: $exitCode."
            }
            else
            {
                throw "Error occurred while registering '$Application'. Exit code: $exitCode.`r`n$standardError"
            }
        }

        $success = $true
        $statusMessage = $successMessage
    }
    catch
    {
        $success = $false
        $statusMessage = $_.Exception.Message
    }
    finally
    {
        if ($null -ne $tmpStandardOutput)
        {
            if (
                Test-Path -LiteralPath $tmpStandardOutput.FullName -PathType Leaf
            )
            {
                Remove-Item -LiteralPath $tmpStandardOutput.FullName -Force -ErrorAction SilentlyContinue
            }
        }

        if ($null -ne $tmpStandardError)
        {
            if (Test-Path -LiteralPath $tmpStandardError.FullName -PathType Leaf)
            {
                Remove-Item -LiteralPath $tmpStandardError.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return [pscustomobject]@{
        Success        = $success
        Message        = $statusMessage
        Application    = $Application
        Mode           = $mode
        ExitCode       = $exitCode
        StandardOutput = $standardOutput
        StandardError  = $standardError
    }
}

