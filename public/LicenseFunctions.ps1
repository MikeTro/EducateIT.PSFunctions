#
# LicenseFunctions.ps1
# ===========================================================================
# (c)2026 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.1
#
# Useful Script functions
# History:
#   V1.0 -19.08.2026 - M.Trojahn - Initial creation, add Register-EitLicense
#   V1.1 -19.08.2026 - M.Trojahn - Add Optimization for  for EducateIT Raptor V4.48.0 - License System & ProxyServer parameter
#								   in Register-EitLicense
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
			
		
		.PARAMETER ProxyServer
			Optional HTTP proxy server used for license activation or reactivation.

			Format:
				http://proxyserver:proxyport

			Example:
				http://192.168.1.10:8888

			The proxy is passed to the application using:
				--license-proxy=<ProxyServer>

			If omitted, no license proxy argument is passed.

        .EXAMPLE
            Register-EitLicense `
                -Application "C:\Program Files\EducateIT\ActionsServer\ActionsServer.exe" `
                -Activate `
                -License "XXXXX-XXXXX-XXXXX"

        .EXAMPLE
            Register-EitLicense `
                -Application "C:\Program Files\EducateIT\ActionsServer\ActionsServer.exe" `
                -Reactivate

		.EXAMPLE
			Register-EitLicense -Application 'C:\Raptor\Raptor.exe' -Reactivate -ProxyServer 'http://192.168.1.10:8888'
			Reactivates the license using the specified HTTP proxy.

		.EXAMPLE
			Register-EitLicense -Application 'C:\Raptor\Raptor.exe' -Activate -License 'ABCDE-12345' -ProxyServer 'http://192.168.1.10:8888'
			Activates the license using the specified HTTP proxy.
	

        .OUTPUTS
            PSCustomObject

        .NOTES
            Copyright	: (c)2026 by EducateIT GmbH
            Version		: 1.01
			History		:
			   V1.00 -19.08.2026 - M.Trojahn - Initial creation
			   V1.01 -20.10.2026 - M.Trojahn - Optimization for  for EducateIT Raptor V4.48.0 - License System
											   Add ProxyServer parameter

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
        [string]$License,
		
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript(
			{
				$uri = $null

				if (-not [System.Uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$uri))
				{
					throw 'ProxyServer must be a valid absolute URL.'
				}

				if ($uri.Scheme -ne 'http')
				{
					throw 'ProxyServer must use the http:// scheme.'
				}

				if ([string]::IsNullOrWhiteSpace($uri.Host) -or
					$uri.Port -le 0 -or
					$uri.Port -gt 65535)
				{
					throw 'ProxyServer must contain a valid host and port.'
				}

				if ($_ -notmatch '^http://(?:\[[0-9a-fA-F:.]+\]|[^/:?#\s]+):[0-9]{1,5}$')
				{
					throw 'ProxyServer must use the format http://proxyserver:proxyport.'
				}

				return $true
			}
		)]
		[string]$ProxyServer
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
				$argumentList = @("--license-activate=$License")
				$successMessage = 'Successfully activated application.'
			}

			'Reactivate'
			{
				$mode = 'Reactivate'
				$argumentList = @('--license-reactivate')
				$successMessage = 'Successfully reactivated application.'
			}

			default
			{
				throw "Unsupported parameter set '$($PSCmdlet.ParameterSetName)'."
			}
		}

		if (-not [string]::IsNullOrWhiteSpace($ProxyServer))
		{
			$argumentList += "--license-proxy=$ProxyServer"
		}
        

        $tmpStandardOutput = New-TemporaryFile -ErrorAction Stop
        $tmpStandardError = New-TemporaryFile -ErrorAction Stop
        $process = Start-Process `
			-FilePath $Application `
			-ArgumentList ($argumentList -join ' ') `
			-Wait `
			-PassThru `
			-RedirectStandardOutput $tmpStandardOutput.FullName `
			-RedirectStandardError $tmpStandardError.FullName `
			-ErrorAction Stop
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
			$errorDetails = @(
				$standardError
				$standardOutput
			) | Where-Object `
			{
				-not [string]::IsNullOrWhiteSpace($_)
			}

			$errorMessage = "Error occurred while registering '$Application'. Exit code: $exitCode."

			if ($errorDetails)
			{
				$errorMessage += "`r`n" + ($errorDetails -join "`r`n")
			}

			throw $errorMessage
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

