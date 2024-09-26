#
# CertificateFunctions.ps1
# ===========================================================================
# (c)2024 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Cerificates functions for Raptor Scripts
#
# History:
#   V1.0 - 26.09.2024 - M.Trojahn - Initial creation
#									add New-EitCACertificate, New-EitCertificateSigningRequest, New-EitSelfSignedCertificate 
#										
#										
#   
#
#
# ===========================================================================


function New-EitCACertificate {
    <#
    .SYNOPSIS
        Generate a CA-certificat

    .DESCRIPTION
        The New-EitCACertificat command generates a CA certificate using the options specified.

    .PARAMETER passphrase
        Key encryption passphrase.

    .PARAMETER ValidDays
		Certificate validy in days. Default is 3650 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

	.PARAMETER OutputPath
		Path to store the certificate

	.PARAMETER OutputName
		the base name of the files
		
	.PARAMETER Country
		the country name 
		
	.PARAMETER State
		the state name 	
		
	.PARAMETER City
		the city name 	

	.PARAMETER OrganizationName	
		the OrganizationName
		
	.PARAMETER emailAddress	
		the emailAddress
		
	.PARAMETER CommonName
		the CommonName
		
    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Default is C:\educateitssl.

    .EXAMPLE
        New-EitCACertificate -Passphrase mySecureString 
        Generate a CA certificate Raptor-CA.crt & Raptor-CA.key in C:\Key using input mySecureString as passphrase

    .INPUTS
        None

    .OUTPUTS
        None
		
	.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 09.09.2024 - M.Trojahn - Initial creation
		
    #>

    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$true, HelpMessage="Key encryption passphrase")]
		[ValidateNotNullOrEmpty()]
		[SecureString]
		$Passphrase,

		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $Country = "CH",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $State = "BE",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $City = "Bern",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $OrganizationName = "EducateIT GmbH",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $emailAddress = "support@educateit.ch",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $CommonName = "EducateIT GmbH",
		
		[Parameter(Mandatory=$false, HelpMessage="Certificate validity in days")]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(30, 9125)]
		[Int] $ValidDays = 3650,

		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OpenSslPath = "C:\educateitssl\openssl.exe",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $OutputPath = "C:\Program Files\EducateIT\Keys",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $OutputName = "Raptor-CA"
    )
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully created CA certificate"
	try
	{
		# OpenSSL executable
		$opensslexe = "openssl.exe"
		if (Test-Path -PathType Container $OpenSslPath) 
		{ 
			throw "Invalid openssl file name"
			Return
		}
		if (!(Test-Path -PathType Leaf $OpenSslPath)) 
		{
			throw "Openssl file '$OpenSslPath' not found"
			Return
		}
		$opensslexe = $OpenSslPath

		if (!(Test-Path $OutputPath)) {New-Item -Path $OutputPath -ItemType "directory" | Out-Null}
		
		$myShortPath = Get-EitShortPath -Path $OutputPath
		
		if ($myShortPath.Success -eq $True)
		{
			$OutputPath = $myShortPath.ShortPath
			$CertificateFile = ($OutputPath + "\" + $OutputName + ".crt")
			$KeyFile = ($OutputPath + "\" + $OutputName + ".key")
			
			# OpenSSL arguments
			$arguments = @("req")

			$arguments += "-new"
			$rand = Join-Path $env:TEMP "opensslrand"
			Get-Random | Set-Content $rand
			$arguments += "-rand"
			$arguments += "`"$rand`""
			$arguments += "-extensions"
			$arguments += "v3_ca"
			$arguments += "-newkey"
			$arguments += "rsa:2048bits"
			$arguments += "-x509"

			$arguments += "-keyout"
			$arguments += "`"$KeyFile`""
			
			$arguments += "-days"
			$arguments += $ValidDays
			   
			$arguments += "-out"
			$arguments += "`"$CertificateFile`""
			
			$arguments += "-subj"
			$arguments += "`"/C=$Country/ST=$State/L=$City/O=$OrganizationName/OU=/CN=$CommonName/emailAddress=$emailAddress`""
			$arguments += "-passout"
			
			# Passout argument
			$password = ''
			$password = (New-Object PSCredential "User",$Passphrase).GetNetworkCredential().Password
			$arguments += "pass:$password"
		  
			# Verbose output
			Write-Verbose "Command:`n`n$opensslexe $([RegEx]::Replace($arguments, 'pass:[^\s].*', 'pass:*** '))`n`n"

			# Run command
			$pinfo = New-Object System.Diagnostics.ProcessStartInfo
			$pinfo.FileName = "$opensslexe"
			$pinfo.RedirectStandardError = $true
			$pinfo.RedirectStandardOutput = $true
			$pinfo.UseShellExecute = $false
			$pinfo.Arguments = $arguments
			$pinfo.WorkingDirectory = Convert-Path .
			$proc = New-Object System.Diagnostics.Process
			$proc.StartInfo = $pinfo
			$proc.Start() | Out-Null
			$proc.WaitForExit(10000) | Out-Null
			$stdout = $proc.StandardOutput.ReadToEnd()
			$stderr = $proc.StandardError.ReadToEnd()

			# Check errors
			if ($proc.ExitCode) 
			{
				throw $stderr
			} 

			# Verbose output
			Write-Verbose "Output:`n`n$stdout`n`n"
			Write-Verbose "Errors:`n`n$stderr`n`n"
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		Write-Error $_.Exception.Message
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;CertificateFile=$CertificateFile;KeyFile=$KeyFile})
    return $ReturnObject
}

function New-EitCertificateSigningRequest {
    <#
    .SYNOPSIS
        Generate a CA-certificat

    .DESCRIPTION
        The New-EitCACertificat command generates a CA certificate using the options specified.

    .PARAMETER passphrase
        Key encryption passphrase.

    .PARAMETER ValidDays
        Certificate validy in days. Default is 30 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

	.PARAMETER OutputPath

	.PARAMETER OutputName

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        New-EitSelfSignedCertificate key.pem CN:server.domain.com cert.pem
        Generate a self-signed certificate using input key file 'key.pem' and subject name provided. Output certificate to file 'cert.pem'.


    .INPUTS
        None

    .OUTPUTS
        None
		
	.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 09.09.2024 - M.Trojahn - Initial creation
		
    #>

    [CmdletBinding()]
    Param (

		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OpenSslPath = "C:\educateitssl\openssl.exe",
		
		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OutputPath = "C:\Program Files\EducateIT\Keys",
		
		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OutputName = "Raptor-Server",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String] $CommonName = "*.$env:DNSDomain"
		
    )

	try
	{
		# OpenSSL executable
		$opensslexe = "openssl.exe"
		if (Test-Path -PathType Container $OpenSslPath) 
		{ 
			throw "Invalid openssl file name"
			Return
		}
		if (!(Test-Path -PathType Leaf $OpenSslPath)) 
		{
			throw "Openssl file '$OpenSslPath' not found"
			Return
		}
		$opensslexe = $OpenSslPath

		
		if (!(Test-Path $OutputPath)) {New-Item -Path $OutputPath -ItemType "directory"}
		
		$myShortPath = Get-EitShortPath -Path $OutputPath
		
		if ($myShortPath.Success -eq $True)
		{
			$OutputPath = $myShortPath.ShortPath
			$CertificateFile = ($OutputPath + "\" + $OutputName + ".csr")
			$KeyFile = ($OutputPath + "\" + $OutputName + ".key")
			
			# OpenSSL arguments
			$arguments = @("req")

			# New argument
			$arguments += "-new"
			$rand = Join-Path $env:TEMP "opensslrand"
			Get-Random | Set-Content $rand
			$arguments += "-rand"
			$arguments += "`"$rand`""
			$arguments += "-newkey"
			$arguments += "rsa:2048"
			$arguments += "-nodes"

			$arguments += "-keyout"
			$arguments += "`"$KeyFile`""
			
			$arguments += "-out"
			$arguments += "`"$CertificateFile`""
			
			$arguments += "-subj"
			$arguments += "`"/CN=$CommonName`""
			
			# Verbose output
			Write-Verbose "Command:`n`n$opensslexe $([RegEx]::Replace($arguments, 'pass:[^\s].*', 'pass:*** '))`n`n"

			# Run command
			$pinfo = New-Object System.Diagnostics.ProcessStartInfo
			$pinfo.FileName = "$opensslexe"
			$pinfo.RedirectStandardError = $true
			$pinfo.RedirectStandardOutput = $true
			$pinfo.UseShellExecute = $false
			$pinfo.Arguments = $arguments
			$pinfo.WorkingDirectory = Convert-Path .
			$proc = New-Object System.Diagnostics.Process
			$proc.StartInfo = $pinfo
			$proc.Start() | Out-Null
			$proc.WaitForExit(10000) | Out-Null
			$stdout = $proc.StandardOutput.ReadToEnd()
			$stderr = $proc.StandardError.ReadToEnd()

			# Check errors
			if ($proc.ExitCode) 
			{
				throw $stderr
			} 

			# Verbose output
			Write-Verbose "Output:`n`n$stdout`n`n"
			Write-Verbose "Errors:`n`n$stderr`n`n"
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		Write-Error $_.Exception.Message
	}
}

function New-EitSelfSignedCertificate {
    <#
    .SYNOPSIS
        Generate a CA-certificat

    .DESCRIPTION
        The New-EitCACertificat command generates a CA certificate using the options specified.

    .PARAMETER passphrase
        Key encryption passphrase.

    .PARAMETER ValidDays
        Certificate validy in days. Default is 30 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

	.PARAMETER OutputPath

	.PARAMETER OutputName

    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
        New-EitSelfSignedCertificate key.pem CN:server.domain.com cert.pem
        Generate a self-signed certificate using input key file 'key.pem' and subject name provided. Output certificate to file 'cert.pem'.


    .INPUTS
        None

    .OUTPUTS
        None
		
	.NOTES  
			Copyright: (c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 09.09.2024 - M.Trojahn - Initial creation
		
    #>

    [CmdletBinding()]
    Param (

		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OpenSslPath = "C:\educateitssl\openssl.exe",
		
		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OutputPath = "C:\Program Files\EducateIT\Keys",
		
		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path")]
		[ValidateNotNullOrEmpty()]
		[String] $OutputName = "Raptor-Server",
		
		[Parameter(Mandatory=$false, HelpMessage="Certificate validity in days")]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(30, 9125)]
		[Int] $ValidDays = 3650,
		
		[Parameter(Mandatory=$true, HelpMessage="Key encryption passphrase")]
		[ValidateNotNullOrEmpty()]
		[SecureString]
		$Passphrase,
		
		
		[Parameter(Mandatory=$true, HelpMessage="Key encryption passphrase")]
		[ValidateNotNullOrEmpty()]
		[String] $CertificateSigningRequest,
		
		[Parameter(Mandatory=$true, HelpMessage="Key encryption passphrase")]
		[ValidateNotNullOrEmpty()]
		[String] $CACertificateFile,
		
		[Parameter(Mandatory=$true, HelpMessage="Key encryption passphrase")]
		[ValidateNotNullOrEmpty()]
		[String] $CAKeyFile
    )
	
	try
	{
		# OpenSSL executable
		$opensslexe = "openssl.exe"
		if (Test-Path -PathType Container $OpenSslPath) 
		{ 
			throw "Invalid openssl file name"
			Return
		}
		if (!(Test-Path -PathType Leaf $OpenSslPath)) 
		{
			throw "Openssl file '$OpenSslPath' not found"
			Return
		}
		$opensslexe = $OpenSslPath

		
		if (!(Test-Path $OutputPath)) {New-Item -Path $OutputPath -ItemType "directory"}
		$myShortPath = Get-EitShortPath -Path $OutputPath
		
		if ($myShortPath.Success -eq $True)
		{
			$OutputPath = $myShortPath.ShortPath
			$CertificateFile = $OutputPath + "\" + $OutputName + ".csr"
			
			# OpenSSL arguments
			$arguments = @("x509")
			$arguments += "-req"
			$arguments += "-in"
			$arguments += "$CertificateSigningRequest"
			
			$arguments += "-CA"
			$arguments += "$CACertificateFile"
			$arguments += "-CAkey"
			$arguments += "$CAKeyFile"
			$arguments += "-out"
			$arguments += "$CertificateFile"
			$arguments += "-days"
			$arguments += "$ValidDays"
			$arguments += "-sha256"
			$arguments += "-passin"
			
			$password = ''
			$password = (New-Object PSCredential "User",$Passphrase).GetNetworkCredential().Password
			$arguments += "pass:$password"
			

			# Verbose output
			Write-Verbose "Command:`n`n$opensslexe $([RegEx]::Replace($arguments, 'pass:[^\s].*', 'pass:*** '))`n`n"

			# Run command
			$pinfo = New-Object System.Diagnostics.ProcessStartInfo
			$pinfo.FileName = "$opensslexe"
			$pinfo.RedirectStandardError = $true
			$pinfo.RedirectStandardOutput = $true
			$pinfo.UseShellExecute = $false
			$pinfo.Arguments = $arguments
			$pinfo.WorkingDirectory = Convert-Path .
			$proc = New-Object System.Diagnostics.Process
			$proc.StartInfo = $pinfo
			$proc.Start() | Out-Null
			$proc.WaitForExit(10000) | Out-Null
			$stdout = $proc.StandardOutput.ReadToEnd()
			$stderr = $proc.StandardError.ReadToEnd()

			# Check errors
			if ($proc.ExitCode) 
			{
				throw $stderr
			} 

			# Verbose output
			Write-Verbose "Output:`n`n$stdout`n`n"
			Write-Verbose "Errors:`n`n$stderr`n`n"
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		Write-Error $_.Exception.Message
	}
}




