#
# CertificateFunctions.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.1
#
# Certificates functions for Raptor Scripts
#
# History:
#   V1.0 - 26.09.2024 - M.Trojahn - Initial creation
#									add New-EitCACertificate, New-EitCertificateSigningRequest, New-EitSelfSignedCertificate 
#   V1.1 - 06.01.2025 - M.Trojahn - add Invoke-EitOpenSSLCommand & Convert-EitPfxFile 
#									modify New-EitCACertificate, New-EitCertificateSigningRequest &  New-EitSelfSignedCertificate to use Invoke-EitOpenSSLCommand
#									Code optimizations
#										
#										
#   
#
#
# ===========================================================================

function Invoke-EitOpenSSLCommand {
<#
    .SYNOPSIS
        Execute an OpenSSL command

    .DESCRIPTION
        The Invoke-EitOpenSSLCommand function executes an OpenSSL command with specified arguments, handling the process execution and output/error collection.

    .PARAMETER Arguments
        Command-line arguments for OpenSSL.

    .PARAMETER OpensslExePath
        Path to the OpenSSL executable. Defaults to "C:\educateitssl\openssl.exe".

    .PARAMETER Timeout
        Timeout in milliseconds for the OpenSSL process execution. Defaults to 10,000 milliseconds (10 seconds).

    .EXAMPLE
		Invoke-EitOpenSSLCommand -Arguments "req -new -extensions v3_ca -days 3650 -newkey rsa:2048 -x509 -out my-ca.crt -keyout my-ca.key"

    .OUTPUTS
        An object with the following properties:
        - Success: True or False indicating execution success.
        - Message: Execution status or error message.
        - StdOut: Standard output of the OpenSSL process.
        - StdErr: Standard error of the OpenSSL process.

    .NOTES  
        Copyright	:	(c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
        Version     :   1.0
            
        History		:
						V1.0 - 03.01.2025	-	M. Trojahn	-	Initial creation

#>
    param (
        [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string[]] $Arguments,

        [Parameter(Mandatory=$false)]
        [string] $OpensslExePath = "C:\educateitssl\openssl.exe",

        [Parameter(Mandatory=$false)]
        [int] $Timeout = 10000
    )
    # Initialize return values
    [boolean]	$bSuccess = $true
    [string]	$StatusMessage = "Successfully executed OpenSSL command"
    [string]	$stdout = ""
    [string] 	$stderr = ""

    # Process object
    $proc = $null

    try 
	{
        # Check if the OpenSSL executable exists
        if (-not (Test-Path -Path $OpensslExePath)) 
		{
            throw "OpenSSL executable '$OpensslExePath' not found"
        }
		# Configure the process
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $OpensslExePath
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $Arguments -join ' '
		$pinfo.Arguments
        $pinfo.WorkingDirectory = (Get-Location).Path

		# Verbose output
		Write-Verbose "Command:`n`n$opensslexe $([RegEx]::Replace($arguments, 'pass:[^\s].*', 'pass:*** '))`n`n"

        # Start the process
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $pinfo
        if (-not $proc.Start()) 
		{
            throw "Failed to start the OpenSSL process."
        }
		
        # Wait for the process to exit and check for timeout
        if (-not $proc.WaitForExit($Timeout)) 
		{
            $proc.Kill()
            throw "The OpenSSL process timed out after $Timeout milliseconds."
        }

        # Read outputs
        $stdout = $proc.StandardOutput.ReadToEnd() -replace "`r`n", "`n"
		$myExitCode = $proc.ExitCode
        if ($myExitCode -ne 0) 
		{
            $stderr = $proc.StandardError.ReadToEnd() -replace "`r`n", "`n"
			throw "OpenSSL command failed with exit code $($proc.ExitCode). Error: $stderr"
        }
    }    
    catch 
	{
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }
    finally 
	{
        # Release process resources
        if ($proc -ne $null) 
		{
            $proc.Dispose()
        }
    }

    # Return an object with execution details
    return [pscustomobject]@{
        Success 	= [boolean] $bSuccess
        Message 	= [string] 	$StatusMessage
		ExitCode 	= [string] 	$myExitCode
        StdOut  	= [string] 	$stdout
        StdErr  	= [string] 	$stderr
    }
}

function New-EitCACertificate {
    <#
    .SYNOPSIS
        Generate a CA-certificat

    .DESCRIPTION
        The New-EitCACertificat command generates a CA certificate using the options specified

    .PARAMETER passphrase
        Key encryption passphrase (must be a secure character string)

    .PARAMETER ValidDays
		Certificate validity in days. Default is 3650 days. Minimum is 30 and maximum is 9125 (i.e. 25 years)

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

    .EXAMPLE
        New-EitCACertificate -Passphrase mySecureString 
        Generate a CA certificate EducateIT-CA.crt & EducateIT-CA.key in "C:\Program Files\EducateIT\Keys" using input mySecureString as passphrase

    .OUTPUTS
        Success						: True or False
		Message						: Successfully created CA certificate
		CertificateSigningRequest	: Path to the created csr file
		KeyFile						: Path to the key file
		
	.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 09.09.2024 - M.Trojahn - Initial creation
				V1.1 - 06.01.2025 - M.Trojahn - Use Invoke-EitOpenSSLCommand
		
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
		[ValidatePattern("^[\w\-. ]+$")]
		[String] $OutputName = "EducateIT-CA"
    )
	# Initialize return values
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully created CA certificate"
	[string] 	$CertificateFile = $null
	[string] 	$KeyFile = $null
	[string] 	$rand = Join-Path $env:TEMP "opensslrand"
	
	try
	{
		if (!(Test-Path $OutputPath)) 
		{
            try 
			{
                New-Item -Path $OutputPath -ItemType "directory" -ErrorAction Stop
            } 
			catch 
			{
                throw "Failed to create directory at $OutputPath. Error: $($_.Exception.Message)"
            }
        }
		$myShortPath = Get-EitShortPath -Path $OutputPath
		
		if ($myShortPath.Success -eq $True)
		{
			$OutputPath = $myShortPath.ShortPath
			$CertificateFile = ($OutputPath + "\" + $OutputName + ".crt")
			$KeyFile = ($OutputPath + "\" + $OutputName + ".key")
			
			if (!(Test-Path $CertificateFile))
			{
				# OpenSSL arguments
				$arguments = @("req")

				$arguments += "-new"
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
				
				
				$password = ''
				$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase))
				$arguments += "pass:$password"

				$rc = Invoke-EitOpenSSLCommand -Arguments $arguments
				$password = $null
				if ($rc.Success -ne $true) 
				{
					throw $rc.Message
				}
			}
			else
			{
				throw "ERROR: CA Certificate $CertificateFile already exists!"
			}	
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	finally 
	{
		if (Test-Path $rand) 
		{
			Remove-Item -Path $rand -Force -ErrorAction SilentlyContinue
		}
	}
	$ReturnObject = ([pscustomobject]@{
		Success			= [boolean] $bSuccess
		Message			= [string] 	$StatusMessage
		CertificateFile	= [string] 	$CertificateFile
		KeyFile			= [string] 	$KeyFile
	})
    return $ReturnObject
}

function New-EitCertificateSigningRequest {
    <#
    .SYNOPSIS
        Generate a certificate signing request

    .DESCRIPTION
        The New-EitCertificateSigningRequest command generates a certificate signing request using the options specified.

   .PARAMETER OutputPath
		Path to store the certificate

	.PARAMETER OutputName
		the base name of the files
	
	.PARAMETER CommonName
		the common name (fqdn)

    .EXAMPLE
		New-EitCertificateSigningRequest 
        Generate a certificate signing request Raptor-Server.csr in "C:\Program Files\EducateIT\Keys" 

    .OUTPUTS
        Success						: True or False
		Message						: Successfully created certificate signing request
		CertificateSigningRequest	: Path to the created csr file
		KeyFile						: Path to the key file
		
	.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 09.09.2024 - M.Trojahn - Initial creation
				V1.1 - 06.01.2025 - M.Trojahn - Use Invoke-EitOpenSSLCommand
		
    #>

    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$false, HelpMessage="The output path")]
		[ValidateNotNullOrEmpty()]
		[String] $OutputPath = "C:\Program Files\EducateIT\Keys",
		
		[Parameter(Mandatory=$false, HelpMessage="the output base name")]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern("^[\w\-. ]+$")]
		[String] $OutputName = "Raptor-Server",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern("^[a-zA-Z0-9\-.*]+$")]
		[String] $CommonName = "*.$env:DNSDomain"
		
    )

	# Initialize return values
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully created certificate signing request"
	[string] 	$CertificateFile = $null
	[string] 	$KeyFile = $null
	[string] 	$rand = Join-Path $env:TEMP "opensslrand"
	
	try
	{
		if (!(Test-Path $OutputPath)) 
		{
            try 
			{
                New-Item -Path $OutputPath -ItemType "directory" -ErrorAction Stop
            } 
			catch 
			{
                throw "Failed to create directory at $OutputPath. Error: $($_.Exception.Message)"
            }
        }
		
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

			$rc = Invoke-EitOpenSSLCommand -Arguments $arguments
			if ($rc.Success -ne $true) 
			{
				throw $rc.Message
			}
			
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	finally 
	{
		if (Test-Path $rand) 
		{ 
			Remove-Item $rand -Force 
		}
	}
	$ReturnObject = ([pscustomobject]@{
		Success						= [boolean] $bSuccess
		Message						= [string] 	$StatusMessage
		CertificateSigningRequest	= [string] 	$CertificateFile
		KeyFile						= [string] 	$KeyFile
	})
    return $ReturnObject
}

function New-EitSelfSignedCertificate {
    <#
    .SYNOPSIS
        Generate a Self Signed Certificate

    .DESCRIPTION
        The New-EitSelfSignedCertificate command generates Self Signed Certificate using the options specified.

    .PARAMETER passphrase
        Key encryption passphrase.

    .PARAMETER ValidDays
        Certificate validy in days. Default is 30 days. Minimum is 30 and maximum is 9125 (i.e. 25 years).

	.PARAMETER OutputPath
		Path to store the certificate

	.PARAMETER OutputName
		the base name of the files

    .EXAMPLE
        New-EitSelfSignedCertificate CACertificateFile myCA.crt -CAKeyFile myCA.key -CertificateSigningRequest myCertificateSigningRequest -Passphrase myCAPassphrase 
 
    .OUTPUTS
        Success			: True or False
		Message			: Successfully created self signed certificate
		CertificateFile	: Path to certificate.crt
		
	.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 09.09.2024 - M.Trojahn - Initial creation
				V1.1 - 06.01.2025 - M.Trojahn - Use Invoke-EitOpenSSLCommand
		
    #>

    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$false, HelpMessage="The output path")]
		[ValidateNotNullOrEmpty()]
		[String] $OutputPath = "C:\Program Files\EducateIT\Keys",
		
		[Parameter(Mandatory=$false, HelpMessage="The output name")]
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
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String] $CertificateSigningRequest,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String] $CACertificateFile,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String] $CAKeyFile
    )
	
	# Initialize return values
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully created self signed certificate"
	[string] 	$CertificateFile = $null

	try
	{
		if (!(Test-Path $OutputPath)) 
		{
            try 
			{
                New-Item -Path $OutputPath -ItemType "directory" -ErrorAction Stop
            } 
			catch 
			{
                throw "Failed to create directory at $OutputPath. Error: $($_.Exception.Message)"
            }
        }
		$myShortPath = Get-EitShortPath -Path $OutputPath
		
		if ($myShortPath.Success -eq $True)
		{
			$OutputPath = $myShortPath.ShortPath
			$CertificateFile = $OutputPath + "\" + $OutputName + ".crt"
			
			if (!(Test-Path $CertificateFile))
			{
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
				$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase))
				$arguments += "pass:$password"
				
				$rc = Invoke-EitOpenSSLCommand -Arguments $arguments
				$password = $null
				if ($rc.Success -ne $true) 
				{
					throw $rc.Message
				}
			}
			else
			{
				throw "ERROR: Certificate $CertificateFile already exists!"
			}	
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{
		Success			= [boolean]	$bSuccess
		Message			= [string]	$StatusMessage
		CertificateFile	= [string]	$CertificateFile
	})
    return $ReturnObject
}

function Convert-EitPfxFile {
    <#
    .SYNOPSIS
        Convert an exported pfx file

    .DESCRIPTION
        The Convert-EitPfxFile command converts a previously exported pfx file.

	.PARAMETER OutputPath
		Path to store the certificate

    .PARAMETER PfxFile
		Path to the pfx file for conversion
		
	.PARAMETER ImportPassword	
		The password for the import (must be a secure character string)
	
    .PARAMETER OpenSslPath
        Full path to the OpenSSL executable file. Optional if 'openssl.exe' is already located in the shell's command search path.

    .EXAMPLE
		Convert-EitPfxFile -PfxFile myPFXFile -ImportPassword mySecureStringPassword 
        Generate a certificate signing request Raptor-Server.csr in "C:\Program Files\EducateIT\Keys" 

    .OUTPUTS
        Success						: True or False
		Message						: Successfully converted pfx file
		KeyFile						: Path to the key file
		localCertificateChain		: Path to the localCertificateChain file
		
		
	.NOTES  
			Copyright: (c)2025 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.01.2025 - M.Trojahn - Initial creation
		
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$PfxFile,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][SecureString]$ImportPassword,
        [Parameter(Mandatory=$false)][String]$OpenSslPath = "C:\educateitssl\openssl.exe",
        [Parameter(Mandatory=$false)][String]$OutputPath = "C:\Program Files\EducateIT\Keys"
    )

	 # Initialize return values
	[boolean]	$bSuccess 				= $true
    [string] 	$StatusMessage 			= "Successfully converted PFX file"
    [string] 	$EncryptedPrivateKey 	= $null
    [string] 	$PrivateKey 			= $null
    [string] 	$localCertificateChain 	= $null
	
	try
	{
		if (!(Test-Path $OutputPath)) 
		{
            try 
			{
                New-Item -Path $OutputPath -ItemType "directory" -ErrorAction Stop
            } 
			catch 
			{
                throw "Failed to create directory at $OutputPath. Error: $($_.Exception.Message)"
            }
        }
		
		$myImportPassword = ''
		$myImportPassword = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ImportPassword)))
		$myPassphrase = [System.Guid]::NewGuid().ToString()
		$myShortPath = Get-EitShortPath -Path $OutputPath
		
		if ($myShortPath.Success -eq $True)
		{
			$OutputPath = $myShortPath.ShortPath
			
			$PfxBaseName = (Get-Item -Path $PfxFile).BaseName
			$EncryptedPrivateKey = Join-Path $OutputPath "$PfxBaseName-enc.key"
			$PrivateKey = Join-Path $OutputPath "$PfxBaseName.key"
			$localCertificateChain = Join-Path $OutputPath "$PfxBaseName.pem"
			
			# Get the private .key from the .pfx certificate
			# OpenSSL arguments
			$arguments = @("pkcs12")
			$arguments += "-in"
			$arguments += "$PfxFile"
			$arguments += "-nocerts"		
			$arguments += "-out"
			$arguments += "$EncryptedPrivateKey"
			$arguments += "-password"
			$arguments += "pass:$myImportPassword"
			$arguments += "-passout"
			$arguments += "pass:$myPassphrase"
		
			$rc = Invoke-EitOpenSSLCommand -Arguments $arguments
			if ($rc.Success -eq $true) 
			{
				# Get the decrypted .key file from the encrypted private .key file
				# OpenSSL arguments
				$arguments = @("rsa")
				$arguments += "-in"
				$arguments += "`"$EncryptedPrivateKey`""
				$arguments += "-out"
				$arguments += "`"$PrivateKey`""
				$arguments += "-passin"
				$arguments += "pass:$myPassphrase"
				
				$rc = Invoke-EitOpenSSLCommand -Arguments $arguments
				if ($rc.Success -eq $true) 
				{
					# Get the .pem file from the .pfx file
					# OpenSSL arguments
					$arguments = @("pkcs12")
					$arguments += "-in"
					$arguments += "`"$PfxFile`""
					$arguments += "-clcerts"		
					$arguments += "-nokeys"		
					$arguments += "-out"
					$arguments += "`"$localCertificateChain`""
					$arguments += "-password"
					$arguments += "pass:$myImportPassword"
								
					$rc = Invoke-EitOpenSSLCommand -Arguments $arguments
					$myImportPassword = $null
					$arguments = $null
					if ($rc.Success -eq $true) 
					{
						# trim the resulting file
						$result = switch -Regex -File $localCertificateChain {
							'^(Bag|subject|issuer|\s)'  { <# skip these lines #> }
							default { $_ }
						}
						$result | Set-Content -Path $localCertificateChain
					}
					else
					{
						
						throw $rc.message
					}
				}
				else
				{
					throw $rc.message
				}
			}
			else
			{
				throw $rc.Message
			}
		}
		else
		{
			throw $myShortPath.Message
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	finally 
	{
        if (Test-Path $EncryptedPrivateKey) 
		{ 
			Remove-Item -Path $EncryptedPrivateKey -Force 
		}
    }
	$ReturnObject = ([pscustomobject]@{
		Success					= [boolean] $bSuccess
		Message					= [string]	$StatusMessage
		KeyFile					= [string] 	$PrivateKey
		localCertificateChain	= [string] 	$localCertificateChain
	})
    return $ReturnObject 
}


