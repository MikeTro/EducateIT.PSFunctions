# ===========================================================================
# LicenseFunctions.Tests.ps1
# ===========================================================================
# (c)2026 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Pester tests for LicenseFunctions.ps1
#
# History:
#   V1.0 - 21.08.2026 - M.Trojahn - Initial creation
#									 
#
#
# ===========================================================================
# Requires -Module Pester -Version 5.5.5
# Run with: -Path .\LicenseFunctions.Tests.ps1 -Output Detailed 

BeforeAll `
{
    Import-Module EducateIT.PSFunctions `
        -MinimumVersion 3.0.6.0 `
        -Force
}


Describe 'Register-EitLicense' `
{
    InModuleScope EducateIT.PSFunctions `
    {
        BeforeEach `
        {
            $script:TestApplication = 'C:\Program Files\EducateIT\Test\Test.exe'
            $script:TempOutputPath = 'C:\Temp\stdout.tmp'
            $script:TempErrorPath = 'C:\Temp\stderr.tmp'
            $script:NewTemporaryFileCallCount = 0

            Mock Test-Path `
            {
                return $true
            }

            Mock New-TemporaryFile `
            {
                if ($script:NewTemporaryFileCallCount -eq 0)
                {
                    $script:NewTemporaryFileCallCount++

                    return [pscustomobject]@{
                        FullName = $script:TempOutputPath
                    }
                }

                $script:NewTemporaryFileCallCount++

                return [pscustomobject]@{
                    FullName = $script:TempErrorPath
                }
            }

            Mock Remove-Item `
            {
            }

            Mock Get-Content `
            {
                param(
                    $LiteralPath
                )

                if ($LiteralPath -eq $script:TempOutputPath)
                {
                    return 'Standard output'
                }

                if ($LiteralPath -eq $script:TempErrorPath)
                {
                    return ''
                }

                return ''
            }
        }


        Context 'Activate parameter set' `
        {
            It 'activates the application successfully' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Activate `
                    -License 'ABCDE-12345'

                $result.Success |
                    Should -BeTrue

                $result.Mode |
                    Should -Be 'Activate'

                $result.ExitCode |
                    Should -Be 0

                $result.Message |
                    Should -Be 'Successfully activated application.'

                $result.Application |
                    Should -Be $script:TestApplication

                $result.StandardOutput |
                    Should -Be 'Standard output'
            }


            It 'passes the correct activation argument to Start-Process' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                Register-EitLicense `
                    -Application $script:TestApplication `
                    -Activate `
                    -License 'ABCDE-12345' |
                    Out-Null

                Should -Invoke Start-Process `
                    -Times 1 `
                    -Exactly `
                    -ParameterFilter `
                    {
                        $FilePath -eq $script:TestApplication -and
                        $ArgumentList -eq '--license-activate=ABCDE-12345'
                    }
            }


            It 'defines License as mandatory for Activate' `
            {
                $command = Get-Command Register-EitLicense

                $activateParameterSet = $command.ParameterSets |
                    Where-Object `
                    {
                        $_.Name -eq 'Activate'
                    }

                $licenseParameter = $activateParameterSet.Parameters |
                    Where-Object `
                    {
                        $_.Name -eq 'License'
                    }

                $licenseParameter.IsMandatory |
                    Should -BeTrue
            }


            It 'rejects an empty License value' `
            {
                {
                    Register-EitLicense `
                        -Application $script:TestApplication `
                        -Activate `
                        -License ''
                } |
                    Should -Throw
            }
        }


        Context 'Reactivate parameter set' `
        {
            It 'reactivates the application successfully' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                $result.Success |
                    Should -BeTrue

                $result.Mode |
                    Should -Be 'Reactivate'

                $result.ExitCode |
                    Should -Be 0

                $result.Message |
                    Should -Be 'Successfully reactivated application.'
            }


            It 'passes the correct reactivation argument to Start-Process' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate |
                    Out-Null

                Should -Invoke Start-Process `
                    -Times 1 `
                    -Exactly `
                    -ParameterFilter `
                    {
                        $FilePath -eq $script:TestApplication -and
                        $ArgumentList -eq '--license-reactivate'
                    }
            }


            It 'does not contain License as a parameter in Reactivate parameter set' `
            {
                $command = Get-Command Register-EitLicense

                $reactivateParameterSet = $command.ParameterSets |
                    Where-Object `
                    {
                        $_.Name -eq 'Reactivate'
                    }

                $licenseParameter = $reactivateParameterSet.Parameters |
                    Where-Object `
                    {
                        $_.Name -eq 'License'
                    }

                $licenseParameter |
                    Should -BeNullOrEmpty
            }
        }


        Context 'Parameter sets' `
        {
            It 'defines Activate and Reactivate parameter sets' `
            {
                $command = Get-Command Register-EitLicense

                $command.ParameterSets.Name |
                    Should -Contain 'Activate'

                $command.ParameterSets.Name |
                    Should -Contain 'Reactivate'
            }


            It 'defines Application as mandatory for Activate' `
            {
                $command = Get-Command Register-EitLicense

                $parameterSet = $command.ParameterSets |
                    Where-Object `
                    {
                        $_.Name -eq 'Activate'
                    }

                $parameter = $parameterSet.Parameters |
                    Where-Object `
                    {
                        $_.Name -eq 'Application'
                    }

                $parameter.IsMandatory |
                    Should -BeTrue
            }


            It 'defines Application as mandatory for Reactivate' `
            {
                $command = Get-Command Register-EitLicense

                $parameterSet = $command.ParameterSets |
                    Where-Object `
                    {
                        $_.Name -eq 'Reactivate'
                    }

                $parameter = $parameterSet.Parameters |
                    Where-Object `
                    {
                        $_.Name -eq 'Application'
                    }

                $parameter.IsMandatory |
                    Should -BeTrue
            }
        }


        Context 'Application validation' `
        {
            It 'returns an error when the application does not exist' `
            {
                Mock Test-Path `
                {
                    param(
                        $LiteralPath
                    )

                    if ($LiteralPath -eq 'C:\Missing\Application.exe')
                    {
                        return $false
                    }

                    return $true
                }

                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                $result = Register-EitLicense `
                    -Application 'C:\Missing\Application.exe' `
                    -Reactivate

                $result.Success |
                    Should -BeFalse

                $result.Message |
                    Should -Match 'does not exist'

                Should -Invoke Start-Process `
                    -Times 0
            }
        }


        Context 'Process errors' `
        {
            It 'returns an error when the application returns a non-zero exit code' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 10
                    }
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                $result.Success |
                    Should -BeFalse

                $result.ExitCode |
                    Should -Be 10

                $result.Message |
                    Should -Match 'Exit code: 10'
            }


            It 'includes StandardError in the returned error message' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 1
                    }
                }

                Mock Get-Content `
                {
                    param(
                        $LiteralPath
                    )

                    if ($LiteralPath -eq $script:TempOutputPath)
                    {
                        return ''
                    }

                    if ($LiteralPath -eq $script:TempErrorPath)
                    {
                        return 'Found no valid subscription code in the settings'
                    }

                    return ''
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                $result.Success |
                    Should -BeFalse

                $result.ExitCode |
                    Should -Be 1

                $result.Message |
                    Should -Match 'Found no valid subscription code in the settings'
            }


            It 'does not fail when StandardError contains text and ExitCode is zero' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                Mock Get-Content `
                {
                    param(
                        $LiteralPath
                    )

                    if ($LiteralPath -eq $script:TempOutputPath)
                    {
                        return 'Operation successful'
                    }

                    if ($LiteralPath -eq $script:TempErrorPath)
                    {
                        return 'This is only a warning'
                    }

                    return ''
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                $result.Success |
                    Should -BeTrue

                $result.ExitCode |
                    Should -Be 0

                $result.StandardError |
                    Should -Be 'This is only a warning'
            }


            It 'handles a Start-Process exception' `
            {
                Mock Start-Process `
                {
                    throw 'Unable to start process'
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                $result.Success |
                    Should -BeFalse

                $result.Message |
                    Should -Match 'Unable to start process'
            }
        }


        Context 'Temporary file cleanup' `
        {
            It 'creates two temporary files' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate |
                    Out-Null

                Should -Invoke New-TemporaryFile `
                    -Times 2 `
                    -Exactly
            }


            It 'removes both temporary files after successful execution' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate |
                    Out-Null

                Should -Invoke Remove-Item `
                    -Times 1 `
                    -Exactly `
                    -ParameterFilter `
                    {
                        $LiteralPath -eq $script:TempOutputPath
                    }

                Should -Invoke Remove-Item `
                    -Times 1 `
                    -Exactly `
                    -ParameterFilter `
                    {
                        $LiteralPath -eq $script:TempErrorPath
                    }
            }


            It 'removes temporary files when Start-Process fails' `
            {
                Mock Start-Process `
                {
                    throw 'Process failure'
                }

                Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate |
                    Out-Null

                Should -Invoke Remove-Item `
                    -Times 2 `
                    -Exactly
            }
        }


        Context 'Return object' `
        {
            It 'returns all expected properties' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                $result.PSObject.Properties.Name |
                    Should -Contain 'Success'

                $result.PSObject.Properties.Name |
                    Should -Contain 'Message'

                $result.PSObject.Properties.Name |
                    Should -Contain 'Application'

                $result.PSObject.Properties.Name |
                    Should -Contain 'Mode'

                $result.PSObject.Properties.Name |
                    Should -Contain 'ExitCode'

                $result.PSObject.Properties.Name |
                    Should -Contain 'StandardOutput'

                $result.PSObject.Properties.Name |
                    Should -Contain 'StandardError'
            }


            It 'returns exactly seven result properties' `
            {
                Mock Start-Process `
                {
                    return [pscustomobject]@{
                        ExitCode = 0
                    }
                }

                $result = Register-EitLicense `
                    -Application $script:TestApplication `
                    -Reactivate

                @($result.PSObject.Properties).Count |
                    Should -Be 7
            }
        }
    }
}
