# ===========================================================================
# LogFunctions.Tests.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Pester tests for LogFunctions.ps1
#
# History:
#   V1.0 - 17.10.2025 - M.Trojahn - Initial creation
#									 
#
#
# ===========================================================================
# Requires -Module Pester -Version 5.5.5

Import-Module EducateIT.PSFunctions -Force -ErrorAction SilentlyContinue
# ===========================================================================
# LogFunctions.Tests.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Pester tests for LogFunctions.ps1
#
# History:
#   V1.0 - 17.10.2025 - M.Trojahn - Initial creation
#									 
#
#
# ===========================================================================
# Requires -Module Pester -Version 5.5.5

# Run with: Invoke-Pester -Path .\SimpleLogger.Tests.ps1


$testLogPath = "$PSScriptRoot\testlog.log"
$dateStamp = (Get-Date).ToString("yyyy-MM-dd")
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($testLogPath)
$extension = [System.IO.Path]::GetExtension($testLogPath)
$directory = [System.IO.Path]::GetDirectoryName($testLogPath)

$datedName = "${baseName}_$dateStamp$extension"
$testLogFile = Join-Path -Path $directory -ChildPath $datedName

Describe 'Logger Module Tests (Pester 5.5.5)' {

    BeforeAll {
        Import-Module EducateIT.PSFunctions -Force -ErrorAction SilentlyContinue
        $global:Logger = New-EitLogger -LogFilePath $testLogPath -MaxFileSizeKB 5 -MaxArchiveFiles 2
    }

    AfterEach {
        $Logger.Clear()
        if (Test-Path $testLogFile) {
            Remove-Item "$testLogFile*" -Force -ErrorAction SilentlyContinue
        }
    }
	Context 'logger creation' {
        It 'returns a logger instance' {
            $Logger | Should -Be 'EitLogger'
        }
    }
    Context 'Memory Logging' {
        It 'should store INFO log in memory' {
            $Logger.Info("Test Info Message")
            $Logger.Get() -join "`n" | Should -Match 'INFO.*Test Info Message'

        }

        It 'should store WARN log in memory' {
            $Logger.Warn("Test Warn Message")
			$Logger.Get() -join "`n" | Should -Match 'WARN.*Test Warn Message'
        }

        It 'should store ERROR log in memory' {
            $Logger.Error("Test Error Message")
			$Logger.Get() -join "`n" | Should -Match 'ERROR.*Test Error Message'
        }

        It 'should store DEBUG log in memory but not output to console' {
            $Logger.Debug("Test Debug Message")
			$Logger.Get() -join "`n" | Should -Match 'DEBUG.*Test Debug Message'
        }

        It 'should clear all memory log entries' {
            $Logger.Info("Message to be cleared")
            $Logger.Clear()
            $Logger.Get().Count | Should -Be 0
        }
    }

    Context 'File Logging' {
        It 'should write log file to disk' {
            $Logger.Info("File log test")
            Start-Sleep -Milliseconds 100
            Test-Path $testLogFile | Should -BeTrue
            (Get-Content $testLogFile) -join "`n" | Should -Match 'INFO.*File log test'
        }

        It 'should create a rolled log file when max size is exceeded' {
            for ($i = 0; $i -lt 300; $i++) {
                $Logger.Info("Filler line $i")
            }
            Start-Sleep -Milliseconds 200
            Test-Path "$testLogFile.1" | Should -BeTrue
        }
    }
}
