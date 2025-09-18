# RunTests.ps1
# PowerShell 5.1-combatible Test-Script


Import-Module EducateIT.PSFunctions -Force -ErrorAction SilentlyContinue

# run Pester
Invoke-Pester -Script "$PSScriptRoot\tests" -Output Detailed #Diagnostic
