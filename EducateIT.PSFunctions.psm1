#Import all the functions from the public folder.
Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" | ForEach-Object {
    . $_.FullName
}