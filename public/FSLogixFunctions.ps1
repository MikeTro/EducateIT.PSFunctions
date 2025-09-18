#
# FSLogixFunctions.ps1
# ===========================================================================
# (c)2020 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# FSLogix Functions for Raptor Scripts
#
# History:
#   V1.0 - 10.08.2020 - M.Trojahn - Initial creation
#                                   Remove-EitRegistryKeysfromFSlogixProfileContainer, Remove-EitFoldersfromFSlogixContainer, Remove-EitFilesfromFSlogixContainer


function Remove-EitRegistryKeysfromFSlogixProfileContainer { 
    <#
     .Synopsis
            Removes registry key from FSLogix Profile Container
    .Description
        Resize a vhd 
    
    .Parameter VHDPath
        Removes registry key from FSLogix Profile Container
        
    .Parameter RegistryKeyPath
        the reg key path to remove
    
    .EXAMPLE
        Remove-EitRegistryKeysfromFSlogixProfileContainer -VHDPath MyVDH.vhdx -RegistryKeyPath Software\EducateIT
        
    .NOTES  
        Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
        Version		:	1.0
        
        History:
            V1.0 - 10.08.2020 - M.Trojahn - Initial creation
    #>	
    Param(
        [Parameter(Mandatory=$True)] [string] $VHDPath,
        [Parameter(Mandatory=$True)] [String[]] $RegistryKeyPath
        
    )
    Try {
        $bSuccess = $True
        $StatusMessage = "Successfully removed $RegistryKeyPath from vhd $VHDPath"
        
        if ((Test-EitFileIsLocked -Path $VHDPath -ErrorAction SilentlyContinue) -eq $false) {
            $MyDisk = (Mount-VHD -Path $VHDPath -PassThru | Get-Disk)
            $MyPartition = Get-Partition -DiskNumber $MyDisk.Number
            $MyVolume = Get-Volume -Partition $MyPartition
            
            if ($MyVolume.DriveLetter -eq $null)  {
                $DriveLetter =  Get-EitNextFreeDrive
                Set-Partition -DiskNumber $MyDisk.DiskNumber -PartitionNumber $MyPartition.PartitionNumber -NewDriveLetter $DriveLetter.Substring(0,1)
            }
            else {
                $DriveLetter = ($MyVolume.DriveLetter + ":")
            }
            $NTuserDatPath = $DriveLetter + "\Profile\ntuser.dat"
            
            if (!(Test-Path $NTuserDatPath)) {
                throw "VHD $VHDPath is not a profile container!"       
            }
            else {
                $MyRandomNumber = Get-Random
                $MyTempName = $MyVolume.FileSystemLabel + $MyRandomNumber
                $MyHive = "HKLM\$MyTempName" 
                # loading ntuser.dat into registry
                reg load $MyHive $NTuserDatPath  | Out-Null

                New-PSDrive -Name $MyTempName -PSProvider Registry -Root $MyHive -Scope Global | Out-Null
                
                foreach ($item in $RegistryKeyPath) {
                    if (Test-Path ($MyTempName + ":\" + $item)) {
                        Remove-Item ($MyTempName + ":\" + $item) -Recurse         
                    }   
                    else {
                        throw "Registry Key $item does not exists!"            
                    }          
                }   
            }
        }
        else {
            throw "Access denied on $VHDPath."            
        }   
    }
    catch {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }
    finally {
        # unloading ntuser.dat from registry
        [gc]::Collect()
        Start-Sleep 1
        Remove-PSDrive -Name $MyTempName | Out-Null
        reg unload $MyHive | Out-Null
        Dismount-VHD -Path $VHDPath   
    }
    $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
    return $ReturnObject
}
    
function Remove-EitFoldersfromFSlogixContainer { 
    <#
        .Synopsis
            Removes folders from FSLogix Container
        .Description
            Removes folders from FSLogix Container
        
        .Parameter VHDPath
            Removes folders key from FSLogix Container
            
        .Parameter Folders
            the folder paths to remove
        
        .EXAMPLE
            Remove-EitFoldrsFSlogixContainer -VHDPath MyVDH.vhdx -Folders OneDrive, Teams
            Removes the Teams and OneDrive Folder
            
        .NOTES  
            Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0
            
            History:
                V1.0 - 10.08.2020 - M.Trojahn - Initial creation
    #>	
    Param(
        [Parameter(Mandatory=$True)] [string] $VHDPath,
        [Parameter(Mandatory=$True)] [String[]] $Folders
        
    )
    Try {
        $bSuccess = $True
        $StatusMessage = "Successfully removed $Folders from vhd $VHDPath"
        
        if ((Test-EitFileIsLocked -Path $VHDPath -ErrorAction SilentlyContinue) -eq $false) {
            $MyDisk = (Mount-VHD -Path $VHDPath -PassThru | Get-Disk)
            $MyPartition = Get-Partition -DiskNumber $MyDisk.Number
            $MyVolume = Get-Volume -Partition $MyPartition
            
            if ($MyVolume.DriveLetter -eq $null)  {
                $DriveLetter =  Get-EitNextFreeDrive
                Set-Partition -DiskNumber $MyDisk.DiskNumber -PartitionNumber $MyPartition.PartitionNumber -NewDriveLetter $DriveLetter.Substring(0,1)
            }
            else {
                $DriveLetter = ($MyVolume.DriveLetter + ":")
            }
            foreach ($item in $Folders) {
                $MyFolder = $DriveLetter + "\" + $item
                Write-Host $MyFolder
                if (Test-Path $MyFolder) {
                    Remove-Item $MyFolder -Recurse         
                }   
                else {
                    throw "Folder $item does not exists!"            
                }          
            }
        }
        else {
            throw "Access denied on $VHDPath."            
        }   
    }
    catch {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }
    finally {
        Dismount-VHD -Path $VHDPath   
    }
    $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
    return $ReturnObject
}

    
    
function Remove-EitFilesfromFSlogixContainer { 
    <#
        .Synopsis
            Removes files from FSLogix Container
        .Description
            Removes files from FSLogix Container
        
        .Parameter VHDPath
            Removes folders key from FSLogix Container
            
        .Parameter Folders
            the files paths to remove
        
        .EXAMPLE
            Remove-EitFilesFSlogixContainer -VHDPath MyVDH.vhdx -Files OneDrive, Teams
            Removes the Teams and OneDrive Folder
            
        .NOTES  
            Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0
            
            History:
                V1.0 - 10.08.2020 - M.Trojahn - Initial creation
    #>	
    Param(
        [Parameter(Mandatory=$True)] [string] $VHDPath,
        [Parameter(Mandatory=$True)] [String[]] $Files
        
    )
    Try {
        $bSuccess = $True
        $StatusMessage = "Successfully removed $Files from vhd $VHDPath"
        
        if ((Test-EitFileIsLocked -Path $VHDPath -ErrorAction SilentlyContinue) -eq $false) {
            $MyDisk = (Mount-VHD -Path $VHDPath -PassThru | Get-Disk)
            $MyPartition = Get-Partition -DiskNumber $MyDisk.Number
            $MyVolume = Get-Volume -Partition $MyPartition
            
            if ($MyVolume.DriveLetter -eq $null)  {
                $DriveLetter =  Get-EitNextFreeDrive
                Set-Partition -DiskNumber $MyDisk.DiskNumber -PartitionNumber $MyPartition.PartitionNumber -NewDriveLetter $DriveLetter.Substring(0,1)
            }
            else {
                $DriveLetter = ($MyVolume.DriveLetter + ":")
            }
            foreach ($item in $Files) {
                $MyFile = $DriveLetter + "\" + $item
                Write-Host $MyFile
                if (Test-Path $MyFile) {
                    Remove-Item $MyFile      
                }   
                else {
                    throw "File $item does not exists!"            
                }          
            }
        }
        else {
            throw "Access denied on $VHDPath."            
        }   
    }
    catch {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
    }
    finally {
        Dismount-VHD -Path $VHDPath   
    }
    $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
    return $ReturnObject
}

    
    