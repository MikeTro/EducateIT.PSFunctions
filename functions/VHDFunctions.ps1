#
# VHDFunctions.ps1
# ===========================================================================
# (c)2021 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.4
#
# VDH Functions for Raptor Scripts
#
# History:
#   V1.0 - 01.06.2020 - M.Trojahn - Initial creation
#                                       Test-EITFileIsLocked, Resize-EitVHD
#   V1.1 - 31.08.2020 - M.Trojahn - Mount-EitVHD
#   V1.2 - 24.04.2021 - M.Trojahn - Add more info to output in Mount-EitVHD
#   V1.3 - 03.05.2021 - M.Trojahn - Supress error message in Test-EITFileIsLocked
#   V1.4 - 05.05.2021 - M.Trojahn - Add parameter LockFilePath in Mount-EitVHD
#									Add function Dismount-EitVHD
#									Use Mount-EitVHD & Dismount-EitVHD in Resize-EitVHD

function Test-EITFileIsLocked {
    <#
    .SYNOPSIS
        This function is checking if a file is being used by another process.
    
    .PARAMETER Path
        Specify the file with path which needs to be checked.
    
    .EXAMPLE
        Test-EITFileIsLocked -Path MyVDH.vhdx
		
	.NOTES  
		Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.1
		
		History:
            V1.0 - 01.06.2020 - M.Trojahn - Initial creation
			V1.1 - 03.05.2021 - M.Trojahn - Supress error message
    #>
    param (
        [parameter(Mandatory = $true)]
        [string]$Path
    )
	$FileIsLocked = $false
	$originalEAP = $ErrorActionPreference;
    $ErrorActionPreference = "ignore"
    $oFile = New-Object System.IO.FileInfo $Path
	
	try {
		$oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
		
	} 
	catch {
		$FileIsLocked = $true
	}
	$ErrorActionPreference = $originalEAP
    if ($oStream) {
        $oStream.Close()
		$FileIsLocked = $false
    }
    else {
       $FileIsLocked = $true
    }
	
	return $FileIsLocked
}

function Resize-EitVHD {
    <#
    .SYNOPSIS
		Resize a VHD 
    .DESCRIPTION
		Resize a vhd 
	
    .PARAMETER VHDPath
		the path to the vhdx file
		
	.PARAMETER ExpandGB
		how much GB to expand
		
	.PARAMETER shrink
		shrink the vhd file
	
	.EXAMPLE
        Resize-EitVHD -VHDPath MyVDH.vhdx -LockFilePath myLockFilePath -shrink
        Shrinks the myVHD.vhdx

    .EXAMPLE
        Resize-EitVHD -VHDPath MyVDH.vhdx -LockFilePath myLockFilePath -ExpandGB 15
        Expands the myVHD.vhdx with 15 GB    
		
	.NOTES  
		Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.1
		
		History:
            V1.0 - 01.06.2020 - M.Trojahn - Initial creation
			V1.0 - 05.05.2021 - M.Trojahn - Use Mount-EitVHD & Dismount-EitVHD 
			
    #>	
	Param(
        [Parameter(Mandatory=$True)] [string] $VHDPath,
        [int] $ExpandGB,
        [switch] $Shrink
    )
    try {
        $bSuccess = $True
        $StatusMessage = "Successfully resized vhd $VHDPath"
        $OldFileSize = (Get-Item $VHDPath).Length / 1GB
        $FileSize = $OldFileSize
        $FileSizeSaving = 0
        $ActualSize = 0
        $NewSize = 0
        if ((Test-EitFileIsLocked -Path $VHDPath -ErrorAction SilentlyContinue) -eq $false) {
			
			if ($Shrink) {
				# Mount ReadOnly 
				$Mount = Mount-EitVHD -VHDPath $VHDPath -ReadOnly
			}
			else {
				$Mount = Mount-EitVHD -VHDPath $VHDPath
			}	
			if ($Mount.Success -eq $True) {
				$MyVolume = Get-Disk -DeviceId $Mount.DiskNumber | Get-Partition | Get-Volume	
				$ActualSize = $MyVolume.Size
				$NewSize = $ActualSize
				if ($Shrink) {
					Optimize-VHD -Path $VHDPath -Mode full
					$FileSize = (Get-Item $VHDPath).Length / 1GB
					$FileSizeSaving = $OldFileSize - $FileSize
					$FileSizeSaving = [math]::Round($FileSizeSaving , 2)
				}
				if ($ExpandGB) {
					$Expand = $ExpandGB * 1073741824
					$NewSize = $ActualSize + $Expand
					Resize-VHD -Path $VHDPath -SizeBytes $NewSize
					$MyPartition = Get-Volume -FileSystemLabel $MyVolume.FileSystemLabel | get-partition
					$MyPartition | Resize-Partition -Size ($MyPartition | Get-PartitionSupportedSize).sizemax
					$FileSize = (Get-Item $VHDPath).Length / 1GB
				}
				
				$Dismount = Dismount-EitVHD -DiskNumber $Mount.DiskNumber
				if ($Dismount.Success -ne $True) {
					throw $Dismount.Message
				}		
			}	
			else {
				throw $Mount.Message
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
    $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;FileSystemLabel=$MyVolume.FileSystemLabel;OldDiskSize=$ActualSize/1GB;DiskSize=$NewSize/1GB;OldFileSize=$OldFileSize;FileSize=$FileSize;FileSizeSaving=$FileSizeSaving})
    return $ReturnObject
}

function Mount-EitVHD { 
    <#
     .SYNOPSIS
            Mount VHD to the next free drive letter
        .DESCRIPTION
            Mount VHD to the next free drive letter
        
        .PARAMETER VHDPath
            the path to the vhdx file
			
		.PARAMETER LockFilePath
			the path for the lock files	
		
		.PARAMETER ReadOnly
			Mount the disk read only.
			Use this paramater for optimizing the disk
			
			
        .OUTPUTS
			Success        	: True
			Message     	: VHD $VHDPath successfully mounted
			DriveLetter 	: a drive letter
			DiskNumber 		: the disknumer
			VHDPath			: the path to the vhd
			ReadOnly		: True or False
			DateTime		: the mount time

        .EXAMPLE
            Mount-EitVHD -VHDPath MyVDH.vhdx
			
		.EXAMPLE
            Mount-EitVHD -VHDPath MyVDH.vhdx -ReadOnly
           
        .NOTES  
            Copyright	: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.4
			Credits to https://github.com/FSLogix/Invoke-FslShrinkDisk/
            
            History:
                V1.0 - 10.08.2020 - M.Trojahn - Initial creation
				V1.1 - 23.04.2021 - M.Trojahn - Add disknumber 
				V1.2 - 24.04.2021 - M.Trojahn - Add VHDPath to output
				V1.3 - 05.05.2021 - M.Trojahn - Add parameter LockFilePath and LockFile generation
				V1.4 - 25.05.2021 - M.Trojahn - Add TimeOut paramtere, waiting for mount (see credits)
				
    #>	
    Param(
        [Parameter(Mandatory=$True)] [string] $VHDPath,
		[Parameter(Mandatory=$False)] [string] $LockFilePath=($env:EducateITFiles + "\" + "VHDLockFiles"),
		[Parameter(Mandatory=$False)] [int] $TimeOut = 30,
		[Parameter(Mandatory=$False)] [switch] $ReadOnly
    )
	
    Try {
		if (!(Test-Path -Path $LockFilePath)) {New-Item -Path $LockFilePath -ItemType Directory}
        $bSuccess = $True
        $StatusMessage = "VHD $VHDPath successfully mounted"
		if (Test-Path -Path $VHDPath) {
			if ((Test-EitFileIsLocked -Path $VHDPath -ErrorAction SilentlyContinue) -eq $false) {
				if ($ReadOnly) {
					# Mount-VHD -ReadOnly 
					$MyMount = (Mount-VHD -Path $VHDPath -ReadOnly -PassThru -ErrorAction Stop ) 
				}
				else {
					$MyMount = (Mount-VHD -Path $VHDPath -PassThru -ErrorAction Stop) 
				}
				
				$MyDiskNumber = $null
				$TimeSpan = (Get-Date).AddSeconds($TimeOut)
				while ($MyDiskNumber -eq $null -and $timespan -gt (Get-Date)) {
					Start-Sleep 0.1
					try {
						$MyVHD = Get-VHD -Path $VHDPath
						if ($MyVHD.Number) {
							$MyDiskNumber = $MyVHD.Number
						}
					}
					catch {
						$MyDiskNumber = $null
					}
				}
				if ($MyDiskNumber -eq $null) {
					throw "Timeout reached, while getting mount information"
				return
				}
				
				$MyDisk = Get-Disk -Number $MyDiskNumber
				$MyPartition = Get-Partition -DiskNumber $MyDisk.Number
				$MyVolume = Get-Volume -Partition $MyPartition
				
				if ($MyVolume.DriveLetter -eq $null)  {
					$DriveLetter =  Get-EitNextFreeDrive
					Set-Partition -DiskNumber $MyDisk.DiskNumber -PartitionNumber $MyPartition.PartitionNumber -NewDriveLetter $DriveLetter.Substring(0,1)
				}
				else {
					$DriveLetter = ($MyVolume.DriveLetter + ":")
				}
				
				$MountInfo = ([pscustomobject]@{DateTime=Get-Date;DriveLetter=$DriveLetter;DiskNumber=$MyDisk.DiskNumber;VHDPath=$VHDPath;ReadOnly=$ReadOnly}) 
				#Create lock file
				$LockFileName = ("Disk" + $MountInfo.DiskNumber + ".lck")
				$MountInfo | Export-Clixml -Path ($LockFilePath + "\" + $LockFileName)
				
			}
			else {
				throw "Access denied on $VHDPath!"            
			}  
		}
		else {
			throw "VHD $VHDPath does not exists!"            
		}  		
    }
    catch {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
        Dismount-VHD -Path $VHDPath -ErrorAction Stop
    }
    finally {
        $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;DateTime=Get-Date;DriveLetter=$DriveLetter;DiskNumber=$MyDisk.DiskNumber;VHDPath=$VHDPath;ReadOnly=$ReadOnly}) 
    }
    return $ReturnObject
}



function Dismount-EitVHD { 
    <#
     .SYNOPSIS
            Dismount a mounted VHD and remove the lock file
        .DESCRIPTION
            Dismount a mounted VHD
        
		.PARAMETER DiskNumber
            the path to the vhdx file	
			
		.PARAMETER LockFilePath
			the path for the lock files	
		
        .OUTPUTS
			Success        	: True
			Message     	: Disk $DiskNumber successfully dismounted

        .EXAMPLE
            Dismount-EitVHD -DiskNumber 1
			
        .NOTES 
            Copyright	: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.1
			Credits to https://github.com/FSLogix/Invoke-FslShrinkDisk/
            
            History:
                V1.0 - 05.05.2021 - M.Trojahn - Initial creation
				V1.1 - 25.05.2021 - M.Trojahn - Add TimeOut param, testing if disk realy dismounted
				
				
    #>	
    Param(
        [Parameter(Mandatory=$True)] [int] $Disknumber,
		[Parameter(Mandatory=$False)] [int] $TimeOut = 30,
		[Parameter(Mandatory=$False)] [string] $LockFilePath=($env:EducateITFiles + "\" + "VHDLockFiles")
    )
    try {
        $bSuccess = $True
		$StatusMessage = "Disk $DiskNumber successfully dismounted"
		$LockFileName = ("Disk" + $DiskNumber + ".lck")
		$timeStampDismount = (Get-Date).AddSeconds($TimeOut)
        while ((Get-Date) -lt $timeStampDismount -and $mountRemoved -ne $true) {
			try {
				Dismount-VHD -DiskNumber $DiskNumber -ErrorAction Stop | Out-Null
				#double/triple check disk is dismounted due to disk manager service being a pain.

				try {
					$MyVHD = Get-VHD -DiskNumber $DiskNumber -ErrorAction Stop

					switch ($MyVHD.Attached) {
						$null { $mountRemoved = $false ; Start-Sleep 0.1; break }
						$true { $mountRemoved = $false ; break}
						$false { $mountRemoved = $true ; break }
						Default { $mountRemoved = $false }
					}
				}
				catch {
					$mountRemoved = $false
				}
			}
			catch {
				$mountRemoved = $false
			}
		}	
		if ($mountRemoved -ne $true) {
			throw "Failed to dismount disknumber $DiskNumber"
		}
		
    }
    catch {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
        
    }
    finally {
        $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;}) 
    }
    return $ReturnObject
}



function New-EitVHD { 
    <#
     .SYNOPSIS
            Create a new VHD, create partition, initalize and format it
        .DESCRIPTION
           Create a new VHD, create partition, initalize and format it
        
		.PARAMETER SizeBytes
            the size in bytes, 1 MB, 1 GB
			
		.PARAMETER VHDPath
            the path to the vhdx file
			
        .OUTPUTS
			Success        	: True
			Message     	: VHD $VHDPath successfully created
			

        .EXAMPLE
           New-EitVHD -VHDPath MyVDH.vhdx -SizeBytes 1GB
			
        .NOTES  
            Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
            Version		:	1.0
            
            History:
                V1.0 - 25.05.2021 - M.Trojahn - Initial creation
				
				
    #>	
    Param(
        [Parameter(Mandatory=$True)] [string] $VHDPath,
		[Parameter(Mandatory=$True)] [int] $SizeBytes

    )
    try {
        $bSuccess = $True
		$StatusMessage = "Disk $VHDPath successfully created"
		if (!(Test-Path -Path $VHDPath)) {
			$MyVHD = New-VHD -Path $VHDPath -Dynamic -SizeBytes $SizeBytes -ErrorAction Stop
			$MyMount = Mount-VHD $VHDPath -Passthru -ErrorAction Stop 
			$MyPartition = $null
			$MyPartition = Get-Partition -DiskNumber $MyMount.Number -ErrorAction SilentlyContinue
			if ($MyPartition -eq $null) {
				$MyInit = Initialize-Disk -Number $MyMount.Number -Passthru -ErrorAction Stop  
				$MyPartition = New-Partition -DiskNumber $MyMount.Number -UseMaximumSize -ErrorAction Stop 		
				$MyFormat = Format-Volume -Partition $MyPartition -FileSystem NTFS -Confirm:$false -Force -ErrorAction Stop 
			}  
		}
		else {
			throw "VHD $VHDPath already exists!"            
		}  
		
    }
    catch {
        $bSuccess = $false
        $StatusMessage = $_.Exception.Message
        
    }
    finally {
		$MyVHDTst = Get-VHD -Path $VHDPath
		if ($MyVHDTst.Attached) {
			Dismount-VHD -Path $VHDPath
		}	
        $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;}) 
    }
    return $ReturnObject
}

