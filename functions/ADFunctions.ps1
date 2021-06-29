#
# ADFunctions.ps1
# ===========================================================================
# (c) 2021 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.8
#
# AD Functions for Raptor Scripts
#
# History:
#   V1.0 - 03.02.2016 - M.Trojahn - Initial creation
#   V1.1 - 13.04.2016 - M.Trojahn - Add Get-EitGroupMembers
#                                 - Add Group Param in Get-EitDirectoryEntry
#   V1.2 - 04.12.2017 - M.Trojahn - Get-EitADUserLastLogon
#   V1.3 - 26.02.2020 - M.Trojahn - Get-EitADComputer
#  									Remove Is-EitGroupMember, add Test-EitGroupMember
#   V1.4 - 31.03.2020 - M.Trojahn - Add Get-EitLapsPassword
#   V1.5 - 08.12.2020 - M.Trojahn - Fix error in Get-EitGroupMembers
#   V1.6 - 06.04.2021 - M.Trojahn - Get-EitBitLockerPassword
#   V1.7 - 14.06.2021 - M.Trojahn - Error handling in Get-EitDirectoryEntry, Get-EitRDSProfilePath, Add-EitUser2Group, Remove-EitUserFromGroup, Get-EitGroupMembers
#   V1.8 - 29.06.2021 - M.Trojahn - Use correct function Test-EitGroupMember instead of Is-EitGroupMember in Add-EitUser2Group


function Get-EitDirectoryEntry
{ 
	<#
		.Synopsis
			Find DirectoryEntry  
		.Description
			Find DirectoryEntry
		
		.Parameter ADFindType
			the ad find type (user / computer, group)
			
		.Parameter DNSDomain
			the dns domain name
			
		.Parameter cName
			the users cname 
		
		.EXAMPLE
			Get-EitDirectoryEntry -ADFindType user -DNSDomain MyDomainFDQN -cName MyUserName
			
		.OUTPUTS
			Success        : True
			Message        : Successfully get GetDirectoryEntry for tbetrmi1
			DirectoryEntry : System.DirectoryServices.DirectoryEntry


		.NOTES  
			Copyright: (c)2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 03.02.2016 - M.Trojahn - Initial creation
				V1.1 - 14.06.2021 - M.Trojahn - return false if object doesn't exists
	#>	
	Param(
		[Parameter(Mandatory=$True)] [ValidateSet("user", "computer", "group")] [string] $ADFindType,
		[Parameter(Mandatory=$True)] [string] $DNSDomain,
		[Parameter(Mandatory=$True)] [string] $cName
	)
	
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully get GetDirectoryEntry for $cName"
	
	try
	{ 
		# Create A New ADSI Call 
		$root = [ADSI]'' 
		# Create a New DirectorySearcher Object 
		$searcher = new-object System.DirectoryServices.DirectorySearcher($root) 
		$searcher.SearchRoot = [adsi]"LDAP://$DNSDomain"
		# Set the filter to search for a specific CNAME 
		$searcher.filter = "(&(objectClass=$ADFindType) (CN=$cName))" 
		# Set results in $adfind variable 
		$adfind = $null
		$adfind = $searcher.FindOne()
		if ($adfind -eq $null)
		{
			throw "$ADFindType $cName not found!"
		}
	}
	
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	if ($bSuccess -ne $false)
	{
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;DirectoryEntry=$adfind.GetDirectoryEntry()})
	}
	else
	{
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;DirectoryEntry="n/a"})
	}
	return $ReturnObject
}

function Get-EitRDSProfilePath
{
	<#
		.Synopsis
			Get RDSProfilePath 
		.Description
			Get RDSProfilePath
		
		.Parameter samAccountName
			the users samAccountName
			
		.Parameter DNSDomain
			the dns domain name
			
		.EXAMPLE
			Get-EitRDSProfilePath -DNSDomain MyDomainFDQN -samAccountName MysamAccountName
			
		.OUTPUTS
			Success        : True
			Message        : Successfully get RDSProfilePath for MyUser
			RDSProfilePath : \\MyServer\UserProfile$\MyUser


		.NOTES  
			Copyright: (c) 2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.1
			
			History:
				V1.0 - 03.02.2016 - M.Trojahn - Initial creation
				V1.1 - 14.06.2021 - M.Trojahn - Error handling from Get-EitDirectoryEntry
				
	#>	
	
	Param(
		[Parameter(Mandatory=$True)] [string] $DNSDomain,
		[Parameter(Mandatory=$True)] [string] $samAccountName
	)
	
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "Successfully get RDSProfilePath for $samAccountName"
	
	try
	{
		$DirectoryEntry = Get-EitDirectoryEntry -ADFindType "User" -DNSDomain $DNSDomain -cName $samAccountName
		if ($DirectoryEntry.Success -eq "True")
		{
			$UserDN = $DirectoryEntry.DirectoryEntry.distinguishedName
			$userSearch = [adsi]("LDAP://" + $UserDN)
			$RDSProfilePath = $userSearch.psbase.InvokeGet("terminalservicesprofilepath")
		}
		else
		{
			throw $DirectoryEntry.Message
		}
	}
	
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	if ($bSuccess -ne $false)
	{
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;RDSProfilePath=$RDSProfilePath})
	}
	else
	{	
		$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;RDSProfilePath="n/a"})
	}
	return $ReturnObject
}

function Set-EitRDSProfilePath
{
	<#
		.Synopsis
			Set RDSProfilePath 
		.Description
			Sets the RDSProfilePath
		
		.Parameter samAccountName
			the users samAccountName
		
		.Parameter RDSProfilePath
			the RDSProfilePath to set
			
		.Parameter DNSDomain
			the dns domain name
		
		Parameter AdminUser
			only use admin user, if you do not have the permission to modify the user
		
		.Parameter AdminPassword
			the password, if you use AdminUser
			
		.EXAMPLE
			Set-EitRDSProfilePath -DNSDomain MyDomainFDQN -samAccountName MysamAccountName -RDSProfilePath \\MyServer\UserProfile$\MyUser
			Set-EitRDSProfilePath -DNSDomain MyDomainFDQN -samAccountName MysamAccountName -RDSProfilePath \\MyServer\UserProfile$\MyUser -AdminUser MyAdminUser -AdminPassword MyAdminPassword
			
		.OUTPUTS
			Success        : True
			Message        : RDSProfilePath has successfully been set for MyUser
			RDSProfilePath : \\MyServer\UserProfile$\MyUser


		.NOTES  
			Copyright: (c)2016 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 03.02.2016 - M.Trojahn - Initial creation
	#>	
	
	Param(
		[Parameter(Mandatory=$True)] [string] $DNSDomain,
		[Parameter(Mandatory=$True)] [string] $samAccountName,
		[Parameter(Mandatory=$True)] [string] $RDSProfilePath,
		[Parameter(Mandatory=$False)] [string] $AdminUser="", 
		[Parameter(Mandatory=$False)] [string] $AdminPassword=$Null
	)
	
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "RDSProfilePath has successfully been set for MyUser $samAccountName"
	
	try
	{
		if ($AdminUser -ne "")
		{
			#Create an object "DirectoryEntry" and specify the domain, username and password
			$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain),($DNSDomain + "\" + $AdminUser), $AdminPassword)
		}
		else
		{
			$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain))
		}
		
		$Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher($DNSDomain)
		# Add the DirectoryEntry to the search
		$Searcher.SearchRoot = $DirectoryEntry
		$Searcher.Filter = "(samAccountName=$samAccountName)";
		
		$found = $searcher.FindOne()  
		$User = $found.GetDirectoryEntry()
		$User.psbase.InvokeSet("TerminalServicesProfilePath", "$RDSProfilePath")
	
		$User.SetInfo() | Out-Null
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;RDSProfilePath=$RDSProfilePath})
	return $ReturnObject
}

function Add-EitUser2Group
{
	<#
		.Synopsis
			Add user to a group 
		.Description
			Add user to a group 
		
		.Parameter GroupName
			the group name
			
		.Parameter DNSDomain
			the dns domain name
			
		.Parameter UserName
			the username (sAmAccountName)
		
		.Parameter AdminUser
			only use admin user, if you do not have the permission to change group membership
		
		.Parameter AdminPassword
			the password, if you use AdminUser
		
		
		.EXAMPLE
			Add-EitUser2Group -DNSDomain MyDomainFDQN -UserName MyUserName -GroupName MyGroupName 
			Add-EitUser2Group -DNSDomain MyDomainFDQN -UserName MyUserName -GroupName MyGroupName -AdminUser MyAdminUser -AdminPassword MyAdminPassword
		
			
		.OUTPUTS
			Success : True
			Message : User MyUserName has successfully been added to the group MyGroupName


		.NOTES  
			Copyright: (c) 2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.2
			
			History:
				V1.0 - 03.02.2016 - M.Trojahn - Initial creation
				V1.1 - 14.06.2021 - M.Trojahn - Add error handling from Get-EitDirectoryEntry
				V1.2 - 29.06.2021 - M.Trojahn - Use correct function Test-EitGroupMember instead of Is-EitGroupMember
	#>
	
	Param(
		[Parameter(Mandatory=$True)] [string] $GroupName,
		[Parameter(Mandatory=$True)] [string] $UserName,
		[Parameter(Mandatory=$True)] [string] $DNSDomain,
		[Parameter(Mandatory=$False)] [string] $AdminUser="", 
		[Parameter(Mandatory=$False)] [string] $AdminPassword=$Null
	)
	
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "User $UserName has successfully been added to the group $GroupName"
	
	try
	{
		if ($AdminUser -ne "")
		{
			#Create an object "DirectoryEntry" and specify the domain, username and password
			$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain),($DNSDomain + "\" + $AdminUser), $AdminPassword)
		}
		else
		{
			$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain))
		}
			
		$Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher($DNSDomain)
		# Add the DirectoryEntry to the search
		$Searcher.SearchRoot = $DirectoryEntry
		$searcher.filter = "(&(objectClass=group) (CN=$GroupName))" 
			
		$found = $searcher.FindOne()  
		$MyGroup = $found.GetDirectoryEntry()

		$DirectoryEntry = Get-EitDirectoryEntry -ADFindType "User" -DNSDomain $DNSDomain -cName $UserName
		if ($DirectoryEntry.Success -eq "True")
		{
			$UserDN = $DirectoryEntry.DirectoryEntry.distinguishedName
			$MyUser = [adsi]("LDAP://" + $UserDN)
			if (!(Test-EitGroupMember -ADObject $MyUser -GroupName $GroupName))
			{
				$myGroup.Add("LDAP://" + $UserDN) | Out-Null
			}
			else
			{
				throw "User $UserName is already member of the group $GroupName"
			}
		}
		else
		{
			throw $DirectoryEntry.Message
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
	return $ReturnObject
}

function Remove-EitUserFromGroup
{
	<#
		.Synopsis
			Remove user from a group 
		.Description
			Remove user from a group  
		
		.Parameter GroupName
			the group name
			
		.Parameter DNSDomain
			the dns domain name
			
		.Parameter UserName
			the username (sAmAccountName)
		
		.Parameter AdminUser
			only use admin user, if you do not have the permission to change group membership
		
		.Parameter AdminPassword
			the password, if you use AdminUser
		
		
		.EXAMPLE
			Remove-EitUserFromGroup -DNSDomain MyDomainFDQN -UserName MyUserName -Group MyGroupName 
			Remove-EitUserFromGroup -DNSDomain MyDomainFDQN -UserName MyUserName -Group MyGroupName -AdminUser MyAdminUser -AdminPassword MyAdminPassword
		
			
		.OUTPUTS
			Success : True
			Message : User MyUserName has successfully been removed from the group MyGroupName



		.NOTES  
			Copyright	: 	(c) 2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.2
			
			History:
				V1.0 - 03.02.2016 - M.Trojahn - Initial creation
				V1.1 - 14.06.2021 - M.Trojahn - error handling from Get-EitDirectoryEntry 
				V1.2 - 29.06.2021 - M.Trojahn - Use correct function Test-EitGroupMember instead of Is-EitGroupMember
	#>
	
	Param(
		[Parameter(Mandatory=$True)] [string] $GroupName,
		[Parameter(Mandatory=$True)] [string] $UserName,
		[Parameter(Mandatory=$True)] [string] $DNSDomain,
		[Parameter(Mandatory=$False)] [string] $AdminUser="", 
		[Parameter(Mandatory=$False)] [string] $AdminPassword=$Null
	)
	
	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "User $UserName has successfully been removed from the group $GroupName"
	
	try
	{
		if ($AdminUser -ne "")
		{
			#Create an object "DirectoryEntry" and specify the domain, username and password
			$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain),($DNSDomain + "\" + $AdminUser), $AdminPassword)
		}
		else
		{
			$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain))
		}
			
		$Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher($DNSDomain)
		# Add the DirectoryEntry to the search
		$Searcher.SearchRoot = $DirectoryEntry
		$searcher.filter = "(&(objectClass=group) (CN=$GroupName))" 
			
		$found = $searcher.FindOne()  
		$MyGroup = $found.GetDirectoryEntry()

		$DirectoryEntry = Get-EitDirectoryEntry -ADFindType "User" -DNSDomain $DNSDomain -cName $UserName
		if ($DirectoryEntry.Success -eq "True")
		{
			$UserDN = $DirectoryEntry.DirectoryEntry.distinguishedName
			$MyUser = [adsi]("LDAP://" + $UserDN)
			if (Test-EitGroupMember -ADObject $MyUser -GroupName $GroupName)
			{
				$myGroup.Remove("LDAP://" + $UserDN) | Out-Null
			}
			else
			{
				throw "User $UserName is not member of the group $GroupName"
			}
		}
		else
		{
			throw $DirectoryEntry.Message
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage})
	return $ReturnObject
}

function Test-EitGroupMember
{ 
	<#
		.Synopsis
			Is user member of a group 
		.Description
			Checks if a user is member of a group  
		
		.Parameter ADObject
			the ADObject to test
			
		.Parameter GroupName
			the group name to remove
			
		.EXAMPLE
			Test-EitGroupMember -ADObject MyADObject -Groupname MyGroupName 
			
		.OUTPUTS
			true or false
			
		.NOTES  
			Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 23.03.2020 - M.Trojahn - Initial creation, based on removed function Is-EitGroupMember
	#>
	
	Param(
		[Parameter(Mandatory=$True)] $ADObject, 
		[Parameter(Mandatory=$True)] $GroupName
	)
	
	# Function to check if $ADObject is a member of security group $GroupName. 
	$GroupList = @{}
	# Check if security group memberships for this principal have been determined. 
	if ($GroupList.ContainsKey($ADObject.sAMAccountName.ToString() + "\") -eq $False)
	{ 
		# Memberships need to be determined for this principal. Add "pre-Windows 2000" 
		# name to the hash table. 
		$GroupList.Add($ADObject.sAMAccountName.ToString() + "\", $True) 
		# Retrieve tokenGroups attribute of principal, which is operational. 
		$ADObject.psbase.RefreshCache("tokenGroups") 
		$SIDs = $ADObject.psbase.Properties.Item("tokenGroups") 
		# Populate hash table with security group memberships. 
		foreach ($Value In $SIDs)
		{ 
			$SID = New-Object System.Security.Principal.SecurityIdentifier $Value, 0 
			# Translate into "pre-Windows 2000" name. 
			$Group = $SID.Translate([System.Security.Principal.NTAccount]) 
			$GroupList.Add($ADObject.sAMAccountName.ToString() + "\" + $Group.Value.Split("\")[1], $True) 
		} 
	} 
	# Check if $ADObject is a member of $GroupName. 
	if ($GroupList.ContainsKey($ADObject.sAMAccountName.ToString() + "\" + $GroupName))
	{ 
		return $True 
	}
	else
	{ 
		return $False 
	} 
} 


function Get-EitGroupMembers
{
	<#
		.Synopsis
			List Group Members 
		.Description
			List Group Members 
		
		.Parameter DNSDomain
			the dns domain name
			
		.Parameter GroupName
			the group name 
			
		Parameter AdminUser
			only use admin user, if you do not have the permission to modify the user
		
		.Parameter AdminPassword
			the password, if you use AdminUser    
		
		.EXAMPLE
			Get-EitGroupMembers -GroupName MyGroupName -DNSDomain MyDomainFDQN
			
		.OUTPUTS
			Success        : True
			Message        : Group members from Group DemoGroup01 have successfully been listed
			GroupMembers   : System.DirectoryServices.ResultPropertyValueCollection


		.NOTES  
			Copyright	: 	(c) 2021 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.2
			
			History:
				V1.0 - 13.04.2016 - M.Trojahn - Initial creation
				V1.1 - 08.12.2020 - M.Trojahn - fix error (use Variable $DNSDomain instead of fix value)
				V1.2 - 14.06.2021 - M.Trojahn - error handling from Get-EitDirectoryEntry
	#>	
	Param (
		[Parameter(Mandatory = $True)]
		[string]$GroupName,
		[Parameter(Mandatory = $True)]
		[string]$DNSDomain,
		[Parameter(Mandatory = $False)]
		[string]$AdminUser = "",
		[Parameter(Mandatory = $False)]
		[string]$AdminPassword = $Null
	)
	
	[boolean]$bSuccess = $true
	[string]$StatusMessage = "Group members from Group $GroupName have successfully been listed"
	
	try
	{
		$DirectoryEntry = new-object DirectoryServices.DirectoryEntry(("LDAP://" + $DNSDomain))
		$GroupEntry = Get-EitDirectoryEntry -ADFindType group -DNSDomain $DNSDomain -cName $GroupName
		if ($GroupEntry.Success -eq "True")
		{
			$MyGroup = New-Object System.DirectoryServices.DirectoryEntry($GroupEntry.DirectoryEntry.Path)
			$Filter = "(&(memberof:1.2.840.113556.1.4.1941:=" + $MyGroup.distinguishedName.toString() + ")(objectCategory=user))"
			$Searcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry)
			$Searcher.PageSize = 1000
			$Searcher.Filter = $Filter
			$Searcher.SearchScope = "Subtree"
			$Searcher.PropertiesToLoad.Add("displayName") | Out-Null
			$Searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
			$Searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
			$colResults = $Searcher.FindAll()
			
			$MemberList = @()
			foreach ($Result in $colResults)
			{
				$UserInfoObject = ([pscustomobject]@{ samaccountname = $Result.Properties["samaccountname"]; DisplayName = $Result.Properties["DisplayName"]; distinguishedName = $Result.Properties["distinguishedName"] })
				$MemberList += $UserInfoObject
			}
		}
		else
		{
			throw $GroupEntry.Message
		}
	}
	
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	if ($bSuccess -ne $false)
	{
		$ReturnObject = ([pscustomobject]@{ Success = $bSuccess; Message = $StatusMessage; GroupMembers = $MemberList })
	}
	else
	{
		$ReturnObject = ([pscustomobject]@{ Success = $bSuccess; Message = $StatusMessage; GroupMembers = "n/a" })
	}
	return $ReturnObject
}



function Get-EitADUserLastLogon
{
	<#
		.Synopsis
			Determining a User's Last Logon Time
		.Description
			Determining a User's Last Logon Time 
		
		.Parameter UserName
			the user name
			
		.EXAMPLE
			Get-EitADUserLastLogon -UserName MyuserName 
			
		.OUTPUTS
			Success        : True
			LastLogin      : 16.11.2017 10:06:00
			DC			   : MyDomainController


		.NOTES  
			Copyright: (c)2016 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 04.12.2017 - M.Trojahn - Initial creation
				V1.1 - 08.01.2018 - M.Trojahn - Add error condition if no lastlogon is found
	#>	
	Param(
		[Parameter(Mandatory=$True)] [string] $UserName,
		[Parameter(Mandatory=$True)] [string] $DomainName
	)
	[string] 	$StatusMessage = "LastLogn for user $Username has successfully been listed"
	$bSuccess = $true
	try
	{
		$DCs = Get-ADDomainController -Filter * -Server $((Get-ADDomainController -DomainName $DomainName -Discover).hostname)
		$Time = 0
		foreach ($DC in $DCs)
		{
			if (Test-EitPort -ComputerName $DC.HostName -port 139)
			{
				$User = Get-ADUser $UserName -Server $DC.HostName| Get-ADObject -Properties lastLogon 
				$User.LastLogon
				$DC.HostName
				if ($User.LastLogon -gt $Time)
				{
					$Time = $User.LastLogon
					$LoginDC = $DC.HostName
				}
			}
		}
		if ($Time -ne 0)
		{
			$dt = [DateTime]::FromFileTime($time)
		}
		else
		{
			$bSuccess = $false
			$StatusMessage = "LastLogon not found"
		}
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;LastLogon=$dt;DC=$LoginDC})
	return $ReturnObject
}


function Get-EitADComputer
{
	<#
		.Synopsis
			Get a computer object from the domain
		.Description
			Get a computer object from the domain
		
		.Parameter ComputerName
			the computer name
			
		.Parameter DNSDomainName
			the dns name of the domain
		
		.EXAMPLE
			Get-EitADComputer -ComputerName MyComputer
			
		.OUTPUTS
			Success        : True
			Message        : AD Computer has successfully been listed
			ADObject	   : LDAP Path

		.NOTES  
			Copyright: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
			Version		:	1.0
			
			History:
				V1.0 - 26.02.2020 - M.Trojahn - Initial creation
	#>	
	Param(
		[Parameter(Mandatory=$True)] [string] $ComputerName,
		[Parameter(Mandatory=$false)] [string] $DNSDomainName
	)

	[boolean] 	$bSuccess = $true
	[string] 	$StatusMessage = "AD Computer has successfully been listed"
	
	try
	{
		if ($DNSDomainName.length -ne 0)
		{
			$ADObject = Get-ADComputer -Identity $ComputerName -Server $DNSDomainName
		}
		else
		{
			$ADObject = Get-ADComputer -Identity $ComputerName
		}
	}
	catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
	{
		$bSuccess = $false
		$ADObject = $null
		$StatusMessage = $_.Exception.Message
	}
		
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;ADObject=$ADObject})
	return $ReturnObject
}



function Get-EitLapsPassword
{
	<#
	.SYNOPSIS
		Get the local administrator password for a specified computer stored in Active Directory by LAPS.
	 
	.DESCRIPTION
		Get the local administrator password for a specified computer stored in Active Directory by
		the Local Administrator Password Solution.
	 
		The LAPS tool periodically changes the local administrator account on a computer and stores the
		password in an Active Directory attribute in the computer account.
	 
	.PARAMETER ComputerName
		Enter a name of a computer
	 
	.PARAMETER AsSecureString
		Optionally retrieve and convert the password to a secure string to be used with a
		credential object.
	 
	.PARAMETER IncludeLocalAdministratorAccount
		
	 
	.PARAMETER Credential
		Optionally provide an alternate credential for accessing the privileged data from Active
		Directory.
	 
	.EXAMPLE
		Get-EitLapsPassword
	 
		ComputerName LapsPassword
		------------ ------------
		COMPUTER01 35J3J2J3#2j
	 
	.EXAMPLE
		Get-EitLapsPassword -ComputerName COMPUTER01,COMPUTER02,COMPUTER03
	 
		ComputerName LapsPassword
		------------ ------------
		COMPUTER01 35J3J2J3#2j
		COMPUTER02 DJEJ#F*&fX
		COMPUTER03 ACCESS DENIED
	 
	.EXAMPLE
		Get-LapsPassword -ComputerName COMPUTER01 -AsSecureString
	 
		ComputerName LapsPassword
		------------ ------------
		COMPUTER01 System.Security.SecureString
		 
	.NOTES  
		Copyright	: (c)2020 by EducateIT GmbH - http://educateit.ch - info@educateit.ch 
		Version		: 1.0
		History:
			V1.0 - 31.03.2020 - M.Trojahn - Initial creation  
	
	
	#>
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [switch]$AsSecureString,
        [switch]$IncludeLocalAdministratorAccountName,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
   
	$ErrorActionPreference = 'Stop'
	$LapsPasswordAttributeName = 'ms-Mcs-AdmPwd'
	
	foreach ($Computer in $ComputerName)
	{
		try
		{
			# get local administrator account information if specified
			if ($IncludeLocalAdministratorAccountName)
			{
				Write-Verbose -Message "Getting local administrator account information from $Computer"
				try
				{
					$LocalAdministratorAccount = $LocalAdministratorAccount = Get-WmiObject -ComputerName $Computer -Class Win32_UserAccount -Filter "LocalAccount='True' And Sid like '%-500'" -Credential $Credential
					$LocalAdministratorAccountName = $LocalAdministratorAccount.Name
				}
				catch [System.UnauthorizedAccessException]
				{
					Write-Warning -Message $_.Exception.Message
					$LocalAdministratorAccountName = '-ACCESS DENIED-'
				}
				catch
				{
					Write-Warning -Message $_.Exception.Message
					$LocalAdministratorAccountName = '-UNKNOWN-'
				}
			}

			# get LAPS password
			Write-Verbose -Message "Getting LAPS password information for $Computer"
			if ($Credential.UserName -ne $null)
			{
				$ADComputer = Get-ADComputer -Identity $Computer -Properties $LapsPasswordAttributeName -Credential $Credential
			}
			else
			{
				$ADComputer = Get-ADComputer -Identity $Computer -Properties $LapsPasswordAttributeName
			}
			
			if ($ADComputer.$LapsPasswordAttributeName)
			{
				if ($AsSecureString)
				{
					$LapsPassword = ConvertTo-SecureString -String $ADComputer.$LapsPasswordAttributeName -AsPlainText -Force
				}
				else
				{
					$LapsPassword = $ADComputer.$LapsPasswordAttributeName
				}
			}
			else
			{
				$LapsPassword = '-ACCESS DENIED-'
			}
		
			$LapsPasswordProperties = [ordered]@{
				ComputerName = $Computer
				LapsPassword = $LapsPassword
			}
			if ($IncludeLocalAdministratorAccountName)
			{
				$LapsPasswordProperties.Add('Username', $LocalAdministratorAccountName)
			}
			$LapsPassword = New-Object -TypeName PSCustomObject -Property $LapsPasswordProperties
			$LapsPassword
		}
		catch
		{
			Write-Error -Message $_.Exception.Message
		}
	}
}

function Get-EitBitLockerPassword
{	
<#
 .Synopsis
		List BitLocker Password
    .Description
		List BitLocker Password stored in AD
	
	.Parameter ComputerName
		the computer name
		
	.EXAMPLE
		Get-EitADBitLockerPassword -ComputerName MyComputer
		
	.OUTPUTS

	.NOTES  
		Copyright: (c)2018 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.1
		
		History:
            V1.0 - 17.01.2018 - M.Trojahn - Initial creation
			V1.1 - 24.01.2018 - M.Trojahn - Remove Time "correction", add objects instead of overwrite
    #>	
	Param(
        [Parameter(Mandatory=$True)] [string] $ComputerName
    )
	[string] 	$StatusMessage = "Bitlocker Passwords for computer $ComputerName has successfully been listed"
	$bSuccess = $true
	$BitLockerData = @()
	
	try
	{
		$ComputerObject = Get-ADComputer -Filter {Name -eq $ComputerName}
		if ($ComputerObject -eq $null)
		{
			throw "Computer object for computer $ComputerName not found."
		}
		else
		{
			$AddedTime = ""
			$PasswordID = ""
			$RecoveryPassword = "<not set>"
			$BitLockerObjects = Get-ADObject -Filter {objectclass -eq "msFVE-RecoveryInformation"} -SearchBase $ComputerObject.DistinguishedName -Properties "msFVE-RecoveryPassword"
			if ($BitLockerObjects -ne $null)
			{
				foreach ($BitLockerObject in $BitLockerObjects)
				{
					if ($BitLockerObject.'msFVE-RecoveryPassword')
					{
						$tmpData = $BitLockerObject.Name.Trim("}").Split("{")
						$tmpDate = $tmpData[0].Split("+")
						$AddedTime = [DateTime]$tmpDate[0] 
						$PasswordID = $tmpData[1]
						$RecoveryPassword = $BitLockerObject.'msFVE-RecoveryPassword'
						$BitLockerData += ([pscustomobject]@{DateAdded=$AddedTime;PasswordID=$PasswordID;RecoveryPassword=$RecoveryPassword;})	
					}
					else
					{
						# do nothing
					}
				}
			}
			else
			{
				# do nothing
			}
			$BitLockerData = $BitLockerData | Sort-Object -Property DateAdded
		}	
	}
	catch
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
    $ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;BitLockerPasswords=$BitLockerData})
    return $ReturnObject
}
