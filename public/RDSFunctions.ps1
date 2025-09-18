#
# RDSFunctions.ps1
# ===========================================================================
# (c)2024 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# RDS Functions for Raptor Scripts
#
# History:
#   V1.0 - 01.09.2016 - M.Trojahn - Initial creation
#  
#   
#	
#


#requires -version 3

Add-Type -ErrorAction Stop -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;

    public enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTSINFOEX_LEVEL1_W {
        public Int32                  SessionId;
        public WTS_CONNECTSTATE_CLASS SessionState;
        public Int32                   SessionFlags; // 0 = locked, 1 = unlocked , ffffffff = unknown
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)]
        public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]
        public string UserName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)]
        public string DomainName;
        public UInt64           LogonTime;
        public UInt64           ConnectTime;
        public UInt64           DisconnectTime;
        public UInt64           LastInputTime;
        public UInt64           CurrentTime;
        public Int32            IncomingBytes;
        public Int32            OutgoingBytes;
        public Int32            IncomingFrames;
        public Int32            OutgoingFrames;
        public Int32            IncomingCompressedBytes;
        public Int32            OutgoingCompressedBytes;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTSCONFIGINFOW {
        public UInt32 version;
        public UInt32 fConnectClientDrivesAtLogon;
        public UInt32 fConnectPrinterAtLogon;
        public UInt32 fDisablePrinterRedirection;
        public UInt32 fDisableDefaultMainClientPrinter;
        public UInt32 ShadowSettings;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]   
        public string  LogonUserName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)]   
        public string  LogonDomain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]   
        public string  WorkDirectory;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]   
        public string  InitialProgram;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]   
        public string  ApplicationName;  
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTSCLIENTW {
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]    
      public string   ClientName;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)]
      public string   Domain;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]
      public string   UserName;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
      public string   WorkDirectory;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
      public string   InitialProgram;
      public byte   EncryptionLevel;
      public UInt32  ClientAddressFamily;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 31)]
      public UInt16[] ClientAddress;
      public UInt16 HRes;
      public UInt16 VRes;
      public UInt16 ColorDepth;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
      public string   ClientDirectory;
      public UInt32  ClientBuildNumber;
      public UInt32  ClientHardwareId;
      public UInt16 ClientProductId;
      public UInt16 OutBufCountHost;
      public UInt16 OutBufCountClient;
      public UInt16 OutBufLength;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
      public string   DeviceId;
    }
        
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_CLIENT_DISPLAY
    {
        public uint HorizontalResolution;
        public uint VerticalResolution;
        public uint ColorDepth;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public Int32 SessionID;

        [MarshalAs(UnmanagedType.LPStr)]
        public String pWinStationName;

        public WTS_CONNECTSTATE_CLASS State;
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct WTSINFOEX_LEVEL_W
    { //Union
        [FieldOffset(0)]
        public WTSINFOEX_LEVEL1_W WTSInfoExLevel1;
    } 
    [StructLayout(LayoutKind.Sequential)]
    public struct WTSINFOEX
    {
        public Int32 Level ;
        public WTSINFOEX_LEVEL_W Data;
    }
    public enum WTS_INFO_CLASS
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState,
        WTSClientBuildNumber,
        WTSClientName,
        WTSClientDirectory,
        WTSClientProductId,
        WTSClientHardwareId,
        WTSClientAddress,
        WTSClientDisplay,
        WTSClientProtocolType,
        WTSIdleTime,
        WTSLogonTime,
        WTSIncomingBytes,
        WTSOutgoingBytes,
        WTSIncomingFrames,
        WTSOutgoingFrames,
        WTSClientInfo,
        WTSSessionInfo,
        WTSSessionInfoEx,
        WTSConfigInfo,
        WTSValidationInfo,   // Info Class value used to fetch Validation Information through the WTSQuerySessionInformation
        WTSSessionAddressV4,
        WTSIsRemoteSession
    }
    public static class wtsapi
    {
        [DllImport("wtsapi32.dll", SetLastError=true)]
        public static extern int WTSQuerySessionInformationW(
                 System.IntPtr hServer,
                 int SessionId,
                 int WTSInfoClass ,
                 ref System.IntPtr ppSessionInfo,
                 ref int pBytesReturned );

        [DllImport("wtsapi32.dll", SetLastError=true)]
        public static extern int WTSEnumerateSessions(
                 System.IntPtr hServer,
                 int Reserved,
                 int Version,
                 ref System.IntPtr ppSessionInfo,
                 ref int pCount);

        [DllImport("wtsapi32.dll", SetLastError=true)]
        public static extern IntPtr WTSOpenServer(string pServerName);
        
        [DllImport("wtsapi32.dll", SetLastError=true)]
        public static extern void WTSCloseServer(IntPtr hServer);
        
        [DllImport("wtsapi32.dll", SetLastError=true)]
        public static extern void WTSFreeMemory(IntPtr pMemory);
    }
'@ 

function Get-EitWTSSessionInformation
<#
	.Synopsis
		Get session information from a rds host.

	.Description
		Use WTSAPi32.dll to get session information from a rds host.
	
	.Parameter Computers
		Array of computer to query for session information
		
	.Example
		Get-EitWTSSessionInformation -Computers MyComputerName 
		
	.Example
		Get-EitWTSSessionInformation -Computers MyComputerName1,  MyComputerName2
			
		
	.Notes
		Copyright	:	(c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History:
			V1.0 - 18.03.2024 - M.Trojahn - Initial creation based on https://github.com/guyrleech/Microsoft/blob/master/WTSApi.ps1
	#>	
{
    [cmdletbinding()]

    param
    (
        [string[]]$Computers = @( $null )
    )

    [long]$count = 0
    [IntPtr]$ppSessionInfo = 0
    [IntPtr]$ppQueryInfo = 0
    [long]$ppBytesReturned = 0
    $wtsSessionInfo = New-Object -TypeName 'WTS_SESSION_INFO'
    $WTSInfoEx = New-Object -TypeName 'WTSINFOEX'
    $wtsClientInfo = New-Object -TypeName 'WTSCLIENTW'
    $wtsConfigInfo = New-Object -TypeName 'WTSCONFIGINFOW'
    [int]$datasize = [system.runtime.interopservices.marshal]::SizeOf( [Type]$wtsSessionInfo.GetType())
	[boolean]$bSuccess = $true
	[string]$StatusMessage = "Successfully received WTSSessionInformation."
	$WTSSessionInformation = @()
	
	try 
	{
		foreach ($Computer in $Computers)
		{
			$WTSInfo = $null
			[string]$machineName = $(if($Computer) {$Computer} else {$env:COMPUTERNAME})
			[IntPtr]$serverHandle = [wtsapi]::WTSOpenServer($Computer)

			## If the function fails, it returns a handle that is not valid. You can test the validity of the handle by using it in another function call.

			[long]$retval = [wtsapi]::WTSEnumerateSessions($serverHandle,0,1,[ref]$ppSessionInfo,[ref]$count);$LastError=[ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

			if ($retval -ne 0)
			{
				Write-Verbose -Message "Got $count sessions for $computer"
				for ([int]$index = 0; $index -lt $count; $index++)
				{
					## session 0 is non-interactive (session zero isolation)
					if (($element = [system.runtime.interopservices.marshal]::PtrToStructure([long]$ppSessionInfo + ($datasize * $index), [type]$wtsSessionInfo.GetType()) ) -and $element.SessionID -ne 0)
					{
						#$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
						if (($retval = [wtsapi]::WTSQuerySessionInformationW($serverHandle, $element.SessionID, [WTS_INFO_CLASS]::WTSSessionInfoEx, [ref]$ppQueryInfo, [ref]$ppBytesReturned) -and $ppQueryInfo) -and $ppQueryInfo)
						{
							if (($value = [system.runtime.interopservices.marshal]::PtrToStructure($ppQueryInfo,[Type]$WTSInfoEx.GetType())) `
								-and $value.Data -and $value.Data.WTSInfoExLevel1.SessionState -ne [WTS_CONNECTSTATE_CLASS]::WTSListen -and $value.Data.WTSInfoExLevel1.SessionState -ne [WTS_CONNECTSTATE_CLASS]::WTSConnected )
							{
								$WTSInfo = $value.Data.WTSInfoExLevel1
								$idleTime = New-TimeSpan -End ([datetime]::FromFileTimeUtc($WTSInfo.CurrentTime)) -Start ([datetime]::FromFileTimeUtc($WTSInfo.LastInputTime))
								Add-Member -InputObject $WTSInfo -Force -NotePropertyMembers @{
									'IdleTimeInSeconds' =  [math]::Round(($idleTime | Select -ExpandProperty TotalSeconds),1)
									'IdleTimeInMinutes' =  [math]::Round(($idleTime | Select -ExpandProperty TotalMinutes),2)
									'Computer' = $machineName
									'LogonTime' = [datetime]::FromFileTime( $WTSInfo.LogonTime )
									'DisconnectTime' = $($time = [datetime]::FromFileTime($WTSInfo.DisconnectTime) ; if( $time.Year -lt 1900 ) {$null} else {$time})
									'LastInputTime' = [datetime]::FromFileTime( $WTSInfo.LastInputTime )
									'SessionState' = $WTSInfo.SessionState
									'ConnectTime' = [datetime]::FromFileTime($WTSInfo.ConnectTime)
									'CurrentTime' = [datetime]::FromFileTime($WTSInfo.CurrentTime)
								}
							}
							[wtsapi]::WTSFreeMemory($ppQueryInfo)
							$ppQueryInfo = [IntPtr]::Zero
						 }
						 else
						 {
							throw "$($machineName): $LastError"
						 }
						 if ($WTSInfo)
						 {
							## WTSClientInfo
							$ppQueryInfo = [IntPtr]::Zero
							if( ( $retval = [wtsapi]::WTSQuerySessionInformationW($serverHandle,$element.SessionID,[WTS_INFO_CLASS]::WTSClientInfo,[ref]$ppQueryInfo,[ref]$ppBytesReturned)) `
								-and $ppQueryInfo -and ($wtsClientInfo = [system.runtime.interopservices.marshal]::PtrToStructure( $ppQueryInfo, [Type]$wtsClientInfo.GetType())))
							{
								foreach ($property in $wtsClientInfo.PSObject.Properties)
								{
									Add-Member -InputObject $WTSInfo -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
								}
							   [wtsapi]::WTSFreeMemory($ppQueryInfo)
							   $ppQueryInfo = [IntPtr]::Zero
							}
							else
							{
								$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
								throw "Failed to get WTSClientInfo for session id $($element.SessionID) - $($LastError)"
							}
							
							## WTSConfigInfo
							$ppQueryInfo = [IntPtr]::Zero
							if (($retval = [wtsapi]::WTSQuerySessionInformationW($serverHandle,$element.SessionID, [WTS_INFO_CLASS]::WTSConfigInfo, [ref]$ppQueryInfo, [ref]$ppBytesReturned)) `
								-and $ppQueryInfo -and ($wtsConfigInfo = [system.runtime.interopservices.marshal]::PtrToStructure($ppQueryInfo, [Type]$wtsConfigInfo.GetType())))
							{
								foreach ($property in $wtsConfigInfo.PSObject.Properties)
								{
									## WorkDirectory and InitialProgram don't seem to work and we have no new strings here so don't add string type properties
									if ($property.TypeNameOfValue -ne 'System.String')
									{
										Add-Member -InputObject $WTSInfo -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
									}
								}
							   [wtsapi]::WTSFreeMemory($ppQueryInfo)
							   $ppQueryInfo = [IntPtr]::Zero
							}
							else
							{
								$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
								throw "Failed to get WTSConfigInfo for session id $($element.SessionID) - $($LastError)"
							}

							[UInt16]$clientProtocolType = ([UInt16]::MaxValue)
							
							if (($retval = [wtsapi]::WTSQuerySessionInformationW($serverHandle, $element.SessionID, [WTS_INFO_CLASS]::WTSClientProtocolType, [ref]$ppQueryInfo, [ref]$ppBytesReturned)) -and $ppQueryInfo)
							{
								$clientProtocolType = [system.runtime.interopservices.marshal]::PtrToStructure($ppQueryInfo , [Type]$clientProtocolType.GetType())
								Add-Member -InputObject $WTSInfo -MemberType NoteProperty -Name ClientProtocolType -Value $clientProtocolType
								[wtsapi]::WTSFreeMemory($ppQueryInfo)
								$ppQueryInfo = [IntPtr]::Zero
							}
							$WTSSessionInformation += $WTSInfo
							$WTSInfo = $null
						}
					}
				}
			}
			else
			{
				throw "$($machineName): $LastError"
			}

			if ($ppSessionInfo -ne [IntPtr]::Zero)
			{
				[wtsapi]::WTSFreeMemory($ppSessionInfo)
				$ppSessionInfo = [IntPtr]::Zero
			}
			[wtsapi]::WTSCloseServer($serverHandle)
			$serverHandle = [IntPtr]::Zero
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;WTSSessionInformation=$WTSSessionInformation})
	return $ReturnObject	
}

 function Get-EitWTSSessionId
<#
	.Synopsis
		Gets the rds sessionid for a given user.

	.Description
		Gets the rds sessionid for a given user by calling Get-EitWTSSessionInformation
	
	.Parameter Computer
		the computer to query for session information
		
	.Parameter UserName
		the username to query for session information	
	
	.Example
		Get-EitWTSSessionId 
		Get sessionid from the actual user in the actual server.
		
	.Example	
		Get-EitWTSSessionId -Cumputer MyCompurer -Username MyUserName
		Get sessionid for user MyUserName on server MyComputer.
		
	.Notes  
		Copyright	:	(c)2024 by EducateIT GmbH - http://educateit.ch - info@educateit.ch
		Version		:	1.0
		
		History:
			V1.0 - 18.03.2024 - M.Trojahn - Initial creation
	#>	
{
    [cmdletbinding()]

    param
    (
        [string]$Computer = $env:ComputerName,
		[string]$UserName = $env:UserName
    )

    [boolean]$bSuccess = $true
	[string]$StatusMessage = "Successfully received WTSSessionId."
	$WTSSessionId = $null
	
	try 
	{
		$WTSSessionInformations = Get-EitWTSSessionInformation -Computers $Computer
		if ($WTSSessionInformations.Success -eq $true)
		{
			$WTSSessionId = $WTSSessionInformations.WTSSessionInformation | Where-Object {$_.UserName -eq $UserName} | select SessionId
			if ($WTSSessionId -eq $null)
			{
				throw "No session found for user $UserName on computer $ComputerName"
			}
		}
		else
		{
			throw $WTSSessionInformations.Message
		}
	}
	catch 
	{
		$bSuccess = $false
		$StatusMessage = $_.Exception.Message
	}
	$ReturnObject = ([pscustomobject]@{Success=$bSuccess;Message=$StatusMessage;WTSSessionId=$WTSSessionId.SessionId})
	return $ReturnObject	
}

