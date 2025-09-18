# ===========================================================================
# MSAvDFunctions.Tests.ps1
# ===========================================================================
# (c)2025 by EducateIT GmbH. http://educateit.ch/ info@educateit.ch
# Version 1.0
#
# Pester tests for MSAvDFunctions.ps1
#
# History:
#   V1.0 - 12.09.2025 - M.Trojahn - Initial creation
#									 
#
#
# ===========================================================================
# Requires -Module Pester -Version 5.5.5
 
# define test data
BeforeAll {
	Import-Module EducateIT.PSFunctions -Force -ErrorAction SilentlyContinue
	
	
	$validToken 			= 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
	$appId 					= 'test-app-id'
	$appSecret 				= 'test-app-secret'
	$tenantId 				= 'test-tenant-id'
	$baseUrl 				= 'https://management.azure.com'
	$Subscription 			= '00000000-0000-0000-0000-000000000000'
	$ValidSessionId 		= "/subscriptions/$Subscription/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/hp/sessionHosts/sh/userSessions/us"
	$InvalidSessionId 		= 'invalid'	
	$validSessionHostId 	= '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myrg/providers/Microsoft.DesktopVirtualization/hostPools/mypool/sessionHosts/myhost.domain.com'
	$invaliSessionHostdId 	= '/invalid/resource/id'
	$ValidHostPoolId 		= "/subscriptions/$Subscription/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/hp"
	$InvalidHostPoolId 		= 'invalid-id'
	
	
	
	$FakeHostPools = @(
		@{
			name       = 'hostpool1'
			id         = "/subscriptions/.../hostpool1"
			type       = 'Microsoft.DesktopVirtualization/hostpools'
			location   = 'westeurope'
			tags       = @{}
			properties = @{ hostPoolType = 'Pooled'; maxSessionLimit = 30 }
		},
		@{
			name       = 'hostpool2'
			id         = "/subscriptions/.../hostpool2"
			type       = 'Microsoft.DesktopVirtualization/hostpools'
			location   = 'westeurope'
			tags       = @{}
			properties = @{ hostPoolType = 'Pooled'; maxSessionLimit = 30 }
		}
	)

	$FakeHostPoolResponse = [pscustomobject]@{
		StatusCode = 200
		Headers    = @{}
		# IMPORTANT: wrap under 'value', because the function does:
		# ($response.Content | ConvertFrom-Json).value
		Content    = (@{ value = $FakeHostPools } | ConvertTo-Json -Depth 10)
	}
	
	$FakeSessionHosts = @(
		@{
			name       = 'sh1'
			id         = "/subscriptions/.../sh1"
		},
		@{
			name       = 'sh2'
			id         = "/subscriptions/.../sh2"
		}
	)
		
	$FakeSessionHostsResponse = [pscustomobject]@{
		StatusCode = 200
		Headers    = @{}
		# IMPORTANT: wrap under 'value', because the function does:
		# ($response.Content | ConvertFrom-Json).value
		Content    = (@{ value = $FakeSessionHosts } | ConvertTo-Json -Depth 10)
	}
	
	$FakeUserSessions = @(
		@{ 
			id = 'us1'
			state = 'Active' 
		}
		@{ 
			id = 'us2'
			state = 'Active' 
		}
	)
	
	$FakeUserSessionsResponse =  [pscustomobject]@{
		StatusCode = 200
		Headers    = @{}
		# IMPORTANT: wrap under 'value', because the function does:
		# ($response.Content | ConvertFrom-Json).value
		Content    = (@{ value = $FakeUserSessions } | ConvertTo-Json -Depth 10)
	}
	
	$FakeUserSession = @{
		name = "myhostPool/mysessionHost/3"
		id   = "/subscriptions/../resourcegroups/XXX/providers/Microsoft.DesktopVirtualization/hostpools/myhostPool/sessionhosts/mysessionHost/usersessions/3"
		type = "Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions"
		properties = @{
			createTime              = ""
			userPrincipalName       = ""
			sessionState            = "Active"
			applicationType         = ""
			activeDirectoryUserName = ""
			objectId                = ""
		}
		systemData = @{
			createdBy          = $null
			createdByType      = $null
			createdAt          = $null
			lastModifiedBy     = $null
			lastModifiedByType = $null
			lastModifiedAt     = $null
		}
	}
	
	$FakeUserSessionResponse =  [pscustomobject]@{
		StatusCode = 200
		Headers    = @{}
		# IMPORTANT: wrap under 'value', because the function does:
		# ($response.Content | ConvertFrom-Json).value
		Content    = ($FakeUserSession  | ConvertTo-Json -Depth 10)
	}
}


Describe 'Get-EitAzBearerToken' {

    Context 'When token is successfully retrieved' {
		BeforeEach {
			Mock -CommandName Invoke-RestMethod -MockWith {
				return @{
					access_token = $validToken
				}
			} -ModuleName EducateIT.PSFunctions
		}
		
        It 'Should return a PSCustomObject with Success = $true and a valid BearerToken' {
            $response = Get-EitAzBearerToken -AppId $appId -AppSecret $appSecret -TenantId $tenantId -BaseUrl $baseUrl
            $response | Should -BeOfType 'pscustomobject'
            $response.Success | Should -Be $true
            $response.Message | Should -Be 'Successfully retrieved bearer token.'
            $response.BearerToken | Should -Be $validToken
        }

        
    }

    Context 'When Invoke-RestMethod throws an exception' {
        BeforeEach {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw "401 Unauthorized"
            } -ModuleName EducateIT.PSFunctions
        }

        It 'Should return Success = $false and a proper error message' {
            $response = Get-EitAzBearerToken -AppId $appId -AppSecret $appSecret -TenantId $tenantId -BaseUrl $baseUrl

            $response.Success | Should -Be $false
            $response.Message | Should -Match 'Error retrieving token: .*'
            $response.BearerToken | Should -Be $null
        }
    }

    Context 'When the token is missing in the response' {
        BeforeEach {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{ someOtherKey = 'value' }
            } -ModuleName EducateIT.PSFunctions
        }

        It 'Should return Success = $false and an error about missing bearer token' {
            $response = Get-EitAzBearerToken -AppId $appId -AppSecret $appSecret -TenantId $tenantId -BaseUrl $baseUrl

            $response.Success | Should -Be $false
            $response.Message | Should -Match 'Error retrieving token: .*'
            $response.BearerToken | Should -Be $null
        }
    }
}

Describe 'Get-EitAzHostPoolsBySubscription' {

    Context 'When the API call is successful' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return $FakeHostPoolResponse
			} -ModuleName EducateIT.PSFunctions
		}
		
        It 'should return success and host pools' {
            $response = Get-EitAzHostPoolsBySubscription -BearerToken $validToken -Subscription $Subscription
            $response.Success | Should -Be $true
            $response.Message | Should -Be 'Successfully retrieved hostpools.'
            $response.HostPools.Count | Should -Be 2
			$response.HostPools[0].name | Should -Be 'hostpool1'
        }
     
    }

    Context 'When the API call fails' {
        BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				throw [System.Net.WebException]::new("API call failed.")
			} -ModuleName EducateIT.PSFunctions
		}
        It 'should return failure and error message' {
            $response = Get-EitAzHostPoolsBySubscription -BearerToken $validToken -Subscription $Subscription

            $response.Success | Should -Be $false
            $response.Message | Should -Match 'API call failed'
            $response.HostPools | Should -Be $null
        }
    }
}

Describe 'Get-EitAzSessionHostsByHostPool' {
	Context 'handle invalid HostPoolId format' {
		
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				throw 'unused' 
			} -ModuleName EducateIT.PSFunctions
		}
		It 'should handle invalid HostPoolId format' {
			$response = Get-EitAzSessionHostsByHostPool -BearerToken $validToken -Subscription $Subscription -HostPoolId $InvalidHostPoolId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Invalid HostPoolId format'
		}	
	}
	
	Context 'handle valid request' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return $FakeSessionHostsResponse
			} -ModuleName EducateIT.PSFunctions
		}
		 
		
		It ' Should return session hosts on valid request' {
			$response = Get-EitAzSessionHostsByHostPool -BearerToken $validToken -Subscription $Subscription -HostPoolId $ValidHostPoolId
			$response.Success | Should -BeTrue
			$response.SessionHosts.Count | Should -Be 2
			$response.SessionHosts[0].name | Should -Be 'sh1'
		}	
	}	
}
 
Describe 'Get-EitAzUserSessionsByHostPool' {
	
	Context 'invalid HostPoolId' {
		It 'should fails on invalid HostPoolId' {
			$response = Get-EitAzUserSessionsByHostPool -BearerToken $validToken -Subscription $Subscription -HostPoolId 'bad'
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Invalid HostPoolId format'
		}
	}
	
	Context 'valid HostPoolId' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				$FakeUserSessionsResponse
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should returns sessions when valid' {
			$response = Get-EitAzUserSessionsByHostPool -BearerToken $validToken -Subscription $Subscription -HostPoolId $ValidHostPoolId
			$response.Success | Should -BeTrue
			$response.Sessions.Count | Should -Be 2
			$response.Sessions[0].id | Should -Be 'us1'
		}
	}
} 


Describe 'Send-EitAzUserMessage' {
	
	Context 'invalid SessionId' {
		It 'should fails on invalid SessionId' {
			$response = Send-EitAzUserMessage -BearerToken $validToken -SessionId $InvalidSessionId -MessageTitle 'T' -MessageBody 'B'
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Invalid SessionId'
		}
	}
	
	Context 'valid SessionId' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 200 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should succeeds on valid SessionId' {
			$response = Send-EitAzUserMessage -BearerToken $validToken -SessionId $ValidSessionId -MessageTitle 'T' -MessageBody 'B'
			$response.Success | Should -BeTrue
			$response.StatusCode | Should -Be 200
		}
	}
	
	Context 'failure when API throws' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				throw [System.Net.WebException]::new('fw')
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should returns failure when API throws' {
			$response = Send-EitAzUserMessage -BearerToken $validToken -SessionId $ValidSessionId -MessageTitle 'T' -MessageBody 'B'
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Failed to send message'
		}
	}
	
} 



Describe 'Disconnect-EitAzUserSession' {
	
	Context 'invalid SessionId' {
		It 'should fails on invalid SessionId' {
			$response = Disconnect-EitAzUserSession -BearerToken $validToken -SessionId $InvalidSessionId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Invalid SessionId format'
		}
	}
	
	Context 'valid SessionId' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 200 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should succeeds on valid SessionId' {
			$response = Disconnect-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$response.Success | Should -BeTrue
		}
	}
	
	Context 'unexpected status code' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 500 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should fails on unexpected status code' {
			$response = Disconnect-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Unexpected status code'
		}
	}
} 


Describe 'Remove-EitAzUserSession' {
	
	Context 'invalid SessionId' {
		It 'should fails on invalid SessionId' {
			$response = Remove-EitAzUserSession -BearerToken $validToken -SessionId $InvalidSessionId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Invalid SessionId format'
		}
	}
		
	Context 'valid SessionId' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 200 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should succeeds on valid SessionId' {
			$response = Remove-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$response.Success | Should -BeTrue
		}
	}
	
	Context 'unexpected status code' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 500 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should fails on unexpected status code' {
			$response = Remove-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Unexpected status code'
		}
	}
	
	Context 'correct URI with and without Force' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 200 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should builds correct URI with and without Force' {
			$res1 = Remove-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$res1.Success | Should -BeTrue
			$res1.URI | Should -Match 'force=false'

			$res2 = Remove-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId -Force
			$res2.URI | Should -Match 'force=true'
		}
	}
	
} 

Describe 'Get-EitAzUserSession' {
	
	Context 'invalid SessionId' {
		It 'should fails on invalid SessionId' {
			$response = Get-EitAzUserSession -BearerToken $validToken -SessionId $InvalidSessionId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Invalid SessionId format'
		}
	}
		
	Context 'unexpected status code' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{ StatusCode = 500 }
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should fails on unexpected status code' {
			$response = Remove-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$response.Success | Should -BeFalse
			$response.Message | Should -Match 'Unexpected status code'
		}
	}
	
	Context 'valid SessionId' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return $FakeUserSessionResponse
			} -ModuleName EducateIT.PSFunctions
		}
		
		It 'should returns SessionState and Session on valid call' {
			$response = Get-EitAzUserSession -BearerToken $validToken -SessionId $ValidSessionId
			$response.Success | Should -BeTrue
			$response.SessionState | Should -Be 'Active'
			$response.Session | Should -Not -BeNullOrEmpty
		}
	}
} 




Describe 'Get-EitAzSessionHost' {
    
    Context 'When Invoke-WebRequest returns 200 with content' {
        BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{
					StatusCode = 200
					StatusDescription = "OK"
					Content = '{ "name": "myhost.domain.com", "properties": { "status": "Available" } }'
				} | ConvertTo-Json -Depth 10 | ConvertFrom-Json
			} -ModuleName EducateIT.PSFunctions
		}
		
				

        It 'should return success with parsed session host data' {
            $result = Get-EitAzSessionHost -BearerToken $validToken -SessionHostId $validSessionHostId
            $result.Success | Should -BeTrue
            $result.StatusCode | Should -Be 200
            $result.SessionHost.name | Should -Be 'myhost.domain.com'
            $result.SessionHost.properties.status | Should -Be 'Available'
        }
    }

    Context 'When Invoke-WebRequest returns 200 without content' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				return @{
					StatusCode = 200
					StatusDescription = "OK"
					Content = $null
				} | ConvertTo-Json -Depth 10 | ConvertFrom-Json
			} -ModuleName EducateIT.PSFunctions
		}
        

        It 'should return failure due to empty content' {
            $result = Get-EitAzSessionHost -BearerToken $validToken -SessionHostId $validSessionHostId
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'Did not get any content'
        }
    }

    Context 'When SessionHostId format is invalid' {
        It 'should throw an error and return failure' {
           

            $result = Get-EitAzSessionHost -BearerToken $validToken -SessionHostId $invaliSessionHostdId
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'Invalid SessionHostId format'
        }
    }

    Context 'When Invoke-WebRequest throws an exception' {
		BeforeEach {
			Mock -CommandName Invoke-WebRequest -MockWith {
				throw "Network error"
			} -ModuleName EducateIT.PSFunctions
		}
        
        It 'should catch the exception and return failure' {
            $result = Get-EitAzSessionHost -BearerToken $validToken -SessionHostId $validSessionHostId
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'Network error'
        } 
    }
}

Describe 'Set-EitAzSessionHostAllowNewSession' {

    Context 'When Mode is Allow' {
		
		BeforeEach {
			Mock -CommandName Invoke-RestMethod -MockWith {
				return @{ properties = @{ allowNewSession = $true } }
			} -ModuleName EducateIT.PSFunctions
		}
		
        It 'should send allowNewSession = true and succeed' {
            $result = Set-EitAzSessionHostAllowNewSession -BearerToken $validToken -SessionHostId $validSessionHostId -Mode Allow

            $result.Success | Should -BeTrue
            $result.Message | Should -Match 'Successfully'

            Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {
                $Body.properties.allowNewSession -eq $true -and
                $Method -eq 'Patch'
            } -ModuleName EducateIT.PSFunctions
        }
    }

    Context 'When Mode is Disallow' {
        BeforeEach {
			Mock -CommandName Invoke-RestMethod -MockWith {
				return @{ properties = @{ allowNewSession = $false } }
			} -ModuleName EducateIT.PSFunctions
		}

        It 'should send allowNewSession = false and succeed' {
            $result = Set-EitAzSessionHostAllowNewSession -BearerToken $validToken -SessionHostId $validSessionHostId -Mode Disallow

            $result.Success | Should -BeTrue
            $result.Message | Should -Match 'Successfully'

            Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {
                $Body.properties.allowNewSession -eq $false -and
                $Method -eq 'Patch'
            } -ModuleName EducateIT.PSFunctions
        }
    }
}
