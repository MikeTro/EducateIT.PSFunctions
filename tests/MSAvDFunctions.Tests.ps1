# File: tests\MSAvDFunctions.Tests.ps1
# Requires -Module Pester -Version 5.5.5
 

BeforeAll {
		Import-Module EducateIT.PSFunctions -Force -ErrorAction SilentlyContinue
		
		$fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
		$appId = 'test-app-id'
		$appSecret = 'test-app-secret'
		$tenantId = 'test-tenant-id'
		$baseUrl = 'https://management.azure.com'
			
        
    }




Describe 'Get-EitAzBearerToken' {

    Context 'When token is successfully retrieved' {
		BeforeEach {
			Mock -CommandName Invoke-RestMethod -MockWith {
				return @{
					access_token = $fakeToken
				}
			} -ModuleName EducateIT.PSFunctions
		}
		
        It 'Should return a PSCustomObject with Success = $true and a valid BearerToken' {
            $result = Get-EitAzBearerToken -AppId $appId -AppSecret $appSecret -TenantId $tenantId -BaseUrl $baseUrl
            $result | Should -BeOfType 'pscustomobject'
            <# $result.Success | Should -Be $true #>
            $result.Message | Should -Be 'Successfully retrieved bearer token.'
            $result.BearerToken | Should -Be $fakeToken
        }

        
    }

    Context 'When Invoke-RestMethod throws an exception' {
        BeforeEach {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw "401 Unauthorized"
            } -ModuleName EducateIT.PSFunctions
        }

        It 'Should return Success = $false and a proper error message' {
            $result = Get-EitAzBearerToken -AppId $appId -AppSecret $appSecret -TenantId $tenantId -BaseUrl $baseUrl

            $result.Success | Should -Be $false
            $result.Message | Should -Match 'Error retrieving token: .*'
            $result.BearerToken | Should -Be $null
        }
    }

    Context 'When the token is missing in the response' {
        BeforeEach {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{ someOtherKey = 'value' }
            } -ModuleName EducateIT.PSFunctions
        }

        It 'Should return Success = $false and an error about missing bearer token' {
            $result = Get-EitAzBearerToken -AppId $appId -AppSecret $appSecret -TenantId $tenantId -BaseUrl $baseUrl

            $result.Success | Should -Be $false
            $result.Message | Should -Match 'Error retrieving token: .*'
            $result.BearerToken | Should -Be $null
        }
    }
}
