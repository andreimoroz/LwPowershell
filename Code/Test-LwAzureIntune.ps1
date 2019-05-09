$tenantId = '698e87df-9f6c-451b-acfd-09fd709efd86'
#$User = 'cloudadmin@logiwayeu.onmicrosoft.com'
#$Password = 'Vab0!240EUA'

Import-Module .\API\LwUtility -Force -DisableNameChecking
Import-Module .\API\LwAuth -Force -DisableNameChecking
Import-Module .\API\LwIntune -Force -DisableNameChecking

.\Invoke-LwCommand.ps1 -Command 'Get-LwIntuneDeviceConfigurationPolicy' -AsJson `
	-TenantId $tenantId -Params @{ }
.\Invoke-LwCommand.ps1 -Command 'Get-LwIntuneDeviceConfigurationPolicy' -AsJson `
	-TenantId $tenantId -Params @{ PolicyId = '35b54cd1-f6a4-4efa-936a-e1b9d17f432b' }
.\Invoke-LwCommand.ps1 -Command 'Get-LwIntuneDeviceConfigurationPolicy' -AsJson `
	-TenantId $tenantId -Params @{ PolicyName = 'AMFavorities' }

.\Invoke-LwCommand.ps1 -Command 'New-LwIntuneDeviceConfigurationPolicy' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'BlockCopy'; ConfigurationType = 'windows10GeneralConfiguration';`
		Settings = @{copyPasteBlocked = $true}}
.\Invoke-LwCommand.ps1 -Command 'Update-LwIntuneDeviceConfigurationPolicy' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'BlockCopyNew'; ConfigurationType = 'windows10GeneralConfiguration';`
		PolicyId = '9e178cc6-d1c0-44e4-b74b-be35a404731c'; Settings = @{copyPasteBlocked = $false}}

.\Invoke-LwCommand.ps1 -Command 'Remove-LwIntuneDeviceConfigurationPolicy' -AsJson `
	-TenantId $tenantId -Params @{ PolicyId = '9e178cc6-d1c0-44e4-b74b-be35a404731c' }

.\Invoke-LwCommand.ps1 -Command 'Get-LwIntuneManagedDevice' -AsJson `
	-Params @{ TenantId = $tenantId }
.\Invoke-LwCommand.ps1 -Command 'Get-LwIntuneManagedDevice' -AsJson `
	-TenantId $tenantId -Params @{ DeviceId = '110b4e49-bd79-48c0-94ec-3b433d41fbcc' }

.\Invoke-LwCommand.ps1 -Command 'Get-LwIntuneDeviceCompliancePolicyAssignment' -AsJson `
	-TenantId $tenantId -Params @{ PolicyId = '35b54cd1-f6a4-4efa-936a-e1b9d17f432b' }

.\Invoke-LwCommand.ps1 -Command 'New-LwIntuneDeviceCompliancePolicyAssignment' -AsJson `
	-TenantId $tenantId -Params @{ PolicyId = '35b54cd1-f6a4-4efa-936a-e1b9d17f432b'; GroupId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0' }

.\Invoke-LwCommand.ps1 -Command 'Remove-LwIntuneDeviceCompliancePolicyAssignment' -AsJson `
	-TenantId $tenantId -Params @{ PolicyId = '35b54cd1-f6a4-4efa-936a-e1b9d17f432b'; GroupId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0' }

.\Invoke-LwCommand.ps1 -Command 'Invoke-LwIntuneManagedDeviceSyncDevice' -AsJson `
	-TenantId $tenantId -Params @{ DeviceId = '110b4e49-bd79-48c0-94ec-3b433d41fbcc' }


