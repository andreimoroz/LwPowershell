$TenantId = '3b811c12-df4a-41b3-834a-5b9420089c1b'

#$OrgaName = 'logiwayeu'
#$AppId = '6a86542a-2144-43ce-a5e1-50f135ccc7aa'
#$Password = 'Passw0rd!'

################################################

################################################
# Azure VM

Import-Module .\API\LwAzure -Force -DisableNameChecking -Global

.\Invoke-LwCommand.ps1 -Command 'New-LwAzResourceGroup' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiway'; Location = 'West Europe'}
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzResourceGroup' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiway' }

.\Invoke-LwCommand.ps1 -Command 'New-LwAzStorageAccount' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'amlogiway'; Location = 'West Europe'; ResourceGroupName = 'AMLogiway'; SkuName = 'Standard_LRS' }
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzStorageAccount' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'amlogiway'; ResourceGroupName = 'AMLogiway' }

.\Invoke-LwCommand.ps1 -Command 'New-LwAzNetworkSecurityGroup' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiway-NSG'; Location = 'West Europe'; ResourceGroupName = 'AMLogiway'; 
	 SecurityRules = @(@{ Name='rdp-rule'; Description = 'Allow RDP'; Access = 'Allow'; 
		Protocol = 'Tcp'; Direction = 'Inbound'; Priority = 100; SourceAddressPrefix = '*';
		SourcePortRange ='*'; DestinationAddressPrefix = '*'; DestinationPortRange = '3389' },
		@{ Name='www-rule'; Description = 'Allow WWW'; Access = 'Allow';
		Protocol = 'Tcp'; Direction = 'Inbound'; Priority = 101; SourceAddressPrefix = '*';
		SourcePortRange ='*'; DestinationAddressPrefix = '*'; DestinationPortRange = '80' }) }
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzNetworkSecurityGroup' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiway-NSG'; ResourceGroupName = 'AMLogiway' }

.\Invoke-LwCommand.ps1 -Command 'New-LwAzVirtualNetwork' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiwayVNet'; Location = 'West Europe'; ResourceGroupName = 'AMLogiway'; AddressPrefix = '10.0.0.0/16';
		Subnets = @(@{ Name = 'FrontendSubnet'; NetworkSecurityGroup = 'AMLogiway-NSG'; AddressPrefix = '10.0.1.0/24' },
			@{ Name = 'BackendSubnet'; NetworkSecurityGroup = 'AMLogiway-NSG'; AddressPrefix = '10.0.2.0/24' })}
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzVirtualNetwork' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiwayVNet'; ResourceGroupName = 'AMLogiway' }

.\Invoke-LwCommand.ps1 -Command 'New-LwAzPublicIpAddress' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiwayIP'; Location = 'West Europe'; ResourceGroupName = 'AMLogiway'; AllocationMethod = 'Static' ; IdleTimeoutInMinutes = 4 }
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzPublicIpAddress' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AMLogiwayIP'; ResourceGroupName = 'AMLogiway' }

.\Invoke-LwCommand.ps1 -Command 'New-LwAzVM' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AmLogiwayVM'; Location = 'West Europe'; ResourceGroupName = 'AMLogiway'; StorageAccountName = 'amlogiway'; `
        Size = 'Standard_A1'; OS = 'Windows'; `
		ComputerName = 'AmLogiwayVM'; User = 'myadmin'; Password = 'Passw0rd!'; `
		PublisherName = 'MicrosoftWindowsServer'; Offer = 'WindowsServer'; Skus = '2016-Datacenter'; Version = 'latest'; `
		OSDisk = @{ Name = 'AMOS'; CreateOption = 'FromImage'}; `
		NetworkInterfaces = @(@{ Name = 'AMLogiwayNic'; VirtualNetworkName = 'AMLogiwayVNet'; SubnetName = 'FrontendSubnet'; `
			PublicIpAddressName = 'AMLogiwayIP'; NetworkSecurityGroupName = 'AMLogiway-NSG' ; Primary = $true })}
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzVM' -AsJson `
	-TenantId $tenantId -Params @{ Name = 'AmLogiwayVM'; ResourceGroupName = 'AMLogiway' }

.\Invoke-LwCommand.ps1 -Command 'New-AzLwResources' -AsJson `
	-TenantId $tenantId -Params @{ Location = 'West Europe'; ResourceGroupName = 'AMLogiway'; StorageAccountName = 'amlogiway'; SkuName = 'Standard_LRS'; `
		SecurityGroups = @(@{ Name = 'AMLogiway-NSG'; `
			Rules = @(@{ Name='rdp-rule'; Description = 'Allow RDP'; Access = 'Allow'; `
			Protocol = 'Tcp'; Direction = 'Inbound'; Priority = 100; SourceAddressPrefix = '*'; `
			SourcePortRange ='*'; DestinationAddressPrefix = '*'; DestinationPortRange = '3389' }, `
			@{ Name='www-rule'; Description = 'Allow WWW'; Access = 'Allow'; `
			Protocol = 'Tcp'; Direction = 'Inbound'; Priority = 101; SourceAddressPrefix = '*'; `
			SourcePortRange ='*'; DestinationAddressPrefix = '*'; DestinationPortRange = '80' }) }); `
		VirtualNetworks = @(@{ Name = 'AMLogiwayVNet'; AddressPrefix = '10.0.0.0/16' ; `
			Subnets = @(@{ Name = 'FrontendSubnet'; NetworkSecurityGroup = 'AMLogiway-NSG'; AddressPrefix = '10.0.1.0/24' }, `
				@{ Name = 'BackendSubnet'; NetworkSecurityGroup = 'AMLogiway-NSG'; AddressPrefix = '10.0.2.0/24' })}); `
		IPAddresses = @(@{ Name = 'AMLogiwayIP'; AllocationMethod = 'Static' ; IdleTimeoutInMinutes = 4 }); `
		VMs = @(@{ Name = 'AmLogiwayVM'; ComputerName = 'AmLogiwayVM'; User = 'myadmin'; Password = 'Passw0rd!';`
			Size = 'Standard_A1'; OS = 'Windows'; `
			PublisherName = 'MicrosoftWindowsServer'; Offer = 'WindowsServer'; Skus = '2016-Datacenter'; Version = 'latest';`
			OSDisk = @{ Name = 'AMOS'; CreateOption = 'FromImage'};`
			NetworkInterfaces = @(@{ Name = 'AMLogiwayNic'; VirtualNetworkName = 'AMLogiwayVNet'; SubnetName = 'FrontendSubnet'; `
				PublicIpAddress = 'AMLogiwayIP'; NetworkSecurityGroupName = 'AMLogiway-NSG' ; Primary = $true }) }) }

Remove-AzResourceGroup -Name 'AMLogiway' -Confirm:$false -Force