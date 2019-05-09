param([guid] $TenantId,
	[string] $Command,
	$Params,
	[switch] $Encoded, 
	[switch] $AsJson, [switch] $Compress)

Import-Module (Join-Path $PSScriptRoot .\API\LwUtility) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwIntune) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwMsol) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwAuth) -Force -DisableNameChecking
#Import-Module (Join-Path $PSScriptRoot .\API\LwPnP) -Force -DisableNameChecking
#Import-Module (Join-Path $PSScriptRoot .\API\LwAzure) -Force -DisableNameChecking

function Get-AppSettings
{
	$apps = Get-Content (Join-Path $PSScriptRoot .\AppSettings.json) | ConvertFrom-Json
	$global:AppSettings = @{ }
	$apps.PSObject.Properties |% { $global:AppSettings[$_.Name] = $_.Value }
	if ($global:AppSettings.Interval) { $global:AppSettings.Interval = [int]$global:AppSettings.Interval } else { $global:AppSettings.Interval = 10 }
}

function Add-Param([string] $cmd, [string] $code, [bool] $Switch = $false, [string] $name)
{
	$_val = Invoke-Expression $code
	if ($_val -ne $null)
	{
		if ($cmd) { $cmd += ' ' }
		if (-not $name) {
			$name = $code.Split('.')[-1]
		}
		if ($Switch)
		{
			$cmd += '-' + $name + ':' + $code
		}
		else
		{
			$cmd += '-' + $name + ' ' + $code
		}
	}
	return $cmd
}

function Add-Params([string] $cmd, $names, [string] $variable = 'Params')
{
	$names |% { 
		if ($_ -is [string]) {
			$_name = $_
			$_Switch = $false
		}
		else {
			$_name = $_.Name
			$_Switch = $_.Switch
		}
		$cmd = Add-Param $cmd "`$$variable.$_name" $_Switch $_name
	}
	return $cmd
}

return LwPerform -AsJson:$AsJson -Compress:$Compress {

	if ($Params -is [string]) {
		if ($Encoded) {
			$Params = Get-DecodedString($Params)
		}
		$Params = Get-HashtableFromJson $Params
	}

	Get-AppSettings

	$conn = $null

	switch ($Command)
	{
	########### Azure AD #####################
	'Get-LwAzureUser' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Get-LwAzureUser'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('ObjectId', 'UPN')
	}
	'New-LwAzureUser' {
		# Login with service principal
		$conn = Login-LwAzure -TenantId $TenantId -AD
		# Interactively (or use next line with certificate with run as admin)
		# Login-LwAzureAD -TenantId $tenantId -ApplicationId $appId -CertificateThumbprint $thumb
		$cmd = 'New-LwAzureUser'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Surname', 'GivenName', 'DisplayName', 'UPN', 'MailNickName',`
			'Password', 'ForceChangePasswordNextLogin', 'EnforceChangePasswordPolicy', 'DisableStrongPassword', 'PasswordNeverExpires',`
			'UserType', 'ImmutableId', 'Country', 'State', 'PostalCode', 'City', 'StreetAddress', 'TelephoneNumber', 'Mobile', 'FacsimileTelephoneNumber', 'ExtProps',`
			@{ Name = 'Enabled'; Switch = $true}, @{ Name = 'LocalAccount'; Switch = $true})
	}
	'Update-LwAzureUser' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = Add-Params 'Update-LwAzureUser' @('ObjectId', 'Surname', 'GivenName', 'DisplayName', 'UPN', 'MailNickName',`
			'Password', 'ForceChangePasswordNextLogin', 'EnforceChangePasswordPolicy', 'DisableStrongPassword', 'PasswordNeverExpires',`
			'UserType', 'ImmutableId', 'Country', 'State', 'PostalCode', 'City', 'StreetAddress', 'TelephoneNumber', 'Mobile', 'FacsimileTelephoneNumber', 'ExtProps',`
			@{ Name = 'Enabled'; Switch = $true}, @{ Name = 'LocalAccount'; Switch = $true})
	}
	'Remove-LwAzureUser' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = Add-Params 'Remove-LwAzUser' @('ObjectId', 'UPN')
	}
	'Set-LwAzUserPassword' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = Add-Params 'Set-LwAzUserPassword' @('UPN', 'Password', @{ Name = 'ForceChangePasswordNextLogin'; Switch = $true})
	}
	'Enable-LwAzUser' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = Add-Params 'Enable-LwAzUser' @('UPN', 'Enabled')
	}
	'Get-LwAzureGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Get-LwAzureGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('ObjectId', 'DisplayName')
	}
	'New-LwAzureGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'New-LwAzureGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('DisplayName', 'Description', 'MailEnabled', 'MailNickName', 'SecurityEnabled')
	}
	'Update-LwAzureGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Update-LwAzureGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('ObjectId', 'DisplayName', 'Description', 'MailEnabled', 'MailNickName', 'SecurityEnabled')
	}
	'Remove-LwAzureGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Remove-LwAzureGroup'
		$cmd = Add-Params $cmd @('ObjectId')
	}
	'Get-LwAzureGroupMember' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Get-LwAzureGroupMember'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('ObjectId')
	}
	'Add-LwAzureGroupMember' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = Add-Params 'Add-LwAzureGroupMember' @('ObjectId', 'RefObjectId')
	}
	'Remove-LwAzureGroupMember' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = Add-Params 'Remove-LwAzureGroupMember' @('ObjectId', 'MemberId')
	}
	'Get-LwAzureDevice' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Get-LwAzureDevice'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('ObjectId', 'DisplayName')
	}
	'New-LwAzureDevice' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'New-LwAzureDevice'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('DisplayName', 'DeviceId', 'DeviceOSType', 'DeviceOSVersion', 'DeviceObjectVersion', `
				'AccountEnabled', 'IsCompliant', 'IsManaged', 'AlternativeSecurityIds', 'ApproximateLastLogonTimeStamp', 'DevicePhysicalIds', 'DeviceMetadata')
	}
	'Remove-LwAzureDevice' {
		$conn = Login-LwAzure -TenantId $TenantId -AD
		$cmd = 'Remove-LwAzureDevice'
		$cmd = Add-Params $cmd @('ObjectId')
	}

	########### Azure ###################
	'Get-LwAzResourceGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzResourceGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name')
	}
	'New-LwAzResourceGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzResourceGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location')
	}
	'Get-LwAzStorageAccount' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzStorageAccount'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'ResourceGroupName')
	}
	'New-LwAzStorageAccount' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzStorageAccount'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'SkuName', 'Kind', 'NetworkRuleSet')
	}
	'Get-LwAzNetworkSecurityGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzNetworkSecurityGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'ResourceGroupName')
	}
	'New-LwAzNetworkSecurityGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzNetworkSecurityGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'SecurityRules', 'Tag')
	}
	'New-LwAzVirtualNetworkSubnetConfig' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzVirtualNetworkSubnetConfig'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'VNetName', 'AddressPrefix', 'NetworkSecurityGroup', 'ServiceEndpoint')
	}
	'Get-LwAzVirtualNetwork' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzVirtualNetwork'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'ResourceGroupName')
	}
	'New-LwAzVirtualNetwork' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzVirtualNetwork'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'AddressPrefix', 'DnsServer', 'Subnets', 'Tag', 'EnableDdosProtection', 'DdosProtectionPlanId')
	}
	'Get-LwAzPublicIpAddress' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzPublicIpAddress'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'ResourceGroupName')
	}
	'New-LwAzPublicIpAddress' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzPublicIpAddress'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'Sku', 'AllocationMethod',`
			'IpAddressVersion', 'DomainNameLabel', 'ReverseFqdn', 'IdleTimeoutInMinutes', 'Zone', 'Tag')
	}
	'Get-LwAzNetworkInterface' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzNetworkInterface'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'ResourceGroupName')
	}
	'New-LwAzNetworkInterface' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzNetworkInterface'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'VirtualNetworkName', 'SubnetName', 'PublicIpAddressName', 'NetworkSecurityGroupName',`
				'PrivateIpAddress', 'InternalDnsNameLabel', 'DnsServer', 'Tag')
	}
	'Get-LwAzVM' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'Get-LwAzVM'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'ResourceGroupName')
	}
	'New-LwAzVM' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-LwAzVM'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Name', 'Location', 'ResourceGroupName', 'Size', 'AvailabilitySetId', 'LicenseType', 'Tags', 'Zone',`
				'EnableUltraSSD', 'OS', 'ComputerName', 'User', 'Password', 'WinRMHttp', 'WinRMHttps',`
				'PublisherName', 'Offer', 'Skus', 'Version', 'OSDisk', 'BootDiagnostics', 'StorageAccountName', 'NetworkInterfaces')
	}
	'New-AzLwResources' {
		$conn = Login-LwAzure -TenantId $TenantId -Account
		$cmd = 'New-AzLwResources'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Location', 'ResourceGroupName', 'StorageAccountName', 'SkuName', 'SecurityGroups', 'VirtualNetworks', 'IPAddresses', 'VMs')
	}
	########### SPO #####################
	'New-LwSPOSite' {
		$conn = Login-LwAzure -TenantId $TenantId -SPO
		$cmd = 'New-LwSPOSite'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Url', 'Title', 'Owner', 'StorageQuota',`
			'CompatibilityLevel', 'LocaleId', 'ResourceQuota', 'Template', 'TimeZoneId',`
			@{ Name = 'NoWait'; Switch = $true}, @{ Name = 'ClearSubscopes'; Switch = $true})
	}
	'Get-LwSPOSite' {
		$conn = Login-LwAzure -TenantId $TenantId -SPO
		$cmd = 'Get-LwSPOSite'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Url', 'DisableSharingForNonOwnersStatus', 'Detailed', 'Limit', 'Filter', 'Template',`
			@{ Name = 'IncludePersonalSite'; Switch = $true})
	}
	'Remove-LwSPOSite' {
		$conn = Login-LwAzure -TenantId $TenantId -SPO
		$cmd = Add-Params 'Remove-LwSPOSite' @('Url',`
			@{ Name = 'NoWait'; Switch = $true}, @{ Name = 'Permanently'; Switch = $true})
	}
	'Get-LwSPOPersonalSiteForUser' {
		$conn = Login-LwAzure -TenantId $TenantId -SPO
		$cmd = 'Get-LwSPOPersonalSiteForUser'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('UPN')
	}
	########### PNP #####################
	'Add-LwPnpFile' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = 'Add-LwPnpFile'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Path', 'Stream', 'Folder', 'NewFileName',`
			@{ Name = 'Checkout'; Switch = $true}, 'CheckInComment', @{ Name = 'Approve'; Switch = $true}, 'ApproveComment',`
			@{ Name = 'Publish'; Switch = $true}, 'PublishComment', 'FieldValues')
	}
	'Add-LwPnpFolder'{
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = Add-Params 'Add-LwPnpFolder' @('Folder', 'Name')
	}
	'Break-LwPnPRoleInheritance' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = Add-Params 'Break-LwPnPRoleInheritance' @('Folder', 'File',`
			@{ Name = 'CopyRoleAssignments'; Switch = $true}, @{ Name = 'ClearSubscopes'; Switch = $true})
	}
	'Reset-LwPnPRoleInheritance' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = Add-Params 'Reset-LwPnPRoleInheritance' @('Folder', 'File')
	}
	'Add-LwPnPRoleAssignment' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = Add-Params 'Add-LwPnPRoleAssignment -AsObject' @('Folder', 'File',`
			@{ Name = 'CopyRoleAssignments'; Switch = $true}, @{ Name = 'ClearSubscopes'; Switch = $true},`
			'Identity', 'RoleName')
	}
	'Remove-LwPnPRoleAssignment' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = Add-Params 'Remove-LwPnPRoleAssignment' @('Folder', 'File', 'Identity')
	}
	'Get-LwPnPRoleAssignments' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = Add-Params 'Get-LwPnPRoleAssignments' @('Folder', 'File')
	}
	'Add-LwPnpShare' {
		$conn = Login-LwAzure -TenantId $TenantId -PnP -SiteUrl $Params.SiteURL -User $Params.User
		$cmd = 'Add-LwPnpShare'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Folder', 'File', 'UPN', 'IsGuestUser', 'Role', 'EmailSubject',`
			@{ Name = 'AnonymousLink'; Switch = $true}, @{ Name = 'PropageAcl'; Switch = $true}, @{ Name = 'SendEmail'; Switch = $true})
	}
	########### Msol ####################
	'Get-LwMsolUsersReport' {
		$conn = Login-LwAzure -TenantId $TenantId -Msol
		$cmd = "Get-LwMsolUsersReport (Get-MsolUser -All)"
	}
	########### Office 365 #####################
	'Get-LwOfficeGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Office365
		$cmd = 'Get-LwOfficeGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Identity')
	}
	'New-LwOfficeGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Office365
		$cmd = 'New-LwOfficeGroup'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('DisplayName', 'Alias', 'AccessType', 'Members', 'Notes', 'Owner', 'AutoSubscribeNewMembers')
	}
	'Update-LwOfficeGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Office365
		$cmd = 'Update-LwOfficeGroup'
		$cmd = Add-Params $cmd @('Identity', 'DisplayName', 'Alias', 'AccessType', 'Members', 'Notes', 'Owner', 'AutoSubscribeNewMembers',`
				'AcceptMessagesOnlyFromSendersOrMembers', 'AlwaysSubscribeMembersToCalendarEvents', 'CalendarMemberReadOnly', 'SubscriptionEnabled', 'RejectMessagesFromSendersOrMembers', 'UnifiedGroupWelcomeMessageEnabled')
	}
	'Remove-LwOfficeGroup' {
		$conn = Login-LwAzure -TenantId $TenantId -Office365
		$cmd = 'Remove-LwOfficeGroup'
		$cmd = Add-Params $cmd @('Identity')
	}
	'Get-LwOfficeGroupMembers' {
		$conn = Login-LwAzure -TenantId $TenantId -Office365
		$cmd = 'Get-LwOfficeGroupMembers'
		if ($AsJson) { $cmd += ' -AsObject'}
		$cmd = Add-Params $cmd @('Identity', 'Type')
	}
	'Add-LwOfficeGroupMembers' {
		$conn = Login-LwAzure -TenantId $TenantId -Office365
		$cmd = 'Add-LwOfficeGroupMembers'
		$cmd = Add-Params $cmd @('Identity', 'Members', 'Type')
	}
	'Get-LwIntuneDeviceConfigurationPolicy' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Get-LwIntuneDeviceConfigurationPolicy'
		$cmd = Add-Params $cmd @('PolicyId', 'PolicyName')
	}
	'New-LwIntuneDeviceConfigurationPolicy' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'New-LwIntuneDeviceConfigurationPolicy'
		$cmd = Add-Params $cmd @('DisplayName', 'Description', 'Description', 'ConfigurationType', 'Settings')
	}
	'Update-LwIntuneDeviceConfigurationPolicy' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Update-LwIntuneDeviceConfigurationPolicy'
		$cmd = Add-Params $cmd @('PolicyId', 'DisplayName', 'Description', 'Description', 'ConfigurationType', 'Settings')
	}
	'Remove-LwIntuneDeviceConfigurationPolicy' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Remove-LwIntuneDeviceConfigurationPolicy'
		$cmd = Add-Params $cmd @('PolicyId')
	}
	'Get-LwIntuneManagedDevice' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Get-LwIntuneManagedDevice'
		$cmd = Add-Params $cmd @('DeviceId')
	}
	'Get-LwIntuneDeviceCompliancePolicyAssignment' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Get-LwIntuneDeviceCompliancePolicyAssignment'
		$cmd = Add-Params $cmd @('PolicyId')
	}
	'New-LwIntuneDeviceCompliancePolicyAssignment' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'New-LwIntuneDeviceCompliancePolicyAssignment'
		$cmd = Add-Params $cmd @('PolicyId', 'GroupId')
	}
	'Remove-LwIntuneDeviceCompliancePolicyAssignment' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Remove-LwIntuneDeviceCompliancePolicyAssignment'
		$cmd = Add-Params $cmd @('PolicyId', 'GroupId')
	}
	'Invoke-LwIntuneManagedDeviceSyncDevice' {
		$conn = Login-LwAzure -TenantId $TenantId -Intune
		$cmd = 'Invoke-LwIntuneManagedDeviceSyncDevice'
		$cmd = Add-Params $cmd @('DeviceId')
	}

	default {
		throw 'Unknown Command'
	}
	}

	try
	{
		return (Invoke-Expression $cmd)
	}
	catch
	{
		throw
	}
	finally
	{
		if ($conn -and $conn['Office365']) {
			Remove-PSSession $conn['Office365']
		}
	}
}
