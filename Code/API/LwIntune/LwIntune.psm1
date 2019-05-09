Import-Module -Name Microsoft.Graph.Intune -Global

<# 
   .Synopsis 
    Login user to Azure with credentials
   .Parameter TenantId
    Tenant Id
   .Parameter User
    User login name (e-mail)
   .Parameter Password
    User password
#> 


function Login-LwIntune([string] $User, [string] $Password)
{
	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	$pscred = New-Object System.Management.Automation.PSCredential($User, $spasswd)
	$conn = Connect-MSGraph -PSCredential $pscred
	return $conn
}

function Get-LwIntuneDeviceConfigurationPolicy([guid] $PolicyId, [string] $PolicyName)
{
	$cmd = 'Get-IntuneDeviceConfigurationPolicy -EA 0'
	if ($PolicyId) { $cmd += ' -deviceConfigurationId $PolicyId'}
	if ($Name) { $cmd += ' -Filter "displayName eq ''$PolicyName''"'}
	return (Invoke-Expression $cmd)
}

function New-LwIntuneDeviceConfigurationPolicy(
	[Parameter(Mandatory=$true, HelpMessage='Device configuration display name')] [string] $DisplayName,
	[Parameter(Mandatory=$false, HelpMessage='Device configuration description')] [string] $Description,
	[Parameter(Mandatory=$true, HelpMessage='Configuration type')] 
	[ValidateSet('androidCustomConfiguration', 'androidGeneralDeviceConfiguration', 'androidWorkProfileCustomConfiguration', 'androidWorkProfileGeneralDeviceConfiguration', 
	'editionUpgradeConfiguration', 'sharedPCConfiguration',
	'iosCustomConfiguration', 'iosDeviceFeaturesConfiguration', 'iosGeneralDeviceConfiguration', 'iosUpdateConfiguration',
	'macOSCustomConfiguration', 'macOSDeviceFeaturesConfiguration', 'macOSGeneralDeviceConfiguration',
	'windows10CustomConfiguration', 'windows10EndpointProtectionConfiguration', 'windows10EnterpriseModernAppManagementConfiguration', 'windows10GeneralConfiguration', 'windows10SecureAssessmentConfiguration', 'windows10TeamGeneralConfiguration',
	'windows81GeneralConfiguration', 'windowsDefenderAdvancedThreatProtectionConfiguration', 'windowsPhone81CustomConfiguration', 'windowsPhone81GeneralConfiguration', 'windowsUpdateForBusinessConfiguration')]
		[string] $ConfigurationType,
	[Parameter(Mandatory=$true, HelpMessage='Hashtable with policy settings')] [hashtable] $Settings)
{
	$cmd = "New-IntuneDeviceConfigurationPolicy -DisplayName $DisplayName -$($ConfigurationType)"
	if ($Description) { $cmd += ' -Description $Description'}
	$Settings.Keys |% { $cmd += " -$($_) `$Settings['$($_)']" }
	return (Invoke-Expression $cmd)
}

function Update-LwIntuneDeviceConfigurationPolicy(
	[Parameter(Mandatory=$true, HelpMessage='Device configuration id')] [string] $PolicyId,
	[Parameter(Mandatory=$false, HelpMessage='Device configuration display name')] [string] $DisplayName,
	[Parameter(Mandatory=$false, HelpMessage='Device configuration description')] [string] $Description,
	[Parameter(Mandatory=$true, HelpMessage='Configuration type')] 
	[ValidateSet('androidCustomConfiguration', 'androidGeneralDeviceConfiguration', 'androidWorkProfileCustomConfiguration', 'androidWorkProfileGeneralDeviceConfiguration', 
	'editionUpgradeConfiguration', 'sharedPCConfiguration',
	'iosCustomConfiguration', 'iosDeviceFeaturesConfiguration', 'iosGeneralDeviceConfiguration', 'iosUpdateConfiguration',
	'macOSCustomConfiguration', 'macOSDeviceFeaturesConfiguration', 'macOSGeneralDeviceConfiguration',
	'windows10CustomConfiguration', 'windows10EndpointProtectionConfiguration', 'windows10EnterpriseModernAppManagementConfiguration', 'windows10GeneralConfiguration', 'windows10SecureAssessmentConfiguration', 'windows10TeamGeneralConfiguration',
	'windows81GeneralConfiguration', 'windowsDefenderAdvancedThreatProtectionConfiguration', 'windowsPhone81CustomConfiguration', 'windowsPhone81GeneralConfiguration', 'windowsUpdateForBusinessConfiguration')]
		[string] $ConfigurationType,
	[Parameter(Mandatory=$false, HelpMessage='Hashtable with policy settings')] [hashtable] $Settings)
{
	$cmd = "Update-IntuneDeviceConfigurationPolicy -deviceConfigurationId $PolicyId -$($ConfigurationType)"
	if ($DisplayName) { $cmd += ' -DisplayName $DisplayName'}
	if ($Description) { $cmd += ' -Description $Description'}
	if ($Settings) { $Settings.Keys |% { $cmd += " -$($_) `$Settings['$($_)']" } }
	Invoke-Expression $cmd

	return (Get-LwIntuneDeviceConfigurationPolicy -PolicyId $PolicyId)
}

function Remove-LwIntuneDeviceConfigurationPolicy([guid] $PolicyId)
{
	Remove-IntuneDeviceConfigurationPolicy -deviceConfigurationId $PolicyId
}

function Get-LwIntuneManagedDevice([guid] $DeviceId)
{
	$cmd = 'Get-IntuneManagedDevice -EA 0'
	if ($DeviceId) { $cmd += ' -ManagedDeviceId $DeviceId'}
	return (Invoke-Expression $cmd)
}

function Get-LwIntuneDeviceCompliancePolicyAssignment([guid] $PolicyId)
{
	$cmd = 'Get-IntuneDeviceCompliancePolicyAssignment -EA 0'
	if ($PolicyId) { $cmd += ' -deviceCompliancePolicyId $PolicyId'}
	return (Invoke-Expression $cmd)
}

function New-LwIntuneDeviceCompliancePolicyAssignment([guid] $PolicyId, [guid] $GroupId)
{
	$ass = $null
	ForEach ($i in @(0,1)) {
		$ass = Get-IntuneDeviceCompliancePolicyAssignment -deviceCompliancePolicyId $PolicyId -EA 0 |? { $_.target.groupId -eq $GroupId }
		if ($ass -or $i) { break }
		$target = New-Object PSObject -Property @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0' }
		New-IntuneDeviceConfigurationPolicyAssignment -deviceConfigurationId $PolicyId -target $target
	}
	return $ass
}

function Remove-LwIntuneDeviceCompliancePolicyAssignment([guid] $PolicyId, [guid] $GroupId)
{
	$ass = Get-IntuneDeviceCompliancePolicyAssignment -deviceCompliancePolicyId $PolicyId -EA 0 |? { $_.target.groupId -eq $GroupId }
	if ($ass) { 
		Remove-IntuneDeviceConfigurationPolicyAssignment -deviceConfigurationId $PolicyId `
			-deviceConfigurationAssignmentId $ass.id
		return $true		
	}
	return $false
}

function Invoke-LwIntuneManagedDeviceSyncDevice([guid] $DeviceId)
{
	return (Invoke-IntuneManagedDeviceSyncDevice -managedDeviceId $DeviceId)
}


Export-ModuleMember -Function Login-LwIntune, Get-LwIntuneDeviceConfigurationPolicy, New-LwIntuneDeviceConfigurationPolicy, Update-LwIntuneDeviceConfigurationPolicy, Remove-LwIntuneDeviceConfigurationPolicy, `
	Get-LwIntuneManagedDevice, Get-LwIntuneDeviceCompliancePolicyAssignment, New-LwIntuneDeviceCompliancePolicyAssignment, Remove-LwIntuneDeviceCompliancePolicyAssignment,
	Invoke-LwIntuneManagedDeviceSyncDevice