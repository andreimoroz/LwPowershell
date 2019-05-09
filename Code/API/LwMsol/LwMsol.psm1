Import-Module MSOnline

function Login-LwMsol([string] $User, [string] $Password)
{
	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	$pscred = New-Object System.Management.Automation.PSCredential($User, $spasswd)
	Connect-MsolService -Credential $pscred -ErrorAction 'Stop'
}

function Get-LicenseServiceByName($user, [string]$accountSkuId, [string]$serviceName)
{
	$lic = $user.Licenses |? { $_.AccountSkuId -eq $accountSkuId } |% { $_.ServiceStatus } |? {$_.ServicePlan.ServiceName -eq $serviceName} |% {$_.ProvisioningStatus.ToString()}
	return $lic
}


function Get-LwMsolUsersReport($users)
{
	if ($global:DebugMode) { return }
	$props = @('UserPrincipalName', 'SignInName', 'DisplayName', 'Title', 'FirstName', 'LastName', 'UserType', 'UsageLocation', 'PreferredDataLocation', 'PreferredLanguage',`
		'ObjectId', 'LiveId', 'ImmutableId', 'IsBlackberryUser',`
		@{Name='WhenCreated'; Expression={Format-Date $_.WhenCreated}},`
		'Password', 'StrongPasswordRequired', 'PasswordNeverExpires', 'PasswordResetNotRequiredDuringActivate', 'BlockCredential',`
		@{Name='LastPasswordChangeTimestamp'; Expression={Format-Date $_.LastPasswordChangeTimestamp}},`
		@{Name='StsRefreshTokensValidFrom'; Expression={Format-Date $_.StsRefreshTokensValidFrom}},`
		@{Name='LastDirSyncTime'; Expression={Format-Date $_.LastDirSyncTime}},`
		'Country', 'State', 'PostalCode', 'City', 'StreetAddress', 'Office', 'Department', 'PhoneNumber', 'MobilePhone', 'Fax',`
		@{Name='AlternateEmailAddresses'; Expression={$_.AlternateEmailAddresses -join ','}},`
		@{Name='AlternateMobilePhones'; Expression={$_.AlternateMobilePhones -join ','}},`
		'ValidationStatus', 'IsLicensed', 'LicenseReconciliationNeeded', 'Status')
# TODO: LicenseAssignmentDetails

#AlternativeSecurityIds
#CloudExchangeRecipientDisplayType
#DirSyncProvisioningErrors
#Errors
#ExtensionData
#IndirectLicenseErrors
#MSExchRecipientTypeDetails
#MSRtcSipDeploymentLocator
#MSRtcSipPrimaryUserAddress
#OverallProvisioningStatus
#PortalSettings
#ProxyAddresses
#ReleaseTrack
##ServiceInformation
#SoftDeletionTimestamp
#StrongAuthenticationMethods
#StrongAuthenticationPhoneAppDetails
#StrongAuthenticationProofupTime
#StrongAuthenticationRequirements
#StrongAuthenticationUserDetails
#UserLandingPageIdentifierForO365Shell
#UserThemeIdentifierForO365Shell
	$userList = $users | Select-Object $props

	# Select plans for all users
	$plans = @{}
	$users |% { $_.Licenses |% {
		$accountSkuId = $_.AccountSkuId
		if (-not $plans[$accountSkuId]) { $plans[$accountSkuId] = @() }
		$_.ServiceStatus |% { if (-not $plans[$accountSkuId].Contains($_.ServicePlan.ServiceName)) { $plans[$accountSkuId] += $_.ServicePlan.ServiceName } }
	}}

	# Fill plans
	for ($i = 0; $i -lt $users.Length; $i++)
	{
		$user = $users[$i]
		$userp = $userList[$i]
		$subscriptions = @{}
		$userp | Add-Member @{ Subscriptions = $subscriptions }
		$plans.Keys |% {
			$accountSkuId = $_
			$userServices = @{}
			$userp.Subscriptions[$accountSkuId] = $userServices
			$plans[$accountSkuId] |% {
				$block = 'Get-LicenseServiceByName $user "' + $accountSkuId + '" "' + $_ + '"'
				$userServices[$_] = . ([scriptblock]::Create($block))
			}
		}
	}

	$userList = $userList | sort UserPrincipalName
	return $userList
}

Export-ModuleMember -Function Login-LwMsol, Get-LwMsolUsersReport