Import-Module -Name Microsoft.Online.SharePoint.PowerShell -DisableNameChecking -Global

# Functions 
function Login-LwSPO(
	[Parameter(Mandatory=$true)] [string] $OrgaName,
	[Parameter(Mandatory=$true)] [string] $User,
	[Parameter(Mandatory=$true)] [string] $Password)
{
	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	$pscred = New-Object System.Management.Automation.PSCredential($User, $spasswd)
	$Url = "https://$($OrgaName)-admin.sharepoint.com"
	Connect-SPOService -Url $Url -Credential $pscred
}

# If $UPN is not specified, all personal sites will be returned
function Get-LwSPOPersonalSiteForUser(
	[Parameter(Mandatory=$true, HelpMessage='Login user Identity')] [string] $UPN,
	[switch] $AsObject)
{
	$filter = "Url -like '-my.sharepoint.com/personal/'"
	if ($UPN) { $filter += "-and Owner -eq $UPN" }
	$res = Get-SPOSite -IncludePersonalSite $true -Limit all -Filter $filter

	if ($AsObject)
	{
		$res = $res | Select Url, Title, CompatibilityLevel, Status, Owner, WebsCount,`
			AllowDownloadingNonWebViewableFiles, AllowEditing, AllowSelfServiceUpgrade, CommentsOnSitePagesDisabled,`
			DisableSharingForNonOwnersStatus, HubSiteId, IsHubSite, LocaleId, LockIssue, LockState,`
			ResourceQuota, ResourceQuotaWarningLevel, ResourceUsageAverage, ResourceUsageCurrent, SensitivityLabel,`
			SharingBlockedDomainList, ShowPeoplePickerSuggestionsForGuestUsers, SocialBarOnSitePagesDisabled,`
			StorageQuota, StorageQuotaType, StorageQuotaWarningLevel, StorageUsageCurrent, Template,`
			@{Name='LastContentModifiedDate'; Expression={ Format-DateUniversal $_.LastContentModifiedDate }},`
			@{Name='ConditionalAccessPolicy'; Expression={ $_.ConditionalAccessPolicy.ToString() }},`
			@{Name='DefaultLinkPermission'; Expression={ $_.DefaultLinkPermission.ToString() }},`
			@{Name='DefaultSharingLinkType'; Expression={ $_.DefaultSharingLinkType.ToString() }},`
			@{Name='DenyAddAndCustomizePages'; Expression={ $_.DenyAddAndCustomizePages.ToString() }},`
			@{Name='DisableAppViews'; Expression={ $_.DisableAppViews.ToString() }},`
			@{Name='DisableCompanyWideSharingLinks'; Expression={ $_.DisableCompanyWideSharingLinks.ToString() }},`
			@{Name='DisableFlows'; Expression={ $_.DisableFlows.ToString() }},`
			@{Name='LimitedAccessFileType'; Expression={ $_.LimitedAccessFileType.ToString() }},`
			@{Name='PWAEnabled'; Expression={ $_.PWAEnabled.ToString() }},`
			@{Name='RestrictedToGeo'; Expression={ $_.RestrictedToGeo.ToString() }},`
			@{Name='SandboxedCodeActivationCapability'; Expression={ $_.SandboxedCodeActivationCapability.ToString() }},`
			@{Name='SharingCapability'; Expression={ $_.SharingCapability.ToString() }},`
			@{Name='SharingDomainRestrictionMode'; Expression={ $_.SharingDomainRestrictionMode.ToString() }},`
			@{Name='SiteDefinedSharingCapability'; Expression={ $_.SiteDefinedSharingCapability.ToString() }}
	}

	return $res
}

function New-LwSPOSite(
	[Parameter(Mandatory=$true, HelpMessage='URL of the new site collection. It must be in a valid managed path in the company''s site (teams, sites)')] $Url,
	[Parameter(Mandatory=$false, HelpMessage='Title of the site collection')] [string] $Title,
	[Parameter(Mandatory=$true, HelpMessage='User name of the site collection''s primary owner')] [string] $Owner,
	[Parameter(Mandatory=$true, HelpMessage='Storage quota in megabytes')] [int64] $StorageQuota,
	[Parameter(Mandatory=$false, HelpMessage='Version of templates to use')] [int] $CompatibilityLevel,
	[Parameter(Mandatory=$false, HelpMessage='Language of this site collection')] [int] $LocaleId,
	[Parameter(Mandatory=$false, HelpMessage='Continue executing script immediately')] [switch] $NoWait,
	[Parameter(Mandatory=$false, HelpMessage='Quota in Sandboxed Solutions units')] [double] $ResourceQuota,
	[Parameter(Mandatory=$false, HelpMessage='Template type. Use the Get-SPOWebTemplate')] [string] $Template,
	[Parameter(Mandatory=$false, HelpMessage='Time zone of the site collection. For more information, see SPRegionalSettings.TimeZones Property')] [int] $TimeZoneId)
{
	$cmd = 'New-SPOSite -Url $Url -Owner $Owner -StorageQuota $StorageQuota'
	if ($Title) { $cmd += ' -Title $Title' }
	if ($CompatibilityLevel) { $cmd += ' -CompatibilityLevel $CompatibilityLevel' }
	if ($LocaleId) { $cmd += ' -LocaleId $LocaleId' }
	if ($NoWait) { $cmd += ' -NoWait' }
	if ($ResourceQuota) { $cmd += ' -ResourceQuota $ResourceQuota' }
	if ($Template) { $cmd += ' -Template $Template' }
	if ($TimeZoneId)  { $cmd += ' -TimeZoneId $TimeZoneId' }
	Invoke-Expression $cmd

	return $null
}

function Get-LwSPOSite(
	[Parameter(Mandatory=$false, HelpMessage='URL of the site collection')] [string] $URL,
	[Parameter(Mandatory=$false, HelpMessage='Prevents non-owner from sharing')] [switch] $DisableSharingForNonOwnersStatus,
	[Parameter(Mandatory=$false, HelpMessage='Get additional property information on a site collection')] [switch] $Detailed,
	[Parameter(Mandatory=$false, HelpMessage='Maximum number of site collections to return. It can be any number. To retrieve all site collections, use ALL. The default value is 200')] [string] $Limit,
	[Parameter(Mandatory=$false, HelpMessage='Script block of the server-side filter to apply')] [string] $Filter,
	[Parameter(Mandatory=$false, HelpMessage='Displays personal sites when value is set to $true')] [switch] $IncludePersonalSite,
	[Parameter(Mandatory=$false, HelpMessage='Displays sites of a specific template. For example, STS, STS#0 or STS#1')] [string] $Template,
	[switch] $AsObject)
{
	$cmd = 'Get-SPOSite'
	if ($URL) { $cmd += ' -Identity $URL' }
	if ($DisableSharingForNonOwnersStatus) { $cmd += ' -DisableSharingForNonOwnersStatus' }
	if ($Detailed) { $cmd += ' Detailed' }
	if ($Limit) { $cmd += ' -Limit $Limit' }
	if ($Filter) { $cmd += ' -Filter $Filter' }
	if ($IncludePersonalSite) { $cmd += ' -IncludePersonalSite $IncludePersonalSite' }
	if ($Template) { $cmd += ' -Template $Template' }

	$res = Invoke-Expression $cmd

	if ($AsObject)
	{
		$props = @('AllowDownloadingNonWebViewableFiles', 'AllowEditing', `
			'CommentsOnSitePagesDisabled', 'DisableSharingForNonOwnersStatus', 'IsHubSite',`
			'LocaleId', 'LockState', 'Owner', 'ResourceQuota', 'ResourceQuotaWarningLevel', `
			'SensitivityLabel', 'SharingAllowedDomainList', 'SharingBlockedDomainList',`
			'ShowPeoplePickerSuggestionsForGuestUsers', 'SocialBarOnSitePagesDisabled', 'Status',`
			'StorageQuota', 'StorageQuotaType', 'StorageQuotaWarningLevel', 'Template', 'Title', 'Url',`
			@{Name='ConditionalAccessPolicy'; Expression={$_.ConditionalAccessPolicy.ToString()}},`
			@{Name='DefaultLinkPermission'; Expression={$_.DefaultLinkPermission.ToString()}},`
			@{Name='DefaultSharingLinkType'; Expression={$_.DefaultSharingLinkType.ToString()}},`
			@{Name='DenyAddAndCustomizePages'; Expression={$_.DenyAddAndCustomizePages.ToString()}},`
			@{Name='DisableAppViews'; Expression={$_.DisableAppViews.ToString()}},`
			@{Name='DisableCompanyWideSharingLinks'; Expression={$_.DisableCompanyWideSharingLinks.ToString()}},`
			@{Name='DisableFlows'; Expression={$_.DisableFlows.ToString()}},`
			@{Name='LastContentModifiedDate'; Expression={ Format-DateUniversal $_.LastContentModifiedDate }},`
			@{Name='LimitedAccessFileType'; Expression={$_.LimitedAccessFileType.ToString()}},`
			@{Name='PWAEnabled'; Expression={$_.PWAEnabled.ToString()}},`
			@{Name='RestrictedToGeo'; Expression={$_.RestrictedToGeo.ToString()}},`
			@{Name='SandboxedCodeActivationCapability'; Expression={$_.SandboxedCodeActivationCapability.ToString()}},`
			@{Name='SharingDomainRestrictionMode'; Expression={$_.SharingDomainRestrictionMode.ToString()}})

			if ($Detailed)
			{
				$props += @('AllowSelfServiceUpgrade', 'CompatibilityLevel', 'LockIssue', 'ResourceUsageCurrent', 'ResourceUsageAverage', 'StorageUsageCurrent', 'WebsCount',`
					@{Name='SharingCapability'; Expression={$_.SharingCapability.ToString()}},`
					@{Name='SiteDefinedSharingCapability'; Expression={$_.SiteDefinedSharingCapability.ToString()}})
			}
			$res = $res | Select $props
	}

	return $res
}

function Remove-LwSPOSite(
	[Parameter(Mandatory=$true, HelpMessage='URL of the new site collection. It must be in a valid managed path in the company''s site (teams, sites)')] $Url,
	[Parameter(Mandatory=$false, HelpMessage='Continue executing script immediately')] [switch] $NoWait,
	[Parameter(Mandatory=$false, HelpMessage='Remove also from recycle bin')] [switch] $Permanently,
	[switch] $AsJson, [switch] $Compress)
{
	Remove-SPOSite -Identity $Url -Confirm:$false -NoWait:$NoWait

	if ($Permanently)
	{
		Remove-SPODeletedSite -Identity $Url -Confirm:$false -NoWait:$NoWait
	}

	return $null
}

Export-ModuleMember -Function Login-LwSPO, Get-LwSPOPersonalSiteForUser, New-LwSPOSite, Get-LwSPOSite, Remove-LwSPOSite