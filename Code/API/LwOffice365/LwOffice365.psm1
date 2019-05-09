function Login-LwOffice365([string] $User, [string] $Password)
{
	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	$pscred = New-Object System.Management.Automation.PSCredential($User, $spasswd)

	$Session = New-PSSession -ConfigurationName Microsoft.Exchange `
		-ConnectionUri 'https://outlook.office365.com/powershell-liveid/' `
		-Credential $pscred -Authentication Basic -AllowRedirection

	Import-PSSession $Session -DisableNameChecking -AllowClobber | Out-Null
	return $Session
}


function Get-LwOfficeGroup(
	[Parameter(Mandatory=$false, HelpMessage='Group identity (name, alias, DN, email, guid)')] [string] $Identity,
	[switch] $AsObject)
{
	$cmd = 'Get-UnifiedGroup'
	$cmd = Add-OptionalParam $cmd '-Identity $Identity' $Identity $true

	$res = Invoke-Expression $cmd
	if ($AsObject) {
		return (Get-LwOfficeGroupAsObject $res)
	}

	return $res	
<##
AcceptMessagesOnlyFrom                 Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
AcceptMessagesOnlyFromDLMembers        Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
AcceptMessagesOnlyFromSendersOrMembers Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
AddressListMembership                  Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
AdministrativeUnits                    Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
BypassModerationFromSendersOrMembers   Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
Classification                         Property      {get;set;}
DataEncryptionPolicy                   Property      {get;set;}
ExpirationTime                         Property      {get;set;}
ExtensionCustomAttribute1              Property     Deserialized.Microsoft.Exchange.Data.MultiValuedProperty`1[[Syst...
ExtensionCustomAttribute2              Property     Deserialized.Microsoft.Exchange.Data.MultiValuedProperty`1[[Syst...
ExtensionCustomAttribute3              Property     Deserialized.Microsoft.Exchange.Data.MultiValuedProperty`1[[Syst...
ExtensionCustomAttribute4              Property     Deserialized.Microsoft.Exchange.Data.MultiValuedProperty`1[[Syst...
ExtensionCustomAttribute5              Property     Deserialized.Microsoft.Exchange.Data.MultiValuedProperty`1[[Syst...
FileNotificationsSettings              Property      {get;set;}
GrantSendOnBehalfTo                    Property     Deserialized.Microsoft.Exchange.Data.Directory.ADMultiValuedProp...
GroupPersonification                   Property      {get;set;}
LastExchangeChangedTime                Property      {get;set;}
MailboxProvisioningConstraint          Property      {get;set;}
MailboxRegion                          Property      {get;set;}
MailTip                                Property      {get;set;}
MailTipTranslations                    Property     Deserialized.Microsoft.Exchange.Data.MultiValuedProperty`1[[Syst...
SharePointDocumentsUrl                 Property      {get;set;}
SharePointNotebookUrl                  Property      {get;set;}
SharePointSiteUrl                      Property      {get;set;}
WhenSoftDeleted                        Property      {get;set;}
##>
}

function Get-LwOfficeGroupAsObject($res) {
	return $res | Select AccessType, Alias, AllowAddGuests, AlwaysSubscribeMembersToCalendarEvents,`
		AuditLogAgeLimit, AutoSubscribeNewMembers, CalendarMemberReadOnly, CalendarUrl, ConnectorsEnabled,`
		CustomAttribute1, CustomAttribute2, CustomAttribute3, CustomAttribute4, CustomAttribute5, CustomAttribute6,`
		CustomAttribute7, CustomAttribute8, CustomAttribute9, CustomAttribute10, CustomAttribute11,`
		CustomAttribute12, CustomAttribute13, CustomAttribute14, CustomAttribute15,`
		Database, DisplayName, DistinguishedName, EmailAddresses, EmailAddressPolicyEnabled,`
		ExchangeGuid, ExchangeObjectId, ExchangeVersion, ExpansionServer, ExternalDirectoryObjectId, GroupExternalMemberCount, GroupMemberCount,`
		GroupSKU, GroupType, Guid, HiddenFromAddressListsEnabled, HiddenFromExchangeClientsEnabled, HiddenGroupMembershipEnabled,`
		Id, Identity, InboxUrl, IsDirSynced, IsExternalResourcesPublished, IsMailboxConfigured, IsMembershipDynamic, IsValid,`
		@{Name='LanguageLCID'; Expression={$_.Language.LCID}}, @{Name='LanguageName'; Expression={$_.Language.DisplayName}},`
		LegacyExchangeDN, ManagedBy, ManagedByDetails, MaxReceiveSize, MaxSendSize, MigrationToUnifiedGroupInProgress,`
		ModeratedBy, ModerationEnabled, Name, Notes, ObjectCategory, ObjectClass, ObjectState,`
		OrganizationalUnit, OrganizationId, OriginatingServer, PeopleUrl, PhotoUrl,`
		PoliciesExcluded, PoliciesIncluded, PrimarySmtpAddress, RecipientType, RecipientTypeDetails,
		RejectMessagesFrom, RejectMessagesFromDLMembers, RejectMessagesFromSendersOrMembers,`
		ReportToManagerEnabled, ReportToOriginatorEnabled, RequireSenderAuthenticationEnabled,`
		SendModerationNotifications, SendOofMessageToOriginatorEnabled,`
		ServerName, SubscriptionEnabled, WelcomeMessageEnabled,`
		@{Name='WhenChanged'; Expression={ Format-Date $_.WhenChanged }},`
		@{Name='WhenChangedUTC'; Expression={ Format-Date $_.WhenChangedUTC }},`
		@{Name='WhenCreated'; Expression={ Format-Date $_.WhenCreated }},`
		@{Name='WhenCreatedUTC'; Expression={ Format-Date $_.WhenCreatedUTC }},`
		YammerEmailAddress
}

function New-LwOfficeGroup(
	[Parameter(Mandatory=$true, HelpMessage='Group display name')] [string] $DisplayName,
	[Parameter(Mandatory=$false, HelpMessage='Mail nick name')] [string] $Alias,
	[Parameter(Mandatory=$false, HelpMessage='Privacy type for the Office 365 Group <Public | Private>')] [ValidateSet('Public', 'Private')] [string] $AccessType,
	[Parameter(Mandatory=$false, HelpMessage='Group members'' identities (name, alias, DN, email, guid)')] [string[]] $Members,
	[Parameter(Mandatory=$false, HelpMessage='Description of the Office 365 Group')] [string] $Notes,
	[Parameter(Mandatory=$false, HelpMessage='An owner is a group member who has certain privileges, such as the ability to edit group properties.')] [string] $Owner,
	[Parameter(Mandatory=$false, HelpMessage='Whether to automatically subscribe new members that are added to the Office 365 Group to conversations and calendar events.')] [bool] $AutoSubscribeNewMembers,`
	[Parameter(Mandatory=$false, HelpMessage=' Default subscription settings of new members that are added to the Office 365 Group.')] [nullable[bool]] $AlwaysSubscribeMembersToCalendarEvents,`
	[switch] $AsObject)
{
	$cmd = 'New-UnifiedGroup -DisplayName $DisplayName'
	$cmd = Add-OptionalParam $cmd '-Alias $Alias' $Alias $true
	$cmd = Add-OptionalParam $cmd '-AccessType $AccessType' $AccessType $true
	$cmd = Add-OptionalParam $cmd '-Members $Members' $Members $true
	$cmd = Add-OptionalParam $cmd '-Notes $Notes' $Notes $true
	$cmd = Add-OptionalParam $cmd '-Owner $Owner' $Owner $true
	if ($AutoSubscribeNewMembers) { $cmd += ' -AutoSubscribeNewMembers'}
	if ($AlwaysSubscribeMembersToCalendarEvents) { $cmd += ' -AlwaysSubscribeMembersToCalendarEvents'}

	$res = Invoke-Expression $cmd
	if ($AsObject) {
		return (Get-LwOfficeGroupAsObject $res)
	}
	return $res	

<##
New-UnifiedGroup
   [-MailboxRegion <String>]
   [-Classification <String>]
   [-Confirm]
   [-DataEncryptionPolicy <DataEncryptionPolicyIdParameter>]
   [-EmailAddresses <ProxyAddressCollection>]
   [-ExecutingUser <RecipientIdParameter>]
   [-ExoErrorAsWarning]
   [-HiddenGroupMembershipEnabled]
   [-Language <CultureInfo>]
   [-ManagedBy <RecipientIdParameter[]>]
   [-PrimarySmtpAddress <SmtpAddress>]
   [-RequireSenderAuthenticationEnabled <$true | $false>]
   [-SuppressWarmupMessage]
   [-WhatIf]
   [<CommonParameters>]

New-UnifiedGroup
   -DlIdentity <DistributionGroupIdParameter>
   [-ConvertClosedDlToPrivateGroup]
   [-DeleteDlAfterMigration]
   [-Confirm]
   [-ExecutingUser <RecipientIdParameter>]
   [-ManagedBy <RecipientIdParameter[]>]
   [-Members <RecipientIdParameter[]>]
   [-Owner <RecipientIdParameter>]
   [-WhatIf]
   [<CommonParameters>]
##>
}

function Update-LwOfficeGroup(
	[Parameter(Mandatory=$true, HelpMessage='Group identity (name, alias, DN, email, guid)')] [string] $Identity,
	[Parameter(Mandatory=$false, HelpMessage='Group display name')] [string] $DisplayName,
	[Parameter(Mandatory=$false, HelpMessage='Mail nick name')] [string] $Alias,
	[Parameter(Mandatory=$false, HelpMessage='Privacy type for the Office 365 Group <Public | Private>')] [ValidateSet('Public', 'Private')] [string] $AccessType,
	[Parameter(Mandatory=$false, HelpMessage='Description of the Office 365 Group')] [string] $Notes,
	[Parameter(Mandatory=$false, HelpMessage='An owner is a group member who has certain privileges, such as the ability to edit group properties.')] [string] $Owner,
	[Parameter(Mandatory=$false, HelpMessage='Whether to automatically subscribe new members that are added to the Office 365 Group to conversations and calendar events.')] [nullable[bool]] $AutoSubscribeNewMembers,`
	[Parameter(Mandatory=$false, HelpMessage='Who is allowed to send messages to this recipient. Messages from other senders are rejected.')] [string[]] $AcceptMessagesOnlyFromSendersOrMembers,`
	[Parameter(Mandatory=$false, HelpMessage='Default subscription settings of new members that are added to the Office 365 Group.')] [nullable[bool]] $AlwaysSubscribeMembersToCalendarEvents,`
	[Parameter(Mandatory=$false, HelpMessage='Whether to set read-only Calendar permissions to the Office 365 Group for members of the group.')] [nullable[bool]] $CalendarMemberReadOnly,`
	[Parameter(Mandatory=$false, HelpMessage='Specifies whether subscriptions to conversations and calendar events are enabled for the Office 365 Group.')] [nullable[bool]] $SubscriptionEnabled,`
	[Parameter(Mandatory=$false, HelpMessage='Who isn''t allowed to send messages to this recipient. Messages from these senders are rejected.')] [string[]] $RejectMessagesFromSendersOrMembers,`
	[Parameter(Mandatory=$false, HelpMessage='Whether to enable or disable sending system-generated welcome messages to users who are added as members to the Office 365 Group.')] [nullable[bool]] $UnifiedGroupWelcomeMessageEnabled)
{
	$cmd = 'Set-UnifiedGroup -Identity $Identity'
	$cmd = Add-OptionalParam $cmd '-DisplayName $DisplayName' $DisplayName $true
	$cmd = Add-OptionalParam $cmd '-Alias $Alias' $Alias $true
	$cmd = Add-OptionalParam $cmd '-AccessType $AccessType' $AccessType $true
	$cmd = Add-OptionalParam $cmd '-Notes $Notes' $Notes $true
	$cmd = Add-OptionalParam $cmd '-Owner $Owner' $Owner $true
	if ($AutoSubscribeNewMembers -ne $null) { $cmd += ' -AutoSubscribeNewMembers:$AutoSubscribeNewMembers'}
	$cmd = Add-OptionalParam $cmd '-AcceptMessagesOnlyFromSendersOrMembers $AcceptMessagesOnlyFromSendersOrMembers' $AcceptMessagesOnlyFromSendersOrMembers $true
	if ($AlwaysSubscribeMembersToCalendarEvents -ne $null) { $cmd += ' -AlwaysSubscribeMembersToCalendarEvents:$AlwaysSubscribeMembersToCalendarEvents'}
	if ($CalendarMemberReadOnly -ne $null) { $cmd += ' -CalendarMemberReadOnly:$CalendarMemberReadOnly'}
	if ($SubscriptionEnabled -ne $null) { $cmd += ' -SubscriptionEnabled:$SubscriptionEnabled'}
	$cmd = Add-OptionalParam $cmd '-RejectMessagesFromSendersOrMembers $RejectMessagesFromSendersOrMembers' $RejectMessagesFromSendersOrMembers $true
	if ($UnifiedGroupWelcomeMessageEnabled -ne $null) { $cmd += ' -UnifiedGroupWelcomeMessageEnabled:$UnifiedGroupWelcomeMessageEnabledUnifiedGroupWelcomeMessageEnabled'}

	$res = Invoke-Expression $cmd
	return $res	

<##
Set-UnifiedGroup
   [-Classification <String>]
   [-Confirm]
   [-ConnectorsEnabled]
   [-DataEncryptionPolicy <DataEncryptionPolicyIdParameter>]
   [-EmailAddresses <ProxyAddressCollection>]
   [-ForceUpgrade]
   [-GrantSendOnBehalfTo <MultiValuedProperty>]
   [-HiddenFromAddressListsEnabled <$true | $false>]
   [-HiddenFromExchangeClientsEnabled]
   [-Language <CultureInfo>]
   [-MailboxRegion <String>]
   [-MailTip <String>]
   [-MailTipTranslations <MultiValuedProperty>]
   [-MaxReceiveSize <Unlimited>]
   [-MaxSendSize <Unlimited>]
   [-ModeratedBy <MultiValuedProperty>]
   [-ModerationEnabled <$true | $false>]
   [-PrimarySmtpAddress <SmtpAddress>]
   [-RequireSenderAuthenticationEnabled <$true | $false>]
   [-WhatIf]
   [<CommonParameters>]
   [-CustomAttribute1 <String>]
   [-CustomAttribute10 <String>]
   [-CustomAttribute11 <String>]
   [-CustomAttribute12 <String>]
   [-CustomAttribute13 <String>]
   [-CustomAttribute14 <String>]
   [-CustomAttribute15 <String>]
   [-CustomAttribute2 <String>]
   [-CustomAttribute3 <String>]
   [-CustomAttribute4 <String>]
   [-CustomAttribute5 <String>]
   [-CustomAttribute6 <String>]
   [-CustomAttribute7 <String>]
   [-CustomAttribute8 <String>]
   [-CustomAttribute9 <String>]
   [-ExtensionCustomAttribute1 <MultiValuedProperty>]
   [-ExtensionCustomAttribute2 <MultiValuedProperty>]
   [-ExtensionCustomAttribute3 <MultiValuedProperty>]
   [-ExtensionCustomAttribute4 <MultiValuedProperty>]
   [-ExtensionCustomAttribute5 <MultiValuedProperty>]
##>
}

function Remove-LwOfficeGroup(
	[Parameter(Mandatory=$true, HelpMessage='Group identity (name, alias, DN, email, guid)')] [string] $Identity)
{
	Remove-UnifiedGroup -Identity $Identity -Confirm:$false -Force
}



function Get-LwOfficeGroupMembers(
	[Parameter(Mandatory=$true, HelpMessage='Group identity (name, alias, DN, email, guid)')] [string] $Identity,
	[Parameter(Mandatory=$true, HelpMessage='Members'' type (Members | Owners | Subscribers | Aggregators)')] [ValidateSet('Members', 'Owners', 'Subscribers', 'Aggregators')] [string] $Type = 'Members',
	[switch] $AsObject)
{
	$res = Get-UnifiedGroupLinks -Identity $Identity -LinkType $Type
	if ($AsObject) {
		return $res | Select PSShowComputerName, RunspaceId, ActiveSyncMailboxPolicyIsDefaulted, AddressListMembership,`
			Alias, ArchiveGuid, ArchiveRelease, ArchiveState, ArchiveStatus, Capabilities, City, Company, CountryOrRegion,`
			CustomAttribute1, CustomAttribute2, CustomAttribute3, CustomAttribute4, CustomAttribute5, CustomAttribute6, CustomAttribute7,`
			CustomAttribute8, CustomAttribute9, CustomAttribute10, CustomAttribute11, CustomAttribute12, CustomAttribute13, CustomAttribute14, CustomAttribute15,`
			Database, DatabaseName, Department, DisplayName, DistinguishedName, EmailAddresses, EmailAddressPolicyEnabled,`
			@{Name='ExchangeGuid'; Expression={$_.ExchangeGuid.ToString()}}, @{Name='ExchangeObjectId'; Expression={$_.ExchangeGuid.ToString()}},`
			ExchangeVersion, ExpansionServer, ExtensionCustomAttribute1, ExtensionCustomAttribute2, ExtensionCustomAttribute3, ExtensionCustomAttribute4, ExtensionCustomAttribute5,`
			ExternalDirectoryObjectId, FirstName, @{Name='Guid'; Expression={$_.Guid.ToString()}},`
			HasActiveSyncDevicePartnership, HiddenFromAddressListsEnabled, Id, Identity, IsValid, IsValidSecurityPrincipal, LastName, LitigationHoldEnabled,`
			MailboxMoveBatchName, MailboxMoveFlags, MailboxMoveRemoteHostName, MailboxMoveStatus, MailboxRelease,`
			ManagedBy, Name, Notes, ObjectCategory, ObjectClass, ObjectState, Office, OrganizationalUnit, OrganizationId, OriginatingServer, OwaMailboxPolicy,`
			Phone, PoliciesExcluded, PoliciesIncluded, PostalCode, PrimarySmtpAddress, RecipientType,`
			RecipientTypeDetails, SamAccountName, ServerLegacyDN, ServerName, ShouldUseDefaultRetentionPolicy, SKUAssigned,`
			StateOrProvince, StorageGroupName, Title, UMEnabled, UsageLocation,`
			@{Name='WhenChanged'; Expression={ Format-Date $_.WhenChanged }},`
			@{Name='WhenChangedUTC'; Expression={ Format-Date $_.WhenChangedUTC }},`
			@{Name='WhenCreated'; Expression={ Format-Date $_.WhenCreated }},`
			@{Name='WhenCreatedUTC'; Expression={ Format-Date $_.WhenCreatedUTC }},`
			@{Name='WhenMailboxCreated'; Expression={ Format-Date $_.WhenMailboxCreated }},`
			WindowsLiveID
<## ActiveSyncMailboxPolicy, AddressBookPolicy, ArchiveDatabase, AuthenticationType, BlockedSendersHash, ExternalEmailAddress
MailboxMoveSourceMDB, MailboxMoveTargetMDB, ManagedFolderMailboxPolicy, Manager, ResourceType, RetentionPolicy
SafeRecipientsHash, SafeSendersHash, SharingPolicy, UMMailboxPolicy, UMRecipientDialPlanId, WhenSoftDeleted, ##>
	}

	return $res
}


function Add-LwOfficeGroupMembers(
	[Parameter(Mandatory=$true, HelpMessage='Group identity (name, alias, DN, email, guid)')] [string] $Identity,
	[Parameter(Mandatory=$true, HelpMessage='Group members'' identities (name, alias, DN, email, guid)')] [string[]] $Members,
	[Parameter(Mandatory=$true, HelpMessage='Members'' type (Members | Owners | Subscribers | Aggregators)')] [ValidateSet('Members', 'Owners', 'Subscribers', 'Aggregators')] [string] $Type = 'Members')
{
	Add-UnifiedGroupLinks -Identity $Identity -Links $Members -LinkType $Type -Confirm:$false
}

function Remove-LwOfficeGroupMembers(
	[Parameter(Mandatory=$true, HelpMessage='Group identity (name, alias, DN, email, guid)')] [string] $Identity,
	[Parameter(Mandatory=$true, HelpMessage='Group members'' identities (name, alias, DN, email, guid)')] [string[]] $Members,
	[Parameter(Mandatory=$true, HelpMessage='Members'' type (Members | Owners | Subscribers | Aggregators)')] [ValidateSet('Members', 'Owners', 'Subscribers', 'Aggregators')] [string] $Type = 'Members')
{
	Remove-UnifiedGroupLinks -Identity $Identity -Links $Members -LinkType $Type -Confirm:$false
}


Export-ModuleMember -Function Login-LwOffice365, Get-LwOfficeGroup, New-LwOfficeGroup, Update-LwOfficeGroup, Remove-LwOfficeGroup, Get-LwOfficeGroupMembers, Add-LwOfficeGroupMembers, Remove-LwOfficeGroupMembers