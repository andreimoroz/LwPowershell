Import-Module -Name SharePointPnPPowerShellOnline -DisableNameChecking -Global

# https://sharepoint.stackexchange.com/questions/221118/retrieve-permissions-at-folder-and-file-level-in-powershell
# https://drewmadelung.com/sharing-a-file-in-sharepoint-online-or-onedrive-with-powershell/

# ==============================================================================================

# Functions 
function Login-LwPnP([string] $Url, [string] $User, [string] $Password)
{
	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	$pscred = New-Object System.Management.Automation.PSCredential($User, $spasswd)

	$conn = Connect-PnPOnline $Url -Credentials $pscred -ReturnConnection
	return $conn
}

function Add-LwPnpFile(
	[Parameter(Mandatory=$true, HelpMessage='Local file path')] [string] $Path,
	[Parameter(Mandatory=$true, HelpMessage='File stream')] $Stream,
	[Parameter(Mandatory=$true, HelpMessage='Folder including list identity')] [string] $Folder,
	[Parameter(Mandatory=$false, HelpMessage='File name after upload')] [string] $NewFileName,
	[Parameter(Mandatory=$false, HelpMessage='If versioning is enabled, this will check out the file first if it exists, upload the file, then check it in again')] [switch] $Checkout,
	[Parameter(Mandatory=$false, HelpMessage='The comment added to the checkin')] [string] $CheckInComment,
	[Parameter(Mandatory=$false, HelpMessage='Will auto approve the uploaded file')] [switch] $Approve,
	[Parameter(Mandatory=$false, HelpMessage='The comment added to the approval')] [string] $ApproveComment,
	[Parameter(Mandatory=$false, HelpMessage='Will auto publish the file')] [switch] $Publish,
	[Parameter(Mandatory=$false, HelpMessage='The comment added to the publish action')] [string] $PublishComment,
	[Parameter(Mandatory=$false, HelpMessage='Use the internal names of the fields when specifying field names')] [hashtable] $FieldValues,
	[switch] $AsObject)
{
	if ($Path)
	{
		$file = Add-PnPFile -Path $Path -Folder $Folder -NewFileName $NewFileName -Checkout:$Checkout -CheckInComment $CheckInComment `
			-Approve:$Approve -ApproveComment $ApproveComment -Publish:$Publish -PublishComment $PublishComment -Values $Values
	}
	else
	{
		$file = Add-PnPFile -Stream $Stream -Folder $Folder -NewFileName $NewFileName -Checkout:$Checkout -CheckInComment $CheckInComment `
			-Approve:$Approve -ApproveComment $ApproveComment -Publish:$Publish -PublishComment $PublishComment -Values $Values
	}

	if ($AsObject)
	{
		return $file | Select Name, ServerRelativeUrl, CheckInComment, ETag, Exists, IrmEnabled, Length, Level, MajorVersion, MinorVersion, `
			@{Name='PathIdentity'; Expression={ $_.Path.Identity }},`
			@{Name='TimeCreated'; Expression={ Format-Date $_.TimeCreated }},`
			@{Name='TimeLastModified'; Expression={ Format-Date $_.TimeLastModified }},`
			UIVersion, UIVersionLabel, UniqueId
	}

	return $file
}

function Add-LwPnpFolder(
	[Parameter(Mandatory=$true, HelpMessage='The parent folder in the site including list identity')] [string] $Folder,
	[Parameter(Mandatory=$false, HelpMessage='The folder name')] [string] $Name)
{
	return (Add-PnPFolder -Folder $Folder -Name $Name)
}

function Break-LwPnPObjectRoleInheritance([Microsoft.SharePoint.Client.SecurableObject]$object,`
	[bool] $copyRoleAssignments = $false, [bool] $clearSubscopes = $false)
{
	$object.BreakRoleInheritance($copyRoleAssignments, $clearSubscopes)
	$object.Update()
	(Get-PnPContext).ExecuteQuery()	
}

function Get-LwPnPObjectRoleAssignments($object)
{
	$result = @{ HasUniqueRoleAssignments = $object.HasUniqueRoleAssignments }

	if ($object.HasUniqueRoleAssignments -eq $true)
	{
		$result.RoleAssignments = @()
		$object.RoleAssignments |% {
			$roleAssignments = $_
			Get-PnPProperty -ClientObject $roleAssignments -Property RoleDefinitionBindings, Member

			$permissions = @()
					$roleAssignments.RoleDefinitionBindings |% { $permissions += $_.Name }
			$result.RoleAssignments += @{ UPN = $roleAssignments.Member.UserPrincipalName; `
				LoginName = $roleAssignments.Member.LoginName; `
				Title = $roleAssignments.Member.Title;
				PrincipalType = $roleAssignments.Member.PrincipalType.ToString(); 
				Permissions = $permissions }
		}
	}

	return $result
}

function Get-LwPnPRoleAssignments([string] $Folder, [string] $File)
{
	$listItem = Get-LwListItem $Folder $File -ReadRoleAssignments
	return (Get-LwPnPObjectRoleAssignments $listItem)
}

function Get-LwPnPUser($Identity)
{						  
	$ctx = Get-PnPContext
	$user = $ctx.Web.EnsureUser($Identity)
	$ctx.load($user)
	$ctx.ExecuteQuery()	
	return $user
}

function Break-LwPnPRoleInheritance(
	[Parameter(HelpMessage='Folder name including list identity')] [string] $Folder,
	[Parameter(HelpMessage='File name including list identity')] [string] $File,
	[switch] $CopyRoleAssignments = $false, [switch] $ClearSubscopes = $false)
{
	$listItem = Get-LwListItem -Folder $Folder -File $File -ReadRoleAssignments
	           
	# Break role inheritance if necessary
	if (-not $listItem.HasUniqueRoleAssignments)
	{
		Break-LwPnPObjectRoleInheritance $listItem $CopyRoleAssignments $ClearSubscopes
		return $true
	}

	return $false
}

function Reset-LwPnPRoleInheritance(
	[string] $Folder, [string] $File)
{
	$listItem = Get-LwListItem -Folder $Folder -File $File -ReadRoleAssignments
	           
	# Break role inheritance if necessary
	if ($listItem.HasUniqueRoleAssignments)
	{
		$listItem.ResetRoleInheritance()
		$listItem.Update()
		(Get-PnPContext).ExecuteQuery()	
		return $true
	}

	return $false
}

function Add-LwPnPObjectRoleAssignment($object, [Microsoft.SharePoint.Client.Principal] $principal, [string] $roleName)
{
	$ctx = Get-PnPContext
	$roleDefinition = Get-PnPRoleDefinition $roleName
	$RoleDB = New-Object Microsoft.SharePoint.Client.RoleDefinitionBindingCollection($ctx)
	$RoleDB.Add($roleDefinition)

	$userPermissions = $object.RoleAssignments.Add($principal, $RoleDB)
	$object.Update()
	$ctx.ExecuteQuery()	
}

function Add-LwPnPRoleAssignment(
	[string] $Folder, [string] $File,
	[switch] $CopyRoleAssignments = $false, [switch] $ClearSubscopes = $false,
	[Parameter(Mandatory=$true, HelpMessage='User or group UPN')] $Identity,
	[Parameter(Mandatory=$true, HelpMessage='Role name')] [string] $RoleName,
	[switch] $AsObject)
{
	$listItem = Get-LwListItem -Folder $Folder -File $File -ReadRoleAssignments

	# Break role inheritance if necessary
	if (-not $listItem.HasUniqueRoleAssignments)
	{
		Break-LwPnPObjectRoleInheritance $listItem $CopyRoleAssignments $ClearSubscopes
	}

	$principal = Get-LwPnPUser -Identity $Identity
	Add-LwPnPObjectRoleAssignment $listItem $principal $RoleName

	return $null
}

function Remove-LwPnPObjectRoleAssignment($object, [Microsoft.SharePoint.Client.Principal] $principal)
{
	$ctx = Get-PnPContext
	ForEach ($roleAssignment in $object.RoleAssignments)
	{
		Get-PnPProperty -ClientObject $roleAssignment -Property RoleDefinitionBindings, Member
 
		# remove user permission
		if ($roleAssignment.Member.LoginName -eq $principal.LoginName)
		{

			$object.RoleAssignments.GetByPrincipal($principal).DeleteObject()
			$ctx.ExecuteQuery()	
			return $true
		}
	}
	return $false
}

function Remove-LwPnPRoleAssignment(
	[string] $Folder, [string] $File, $Identity)
{

	$listItem = Get-LwListItem -Folder $Folder -File $File -ReadRoleAssignments

	$principal = Get-LwPnPUser -Identity $Identity
	return (Remove-LwPnPObjectRoleAssignment $listItem $principal)
}

function Add-LwPnpShare(
	[Parameter(Mandatory=$false, HelpMessage='Folder name including list identity')] [string] $Folder,
	[Parameter(Mandatory=$false, HelpMessage='File name including list identity')] [string] $File,
	[Parameter(Mandatory=$true, HelpMessage='The principal name (UPN) of the user')] [MailAddress] $UPN,
	[Parameter(Mandatory=$false, HelpMessage='Is guest user (true) or unvalidated email (false)')] [bool] $IsGuestUser,
	[Parameter(Mandatory=$true, HelpMessage='Edit or view permission')] [string] [ValidateSet('Edit','View')] $Role = 'View',
	[Parameter(Mandatory=$false, HelpMessage='If an e-mail is being sent, this determines if an anonymous link should be added to the message')] [switch] $AnonymousLink,
	[Parameter(Mandatory=$false, HelpMessage='A flag to determine if permissions should be pushed to items with unique permissions')] [switch] $PropageAcl,
	[Parameter(Mandatory=$false, HelpMessage='Flag to determine if an e-mail notification should to sent, if e-mail is configured')] [switch] $SendEmail,
	[Parameter(Mandatory=$false, HelpMessage='Mail subject. Required only if not anonymous link')] [string] $EmailSubject = 'Subject',
	[switch] $AsObject)
### https://drewmadelung.com/sharing-a-file-in-sharepoint-online-or-onedrive-with-powershell/
# ShareObject https://msdn.microsoft.com/en-us/library/office/mt684216.aspx
# External sharing blog https://blogs.msdn.microsoft.com/vesku/2015/10/02/external-sharing-api-for-sharepoint-and-onedrive-for-business/
{
	$ctx = (Get-PnPConnection).Context # $conn.PnP.Context

	$web = $ctx.Web
	$ctx.Load($web)
	$ctx.ExecuteQuery()
 
	#UNVALIDATED_EMAIL_ADDRESS if they are in AD or GUEST_USER if they are not
	if ($IsGuestUser) { $principalType = 'GUEST_USER' } else { $principalType = 'UNVALIDATED_EMAIL_ADDRESS' }
 
	#role:1073741826 = View(40000002), role:1073741827 = Edit(40000003)
	if ($Role -eq 'Edit') { $roleValue = "role:1073741827" } else { $roleValue = "role:1073741826" }
	# Use modern sharing links instead of directly granting access
	$useSimplifiedRoles = $true

	# Get doc url
	$listItem = Get-LwListItem -Folder $Folder -File $File
	$itemUrl = Join-Url (Get-ServerUrl $web.Url) $listItem.FieldValues.FileRef
 
	# Build user object to be shared to
	$jsonPerson = ConvertTo-Json -Depth 10 -Compress -InputObject `
		@(@{ Key = $UPN.Address; Description = $UPN.Address; DisplayText = $UPN.Address; EntityType = '';`
		ProviderDisplayName = ''; ProviderName = ''; IsResolved = $true;`
		EntityData = @{ Email = $UPN.Address; AccountName = $UPN.Address; Title = $UPN.Address; PrincipalType = $principalType };`
		MultipleMatches = @()}) 

	# Initiate share
	# groupId - The ID of the group to be added to. Use zero if not adding to a permissions group.
	# Not actually used by the code even when user is added to existing group. 
	$res = [Microsoft.SharePoint.Client.Web]::ShareObject($ctx, $itemUrl, $jsonPerson, $roleValue,`
		0, $PropageAcl, $SendEmail, $AnonymousLink, $EmailSubject, 'Body', $useSimplifiedRoles)
	$ctx.Load($res)
	$ctx.ExecuteQuery()

	if ($AsObject)
	{
		$res = $res | Select Url, IconUrl, ErrorMessage, Name, ObjectVersion, Path, PermissionsPageRelativeUrl,`
			ServerObjectIsNull, StatusCode, Tag,`
			@{Name='Email'; Expression={ if ($_.InvitedUsers -and $_.InvitedUsers.Count) { $_.InvitedUsers[0].Email } else { $null } }},`
			@{Name='InvitationLink'; Expression={ if ($_.InvitedUsers -and $_.InvitedUsers.Count) { $_.InvitedUsers[0].InvitationLink } else { $null } }},`
			@{Name='Succeeded'; Expression={ if ($_.InvitedUsers -and $_.InvitedUsers.Count) { $_.InvitedUsers[0].Succeeded } else { $null } }},`
			@{Name='TypeId'; Expression={ if ($_.InvitedUsers -and $_.InvitedUsers.Count) { $_.InvitedUsers[0].TypeId } else { $null } }}
	}

	return $res

#Get-PnPProperty -ClientObject $res -Property GroupsSharedWith,GroupUsersAddedTo,InvitedUsers,UniquelyPermissionedUsers,UsersAddedToGroup,UsersWithAccessRequests 
#$g = $res.GroupUsersAddedTo[0]
#$ctx.Load($g)
#$ctx.ExecuteQuery()
#Get-PnPProperty -ClientObject $g -Property Id

#GroupsSharedWith             Property   Microsoft.SharePoint.Client.GroupCollection GroupsSharedWith {get;}
#GroupUsersAddedTo            Property   Microsoft.SharePoint.Client.Group GroupUsersAddedTo {get;}
#InvitedUsers                 Property   System.Collections.Generic.IList[Microsoft.SharePoint.Client.SPInvitationCre...
#UniquelyPermissionedUsers    Property   System.Collections.Generic.IList[Microsoft.SharePoint.Client.Sharing.UserSha...
#UsersAddedToGroup            Property   System.Collections.Generic.IList[Microsoft.SharePoint.Client.Sharing.UserSha...
#UsersWithAccessRequests      Property   Microsoft.SharePoint.Client.SharingUserCollection UsersWithAccessRequests
}

function Get-LwListItem([string] $Folder, [string] $File, [switch] $ReadRoleAssignments)
{
#	$item = (Iif $Folder $File)
#	$foldern = Split-FolderName $item
#	$list = Get-PnPList -Identity $foldern.List
#	$fileUrl = Join-Url $list.RootFolder.ServerRelativeUrl $foldern.File
	$fileUrl = (Iif $Folder $File)

	$listItem = $null
	if ($Folder)
	{
		if ($ReadRoleAssignments)
		{
			$foldero = Get-PnPFolder -Url $fileUrl -Includes ListItemAllFields.RoleAssignments, ListItemAllFields.HasUniqueRoleAssignments
		}
		else
		{
			$foldero = Get-PnPFolder -Url $fileUrl
		}
		$listItem = $foldero.ListItemAllFields
	}
	elseIf ($File)
	{
		$listItem = Get-PnPFile -Url $fileUrl -AsListItem
		if ($ReadRoleAssignments)
		{
			$out = Get-PnPProperty -ClientObject $listItem -Property RoleAssignments, HasUniqueRoleAssignments
		}
	}
	return $listItem
}

Export-ModuleMember -Function Login-LwPnP, Add-LwPnpFile, Add-LwPnpFolder, Break-LwPnPRoleInheritance, Reset-LwPnPRoleInheritance, Get-LwPnPRoleAssignments, Get-LwPnPUser, Add-LwPnPRoleAssignment, Remove-LwPnPRoleAssignment, Add-LwPnpShare