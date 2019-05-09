Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global

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
function Login-LwAzureAccount([guid] $TenantId, [string] $User, [string] $Password, [switch] $ServicePrincipal)
{
	if ($User -and $Password)
	{
		$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
		$pscred = New-Object System.Management.Automation.PSCredential($User, $spasswd)
		if ($ServicePrincipal.IsPresent)
		{
			return (Connect-AzAccount -Credential $pscred -TenantId $TenantId -ServicePrincipal)
		}
		else
		{
			return (Connect-AzAccount -Credential $pscred -TenantId $TenantId)
		}
	}
	else
	{
		# Iteractive
		if ($ServicePrincipal.IsPresent)
		{
			return (Connect-AzAccount -TenantId $TenantId -ServicePrincipal)
		}
		else
		{
			return (Connect-AzAccount -TenantId $TenantId)
		}
	}
}

<# 
   .Synopsis 
    Login user to Azure AD
    Login with Service Principal and Self-Signed Certificate requres script to run under administrative privileges!
     https://github.com/Azure/azure-docs-powershell-azuread/issues/198
     https://docs.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0
     https://techcommunity.microsoft.com/t5/Azure-Active-Directory/Connect-AzureAD-with-login-credentials/td-p/145012
     https://docs.microsoft.com/en-us/powershell/azure/authenticate-azureps?view=azps-1.4.0
       Username/password credential authorization has been removed in Azure PowerShell due to changes in Active Directory authorization implementations and security concerns. If you use credential authorization for automation purposes, instead create a service principal.
   .Parameter TenantId
    Tenant Id
   .Parameter ApplicationId
    Application id, for silent login
   .Parameter CertificateThumbprint
    Certificate thumbprint, for silent login
#> 
function Login-LwAzureAD([guid] $TenantId, [nullable[guid]] $ApplicationId, [string] $CertificateThumbprint)
{
	if ($ApplicationId -and $CertificateThumbprint)
	{
		return (Connect-AzureAD -TenantId $TenantId -ApplicationId $ApplicationId -CertificateThumbprint $CertificateThumbprint)
	}
	else
	{
		return (Connect-AzureAD -TenantId $TenantId)
	}
}

function Login-LwAzureADToken
{
	# Fictive call to refresh token
	$out = Get-AzADGroup

	$ctx = Get-AzContext
	$cacheItems = $ctx.TokenCache.ReadItems()
	$token = $cacheItems |? { ($_.Resource -eq 'https://graph.windows.net/') -and ($_.ClientId -eq $ctx.Account.Id) }
	if ($token)
	{
		$token = @($token)[-1]
		return (Connect-AzureAD -AadAccessToken $token.AccessToken -AccountId $ctx.Account.Id -TenantId $ctx.Tenant.Id)
	}

	throw 'No Azure Graph token found'
}


#=============================================================

<# 
   .Synopsis 
    Create Service Principal with password authentication
   .Parameter Name
    Service principal display name
   .Parameter Password
    Password
   .Parameter Role
    AD Directory role ('User Account Administrator')
#> 
function New-LwAzureServicePrincipalPassword($Name, $Password, $RoleName = 'User Account Administrator')
{
	$role = Get-AzureADDirectoryRole |? { $_.DisplayName -eq $RoleName }
	if (-not $role) { throw "Role $RoleName doesn't exist" }

	$credentials = New-Object Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential -Property @{ StartDate=Get-Date; EndDate=(Get-Date -Year 2999); Password = $Password }
	$sp = New-AzAdServicePrincipal -DisplayName $Name -PasswordCredential $credentials

	Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $sp.Id
	
	return $sp
}

function New-LwAzureServicePrincipalCertificate([string] $Name = 'PSAzureLogin', [string] $CertValue, [string] $Role = 'User Account Administrator')
{
	$application = Get-AzureADApplication |? {$_.DisplayName -eq $Name}
	if (-not $application)
	{
		# New Application
		$application = New-AzureADApplication -DisplayName $Name -IdentifierUris "https://$($Name)"
	}

	# Add certificate credential
	$out = New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier $Name `
		-Type AsymmetricX509Cert -Usage Verify -Value $CertValue

	# New principal
	$sp = New-AzureADServicePrincipal -DisplayName $Name -AppId $application.AppId -AccountEnabled $true

	$role = Get-AzureADDirectoryRole |? { $_.DisplayName -eq $Role }
	Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $sp.ObjectId

	return @($application, $sp)
} 


# Create self-signed certificate
# Run with elevated privileges
function New-LwSelfSignedCertificate([string] $DnsName, [string] $Subject = 'PSAzureLogin', `
	[string] $FileName, [string] $Password)
{
	$cert = New-SelfSignedCertificate -DnsName $DnsName -Subject $Subject `
		-CertStoreLocation 'Cert:\LocalMachine\My' `
		-KeyExportPolicy Exportable -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
		-NotAfter (Get-Date).AddYears(20)
	$thumb = $cert.Thumbprint
	$spwd = ConvertTo-SecureString -String $Password -Force -AsPlainText
	if (-not $FileName)
	{
		$FileName = Join-Path (pwd) "$($Subject).pfx"
	}
	$out = Export-PfxCertificate -Cert "cert:\localmachine\my\$thumb" -FilePath $FileName -Password $spwd -Force

	return $cert
}

# Load certificate. Requires elevated privileges.
function Get-LwCertificateData([string] $FileName, [string] $Password)
{
	$spwd = ConvertTo-SecureString -String $Password -Force -AsPlainText
	$certp = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($FileName, $spwd)
	return ([System.Convert]::ToBase64String($certp.GetRawCertData()))
}

#=============================================================

function ReadUser($user)
{
	return $user | Select ObjectId, CreationType,`
		Surname, GivenName, DisplayName, UserPrincipalName, MailNickName, OtherMails, Mail,`
		UserType, AccountEnabled, ImmutableId, Country, State, PostalCode, City, StreetAddress,`
		TelephoneNumber, Mobile, FacsimileTelephoneNumber, CompanyName, Department, PhysicalDeliveryOfficeName, JobTitle,`
		ExtensionProperty, PreferredLanguage, UsageLocation, ShowInAddressList,`
		@{Name='ForceChangePasswordNextLogin'; Expression={$_.PasswordProfile.ForceChangePasswordNextLogin}},`
		@{Name='EnforceChangePasswordPolicy'; Expression={$_.PasswordProfile.EnforceChangePasswordPolicy}}
}


function Get-LwAzureUser(
	[Parameter(Mandatory=$false, HelpMessage='The unique identifier of a group in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$false, HelpMessage='The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user''s email name. The general format is "alias@domain". For work or school accounts, the domain must be present in the tenant''s collection of verified domains. This property is required when a work or school account is created; it is optional for local accounts')] [string] $UPN,
	[switch] $AsObject)
{
	$cmd = 'Get-AzureADUser'
	if ($ObjectId) { 
		$cmd += ' -ObjectId $ObjectId'
	}
	elseif ($UPN) { 
		$cmd += ' -Filter "UserPrincipalName eq ''$UPN''"'
	}
	else {
		$cmd += ' -All $true'
	}
	$user = Invoke-Expression $cmd
	if ($user -and $AsObject)
	{
		return (ReadUser $user)
	}
	return $user
}


function New-LwAzUser(
	[Parameter(Mandatory=$false, HelpMessage='Name to display in the address book for the user. example ''Alex Wu''')] [string] $DisplayName,` 
	[Parameter(Mandatory=$false, HelpMessage='The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user''s email name. The general format is "alias@domain". For work or school accounts, the domain must be present in the tenant''s collection of verified domains. This property is required when a work or school account is created; it is optional for local accounts')] [string] $UPN,
	[Parameter(Mandatory=$false, HelpMessage='Mail nick name')] [string] $MailNickName,
	[Parameter(Mandatory=$true, HelpMessage='User password')] [string] $Password,`
	[Parameter(Mandatory=$false, HelpMessage='Force to change password on next login')] [switch] $ForceChangePasswordNextLogin,`
	[Parameter(Mandatory=$false, HelpMessage='It needs to be specified only if you are using a federated domain for the user''s user principal name (upn) property')] [string] $ImmutableId
	)
{

	if ((-not $MailNickName) -and ($UPN -match '^(?<m>\w+)@'))
	{
		$MailNickName = $Matches.m
	}

	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	$cmd = 'New-AzADUser -UserPrincipalName $UPN -DisplayName $DisplayName -MailNickname $MailNickname -Password $spasswd -ForceChangePasswordNextLogin:$ForceChangePasswordNextLogin'
	$cmd = Add-OptionalParam $cmd '-ImmutableId $ImmutableId' $ImmutableId

	$user = Invoke-Expression $cmd
	return $user
}

function Run-UserParams(
	[string] $cmd,
	[string] $Surname,
	[string] $GivenName,
	[string] $DisplayName,`
	[string] $UPN,
	[string] $MailNickName,
	[string] $Password,
	[nullable[bool]] $ForceChangePasswordNextLogin,
	[nullable[bool]] $EnforceChangePasswordPolicy,
	[nullable[bool]] $AccountEnabled, #########!!!!!!!!
	[nullable[bool]] $DisableStrongPassword,
	[nullable[bool]] $PasswordNeverExpires,
	[string] $UserType,
	[nullable[bool]] $LocalAccount,
	[string] $ImmutableId,
	[string] $Country,
	[string] $State,
	[string] $PostalCode,
	[string] $City,
	[string] $StreetAddress,
	[string] $TelephoneNumber,
	[string] $Mobile,
	[string] $FacsimileTelephoneNumber,
	[hashtable] $ExtProps,
	[bool] $IgnoreEmptyString = $true)
{
	$creationType = $null
	if ($LocalAccount)
	{
		$creationType = 'LocalAccount'
	}

	$passwordProfile = $null
	if ($password)
	{
		$passwordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
		$passwordProfile.Password = $password
		if ($ForceChangePasswordNextLogin -ne $null)
		{
			$passwordProfile.ForceChangePasswordNextLogin = $ForceChangePasswordNextLogin
		}
		if ($EnforceChangePasswordPolicy -ne $null)
		{
			$passwordProfile.EnforceChangePasswordPolicy = $EnforceChangePasswordPolicy
		}
	}

	$passwordPolicies = $null
	if (($DisableStrongPassword -ne $null) -or ($PasswordNeverExpires -ne $null))
	{
		if ($DisableStrongPassword)
		{
			$passwordPolicies = 'DisableStrongPassword'
		}
		if ($PasswordNeverExpires)
		{
			if ($passwordPolicies) { $passwordPolicies += ', ' }
			$passwordPolicies += 'DisablePasswordExpiration'
		}
	}

	$extension = $null
	if ($ExtProps)
	{
		# Extension variables
		$extension = New-Object 'System.Collections.Generic.Dictionary``2[System.String,System.String]'
		$ExtProps.Keys |% { $extension.Add($_, $ExtProps[$_]) }
	}

	if ($LocalAccount -ne $null)
	{
		$cmd += ' -CreationType $creationType'
	}

	$cmd = Add-OptionalParam $cmd '-Surname $Surname' $Surname $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-GivenName $GivenName' $GivenName $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-DisplayName $DisplayName' $DisplayName $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-UserPrincipalName $UPN' $UPN $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-MailNickName $MailNickName' $MailNickName $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-PasswordProfile $PasswordProfile' $PasswordProfile $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-AccountEnabled $AccountEnabled' $AccountEnabled $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-UserType $UserType' $UserType $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-ImmutableId $ImmutableId' $ImmutableId $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-Country $Country' $Country $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-State $State' $State $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-PostalCode $PostalCode' $PostalCode $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-City $City' $City $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-StreetAddress $StreetAddress' $StreetAddress $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-TelephoneNumber $TelephoneNumber' $TelephoneNumber $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-Mobile $Mobile' $Mobile $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-FacsimileTelephoneNumber $FacsimileTelephoneNumber' $FacsimileTelephoneNumber $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-PasswordPolicies $passwordPolicies' $passwordPolicies $IgnoreEmptyString
	$cmd = Add-OptionalParam $cmd '-ExtensionProperty $extension' $extension $IgnoreEmptyString
	$res = Invoke-Expression $cmd
	return $res	
}



# DisplayName: combined from surname and given name if not present
function New-LwAzureUser(
	[Parameter(Mandatory=$false, HelpMessage='Surname')] [string] $Surname,
	[Parameter(Mandatory=$false, HelpMessage='GivenName')] [string] $GivenName,
	[Parameter(Mandatory=$false, HelpMessage='User display name')] [string] $DisplayName,`
	[Parameter(Mandatory=$false, HelpMessage='The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user''s email name. The general format is "alias@domain". For work or school accounts, the domain must be present in the tenant''s collection of verified domains. This property is required when a work or school account is created; it is optional for local accounts')] [string] $UPN,
	[Parameter(Mandatory=$false, HelpMessage='Mail nick name')] [string] $MailNickName,
	[Parameter(Mandatory=$true, HelpMessage='User password')] [string] $Password,
	[Parameter(Mandatory=$false, HelpMessage='Force to change password on next login')] [nullable[bool]] $ForceChangePasswordNextLogin,
	[Parameter(Mandatory=$false, HelpMessage='Enforce to change password policy on user creation')] [nullable[bool]] $EnforceChangePasswordPolicy,
	[Parameter(Mandatory=$false, HelpMessage='Allow weaker passwords than the default policy to be specified')] [switch] $DisableStrongPassword = $false,
	[Parameter(Mandatory=$false, HelpMessage='Password never expires')] [switch] $PasswordNeverExpires = $false,
	[Parameter(Mandatory=$false, HelpMessage='A string value that can be used to classify user types in your directory, such as "Member" and "Guest"')] [ValidateSet('Member','Guest')] [string] $UserType = 'Member',
	[Parameter(Mandatory=$false, HelpMessage='Whether account is enabled')] [switch] $Enabled = $true,
	[Parameter(Mandatory=$false, HelpMessage='Whether is a local account for an Azure Active Directory B2C tenant')] [switch] $LocalAccount = $false,
	[Parameter(Mandatory=$false, HelpMessage='Is used to associate an on-premises Active Directory user account to their Azure AD user object. This property must be specified when creating a new user account in the Graph if you are using a federated domain for the user''s userPrincipalName (UPN) property')] [string] $ImmutableId,
	[Parameter(Mandatory=$false, HelpMessage='Country')] [string] $Country,
	[Parameter(Mandatory=$false, HelpMessage='State')] [string] $State,
	[Parameter(Mandatory=$false, HelpMessage='Postal code')] [string] $PostalCode,
	[Parameter(Mandatory=$false, HelpMessage='City')] [string] $City,
	[Parameter(Mandatory=$false, HelpMessage='Street address')] [string] $StreetAddress,
	[Parameter(Mandatory=$false, HelpMessage='TelephoneNumber')] [string] $TelephoneNumber,
	[Parameter(Mandatory=$false, HelpMessage='Mobile')] [string] $Mobile,
	[Parameter(Mandatory=$false, HelpMessage='FacsimileTelephoneNumber')] [string] $FacsimileTelephoneNumber,
	[Parameter(Mandatory=$false, HelpMessage='Extension properties')] [hashtable] $ExtProps,
	[switch] $AsObject)
{
	if (-not $DisplayName)
	{
		$DisplayName = "$GivenName $Surname".Trim()
		if (-not $DisplayName)
		{
			throw 'Display name is required'
		}
	}

	if ((-not $MailNickName) -and ($UPN -match '^(?<m>\w+)@'))
	{
		$MailNickName = $Matches.m
	}

	if ((-not $LocalAccount) -and (-not $UPN))
	{
		throw "UPN is required for a work or school account"
	}

	$accountEnabled = [nullable[bool]]($Enabled)
	$user = Run-UserParams 'New-AzureADUser' -Surname $Surname -GivenName $GivenName -DisplayName $DisplayName -UPN $UPN -MailNickName $MailNickName `
		-Password $Password -ForceChangePasswordNextLogin $ForceChangePasswordNextLogin -EnforceChangePasswordPolicy $EnforceChangePasswordPolicy `
		-AccountEnabled $accountEnabled -DisableStrongPassword $DisableStrongPassword -PasswordNeverExpires $PasswordNeverExpires `
		-UserType $UserType -LocalAccount $LocalAccount -ImmutableId $ImmutableId `
		-Country $Country -State $State -PostalCode $PostalCode -City $City -StreetAddress $StreetAddress `
		-TelephoneNumber $TelephoneNumber -Mobile $Mobile -FacsimileTelephoneNumber $FacsimileTelephoneNumber -ExtProps $ExtProps `
		-IgnoreEmptyString $true

	if ($AsObject)
	{
		return (ReadUser $user)
	}
	return $user
}

# TODO Parameters
#   [-SignInNames <System.Collections.Generic.List`1[Microsoft.Open.AzureAD.Model.SignInName]>] # collection of sign-in names for a local account in an Azure Active Directory B2C tenant. Each sign-in name must be unique across the company/tenant. The property must be specified when you create a local account user; do not specify it when you create a work or school account
#   [-OtherMails <System.Collections.Generic.List`1[System.String]>] # list of additional email addresses for the user; for example: "bob@contoso.com", "Robert@fabrikam.com"
#
#   [-PreferredLanguage <String>] # preferred language
#   [-UsageLocation <String>] # A two letter country code (ISO standard 3166). Required for users that will be assigned licenses due to legal requirement to check for availability of services in countries. Examples include: "US", "JP", and "GB"
#   [-ShowInAddressList <Boolean>]
#   [-IsCompromised <Boolean>] # whether this user is compromised
#
# [-PhysicalDeliveryOfficeName <String>] # physical delivery office name
# [-Department <String>] # department
# [-JobTitle <String>] # job title

function Update-LwAzureUser(
	[Parameter(Mandatory=$false, HelpMessage='The unique identifier of a group in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$false, HelpMessage='User display name')] [string] $DisplayName = 'DEFAULTVALUE',`
	[Parameter(Mandatory=$false, HelpMessage='Surname')] [string] $Surname = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='GivenName')] [string] $GivenName = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user''s email name. The general format is "alias@domain". For work or school accounts, the domain must be present in the tenant''s collection of verified domains. This property is required when a work or school account is created; it is optional for local accounts')] [string] $UPN,
	[Parameter(Mandatory=$false, HelpMessage='Mail nick name')] [string] $MailNickName = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='User password')] [string] $Password,
	[Parameter(Mandatory=$false, HelpMessage='Force to change password on next login')] [nullable[bool]] $ForceChangePasswordNextLogin,
	[Parameter(Mandatory=$false, HelpMessage='Enforce to change password policy on user creation')] [nullable[bool]] $EnforceChangePasswordPolicy,
	[Parameter(Mandatory=$false, HelpMessage='Allow weaker passwords than the default policy to be specified')] [nullable[bool]] $DisableStrongPassword = $false,
	[Parameter(Mandatory=$false, HelpMessage='Password never expires')] [nullable[bool]] $PasswordNeverExpires = $false,
	[Parameter(Mandatory=$false, HelpMessage='A string value that can be used to classify user types in your directory, such as "Member" and "Guest"')] [string] $UserType = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='Whether account is enabled')] [nullable[bool]] $Enabled,
	[Parameter(Mandatory=$false, HelpMessage='Whether is a local account for an Azure Active Directory B2C tenant')] [nullable[bool]] $LocalAccount,
	[Parameter(Mandatory=$false, HelpMessage='Is used to associate an on-premises Active Directory user account to their Azure AD user object. This property must be specified when creating a new user account in the Graph if you are using a federated domain for the user''s userPrincipalName (UPN) property')] [string] $ImmutableId = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='Country')] [string] $Country = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='State')] [string] $State = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='Postal code')] [string] $PostalCode = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='City')] [string] $City = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='Street address')] [string] $StreetAddress = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='TelephoneNumber')] [string] $TelephoneNumber = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='Mobile')] [string] $Mobile = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='FacsimileTelephoneNumber')] [string] $FacsimileTelephoneNumber = 'DEFAULTVALUE',
	[Parameter(Mandatory=$false, HelpMessage='Extension properties')] [hashtable] $ExtProps)
{
	if (-not $ObjectId -and $UPN)
	{
		$user = Get-AzADUser -UserPrincipalName $UPN
		if (-not $user) { throw "User with UPN=$UPN can not be found" }
		$ObjectId = $user.Id
	}

	$user = Run-UserParams 'Set-AzureADUser -ObjectId $objectId' -Surname $Surname -GivenName $GivenName -DisplayName $DisplayName -UPN $UPN -MailNickName $MailNickName `
		-Password $Password -ForceChangePasswordNextLogin $ForceChangePasswordNextLogin -EnforceChangePasswordPolicy $EnforceChangePasswordPolicy `
		-AccountEnabled $Enabled -DisableStrongPassword $DisableStrongPassword -PasswordNeverExpires $PasswordNeverExpires `
		-UserType $UserType -LocalAccount $LocalAccount -ImmutableId $ImmutableId `
		-Country $Country -State $State -PostalCode $PostalCode -City $City -StreetAddress $StreetAddress `
		-TelephoneNumber $TelephoneNumber -Mobile $Mobile -FacsimileTelephoneNumber $FacsimileTelephoneNumber -ExtProps $ExtProps `
		-IgnoreEmptyString $false
	return $user
}


function Enable-LwAzUser([string] $UPN, [bool] $enabled = $true)
{
	return (Update-AzADUser -UserPrincipalName $UPN -EnableAccount:$enabled)
}

function Set-LwAzUserPassword([string] $UPN, [string] $Password, [switch] $ForceChangePasswordNextLogin)
{
	$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	return (Update-AzADUser -UserPrincipalName $UPN -Password $spasswd -ForceChangePasswordNextLogin:$ForceChangePasswordNextLogin)
}

function Remove-LwAzUser([guid] $ObjectId, [string] $UPN)
{
	if ($ObjectId) {
		Remove-AzADUser -ObjectId $ObjectId -Confirm:$false -Force
	}
	else {
		Remove-AzADUser -UserPrincipalName $UPN -Confirm:$false -Force
	}
}


function ReadGroup($group)
{
	return $group | Select ObjectId, ObjectType, DisplayName, Description, Mail, MailEnabled, MailNickName,`
			SecurityEnabled, DirSyncEnabled, OnPremisesSecurityIdentifier, ProxyAddresses, `
		@{Name='DeletionTimestamp'; Expression={Format-Date $_.DeletionTimestamp}},`
		@{Name='LastDirSyncTime'; Expression={Format-Date $_.LastDirSyncTime}}
}

function Get-LwAzureGroup(
	[Parameter(Mandatory=$false, HelpMessage='The unique identifier of a group in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$false, HelpMessage='Group display name, may be not unique')] [string] $DisplayName,
	[switch] $AsObject)
{
	$cmd = 'Get-AzureADGroup'
	if ($ObjectId) { 
		$cmd += ' -ObjectId $ObjectId'
	}
	elseif ($DisplayName) { 
		$cmd += ' -Filter "DisplayName eq ''$DisplayName''"'
	}
	else {
		$cmd += ' -All $true'
	}
	$group = Invoke-Expression $cmd
	if ($group -and $AsObject)
	{
		return (ReadGroup $group)
	}
	return $group
}

function New-LwAzureGroup(
	[Parameter(Mandatory=$true, HelpMessage='Display name of the group')] [string] $DisplayName,
	[Parameter(Mandatory=$false, HelpMessage='Description of the group')] [string] $Description,
	[Parameter(Mandatory=$false, HelpMessage='Whether mail is enabled')] [bool] $MailEnabled = $false,
	[Parameter(Mandatory=$true, HelpMessage='Nickname for mail')] [string] $MailNickName,
	[Parameter(Mandatory=$false, HelpMessage='Whether the group is security-enabled')] [bool] $SecurityEnabled = $false,
	[switch] $AsObject)
{
	$cmd = 'New-AzureADGroup -DisplayName $DisplayName -MailEnabled $MailEnabled -MailNickName $MailNickName -SecurityEnabled $SecurityEnabled'
	if ($Description) { $cmd += ' -Description $Description'}

	$group = Invoke-Expression $cmd
	if ($group -and $AsObject)
	{
		return (ReadGroup $group)
	}
	return $group
}

function Update-LwAzureGroup(
	[Parameter(Mandatory=$true, HelpMessage='The unique identifier of a group in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$false, HelpMessage='Display name of the group')] [string] $DisplayName,
	[Parameter(Mandatory=$false, HelpMessage='Description of the group')] [string] $Description,
	[Parameter(Mandatory=$false, HelpMessage='Whether mail is enabled')] [nullable[bool]] $MailEnabled,
	[Parameter(Mandatory=$false, HelpMessage='Nickname for mail')] [string] $MailNickName,
	[Parameter(Mandatory=$false, HelpMessage='Whether the group is security-enabled')] [nullable[bool]] $SecurityEnabled,
	[switch] $AsObject)
{
	$cmd = 'Set-AzureADGroup -ObjectId $ObjectId'
	if ($DisplayName) { $cmd += ' -DisplayName $DisplayName'}
	if ($Description) { $cmd += ' -Description $Description'}
	if ($MailEnabled -ne $null) { $cmd += ' -MailEnabled $MailEnabled'}
	if ($MailNickName) { $cmd += ' -MailNickName $MailNickName'}
	if ($SecurityEnabled -ne $null) { $cmd += ' -SecurityEnabled $SecurityEnabled'}

	Invoke-Expression $cmd

	return (Get-LwAzureGroup -ObjectId $ObjectId -AsObject:$AsObject) 
}

function Remove-LwAzureGroup(
	[Parameter(Mandatory=$true, HelpMessage='The unique identifier of a group in Azure Active Directory')] [guid] $ObjectId)
{
	Remove-AzureADGroup -ObjectId $ObjectId
}

function Get-LwAzureGroupMember(
	[Parameter(Mandatory=$true, HelpMessage='The unique identifier of a group in Azure Active Directory')] [guid] $ObjectId,
	[switch] $AsObject)
{
	$members = Get-AzureADGroupMember -ObjectId $ObjectId -All $true
	if ($members -and $AsObject)
	{
		return $members |% {
			if ($_ -is [Microsoft.Open.AzureAD.Model.User]) { ReadUser $_ }
			elseif ($_ -is [Microsoft.Open.AzureAD.Model.Group]) { ReadGroup $_ }
			elseif ($_ -is [Microsoft.Open.AzureAD.Model.Device]) { ReadDevice $_ }
			else { $_ }
		}
	}
	return $members
}

function Add-LwAzureGroupMember(
	[Parameter(Mandatory=$true, HelpMessage='The ID of a group in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$true, HelpMessage='The ID of the Active Directory object that will be assigned as owner/manager/member')] [guid] $RefObjectId)
{
	Add-AzureADGroupMember -ObjectId $ObjectId -RefObjectId $RefObjectId
}

function Remove-LwAzureGroupMember(
	[Parameter(Mandatory=$true, HelpMessage='The ID of a group in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$true, HelpMessage='The ID of the Active Directory object that will be removed')] [guid] $MemberId)
{
	Remove-AzureADGroupMember -ObjectId $ObjectId -MemberId $MemberId
}

function ReadDevice($device)
{
	return $device | Select ObjectId, ObjectType, DeviceId, DisplayName,`
			AccountEnabled, DirSyncEnabled, IsCompliant, IsManaged, ProfileType,`
			AlternativeSecurityIds, DeviceMetadata, DeviceObjectVersion, DeviceOSType, DeviceOSVersion, DevicePhysicalIds, SystemLabels,`
		@{Name='ApproximateLastLogonTimeStamp'; Expression={Format-Date $_.DeletionTimestamp}},`
		@{Name='ComplianceExpiryTime'; Expression={Format-Date $_.ComplianceExpiryTime}},`
		@{Name='DeletionTimestamp'; Expression={Format-Date $_.DeletionTimestamp}},`
		@{Name='LastDirSyncTime'; Expression={Format-Date $_.LastDirSyncTime}}
#AlternativeSecurityIds              Property   System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.Alternat...
}

function Get-LwAzureDevice(
	[Parameter(Mandatory=$false, HelpMessage='The unique identifier of a device in Azure Active Directory')] [guid] $ObjectId,
	[Parameter(Mandatory=$false, HelpMessage='Device display name, may be not unique')] [string] $DisplayName,
	[switch] $AsObject)
{
	$cmd = 'Get-AzureADDevice'
	if ($ObjectId) { 
		$cmd += ' -ObjectId $ObjectId'
	}
	elseif ($DisplayName) { 
		$cmd += ' -Filter "DisplayName eq ''$DisplayName''"'
	}
	else {
		$cmd += ' -All $true'
	}
	$device = Invoke-Expression $cmd

	if ($device -and $AsObject)
	{
		return (ReadDevice $device)
	}
	return $device
}

<##
# https://www.msxfaq.de/cloud/client/device_registration.htm
$dev = @{DisplayName = 'ANDREI-W540'; DeviceId = 'd224105d-5f46-4fd4-954a-2bb0c6e303d8'; DeviceOSType = 'Windows'; DeviceOSVersion = '10.0.17134.0';`
DeviceObjectVersion = 2; AccountEnabled = $true; DeviceTrustType = 'Workplace';`
AlternativeSecurityIds = @(@{ Type = 2; Key = @(88, 0, 53, 0, 48, 0, 57, 0, 58, 0, 60, 0, 83, 0, 72, 0, 65, 0, 49, 0, 45, 0, 84, 0, 80, 0, 45, 0, 80, 0, 85, 0, 66, 0, 75, 0, 69, 0, 89, 0, 62, 0, 69, 0, 49, 0, 48, 0, 67, 0, 51, 0, 52, 0, 54, 0, 68, 0, 66, 0, 52, 0, 68, 0, 50, 0, 52, 0, 53, 0, 54, 0, 52, 0, 51, 0, 48, 0, 65, 0, 55, 0, 67, 0, 69, 0, 51, 0, 67, 0, 55, 0, 57, 0, 57, 0, 68, 0, 65, 0, 48, 0, 68, 0, 51, 0, 49, 0, 68, 0, 53, 0, 65, 0, 68, 0, 54, 0, 53, 0, 65, 0, 73, 0, 116, 0, 116, 0, 106, 0, 117, 0, 76, 0, 117, 0, 116, 0, 88, 0, 103, 0, 87, 0, 78, 0, 113, 0, 81, 0, 72, 0, 108, 0, 78, 0, 106, 0, 106, 0, 88, 0, 69, 0, 84, 0, 86, 0, 76, 0, 50, 0, 84, 0, 115, 0, 120, 0, 120, 0, 48, 0, 114, 0, 114, 0, 105, 0, 69, 0, 75, 0, 89, 0, 115, 0, 88, 0, 68, 0, 99, 0, 43, 0, 90, 0, 52, 0, 61, 0)});`
DevicePhysicalIds = @('[USER-GID]:a4b7ab35-8a83-4102-b773-6c4f63b54448:6825773979753362', '[GID]:g:6825773979753362', '[USER-HWID]:a4b7ab35-8a83-4102-b773-6c4f63b54448:6755410885010397', '[HWID]:h:6755410885010397')}
##>
function New-LwAzureDevice(
	[Parameter(Mandatory=$true, HelpMessage='Display name of the new device')] [string] $DisplayName,
	[Parameter(Mandatory=$true, HelpMessage='ID of the device')] [guid] $DeviceId,
	[Parameter(Mandatory=$true, HelpMessage='Operating system type of the new device')] [string] $DeviceOSType,
	[Parameter(Mandatory=$true, HelpMessage='Operating system version of the new device')] [string] $DeviceOSVersion,
	[Parameter(Mandatory=$false, HelpMessage='Object version of the device')] [nullable[int]] $DeviceObjectVersion,
	[Parameter(Mandatory=$false, HelpMessage='Whether the account is enabled')] [bool] $AccountEnabled = $true,
	[Parameter(Mandatory=$false, HelpMessage='True if the device complies with Mobile Device Management (MDM) policies; otherwise, false')] [nullable[bool]] $IsCompliant = $false,
	[Parameter(Mandatory=$false, HelpMessage='True if the device is managed by a Mobile Device Management (MDM) app such as Intune; otherwise, false')] [nullable[bool]] $IsManaged = $false,
	[Parameter(Mandatory=$true)] [hashtable[]] $AlternativeSecurityIds,
	[Parameter(Mandatory=$false)] [string] $ApproximateLastLogonTimeStamp,
	[Parameter(Mandatory=$false)] [string[]] $DevicePhysicalIds,
	[Parameter(Mandatory=$false, HelpMessage='Metadata for this device')] [string] $DeviceMetadata,
	[switch] $AsObject)
{
	$sids = New-Object 'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.AlternativeSecurityId]'
	$AlternativeSecurityIds |% {
		$sid = New-Object Microsoft.Open.AzureAD.Model.AlternativeSecurityId
		if ($_.IdentityProvider) { $sid.IdentityProvider = $_.IdentityProvider }
		$sid.Type = $_.Type
		$sid.Key = [byte[]]$_.Key
		$sids.Add($sid)
	}

	if ($DevicePhysicalIds)
	{
		$dids = New-Object 'System.Collections.Generic.List[string]'
		$DevicePhysicalIds |% { $dids.Add($_) }
	}

	$cmd = 'New-AzureADDevice -DisplayName $DisplayName -DeviceId $DeviceId -DeviceOSType $DeviceOSType -DeviceOSVersion $DeviceOSVersion -AccountEnabled $AccountEnabled -AlternativeSecurityIds $sids'
	if ($DeviceObjectVersion -ne $null) { $cmd += ' -DeviceObjectVersion $DeviceObjectVersion'}
#	if ($DeviceTrustType) { $cmd += ' -DeviceTrustType $DeviceTrustType'}
	if ($IsCompliant -ne $null) { $cmd += ' -IsCompliant $IsCompliant'}
	if ($IsManaged -ne $null) { $cmd += ' -IsManaged $IsManaged'}
	if ($DevicePhysicalIds) { $cmd += ' -DevicePhysicalIds $dids'}
	if ($ApproximateLastLogonTimeStamp) { $ts = Parse-Date $ApproximateLastLogonTimeStamp ; $cmd += ' -ApproximateLastLogonTimeStamp $ApproximateLastLogonTimeStamp'}
	if ($DeviceMetadata) { $cmd += ' -DeviceMetadata $DeviceMetadata'}

	$device = Invoke-Expression $cmd
	if ($device -and $AsObject)
	{
		return (ReadDevice $device)
	}
	return $device

}


function Remove-LwAzureDevice(
	[Parameter(Mandatory=$false, HelpMessage='The unique identifier of a device in Azure Active Directory')] [guid] $ObjectId)
{
	Remove-AzureADDevice -ObjectId $ObjectId
}


##############################################################

function CheckResources($resources)
{
	if ($resources)	 { return $resources }
	$resources = @{ ResourceGroups = @{}; StorageAccounts = @{}; SecurityGroups = @{}; VirtualNetworks = @{}; PublicIpAddresses = @{}; VNics = @{}; VMs = @{}}
	return $resources
}

function ReadAzResourceGroup($rg)
{
	 return $rg | Select Location, ManagedBy, ProvisioningState, ResourceGroupName, ResourceId, Tags, TagsTable
}

function Get-LwAzResourceGroup(
	[string] $Name,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$gr = $null
	if ($Resources -and $name) {
		$gr = $Resources.ResourceGroups[$Name]
	}
	if (-not $gr) {
		$cmd = 'Get-AzResourceGroup -EA 0'
		if ($Name) { $cmd += ' -Name $Name'}
		$gr = Invoke-Expression $cmd
		if ($Resources -and $gr -and $Name) { $Resources.ResourceGroups[$Name] = $gr }
	}
	if ($gr -and $AsObject)
	{
		return (ReadAzResourceGroup $gr)
	}

	return $gr
}

function New-LwAzResourceGroup([string] $Name, [string] $Location,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$gr = Get-LwAzResourceGroup -Name $Name -Resources $Resources
	if (-not $gr)
	{
		$gr = New-AzResourceGroup -Name $Name -Location $Location
		if ($Resources -and $gr -and $Name) { $Resources.ResourceGroups[$Name] = $gr }
	}

	if ($AsObject)
	{
		return (ReadAzResourceGroup $gr)
	}

	return $gr
}

function ReadAzStorageAccount($sa)
{
	 return $sa | Select StorageAccountName, Id, Kind, Location, PrimaryLocation, SecondaryLocation, ResourceGroupName,`
			StatusOfPrimary, StatusOfSecondary, Tags, ExtendedProperties, ProvisioningState, EnableHierarchicalNamespace, EnableHttpsTrafficOnly,`
			@{Name='Sku'; Expression={ $_.Sku.Name }},`
			@{Name='LastGeoFailoverTime'; Expression={Format-Date $_.LastGeoFailoverTime}},`
			@{Name='CreationTime'; Expression={Format-Date $_.CreationTime}},`
			@{Name='CustomDomain'; Expression={ $_.CustomDomain.Name }},`
			@{Name='Encryption'; Expression={ $_.Encryption.KeySource }},`
			@{Name='Context'; Expression={ $_.Context | Select Name, BlobEndPoint, FileEndPoint, QueueEndPoint, TableEndPoint, EndPointSuffix, ConnectionString }},`
			@{Name='PrimaryEndpoints'; Expression={ $_.PrimaryEndpoints | Select Blob, Dfs, File, Queue, Table, Web }},`
			@{Name='SecondaryEndpoints'; Expression={ $_.SecondaryEndpoints | Select Blob, Dfs, File, Queue, Table, Web }}
}

function Get-LwAzStorageAccount(
	[Parameter(Mandatory=$false, HelpMessage='Name of the storage account')] [string] $Name,
	[Parameter(Mandatory=$false, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$sa = $null
	if ($Resources -and $Name) {
		$sa = $Resources.StorageAccounts[$Name]
	}
	if (-not $sa) {
		$cmd = 'Get-AzStorageAccount -EA 0'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $Name'}
		$sa = Invoke-Expression $cmd
		if ($Resources -and $sa -and $Name) { $Resources.StorageAccounts[$Name] = $sa }
	}
	if ($sa -and $AsObject)
	{
		return ReadAzStorageAccount $sa
	}

	return $sa
}

function New-LwAzStorageAccount([string] $Name, 
	[Parameter(Mandatory=$true, HelpMessage='Location')] [string] $Location, 
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group')] [string] $ResourceGroupName,
	[ValidateSet('Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_RAGRS', 'Premium_LRS')] [string] $SkuName = 'Standard_LRS',
	[ValidateSet('Storage', 'StorageV2', 'BlobStorage')] [string] $Kind = 'Storage',
	$NetworkRuleSet,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$sa = Get-LwAzStorageAccount -Name $Name -ResourceGroupName $ResourceGroupName -Resources $Resources
	if (-not $sa)
	{
		# Create a new storage account
		$cmd = 'New-AzStorageAccount'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($Location) { $cmd += ' -Location $Location'}
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
		if ($SkuName) { $cmd += ' -Type $SkuName'}
		if ($NetworkRuleSet) { $cmd += ' -NetworkRuleSet $NetworkRuleSet'}
<##
   [-AccessTier <String>]
   [-CustomDomainName <String>]
   [-UseSubDomain <Boolean>]
   [-Tag <Hashtable>]
   [-EnableHttpsTrafficOnly <Boolean>]
   [-AssignIdentity]
   [-EnableHierarchicalNamespace <Boolean>]
##>
		$sa = Invoke-Expression $cmd
		if ($Resources -and $sa -and $Name) { $Resources.StorageAccounts[$Name] = $sa }
	}

	if ($AsObject)
	{
		return (ReadAzStorageAccount $sa)
	}
	return $sa
}


function New-LwAzNetworkSecurityRuleConfig([string] $Name,
	[string] $NetworkSecurityGroupName,
	[string] $Description,
	[string] $Protocol,
	[string[]] $SourcePortRange,
	[string[]] $DestinationPortRange,
	[string[]] $SourceAddressPrefix,
	[string[]] $DestinationAddressPrefix,
	[string] $Access,
	[int] $Priority,
	[string] $Direction,
	[switch] $AsObject)
{
	$rule = $null
#	$rule = Get-AzNetworkSecurityRuleConfig -Name $Name -NetworkSecurityGroup $NetworkSecurityGroupName -EA 0
	if (-not $rule)
	{
		$cmd = 'New-AzNetworkSecurityRuleConfig -Name $Name'
		if ($Description) { $cmd += ' -Description $Description'}
		if ($Protocol) { $cmd += ' -Protocol $Protocol'}
		if ($SourcePortRange) { $cmd += ' -SourcePortRange $SourcePortRange'}
		if ($DestinationPortRange) { $cmd += ' -DestinationPortRange $DestinationPortRange'}
		if ($SourceAddressPrefix) { $cmd += ' -SourceAddressPrefix $SourceAddressPrefix'}
		if ($DestinationAddressPrefix) { $cmd += ' -DestinationAddressPrefix $DestinationAddressPrefix'}
		if ($Access) { $cmd += ' -Access $Access'}
		if ($Priority -ne $null) { $cmd += ' -Priority $Priority'}
		if ($Direction) { $cmd += ' -Direction $Direction'}
		$rule = Invoke-Expression $cmd
<##
   [-SourceApplicationSecurityGroup <PSApplicationSecurityGroup[]>]
   [-DestinationApplicationSecurityGroup <PSApplicationSecurityGroup[]>]
##>
	}
	return $rule
}

function ReadAzNetworkSecurityGroup($gr)
{
	if ($gr -eq $null) { return $null }
	$g = $gr | Select Name, Id, Etag, Location, ResourceGroupName, ResourceGuid, Type, Tag, ProvisioningState,`
			@{Name='DefaultSecurityRules'; Expression={ ConvertFrom-Json $_.DefaultSecurityRulesText  }},`
			@{Name='SecurityRules'; Expression={ ConvertFrom-Json $_.SecurityRulesText }},`
			@{Name='Subnets'; Expression={ ConvertFrom-Json $_.SubnetsText }},`
			@{Name='NetworkInterfaces'; Expression={ ConvertFrom-Json $_.NetworkInterfacesText }}
	$g |% {
		$_.SecurityRules = $_.SecurityRules |% {$_}
		$_.DefaultSecurityRules = $_.DefaultSecurityRules |% {$_}
		$_.Subnets = $_.Subnets |% {$_}
		$_.NetworkInterfaces = $_.NetworkInterfaces |% {$_}
	}

	return $g	
}

function Get-LwAzNetworkSecurityGroup(
	[Parameter(Mandatory=$false, HelpMessage='Name of the security group')] [string] $Name,
	[Parameter(Mandatory=$false, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$gr = $null
	if ($Resources -and $name) {
		$gr = $Resources.SecurityGroups[$Name]
	}
	if (-not $gr) {
		$cmd = 'Get-AzNetworkSecurityGroup -EA 0'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
		$gr = Invoke-Expression $cmd
		if ($Resources -and $gr -and $Name) { $Resources.SecurityGroups[$Name] = $gr }
	}
	if ($gr -and $AsObject)
	{
		return (ReadAzNetworkSecurityGroup $gr)
	}

	return $gr
}

function New-LwAzNetworkSecurityGroup(
	[Parameter(Mandatory=$true, HelpMessage='Name of the security group')] [string] $Name,
	[Parameter(Mandatory=$false, HelpMessage='Region in which to create')] [string] $Location, 
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[hashtable[]] $SecurityRules,
	[hashtable] $Tag,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$rules = @()
	$gr = Get-LwAzNetworkSecurityGroup -Name $Name -ResourceGroupName $ResourceGroupName -Resources $Resources
	if (-not $gr)
	{
		if ($SecurityRules) {
			$SecurityRules |% { $rules += New-LwAzNetworkSecurityRuleConfig -Name $_.Name `
				-NetworkSecurityGroupName $Name -Description $_.Description -Protocol $_.Protocol `
				-SourcePortRange $_.SourcePortRange -DestinationPortRange $_.DestinationPortRange `
				-SourceAddressPrefix $_.SourceAddressPrefix -DestinationAddressPrefix $_.DestinationAddressPrefix `
				-Access $_.Access -Priority $_.Priority -Direction $_.Direction
			}
		}

		$cmd = 'New-AzNetworkSecurityGroup -Name $Name -Location $Location -ResourceGroupName $ResourceGroupName'
		if ($Tag) { $cmd += ' -Tag $Tag'}
		if ($rules) { $cmd += ' -SecurityRules $rules'}
		$gr = Invoke-Expression $cmd
		if ($Resources -and $gr -and $Name) { $Resources.SecurityGroups[$Name] = $gr }
	}
	if ($AsObject)
	{
		return (ReadAzNetworkSecurityGroup $gr)
	}

	return $gr
}

function New-LwAzVirtualNetworkSubnetConfig([string] $Name,
	[Parameter(Mandatory=$false, HelpMessage='Region in which to create')] [string] $Location, 
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[string] $VNetName,
	[string[]] $AddressPrefix, 
	$NetworkSecurityGroup,
	[string[]] $ServiceEndpoint)
{

	$sn = $null
#	$sn = Get-AzVirtualNetworkSubnetConfig -Name $Name -VirtualNetwork $VNetName -EA 0
	if (-not $sn)
	{
		$cmd = 'New-AzVirtualNetworkSubnetConfig -Name $Name'
		if ($AddressPrefix) { $cmd += ' -AddressPrefix $AddressPrefix'}
		if ($NetworkSecurityGroup) { $cmd += ' -NetworkSecurityGroup $NetworkSecurityGroup'}
		if ($ServiceEndpoint) { $cmd += ' -ServiceEndpoint $ServiceEndpoint'}

		$sn = Invoke-Expression $cmd
<## 
   [-RouteTable <PSRouteTable>]
   [-ServiceEndpointPolicy <PSServiceEndpointPolicy[]>]
   [-Delegation <PSDelegation[]>]

   [-RouteTableId <String>]
##>
	}
	return $sn
}


function ReadAzVirtualNetwork($vn)
{
	if ($vn -eq $null) { return $null }
	$v = $vn | Select Name, Id, Etag, Location, ResourceGroupName, ResourceId, Type, ProvisioningState, EnableDdosProtection, Tag, `
			@{Name='AddressSpace'; Expression={ ConvertFrom-Json $_.AddressSpaceText  }},`
			@{Name='DdosProtectionPlan'; Expression={ ConvertFrom-Json $_.DdosProtectionPlanText  }},`
			@{Name='DhcpOptions'; Expression={ ConvertFrom-Json $_.DhcpOptionsText  }},`
			@{Name='Subnets'; Expression={ (ConvertFrom-Json $_.SubnetsText) |% {$_}  }},`
			@{Name='VirtualNetworkPeerings'; Expression={ ConvertFrom-Json $_.VirtualNetworkPeeringsText  }}
	$v |% {
		$_.Subnets = $_.Subnets |% {$_}
		$_.VirtualNetworkPeerings = $_.VirtualNetworkPeerings |% {$_}
	}

	return $v	
}

function Get-LwAzVirtualNetwork(
	[Parameter(Mandatory=$false, HelpMessage='Name of the virtual network')] [string] $Name,
	[Parameter(Mandatory=$false, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$vn = $null
	if ($Resources -and $Name) {
		$vn = $Resources.VirtualNetworks[$Name]
	}

	if (-not $vn) {
		$cmd = 'Get-AzVirtualNetwork -EA 0'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
		$vn = Invoke-Expression $cmd
		if ($Resources -and $vn -and $Name) { $Resources.VirtualNetworks[$Name] = $vn }
	}
	if ($vn -and $AsObject)
	{
		return (ReadAzVirtualNetwork $vn)
	}

	return $vn
}

function New-LwAzVirtualNetwork([string] $Name, 
	[Parameter(Mandatory=$false, HelpMessage='Region in which to create')] [string] $Location, 
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[string[]] $AddressPrefix,
	[string[]] $DnsServer,
	[hashtable[]] $Subnets,
	[hashtable] $Tag,
	[bool] $EnableDdosProtection,
	[string] $DdosProtectionPlanId,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$vn = Get-LwAzVirtualNetwork -Name $Name -ResourceGroupName $ResourceGroupName -Resources $Resources
	if (-not $vn)
	{
		$subnetList = @()
		if ($Subnets) {
			$Resources = CheckResources $resources
			$Subnets |% {
				$sg = $null
				if ($_.NetworkSecurityGroup) { 
					$sg = Get-LwAzNetworkSecurityGroup -Name $_.NetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Resources $Resources
					if (-not $sg) { throw "NetworkSecurityGroup '$($_.NetworkSecurityGroup)' does not exist" }
				}
				$subnet = New-LwAzVirtualNetworkSubnetConfig -Name $_.Name -Location $Location -ResourceGroupName $ResourceGroupName `
					-VNetName $Name -AddressPrefix $_.AddressPrefix -NetworkSecurityGroup $sg -ServiceEndpoint $_.ServiceEndpoint
				$subnetList += $subnet
			}
		}

		$cmd = 'New-AzVirtualNetwork -Name $Name -Location $Location -ResourceGroupName $ResourceGroupName -AddressPrefix $AddressPrefix'
		if ($DnsServer) { $cmd += ' -DnsServer $DnsServer'}
		if ($subnetList) { $cmd += ' -Subnet $subnetList' }
		if ($Tag) { $cmd += ' -Tag $Tag'}
		if ($EnableDdosProtection) { $cmd += ' -EnableDdosProtection'}
		if ($DdosProtectionPlanId) { $cmd += ' -DdosProtectionPlanId $DdosProtectionPlanId'}
		$vn = Invoke-Expression $cmd
		if ($Resources -and $vn -and $Name) { $Resources.VirtualNetworks[$Name] = $vn }
	}
	if ($AsObject)
	{
		return (ReadAzVirtualNetwork $vn)
	}
	return $vn
}

function ReadAzPublicIpAddress($ip)
{
	if ($ip -eq $null) { return $null }
	$i = $ip | Select Name, Id, Etag, Location, ResourceGroupName, ResourceId, Type, ProvisioningState, Tag, `
			IpAddress, IdleTimeoutInMinutes, PublicIpAddressVersion, PublicIpAllocationMethod, Zones,`			
			@{Name='DnsSettings'; Expression={ ConvertFrom-Json $_.DnsSettingsText }},`
			@{Name='IpConfiguration'; Expression={ ConvertFrom-Json $_.IpConfigurationText }},`
			@{Name='IpTags'; Expression={ ConvertFrom-Json $_.IpTagsText }},`
			@{Name='PublicIpPrefix'; Expression={ ConvertFrom-Json $_.PublicIpPrefixText }},`
			@{Name='Sku'; Expression={ ConvertFrom-Json $_.SkuText }}
	$i |% {
		$_.IpTags = $_.IpTags |% {$_}
		$_.Zones = $_.Zones |% {$_}
	}
	return $i
}


function Get-LwAzPublicIpAddress([string] $Name, [string] $ResourceGroupName, [hashtable] $Resources,
	[switch] $AsObject)
{
	$ip = $null
	if ($Resources -and $Name) {
		$ip = $Resources.PublicIpAddresses[$Name]
	}

	if (-not $ip) {
		$cmd = 'Get-AzPublicIpAddress -EA 0'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
		$ip = Invoke-Expression $cmd
		if ($Resources -and $ip -and $Name) { $Resources.PublicIpAddresses[$Name] = $ip }
	}
	if ($AsObject)
	{
		return (ReadAzPublicIpAddress $ip)
	}
	return $ip
}


function New-LwAzPublicIpAddress(
	[Parameter(Mandatory=$false, HelpMessage='Name of the public IP address')] [string] $Name,
	[Parameter(Mandatory=$false, HelpMessage='Region in which to create a public IP address')] [string] $Location, 
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group in which to create a public IP address')] [string] $ResourceGroupName, 
	[Parameter(Mandatory=$false, HelpMessage='The public IP Sku name')] [string] $Sku, 
	[Parameter(Mandatory=$false, HelpMessage='Method with which to allocate the public IP address. The acceptable values for this parameter are: Static or Dynamic')] [ValidateSet('Static', 'Dynamic')] [string] $AllocationMethod = 'Dynamic', 
	[Parameter(Mandatory=$false, HelpMessage='Version of the IP address')] [ValidateSet('IPv4', 'IPv6')] [string] $IpAddressVersion = 'IPv4', 
	[Parameter(Mandatory=$false, HelpMessage='Relative DNS name for a public IP address')] [string] $DomainNameLabel, 
	[Parameter(Mandatory=$false, HelpMessage='Reverse fully qualified domain name (FQDN)')] [string] $ReverseFqdn, 
	[Parameter(Mandatory=$false, HelpMessage='Idle time-out, in minutes')] [int] $IdleTimeoutInMinutes, 
	[Parameter(Mandatory=$false, HelpMessage='A list of availability zones denoting the IP allocated for the resource needs to come from')] [string[]] $Zone, 
	[Parameter(Mandatory=$false, HelpMessage='Key-value pairs in the form of a hash table. For example: @{key0="value0";key1=$null;key2="value2"}')] [hashtable] $Tag,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$ip = Get-LwAzPublicIpAddress -Name $Name -ResourceGroupName $ResourceGroupName -Resources $Resources
	if (-not $ip)
	{
		$cmd = 'New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -AllocationMethod $AllocationMethod'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($Location) { $cmd += ' -Location $Location'}
		if ($Sku) { $cmd += ' -Sku $Sku'}
		if ($IpAddressVersion) { $cmd += ' -IpAddressVersion $IpAddressVersion'}
		if ($DomainNameLabel) { $cmd += ' -DomainNameLabel $DomainNameLabel'}
		if ($ReverseFqdn) { $cmd += ' -ReverseFqdn $ReverseFqdn'}
		if ($IdleTimeoutInMinutes) { $cmd += ' -IdleTimeoutInMinutes $IdleTimeoutInMinutes'}
		if ($Zone) { $cmd += ' -Zone $Zone'}
		if ($Tag) { $cmd += ' -Tag $Tag'}

		$ip = Invoke-Expression $cmd
		if ($Resources -and $ip -and $Name) { $Resources.PublicIpAddresses[$Name] = $ip }
<##
   [-IpTag <PSPublicIpTag[]>]
   [-PublicIpPrefix <PSPublicIpPrefix>]
##>
	}
	if ($AsObject)
	{
		return (ReadAzPublicIpAddress $ip)
	}
	return $ip
}

function Get-LwAzNetworkInterface([string] $Name, [string] $ResourceGroupName, [hashtable] $Resources,
	[switch] $AsObject)
{
	if ($Resources -and $Name) {
		$ip = $Resources.VNics[$Name]
		if ($ip) { return $ip }
	}
	$cmd = 'Get-AzNetworkInterface -EA 0'
	if ($Name) { $cmd += ' -Name $Name'}
	if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
	$ip = Invoke-Expression $cmd
	if ($Resources -and $ip -and $Name) { $Resources.VNics[$Name] = $ip }
	return $ip
}


function New-LwAzNetworkInterface(
	[Parameter(Mandatory=$true, HelpMessage='Name of the network interface to create')] [string] $Name,
	[Parameter(Mandatory=$true, HelpMessage='Region for a network interface')] [string] $Location,
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group in which to create a public IP address')] [string] $ResourceGroupName, 
	[Parameter(Mandatory=$true, HelpMessage='Name of the virtual network for which to create a network interface')] [string] $VirtualNetworkName,
	[Parameter(Mandatory=$true, HelpMessage='Name of the subnet for which to create a network interface')] [string] $SubnetName,
	[Parameter(Mandatory=$false, HelpMessage='Name of a PublicIPAddress object to assign to a network interface')] [string] $PublicIpAddressName,
	[Parameter(Mandatory=$false, HelpMessage='Name of a network security group')] [string] $NetworkSecurityGroupName,
	[Parameter(Mandatory=$false, HelpMessage='Static IPv4 IP address to assign to this network interface.')] [string] $PrivateIpAddress,
	[Parameter(Mandatory=$false, HelpMessage='Internal DNS name label for the new network interface')] [string] $InternalDnsNameLabel,
	[Parameter(Mandatory=$false, HelpMessage='DNS server for the network interface')] [string[]] $DnsServer,
	[Parameter(Mandatory=$false, HelpMessage='Key-value pairs in the form of a hash table. For example: @{key0="value0";key1=$null;key2="value2"}')] [hashtable] $Tag,
	[hashtable] $Resources,
	[switch] $AsObject)
{
	$ip = Get-LwAzNetworkInterface -Name $Name -ResourceGroupName $ResourceGroupName -Resources $Resources
	if (-not $ip)
	{
		$cmd = 'New-AzNetworkInterface -Name $Name -ResourceGroupName $ResourceGroupName -Location $Location'
		$sg = $null
		if ($NetworkSecurityGroupName) { 
			$sg = Get-LwAzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Resources $resources
            if (-not $sg) { throw "NetworkSecurityGroup '$NetworkSecurityGroupName' does not exist" }
			$cmd += ' -NetworkSecurityGroupId $sg.Id'
		}
		$snet = $null
		if ($VirtualNetworkName -and $SubnetName) {
			$vnet = Get-LwAzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName -Resources $resources
			if (-not $vnet) { throw "VirtualNetwork '$VirtualNetworkName' does not exist" }
			$snet = $vnet.Subnets |? {$_.Name -eq $SubnetName }
            if (-not $snet) { throw "Subnet '$SubnetName' does not exist" }
			$cmd += ' -SubnetId $snet.Id'
		}
		$pip = $null
		if ($NetworkSecurityGroupName) { 
			$pip = Get-LwAzPublicIpAddress -Name $PublicIpAddressName -ResourceGroupName $ResourceGroupName -Resources $resources
            if (-not $pip) { throw "PublicIpAddress '$PublicIpAddressName' does not exist" }
			$cmd += ' -PublicIpAddressId $pip.Id'
		}
		if ($PrivateIpAddress) { $cmd += ' -PrivateIpAddress $PrivateIpAddress'}
		if ($InternalDnsNameLabel) { $cmd += ' -InternalDnsNameLabel $InternalDnsNameLabel'}
		if ($DnsServer) { $cmd += ' -DnsServer $DnsServer'}
		if ($Tag) { $cmd += ' -Tag $Tag'}

		$ip = Invoke-Expression $cmd
		if ($Resources -and $ip -and $Name) { $Resources.VNics[$Name] = $ip }
<##
   -IpConfiguration <PSNetworkInterfaceIPConfiguration[]>
   -Subnet <PSSubnet>
   [-PublicIpAddress <PSPublicIpAddress>]
   [-NetworkSecurityGroup <PSNetworkSecurityGroup>]
   [-LoadBalancerBackendAddressPool <PSBackendAddressPool[]>]
   [-LoadBalancerInboundNatRule <PSInboundNatRule[]>]
   [-ApplicationGatewayBackendAddressPool <PSApplicationGatewayBackendAddressPool[]>]
   [-ApplicationSecurityGroup <PSApplicationSecurityGroup[]>]
   [-LoadBalancerBackendAddressPoolId <String[]>]
   [-LoadBalancerInboundNatRuleId <String[]>]
   [-ApplicationGatewayBackendAddressPoolId <String[]>]
   [-ApplicationSecurityGroupId <String[]>]
   [-IpConfigurationName <String>]
   [-NetworkSecurityGroup <PSNetworkSecurityGroup>]
   [-EnableIPForwarding]
   [-EnableAcceleratedNetworking]
   [-DefaultProfile <IAzureContextContainer>]

##>
	}

    return $ip
}

function ReadAzVM($vm)
{
	if ($vm -eq $null) { return $null }
	$v = $vm | Select Name, Id, Location, ResourceGroupName, VmId, RequestId, Type, ProvisioningState, Tags, `
			FullyQualifiedDomainName, LicenseType, AdditionalCapabilities, AvailabilitySetReference, Zones,`
			@{Name='StatusCode'; Expression={ $_.StatusCode.ToString() }},`
			@{Name='DisplayHint'; Expression={ $_.DisplayHint.ToString() }},`
			@{Name='DiagnosticsProfile'; Expression={ $_.DiagnosticsProfile.BootDiagnostics | Select Enabled, StorageUri }},`
			@{Name='Size'; Expression={ $_.HardwareProfile.VmSize }},`
			@{Name='NetworkInterfaces'; Expression={ $r = @(); $_.NetworkProfile.NetworkInterfaces |% { $r += ($_ | Select Id, Primary) }; ,$r }},`
			@{Name='OSProfile'; Expression={ $_.OSProfile | Select ComputerName, CustomData, AdminUsername, AdminPassword, AllowExtensionOperations }},`
			@{Name='WindowsConfiguration'; Expression={ $_.OSProfile.WindowsConfiguration | Select AdditionalUnattendContent, EnableAutomaticUpdates, ProvisionVMAgent, TimeZone }},`
			@{Name='ImageReference'; Expression={ $_.StorageProfile.ImageReference | Select Id, Offer, Publisher, Sku, Version }},`
			@{Name='OsDisk'; Expression={ $_.StorageProfile.OsDisk | Select Name, DiskSizeGB, OsType, CreateOption, Caching, WriteAcceleratorEnabled, @{Name='ManagedDiskId'; Expression={ $_.ManagedDisk.Id }}, @{Name='StorageAccountType'; Expression={ $_.ManagedDisk.StorageAccountType }} }}
# Extensions               Property   System.Collections.Generic.IList[Microsoft.Azure.Management.Compute.Models.VirtualMachineExtension] Extensions {get;set;}
# Identity                 Property   Microsoft.Azure.Management.Compute.Models.VirtualMachineIdentity Identity {get;set;}                                     
# InstanceView             Property   Microsoft.Azure.Management.Compute.Models.VirtualMachineInstanceView InstanceView {get;set;}                             
# OSProfile.LinuxConfiguration
# OSProfile.Secrets
# OSProfile.WindowsConfiguration.WinRM
# StorageProfile.OSDisk.DiffDiskSettings
# StorageProfile.OSDisk.EncryptionSettings
# StorageProfile.OSDisk.Image
# StorageProfile.OSDisk.Vhd
# StorageProfile.DataDisks
# Plan                     Property   Microsoft.Azure.Management.Compute.Models.Plan Plan {get;set;}                                                           
	$v |% {
		$_.Zones = $_.Zones |% {$_}
	}
	return $v
}

function Get-LwAzVM([string] $Name, [string] $ResourceGroupName, [hashtable] $Resources,
	[switch] $AsObject)
{
	$vm = $null
	if ($Resources -and $Name) {
		$vm = $Resources.VMs[$Name]
	}

	if (-not $vm) {
		$cmd = 'Get-AzVM -EA 0'
		if ($Name) { $cmd += ' -Name $Name'}
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
		$vm = Invoke-Expression $cmd
		if ($Resources -and $vm -and $Name) { $Resources.VMs[$Name] = $vm }
	}
	if ($AsObject)
	{
		return (ReadAzVM $vm)
	}
	return $vm
}

function New-LwAzVM(
	[Parameter(Mandatory=$false, HelpMessage='Name for the virtual machine')] [string] $Name,
	[Parameter(Mandatory=$true, HelpMessage='Region for a network interface')] [string] $Location,
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group in which to create a public IP address')] [string] $ResourceGroupName, 
	[Parameter(Mandatory=$false, HelpMessage='Size for the virtual machine')] [string] $Size,
	[Parameter(Mandatory=$false, HelpMessage='ID of an availability set. To obtain an availability set object, use the Get-AzAvailabilitySet cmdlet. The availability set object contains an ID property')] [string] $AvailabilitySetId,
	[Parameter(Mandatory=$false, HelpMessage='The license type, which is for bringing your own license scenario')] [string] $LicenseType,
	[Parameter(Mandatory=$false, HelpMessage='The tags attached to the resource')] [hashtable] $Tags,
	[Parameter(Mandatory=$false, HelpMessage='the availability zone list for the virtual machine. The allowed values depend on the capabilities of the region. Allowed values will normally be 1,2,3')] [string[]] $Zone,
	[Parameter(Mandatory=$false, HelpMessage='Enables a capability to have one or more managed data disks with UltraSSD_LRS storage account type on the VM. Managed disks with storage account type UltraSSD_LRS can be added to a virtual machine only if this property is enabled')] [bool] $EnableUltraSSD,
	[Parameter(Mandatory=$false, HelpMessage='Operating system')] [ValidateSet('Windows', 'Linux')] [string] $OS = 'Windows',
	[Parameter(Mandatory=$false, HelpMessage='ComputerName')] [string] $ComputerName,
	[Parameter(Mandatory=$false, HelpMessage='Admin user name')] [string] $User,
	[Parameter(Mandatory=$false, HelpMessage='Admin user password')] [string] $Password,
	[Parameter(Mandatory=$false, HelpMessage='This operating system uses HTTP WinRM')] [bool] $WinRMHttp,
	[Parameter(Mandatory=$false, HelpMessage='This operating system uses HTTPS WinRM')] [bool] $WinRMHttps,
	[Parameter(Mandatory=$false, HelpMessage='The name of a publisher of a VMImage. To obtain a publisher, use the Get-AzVMImagePublisher cmdlet.')] [string] $PublisherName = 'MicrosoftWindowsServer',
	[Parameter(Mandatory=$false, HelpMessage='The type of VMImage offer. To obtain an image offer, use the Get-AzVMImageOffer cmdlet.')] [string] $Offer = 'WindowsServer',
	[Parameter(Mandatory=$false, HelpMessage='VMImage SKU. To obtain SKUs, use the Get-AzVMImageSku cmdlet.')] [string] $Skus,
	[Parameter(Mandatory=$false, HelpMessage='Version of a VMImage. To use the latest version, specify a value of latest instead of a particular version')] [string] $Version = 'latest',
	[Parameter(Mandatory=$false, HelpMessage='OS Disk data')] [hashtable] $OSDisk,
	[Parameter(Mandatory=$false, HelpMessage='Enable or disable boot diagnostics')] [nullable[bool]] $BootDiagnostics = $true,
	[Parameter(Mandatory=$false, HelpMessage='Name of the storage account in which to save boot diagnostics data')] [string] $StorageAccountName,
	[Parameter(Mandatory=$false, HelpMessage='Array with Network interfaces')] [hashtable[]] $NetworkInterfaces,
    [hashtable] $Resources,
	[switch] $AsObject
)
{
	$vm = Get-LwAzVM -Name $Name -ResourceGroupName $ResourceGroupName -Resources $Resources
	if (-not $vm)
	{
		$resources = CheckResources $resources

		$cmd = 'New-AzVMConfig'
		if ($Name) { $cmd += ' -VMName $Name'}
		if ($Size) { $cmd += ' -VMSize $Size'}
		if ($AvailabilitySetId) { $cmd += ' -AvailabilitySetId $AvailabilitySetId'}
		if ($LicenseType) { $cmd += ' -LicenseType $LicenseType'}
		if ($Tags) { $cmd += ' -Tags $Tags'}
		if ($Zone) { $cmd += ' -Zone $Zone'}
		if ($EnableUltraSSD) { $cmd += ' -EnableUltraSSD'}
<##
   [-AssignIdentity]
   [-IdentityType] <ResourceIdentityType>
   [-IdentityId <String[]>]
   [-DefaultProfile <IAzureContextContainer>]
##>
		$vm = Invoke-Expression $cmd

		$cred = $null
		$cmd = 'Set-AzVMOperatingSystem -VM $vm'
		if ($User -or $Password) { 
    		$spasswd = ConvertTo-SecureString $Password -AsPlainText -Force
	    	$cred = New-Object System.Management.Automation.PSCredential($User, $spasswd)
			$cmd += ' -Credential $cred'
		}

		if ($OS -eq 'Windows') { $cmd += ' -Windows'}
		if ($OS -eq 'Linux') { $cmd += ' -Linux'}
		if ($ComputerName) { $cmd += ' -ComputerName $ComputerName'}
		if ($WinRMHttp) { $cmd += ' -WinRMHttp'}
		if ($WinRMHttps) { $cmd += ' -WinRMHttps'}
		$vm = Invoke-Expression $cmd
<##
   [[-CustomData] <String>]
   [-ProvisionVMAgent]
   [-DisableVMAgent]
   [-EnableAutoUpdate]
   [-DisablePasswordAuthentication]
   [[-TimeZone] <String>]
   [-WinRMCertificateUrl] <Uri>
   [-DefaultProfile <IAzureContextContainer>]
##>

		$cmd = 'Set-AzVMSourceImage -VM $vm'
		if ($PublisherName) { $cmd += ' -PublisherName $PublisherName'}
		if ($Offer) { $cmd += ' -Offer $Offer'}
		if ($Skus) { $cmd += ' -Skus $Skus'}
		if ($Version) { $cmd += ' -Version $Version'}
<##
   [-Id] <String>
   [-DefaultProfile <IAzureContextContainer>]
##>
		$vm = Invoke-Expression $cmd

		if ($OSDisk)
		{
			$cmd = 'Set-AzVMOSDisk -VM $vm'
			if ($OSDisk.Name) { $cmd += ' -Name $OSDisk.Name'}
			if ($OSDisk.VhdUri) { $cmd += ' -VhdUri $OSDisk.VhdUri'}
			if ($OSDisk.Caching) { $cmd += ' -Caching $OSDisk.Caching'}
			if ($OSDisk.SourceImageUri) { $cmd += ' -SourceImageUri $OSDisk.SourceImageUri'}
			if ($OSDisk.CreateOption) { $cmd += ' -CreateOption $OSDisk.CreateOption'}
			if ($OS -eq 'Windows') { $cmd += ' -Windows'}
			if ($OS -eq 'Linux') { $cmd += ' -Linux'}
			if ($OSDisk.DiskSizeInGB) { $cmd += ' -DiskSizeInGB $OSDisk.DiskSizeInGB'}
			if ($OSDisk.ManagedDiskId) { $cmd += ' -ManagedDiskId $OSDisk.ManagedDiskId'}
			if ($OSDisk.StorageAccountType) { $cmd += ' -StorageAccountType $OSDisk.StorageAccountType'}
			if ($OSDisk.WriteAccelerator) { $cmd += ' -WriteAccelerator'}
			if ($OSDisk.DiffDiskSetting) { $cmd += ' -DiffDiskSetting $OSDisk.DiffDiskSetting'}
<##
   [-DiskEncryptionKeyUrl] <String>
   [-DiskEncryptionKeyVaultId] <String>
   [[-KeyEncryptionKeyUrl] <String>]
   [[-KeyEncryptionKeyVaultId] <String>]
   [-DefaultProfile <IAzureContextContainer>]
##>
			$vm = Invoke-Expression $cmd
		}

		if (($BootDiagnostics -ne $null) -or $ResourceGroupName -or $StorageAccountName)
		{
			$cmd = 'Set-AzVMBootDiagnostics -VM $vm'
			if ($BootDiagnostics -ne $null) { if ($BootDiagnostics) { $cmd += ' -Enable'} else { $cmd += ' -Disable' } }
			if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
			if ($StorageAccountName) { $cmd += ' -StorageAccountName $StorageAccountName'}
<## [-DefaultProfile <IAzureContextContainer>] ##>
			$vm = Invoke-Expression $cmd
		}

		$nics = @()
		if ($NetworkInterfaces) {
			$NetworkInterfaces |% {
				$vn = New-LwAzNetworkInterface -Name $_.Name -Location $Location -ResourceGroupName $ResourceGroupName `
					-VirtualNetworkName $_.VirtualNetworkName -SubnetName $_.SubnetName -PublicIpAddressName $_.PublicIpAddressName -NetworkSecurityGroupName $NetworkSecurityGroupName `
					-PrivateIpAddress $_.PrivateIpAddress -InternalDnsNameLabel $_.InternalDnsNameLabel -DnsServer $DnsServer -Tag $Tag -Resources $Resources
				$cmd = 'Add-AzVMNetworkInterface -VM $vm -ID $vn.Id'
				if ($_.Primary) { $cmd += ' -Primary'}
				$vm = Invoke-Expression $cmd	
			}
		}

		$cmd = 'New-AzVM -VM $vm'
		if ($ResourceGroupName) { $cmd += ' -ResourceGroupName $ResourceGroupName'}
		if ($Location) { $cmd += ' -Location $Location'}
		$vm = Invoke-Expression $cmd	

    	$vm = Get-AzVM -Name $Name -ResourceGroupName $ResourceGroupName
		if ($Resources -and $vm -and $Name) { $Resources.VMs[$Name] = $vm }
	}

	if ($AsObject)
	{
		return (ReadAzVM $vm)
	}
	return $vm
}


function New-AzLwResources(
	[Parameter(Mandatory=$true, HelpMessage='Region')] [string] $Location,
	[Parameter(Mandatory=$true, HelpMessage='Name of the resource group')] [string] $ResourceGroupName, 
	[Parameter(Mandatory=$false, HelpMessage='Name of the storage account')] [string] $StorageAccountName,
	[ValidateSet('Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_RAGRS', 'Premium_LRS')] [string] $SkuName = 'Standard_LRS',
    [hashtable[]] $SecurityGroups,
    [hashtable[]] $VirtualNetworks,
    [hashtable[]] $IPAddresses,
    [hashtable[]] $VMs,
	[switch] $AsObject)
{
	$resources = CheckResources $null

    $res = @{}
	if ($ResourceGroupName) {
		$res.ResourceGroups = @{}
		$res.ResourceGroups[$ResourceGroupName] = New-LwAzResourceGroup -Name $ResourceGroupName -Location $Location -Resources $resources -AsObject:$AsObject
	}

	if ($StorageAccountName) {
		$res.StorageAccounts = @{}
		$res.StorageAccounts[$StorageAccountName] = New-LwAzStorageAccount -Name $StorageAccountName `
			-Location $Location -ResourceGroupName $ResourceGroupName -SkuName $SkuName -Resources $resources -AsObject:$AsObject
	}

	if ($SecurityGroups) {
		$res.SecurityGroups = @{}
		$SecurityGroups |% { $res.SecurityGroups[$_.Name] = New-LwAzNetworkSecurityGroup -Name $_.Name -Location $Location `
			-ResourceGroupName $ResourceGroupName -SecurityRules $_.Rules -Tag $_.Tag -Resources $resources -AsObject:$AsObject }
	}

	if ($VirtualNetworks) {
		$res.VirtualNetworks = @{}
		$VirtualNetworks |% { $res.VirtualNetworks[$_.Name] = New-LwAzVirtualNetwork -Name $_.Name `
				-Location $Location -ResourceGroupName $ResourceGroupName `
				-AddressPrefix $_.AddressPrefix -Subnets $_.Subnets -Resources $resources -AsObject:$AsObject
		}
	}

	if ($IPAddresses) {
		$res.PublicIpAddresses = @{}
		$IPAddresses |% { $res.PublicIpAddresses[$_.Name] = New-LwAzPublicIpAddress -Name $_.Name -Location $Location -ResourceGroupName $ResourceGroupName `
				-AllocationMethod $_.AllocationMethod -IdleTimeoutInMinutes $_.IdleTimeoutInMinutes -Resources $resources -AsObject:$AsObject
		}
	}

	if ($VMs) {
		$res.VMs = @{}
		$VMs |% { $res.VMs[$_.Name] = New-LwAzVM -ResourceGroupName $ResourceGroupName -Location $Location -Name $_.Name -Size $_.Size `
				-OS $_.OS -ComputerName $_.ComputerName -User $_.User -Password $_.Password `
				-PublisherName $_.PublisherName -Offer $_.Offer -Skus $_.Skus -OSDisk $_.OSDisk `
				-StorageAccountName $StorageAccountName -NetworkInterfaces $_.NetworkInterfaces -Resources $resources -AsObject:$AsObject
		}
	}

	return $res
}

Export-ModuleMember -Function Login-LwAzureAccount, Login-LwAzureAD, Login-LwAzureADToken, New-LwAzureServicePrincipalPassword, New-LwAzureServicePrincipalCertificate, New-LwSelfSignedCertificate, Get-LwCertificateData,`
	Get-LwAzureUser, New-LwAzUser, New-LwAzureUser, Update-LwAzureUser, Enable-LwAzUser, Set-LwAzUserPassword, Remove-LwAzUser,`
	Get-LwAzureGroup, New-LwAzureGroup, Update-LwAzureGroup, Remove-LwAzureGroup,`
	Get-LwAzureDevice, New-LwAzureDevice, Remove-LwAzureDevice, Get-LwAzureGroupMember, Add-LwAzureGroupMember, Remove-LwAzureGroupMember,`
	Get-LwAzResourceGroup, New-LwAzResourceGroup, Get-LwAzStorageAccount, New-LwAzStorageAccount, New-LwAzNetworkSecurityRuleConfig, Get-LwAzNetworkSecurityGroup, New-LwAzNetworkSecurityGroup, New-LwAzVirtualNetworkSubnetConfig, Get-LwAzVirtualNetwork, New-LwAzVirtualNetwork, Get-LwAzPublicIpAddress, New-LwAzPublicIpAddress, Get-LwAzNetworkInterface, New-LwAzNetworkInterface, Get-LwAzVM, New-LwAzVM, New-AzLwResources