Import-Module (Join-Path $PSScriptRoot ..\LwUtility) -Global
$global:Tenants = @{}
$global:PersonalSites = @{}

function Get-LwAuthInfo([guid] $TenantId)
{
#	if ($tenantId -eq '698e87df-9f6c-451b-acfd-09fd709efd86')
#	{
#		return @{ TenantId = '698e87df-9f6c-451b-acfd-09fd709efd86'; DomainName = 'logiwayeu';`
#			AdminUser = 'cloudadmin@logiwayeu.onmicrosoft.com'; AdminPassword = 'Vab0!240EUA';`
#			AppId = '6a86542a-2144-43ce-a5e1-50f135ccc7aa'; AppPassword = 'Passw0rd!' }
#	}

	$res = $global:Tenants[$TenantId]
	if ($res) { return $res }

	Import-Module (Join-Path $PSScriptRoot ..\LwSQL) -DisableNameChecking -Global
	$ds = Get-LwSQLDataSet -ConnectionString $global:AppSettings.ConnectionString `
		-Command 'SELECT TenantId, DomainName, AdminUser, AdminPassword, AppId, AppPassword FROM [dbo].[Tenants]'
	$ds |% {
		$tId = [guid]$_.TenantId
		$global:Tenants[$tId] = @{ TenantId = $_.TenantId; DomainName = Get-DBValue $_.DomainName;`
			AdminUser = Get-DBValue $_.AdminUser; AdminPassword = Get-DBValue $_.AdminPassword; AppId = Get-DBValue $_.AppId; AppPassword = Get-DBValue $_.AppPassword }
	}

	$res = $global:Tenants[$TenantId]
	if (-not $res)
	{
		throw 'Unknown tenant'
	}

	return $res
}

#	if ($authInfo.DomainName -eq 'logiwayeu')
#	{
#		if ($User -eq 'cloudadmin@logiwayeu.onmicrosoft.com')
#		{
#			return 'https://logiwayeu-my.sharepoint.com/personal/cloudadmin_logiwayeu_onmicrosoft_com'
#		}
#	}	


function Get-LwPersonalSiteUrlForUser($authInfo, [string] $User, $conn)
{
	$ID = '' + $authInfo.TenantId + '_' + $User
	$res = $global:PersonalSites[$ID]
	if ($res) { return $res }

	# read from DB
	Import-Module (Join-Path $PSScriptRoot ..\LwSQL) -DisableNameChecking -Global
	$ds = Get-LwSQLDataSet -ConnectionString $global:AppSettings.ConnectionString `
		-Command "SELECT URL FROM [dbo].[PersonalSites] WHERE TenantId='$($authInfo.TenantId)' AND UPN='$User'"
	if ($ds)
	{
		$global:PersonalSites[$ID] = $ds.Url
		return $global:PersonalSites[$ID]
	}

	Import-Module (Join-Path $PSScriptRoot ..\LwSPO) -DisableNameChecking
	if ((-not $authInfo.AdminUser) -or -not ($authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
	Login-LwSPO -OrgaName $authInfo.DomainName -User $authInfo.AdminUser -Password $authInfo.AdminPassword
	if ($conn)
	{
		$conn['SPO'] = $true
	}
	$site = Get-LwSPOPersonalSiteForUser -UPN $User
	if (-not $site) { throw "Unknown user '$User'" }

	$SqlCmd = Get-LwSQLCommand -ConnectionString $global:AppSettings.ConnectionString `
		-Command "INSERT INTO [dbo].[PersonalSites] (TenantId, UPN, URL) VALUES ('$($authInfo.TenantId)', '$User', '$($site.Url)')"
	$out = $SqlCmd.ExecuteNonQuery()

	$global:PersonalSites[$ID] = $site.Url
	return $global:PersonalSites[$ID]
}

function Login-LwAzure(
	[Parameter(Mandatory=$true, HelpMessage='Tenant Identity')] [guid] $TenantId,
	[Parameter(Mandatory=$false, HelpMessage='Login to Az')] [switch] $Account,
	[Parameter(Mandatory=$false, HelpMessage='Login to Azure AD')] [switch] $AD, 
	[Parameter(Mandatory=$false, HelpMessage='Login to PnP')] [switch] $PnP,
	[Parameter(Mandatory=$false, HelpMessage='Login to SPO')] [switch] $SPO,
	[Parameter(Mandatory=$false, HelpMessage='Site url')] [string] $SiteURL,
	[Parameter(Mandatory=$false, HelpMessage='Personal site identity')] [string] $User,
	[Parameter(Mandatory=$false, HelpMessage='Login to Msol')] [switch] $Msol,
	[Parameter(Mandatory=$false, HelpMessage='Login to Office365')] [switch] $Office365,
	[Parameter(Mandatory=$false, HelpMessage='Login to Intune')] [switch] $Intune)
{
	$authInfo = Get-LwAuthInfo $TenantId
	$conn = @{ TenantId = $authInfo.TenantId ; DomainName = $authInfo.DomainName }
	if ($Account -or $AD)
	{
		Import-Module (Join-Path $PSScriptRoot ..\LwAzure) -DisableNameChecking -Global
		if ($authInfo.AppId -and $authInfo.AppPassword) { 
			$conn['Account'] = Login-LwAzureAccount -TenantId $authInfo.TenantId -User $authInfo.AppId -Password $authInfo.AppPassword -ServicePrincipal
		}
		else {
			if ((-not $authInfo.AdminUser) -or (-not $authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
			$conn['Account'] = Login-LwAzureAccount -TenantId $authInfo.TenantId -User $authInfo.AdminUser -Password $authInfo.AdminPassword
		}
	}
	if ($AD)
	{
		$conn['AD'] = Login-LwAzureADToken
	}
	if ($Intune)
	{
		if ((-not $authInfo.AdminUser) -or (-not $authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
		Import-Module (Join-Path $PSScriptRoot ..\LwIntune) -DisableNameChecking -Global
		$conn['Intune'] = Login-LwIntune -User $authInfo.AdminUser -Password $authInfo.AdminPassword
	}
	if ($SPO)
	{
		if ((-not $authInfo.AdminUser) -or (-not $authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
		Import-Module (Join-Path $PSScriptRoot ..\LwSPO) -DisableNameChecking -Global
		Login-LwSPO -OrgaName $authInfo.DomainName -User $authInfo.AdminUser -Password $authInfo.AdminPassword
		$conn['SPO'] = $true
	}
	if ($PnP)
	{
		if ((-not $authInfo.AdminUser) -or (-not $authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
		Import-Module (Join-Path $PSScriptRoot ..\LwPnP) -DisableNameChecking -Global
		if (-not $SiteURL)
		{
			$SiteUrl = Get-LwPersonalSiteUrlForUser $authInfo $User $conn
		}

		$conn['PnP'] = Login-LwPnP -Url $siteUrl -User $authInfo.AdminUser -Password $authInfo.AdminPassword
	}
	if ($Msol)
	{
		if ((-not $authInfo.AdminUser) -or (-not $authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
		Import-Module (Join-Path $PSScriptRoot ..\LwMsol) -DisableNameChecking -Global
		$conn['Msol'] = Login-LwMsol -User $authInfo.AdminUser -Password $authInfo.AdminPassword
	}
	if ($Office365)
	{
		if ((-not $authInfo.AdminUser) -or (-not $authInfo.AdminPassword)) { throw 'Admin credentials are not provided' }
		Import-Module (Join-Path $PSScriptRoot ..\LwOffice365) -DisableNameChecking -Global
		$conn['Office365'] = Login-LwOffice365 -User $authInfo.AdminUser -Password $authInfo.AdminPassword
	}
	return $conn
}

Export-ModuleMember -Function Get-LwAuthInfo, Get-LwPersonalSiteUrlForUser, Login-LwAzure