$tenantId = '698e87df-9f6c-451b-acfd-09fd709efd86'
$User = 'cloudadmin@logiwayeu.onmicrosoft.com'
$Password = 'Vab0!240EUA'
$SiteUrl = 'https://logiwayeu.sharepoint.com/sites/AMTest'
$UPN = 'test@logiway.eu'
#$OrgaName = 'logiwayeu'
#$AppId = '6a86542a-2144-43ce-a5e1-50f135ccc7aa'
#$Password = 'Passw0rd!'

Import-Module .\API\LwUtility -Force -DisableNameChecking
Import-Module .\API\LwAzure -Force -DisableNameChecking
Import-Module .\API\LwIntune -Force -DisableNameChecking
Import-Module .\API\LwAuth -Force -DisableNameChecking


################################################
# MS 365 Users Report

.\Invoke-LwCommand.ps1 -Command 'Get-LwMsolUsersReport' -AsJson `
	-TenantId $tenantId -Params @{ }

.\Enqueue.ps1 -Command 'Get-LwMsolUsersReport' -AsJson `
	-TenantId $tenantId -Params @{ }

################################################
# Azure AD Users

.\Invoke-LwCommand.ps1 -Command 'New-LwAzureUser' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'John Smith'; Password = 'Passw0rd!'; UPN = 'john_smith@logiway.eu' }

.\Invoke-LwCommand.ps1 -Command 'Get-LwAzureUser' -AsJson `
	-TenantId $tenantId -Params @{ UPN = 'john_smith@logiway.eu' }


.\Invoke-LwCommand.ps1 -Command 'Update-LwAzureUser' -AsJson `
	-Params @{ TenantId = '698e87df-9f6c-451b-acfd-09fd709efd86'; UPN = 'john_smith@logiway.eu'; DisplayName = 'John Smith 5' }

###
.\Invoke-LwCommand.ps1 -Command 'Set-LwAzUserPassword' -AsJson `
	-TenantId $tenantId -Params @{ UPN = 'john_smith@logiway.eu'; Password = 'Hu7#kl0!d' }

.\Invoke-LwCommand.ps1 -Command 'Enable-LwAzUser' -AsJson `
	-TenantId $tenantId -Params @{ UPN = 'john_smith@logiway.eu'; Enabled = $true }

.\Invoke-LwCommand.ps1 -Command 'Remove-LwAzureUser' -AsJson `
	-TenantId $tenantId -Params @{ UPN = 'john_smith@logiway.eu' }


.\Invoke-LwCommand.ps1 -Command 'New-LwAzureGroup' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'TestGroup'; Description = 'PowerShell Tests'; `
		MailEnabled = $false ; MailNickName = 'sample' ; SecurityEnabled = $true }
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzureGroup' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'TestGroup' }
.\Invoke-LwCommand.ps1 -Command 'Remove-LwAzureGroup' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = '12f8f41f-c479-4798-b623-e50b457f97f9' }

.\Invoke-LwCommand.ps1 -Command 'Get-LwAzureGroup' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0' }
.\Invoke-LwCommand.ps1 -Command 'Update-LwAzureGroup' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0'; DisplayName = 'SecGroup2' }


.\Invoke-LwCommand.ps1 -Command 'Get-LwAzureDevice' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = 'a9582f31-12b4-402d-b5f6-f64e504e986d' }
.\Invoke-LwCommand.ps1 -Command 'Get-LwAzureDevice' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'VM10Logiway' }


.\Invoke-LwCommand.ps1 -Command 'New-LwAzureDevice' -AsJson `
	-Params @{TenantId = $tenantId; DisplayName = 'ANDREI-W540'; DeviceId = 'd224105d-5f46-4fd4-954a-2bb0c6e303d8'; DeviceOSType = 'Windows'; DeviceOSVersion = '10.0.17134.0';`
	DeviceObjectVersion = 2; AccountEnabled = $true; DeviceTrustType = 'Workplace';`
	AlternativeSecurityIds = @(@{ Type = 2; Key = @(88, 0, 53, 0, 48, 0, 57, 0, 58, 0, 60, 0, 83, 0, 72, 0, 65, 0, 49, 0, 45, 0, 84, 0, 80, 0, 45, 0, 80, 0, 85, 0, 66, 0, 75, 0, 69, 0, 89, 0, 62, 0, 69, 0, 49, 0, 48, 0, 67, 0, 51, 0, 52, 0, 54, 0, 68, 0, 66, 0, 52, 0, 68, 0, 50, 0, 52, 0, 53, 0, 54, 0, 52, 0, 51, 0, 48, 0, 65, 0, 55, 0, 67, 0, 69, 0, 51, 0, 67, 0, 55, 0, 57, 0, 57, 0, 68, 0, 65, 0, 48, 0, 68, 0, 51, 0, 49, 0, 68, 0, 53, 0, 65, 0, 68, 0, 54, 0, 53, 0, 65, 0, 73, 0, 116, 0, 116, 0, 106, 0, 117, 0, 76, 0, 117, 0, 116, 0, 88, 0, 103, 0, 87, 0, 78, 0, 113, 0, 81, 0, 72, 0, 108, 0, 78, 0, 106, 0, 106, 0, 88, 0, 69, 0, 84, 0, 86, 0, 76, 0, 50, 0, 84, 0, 115, 0, 120, 0, 120, 0, 48, 0, 114, 0, 114, 0, 105, 0, 69, 0, 75, 0, 89, 0, 115, 0, 88, 0, 68, 0, 99, 0, 43, 0, 90, 0, 52, 0, 61, 0)});`
	DevicePhysicalIds = @('[USER-GID]:a4b7ab35-8a83-4102-b773-6c4f63b54448:6825773979753362', '[GID]:g:6825773979753362', '[USER-HWID]:a4b7ab35-8a83-4102-b773-6c4f63b54448:6755410885010397', '[HWID]:h:6755410885010397')}

$ObjectId = (Get-AzureADDevice -Filter "DisplayName eq 'ANDREI-W540'").ObjectId
.\Invoke-LwCommand.ps1 -Command 'Remove-LwAzureDevice' -AsJson `
	-Params @{TenantId = $tenantId; ObjectId = $ObjectId }

.\Invoke-LwCommand.ps1 -Command 'Get-LwAzureGroupMember' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = '9c419ace-5faa-4b80-b29f-af0bae8cda4d' }
.\Invoke-LwCommand.ps1 -Command 'Add-LwAzureGroupMember' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = '9c419ace-5faa-4b80-b29f-af0bae8cda4d'; RefObjectId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0' }
.\Invoke-LwCommand.ps1 -Command 'Remove-LwAzureGroupMember' -AsJson `
	-TenantId $tenantId -Params @{ ObjectId = '9c419ace-5faa-4b80-b29f-af0bae8cda4d'; MemberId = '5e7134d8-4edd-4cfe-a21f-585b0f4ed6d0' }

################################################
# SharePoint Sites

.\Invoke-LwCommand.ps1 -Command 'Get-LwSPOPersonalSiteForUser' -AsJson `
	-TenantId $tenantId -Params @{ UPN = $UPN }

# Create site collection
.\Invoke-LwCommand.ps1 -Command 'New-LwSPOSite' -AsJson `
	-TenantId $tenantId -Params @{ Url = $SiteUrl;
	 Owner = $User; StorageQuota = 1000; Template = 'STS#3'}

# Get site collection
.\Invoke-LwCommand.ps1 -Command 'Get-LwSPOSite' -AsJson `
	-TenantId $tenantId -Params @{ Url = $SiteUrl}

# Delete site collection
.\Invoke-LwCommand.ps1 -Command 'Remove-LwSPOSite' -AsJson `
	-TenantId $tenantId -Params @{ Url = $SiteUrl; Permanently = $true}


################################################
# SharePoint File Management

# Create Folder
.\Invoke-LwCommand.ps1 -Command 'Add-LwPnpFolder' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Folder = 'Freigegebene Dokumente'; Name = 'Test-Folder'}

$file = .\Invoke-LwCommand.ps1 -Command 'Add-LwPnpFile' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Path = '.\Test-LwPnPOneDrive.ps1'; Folder = 'Freigegebene Dokumente'; NewFileName = 'Test-LwPnPNew1.ps1';`
	 Checkout = $true; CheckInComment = 'CheckIn: Uploaded by PowerShell'}
$file

# Break inheritance on folder
.\Invoke-LwCommand.ps1 -Command 'Break-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Folder = 'Freigegebene Dokumente/Test-Folder' }
.\Invoke-LwCommand.ps1 -Command 'Reset-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Folder = 'Freigegebene Dokumente/Test-Folder' }

# Break inheritance on file
.\Invoke-LwCommand.ps1 -Command 'Break-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 File = 'Freigegebene Dokumente/Test-LwPnPNew.ps1' }
.\Invoke-LwCommand.ps1 -Command 'Reset-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 File = 'Freigegebene Dokumente/Test-LwPnPNew.ps1' }

# report role assignments
.\Invoke-LwCommand.ps1 -Command 'Get-LwPnPRoleAssignments' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Folder = 'Freigegebene Dokumente/Test-Folder' }

# Grant user rights
.\Invoke-LwCommand.ps1 -Command 'Add-LwPnPRoleAssignment' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Folder = 'Freigegebene Dokumente/Test-Folder';
	 Identity = 'test@logiway.eu'; RoleName = 'Contribute' }
.\Invoke-LwCommand.ps1 -Command 'Remove-LwPnPRoleAssignment' -AsJson `
	-TenantId $tenantId -Params @{ SiteUrl = $SiteUrl;
	 Folder = 'Freigegebene Dokumente/Test-Folder';
	 Identity = 'test@logiway.eu' }


################################################
# OneDrive File Management

# Create Folder
.\Invoke-LwCommand.ps1 -Command 'Add-LwPnpFolder' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;
	 Folder = 'Documents/Test-Folder'; Name = 'Subfolder'}

# Upload file to OneDrive
$file = .\Invoke-LwCommand.ps1 -Command 'Add-LwPnpFile' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;`
	 Path = '.\Test-LwPnPOneDrive.ps1'; Folder = 'Documents'; NewFileName = 'Test-LwPnPNew1.ps1';`
	 Checkout = $true; CheckInComment = 'CheckIn: Uploaded by PowerShell' }
$file

# Break inheritance on folder
.\Invoke-LwCommand.ps1 -Command 'Break-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;`
	 Folder = 'Documents/Test-Folder' }
.\Reset-LwPnPRoleInheritanceScript.ps1 -TenantId $tenantId -User $User `
	-Folder 'Documents/Test-Folder' -AsJson

# Break inheritance on file
.\Invoke-LwCommand.ps1 -Command 'Break-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;`
	 File = 'Documents/todo-admin.txt' }
.\Invoke-LwCommand.ps1 -Command 'Reset-LwPnPRoleInheritance' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;`
	 File = 'Documents/todo-admin.txt' }

# report role assignments
.\Invoke-LwCommand.ps1 -Command 'Get-LwPnPRoleAssignments' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;`
	 Folder = 'Documents/Test-Folder' }

# Grant user rights
.\Invoke-LwCommand.ps1 -Command 'Add-LwPnPRoleAssignment' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;`
	 Folder = 'Documents/Test-Folder'; Identity = 'test@logiway.eu'; RoleName = 'Contribute' }
.\Invoke-LwCommand.ps1 -Command 'Remove-LwPnPRoleAssignment' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;
	 Folder = 'Documents/Test-Folder'; Identity = 'test@logiway.eu' }

# Share File
.\Invoke-LwCommand.ps1 -Command 'Add-LwPnpShare' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;
	 File = 'Documents/share-guest.txt';
	 UPN = 'gen444ral@mail.ru' ; IsGuestUser = $true ; Role = 'Edit' ; SendEmail = $true ;
	 EmailSubject = 'There is a document for you' }

.\Invoke-LwCommand.ps1 -Command 'Add-LwPnpShare' -AsJson `
	-TenantId $tenantId -Params @{ User = $User;
	 File = 'Documents/share-unvalidated.txt';
	 UPN = 'gen444ral@mail.ru' ; IsGuestUser = $false ; Role = 'Edit' ; SendEmail = $true ;
	 EmailSubject = 'There is a document for you' }

################################################
# Office 365

.\Invoke-LwCommand.ps1 -Command 'New-LwOfficeGroup' -AsJson `
	-TenantId $tenantId -Params @{ DisplayName = 'OfGroup1'; Alias='MyMail' }
.\Invoke-LwCommand.ps1 -Command 'Update-LwOfficeGroup' -AsJson `
	-TenantId $tenantId -Params @{ Identity = 'MyMail'; DisplayName = 'OfGroup1A'; AutoSubscribeNewMembers = $false; SubscriptionEnabled = $false }
.\Invoke-LwCommand.ps1 -Command 'Get-LwOfficeGroup' -AsJson `
	-TenantId $tenantId -Params @{ Identity = 'MyMail' }
.\Invoke-LwCommand.ps1 -Command 'Add-LwOfficeGroupMembers' -AsJson `
	-TenantId $tenantId -Params @{ Identity = 'MyMail'; Members=@($UPN); Type='Members' }
.\Invoke-LwCommand.ps1 -Command 'Get-LwOfficeGroupMembers' -AsJson `
	-TenantId $tenantId -Params @{ Identity = 'MyMail'; Type='Members' }
.\Invoke-LwCommand.ps1 -Command 'Remove-LwOfficeGroupMembers' -AsJson `
	-TenantId $tenantId -Params @{ Identity = 'MyMail'; Members=@($UPN); Type='Members' }
.\Invoke-LwCommand.ps1 -Command 'Remove-LwOfficeGroup' -AsJson `
	-TenantId $tenantId -Params @{ Identity = 'MyMail' }
