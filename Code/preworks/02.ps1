$TenantId = '3b811c12-df4a-41b3-834a-5b9420089c1b'
$AdminUser = 'admin@thomasschmitzlogiway.onmicrosoft.com'
$AdminPassword = 'Wasser9!'
$AppName = 'PSAzureSP'
$AppPassword = 'Passw0rd!'

###################################################################################
# Create Service Account


Import-Module .\API\LwAzure.ps1 -Force

# login interactively
Login-LwAzureAccount -TenantId $TenantId -User $AdminUser -Password $AdminPassword
Login-LwAzureAD -TenantId $TenantId

$sp = New-LwAzureServicePrincipalPassword -Name $AppName -Password $AppPassword -RoleName 'Company Administrator'
Write-Host "AppId: $($sp.ApplicationId)"
Write-Host "ObjectId: $($sp.Id)"

# AppId: 6a86542a-2144-43ce-a5e1-50f135ccc7aa
# ObjectId: 6ab1a802-172d-42a6-814a-1867055d9a7b

# Test Login
Login-LwAzureAccount -TenantId $TenantId -User $sp.ApplicationId -Password $AppPassword -ServicePrincipal
###################################################################################

# $AppId = '6a86542a-2144-43ce-a5e1-50f135ccc7aa'