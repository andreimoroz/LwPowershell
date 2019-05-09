############################
# OneDrive

$tenantId = '698e87df-9f6c-451b-acfd-09fd709efd86'
$User = 'cloudadmin@logiwayeu.onmicrosoft.com'
#$Password = 'Vab0!240EUA'
#$SiteUrl = 'https://logiwayeu-my.sharepoint.com/personal/cloudadmin_logiwayeu_onmicrosoft_com'

# Other functions
Import-Module .\API\LwUtility.ps1 -Force
Import-Module .\API\LwPnP.ps1 -Force

# Connect to SPO
$conn = Login-LwPnP -Url $SiteUrl -User $User -Password $Password

# Get Site
$site = Get-PnPSite

# Get Web
$web = Get-PnPWeb

# All lists
Get-PnPList

$list = Get-PnPList -Identity 'Documents'
$rootFolderUrl = $list.RootFolder.ServerRelativeUrl

# Read folder permissions
$folder = Get-PnPFolder -Url "$rootFolderUrl/Test-Folder" -Includes ListItemAllFields.RoleAssignments, ListItemAllFields.HasUniqueRoleAssignments

Break-LwRoleInheritance $folder.ListItemAllFields

$folder = Get-PnPFolder -Url "$rootFolderUrl/Test-Folder" -Includes ListItemAllFields.RoleAssignments, ListItemAllFields.HasUniqueRoleAssignments
Get-LwObjectRoleAssignments $folder.ListItemAllFields

# Grant new permission
$user = Get-LwUser -Identity 'test@logiway.eu' -Web $web
Add-LwObjectRoleAssignment $folder.ListItemAllFields $user 'Read'

# Re-read folder
$folder = Get-PnPFolder -Url "$rootFolderUrl/Test-Folder" -Includes ListItemAllFields.RoleAssignments, ListItemAllFields.HasUniqueRoleAssignments

# Remove permisson
Remove-LwObjectRoleAssignment $folder.ListItemAllFields $user 'Read'

######################

# Read folder as items
Get-PnPFolderItem -FolderSiteRelativeUrl 'Documents'

# Get specific FolderItem
$item = Get-PnPFolderItem -FolderSiteRelativeUrl 'Documents' -ItemName 'todo-admin.txt'

$file = Get-PnPFile -Url '/personal/cloudadmin_logiwayeu_onmicrosoft_com/Documents/todo-admin.txt' -AsListItem
Get-PnPProperty -ClientObject $file -Property HasUniqueRoleAssignments, RoleAssignments
Get-LwObjectRoleAssignments $file

# Break inheritance
Break-LwRoleInheritance $file
Get-PnPProperty -ClientObject $file -Property HasUniqueRoleAssignments, RoleAssignments
Get-LwObjectRoleAssignments $file

# Create new group
$group = New-PnPGroup -Web $web -Title 'Group1'

# ========================
$rootFolderUrl = $list.RootFolder.ServerRelativeUrl
$folder = Get-PnPFolder -Url "$rootFolderUrl/Documents" -Includes ListItemAllFields.RoleAssignments, ListItemAllFields.HasUniqueRoleAssignments



$SiteUrl = 'https://logiwayeu-my.sharepoint.com/personal/test_logiway_eu'

########################################################################################

Import-Module .\API\LwAuth -DisableNameChecking

Login-LwSPO -OrgaName $OrgaName -User $User -Password $Password


# TODO
$ctx = New-Object Microsoft.SharePoint.Client.ClientContext($url)

# Get Sites
Get-SPOSite -IncludePersonalSite $true

# Get Sites
Get-SPOSite -IncludePersonalSite $true -Limit all -Filter "Url -like '-my.sharepoint.com/personal/' -and Owner -eq $upn"

# Get site of specific user
$upn = 'test@logiway.eu'
Get-SPOSite -IncludePersonalSite $true -Limit all -Filter { $_.Owner -eq $upn }
Get-SPOSite -IncludePersonalSite $true -Limit all -Filter "Url -like '-my.sharepoint.com/personal/'"

################################

