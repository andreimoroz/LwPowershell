# Status: 0-NotProcessed, 1-Processed, 2-Error, 3-Processing

# https://partner.microsoft.com/de-de/pcv/customers/1591d20e-e0bd-4d42-b220-44fa0c3d5806/users
#  dbadmin@andreimorozhotmail.onmicrosoft.com Passw0rd!  Bopo9275
# dbadmin@thomasschmitzlogiway.onmicrosoft.com s52fG6!Av
# Server=tcp:psqueue.database.windows.net,1433;Initial Catalog=PSQueue;Persist Security Info=False;User ID=dbadmin;Password=s52fG6!Av;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
# Server: psqueue.database.windows.net
# User: dbadmin
# Password: s52fG6!Av

# DB: PSQueue

Import-Module (Join-Path $PSScriptRoot .\API\LwUtility) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwAuth) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwSQL) -Force -DisableNameChecking

function Get-AppSettings
{
	$apps = Get-Content (Join-Path $PSScriptRoot .\AppSettings.json) | ConvertFrom-Json
	$global:AppSettings = @{ }
	$apps.PSObject.Properties |% { $global:AppSettings[$_.Name] = $_.Value }
	if ($global:AppSettings.Interval) { $global:AppSettings.Interval = [int]$global:AppSettings.Interval } else { $global:AppSettings.Interval = 10 }
}

function Get-LwQueueRows
{
	$PackageId = [guid]::NewGuid().ToString()
	$Command = "UPDATE q SET [PackageId]=@PackageID, [Status]=3 " +
		"FROM [dbo].[Queue] q " +
		"WHERE q.Status = 0 AND (q.AllowParallel = 1 OR NOT EXISTS " +
		"(SELECT ID FROM [dbo].[Queue] AS q2 WHERE (Status=0 OR Status=3) AND q2.AllowParallel=0 AND q.TenantID=q2.TenantID AND q.CreatedTime < q2.CreatedTime)); " +
	"SELECT * FROM [dbo].[Queue] WHERE PackageId=@PackageID"
	$SqlCmd = Get-LwSQLCommand -ConnectionString $global:AppSettings.ConnectionString -Command $Command

	# Bind Parameter
	$out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@PackageID",[Data.SQLDBType]::NVarChar, 50)))
	$SqlCmd.Parameters[0].Value = $PackageId

	$Table = Get-LwSQLDataSet -SqlCmd $SqlCmd
	return $Table
}

function Update-LwQueueRow([int] $ID, [int] $Status, [string] $Response)
{
	$SqlCmd = Get-LwSQLCommand -ConnectionString $global:AppSettings.ConnectionString `
		-Command 'UPDATE dbo.Queue SET Status=@Status, Response=@Response, ProcessedTime=(GetDate()) WHERE ID=@ID'

    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@ID",[Data.SQLDBType]::Int)))
    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@Status",[Data.SQLDBType]::Int)))
    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@Response",[Data.SQLDBType]::NVarChar, -1)))

    $SqlCmd.Parameters[0].Value = $ID
    $SqlCmd.Parameters[1].Value = $Status
	if ($Response)
	{
	    $SqlCmd.Parameters[2].Value = $Response
	}
	else
	{
	    $SqlCmd.Parameters[2].Value = [DBNull]::Value
	}
	$out = $SqlCmd.ExecuteNonQuery()
}


##################################################
Get-AppSettings

while ($true)
{
	$tb = Get-Date
	$rs = Get-LwQueueRows
	$rs |% {
		$q = $_
		Write-Host "ID=$($q.ID) RequestID=$($q.RequestID) TenantId=$($q.TenantId) Command=$($q.Command) Params=$($q.Params)"

		$cmd = """$(Join-Path $PSScriptRoot '.\Invoke-LwQueueTask.ps1')"" -Id $($q.Id) -TenantId '$($q.TenantId)' -Command '$($q.Command)' -Params '$(Get-EncodedString $q.Params)' -Encoded -AsJson -Compress"
		$out = Start-Job -ScriptBlock { powershell.exe $args[0] } -ArgumentList $cmd
	}

	# Sleep
	$td = $global:AppSettings.Interval - ((Get-Date)-$tb).TotalSeconds
	if ($td -gt 0)
	{
		Write-Host "Sleep $td seconds"
		Sleep -Seconds $td
	}
}
