param([int] $Id,
	[guid] $TenantId,
	[string] $Command,
	$Params)

function Get-AppSettings
{
	$apps = Get-Content (Join-Path $PSScriptRoot .\AppSettings.json) | ConvertFrom-Json
	$global:AppSettings = @{ }
	$apps.PSObject.Properties |% { $global:AppSettings[$_.Name] = $_.Value }
	if ($global:AppSettings.Interval) { $global:AppSettings.Interval = [int]$global:AppSettings.Interval } else { $global:AppSettings.Interval = 10 }
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

Import-Module (Join-Path $PSScriptRoot .\API\LwUtility) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwAuth) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwSQL) -Force -DisableNameChecking

Get-AppSettings
# $job  = start-job { get-childitem c:\andy -recurse |% { Write-Host $_ } }

$Status = 2
$Response = $null
$res = $null
try {
	$Response = . (Join-Path $PSScriptRoot '.\Invoke-LwCommand.ps1') -TenantId $TenantId -Command $Command -Params $Params -Encoded -AsJson -Compress
	$res = ConvertFrom-Json -InputObject $Response
	if ($res.Success -eq 'true') { $Status = 1 }
}
catch {
	if (-not $res) { $res = @{} }
	$res.Success = $false
	if (-not $res.Exception) {
	try
	{
		$res.Exception = SerializeException $_.Exception
		$Response = ConvertTo-Json -Depth 10 -InputObject $res -Compress:$true
	}
	catch { } }
}

Update-LwQueueRow $ID $Status $Response
