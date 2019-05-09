param([guid] $TenantId, [string] $Command, [hashtable] $Params)

Import-Module (Join-Path $PSScriptRoot .\API\LwUtility) -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot .\API\LwSQL) -Force -DisableNameChecking

function Get-AppSettings
{
	$apps = Get-Content (Join-Path $PSScriptRoot .\AppSettings.json) | ConvertFrom-Json
	$global:AppSettings = @{ }
	$apps.PSObject.Properties |% { $global:AppSettings[$_.Name] = $_.Value }
	if ($global:AppSettings.Interval) { $global:AppSettings.Interval = [int]$global:AppSettings.Interval } else { $global:AppSettings.Interval = 10 }
}

function Insert-LwQueueRow([string] $Command, [string] $Params)
{
	$SqlCmd = Get-LwSQLCommand -ConnectionString $global:AppSettings.ConnectionString `
		-Command 'INSERT INTO [dbo].[Queue] (RequestID, TenantId, Command, Params) VALUES (@RequestID, @TenantId, @Command, @Params)'

    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@RequestID",[Data.SQLDBType]::NVarChar, 50)))
    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@TenantId",[Data.SQLDBType]::NVarChar, 50)))
    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@Command",[Data.SQLDBType]::NVarChar, 50)))
    $out = $SqlCmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@Params",[Data.SQLDBType]::NVarChar, -1)))

    $SqlCmd.Parameters[0].Value = [guid]::NewGuid().ToString()
    $SqlCmd.Parameters[1].Value = $TenantId.ToString()
    $SqlCmd.Parameters[2].Value = $Command
	if ($Params)
	{
	    $SqlCmd.Parameters[3].Value = $Params
	}
	else
	{
	    $SqlCmd.Parameters[3].Value = [DBNull]::Value
	}
	$out = $SqlCmd.ExecuteNonQuery()
}


##################################################
Get-AppSettings

$json = $null
if ($Params)
{
	$json = ConvertTo-Json -Depth 10 -Compress -InputObject $Params
}
Insert-LwQueueRow $Command $json
