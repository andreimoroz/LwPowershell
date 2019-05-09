function Get-LwSQLCommand([string] $ConnectionString, [string] $Command)
{
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlConnection.ConnectionString = $ConnectionString
	$SqlConnection.Open()

	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.Connection = $SqlConnection
	$SqlCmd.CommandText = $command
	return $SqlCmd
}


function Get-LwSQLDataSet([string] $ConnectionString, [string] $Command, $SqlCmd)
{
	if (-not $SqlCmd)
	{
		$SqlCmd = Get-LwSQLCommand $ConnectionString $Command
	}

	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd
	$DataSet = New-Object System.Data.DataSet
	$out = $SqlAdapter.Fill($DataSet)
	return $DataSet.Tables[0]
}

Export-ModuleMember -Function Get-LwSQLCommand, Get-LwSQLDataSet