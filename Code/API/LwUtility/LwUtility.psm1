$global:ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Web

function LwPerform([scriptblock] $_block, [switch] $AsJson, [switch] $Compress)
{
	$_res = @{}
	try
	{
		$result = (. $_block)
		if ($result -ne $null) { $_res.Result = $result }
		$_res.Success = $true
	}
	catch
	{
		$_res.Success = $false
		try
		{
			$_res.Exception = SerializeException $_.Exception $AsJson
		}
		catch { }
	}

	if ($AsJson)
	{
		try {
			$_res = ConvertTo-Json -Depth 10 -InputObject $_res -Compress:$Compress
		}
		catch {
			$_res = ConvertTo-Json -Depth 10 -InputObject @{ Success = $false } -Compress:$Compress
		}
	}

	return $_res
}

function Add-OptionalParam($cmd, $code, $value, $IgnoreEmptyString)
{
	if (($value -eq $null) -or ($IgnoreEmptyString -and ($value -eq '')) -or (($value -is [string]) -and ($value -eq 'DEFAULTVALUE'))) { return $cmd }
	return ($cmd + ' ' + $code)
}

function SerializeProperty([hashtable] $res, [string] $name, $obj)
{
	if ($obj)
	{
		$res[$name] = $obj
	}
}

function SerializeException($ex, [bool] $AsObject)
{
	if (-not $ex) { return $null }
	$res = @{ Message = $ex.Message }

	SerializeProperty $res 'Source' $ex.Source
	if ($ex.TargetSite)
	{
		SerializeProperty $res 'TargetSiteName' $ex.TargetSite.Name
	}
	SerializeProperty $res 'StackTrace' $ex.StackTrace
	SerializeProperty $res 'HResult' $ex.HResult
	SerializeProperty $res 'HelpLink' $ex.HelpLink

	$er = $ex.ErrorRecord
	if ($er)
	{
		SerializeProperty $res 'FullyQualifiedErrorId' $er.FullyQualifiedErrorId
		if ($er.CategoryInfo) { SerializeProperty $res Category $er.CategoryInfo.Category }
		SerializeProperty $res 'ScriptStackTrace' $er.ScriptStackTrace
		$ii = $er.InvocationInfo
		if ($ii)
		{
			SerializeProperty $res 'PositionMessage' $ii.PositionMessage
			SerializeProperty $res 'ScriptName' $ii.ScriptName
			SerializeProperty $res 'ScriptLineNumber' $ii.ScriptLineNumber
			SerializeProperty $res 'OffsetInLine' $ii.OffsetInLine
#			SerializeProperty $res 'MyCommand' $ii.MyCommand
			SerializeProperty $res 'HistoryId' $ii.HistoryId
			SerializeProperty $res 'PSScriptRoot' $ii.PSScriptRoot
			SerializeProperty $res 'PSCommandPath' $ii.PSCommandPath
			SerializeProperty $res 'InvocationName' $ii.InvocationName
			SerializeProperty $res 'PipelineLength' $ii.PipelineLength
			SerializeProperty $res 'PipelinePosition' $ii.PipelinePosition
			SerializeProperty $res 'ExpectingInput' $ii.ExpectingInput
			SerializeProperty $res 'CommandOrigin' $ii.CommandOrigin
			SerializeProperty $res 'DisplayScriptPosition' $ii.DisplayScriptPosition

			if ($ii.MyCommand)
			{
				$mc = $ii.MyCommand
				$rmc = @{}
				$res['MyCommand'] = $rmc
				SerializeProperty $rmc 'CmdletBinding' $mc.CmdletBinding
				SerializeProperty $rmc 'CommandType' $mc.CommandType
				SerializeProperty $rmc 'Definition' $mc.Definition
				SerializeProperty $rmc 'Description' $mc.Description
				SerializeProperty $rmc 'HelpFile' $mc.HelpFile
				SerializeProperty $rmc 'ModuleName' $mc.ModuleName
				SerializeProperty $rmc 'Name' $mc.Name
				SerializeProperty $rmc 'Noun' $mc.Noun
				SerializeProperty $rmc 'Options' $mc.Options
				SerializeProperty $rmc 'OutputType' $mc.OutputType
				SerializeProperty $rmc 'RemotingCapability' $mc.RemotingCapability
				SerializeProperty $rmc 'Source' $mc.Source
				SerializeProperty $rmc 'Verb' $mc.Verb
				SerializeProperty $rmc 'Version' $mc.Version
				SerializeProperty $rmc 'Visibility' $mc.Visibility
			}
		}
	} 

	if ($ex.InnerException)
	{
		$res.InnerException = SerializeException $ex.InnerException $AsObject
	}

	return $res
}

<# 
   .Synopsis
	Joins to parts of a URL to a new URL (e.g. basepath and filename)
   .Parameter url1
    First part of the url
   .Parameter url2
    Second part of the url
#>
function Join-URL(
	[parameter(HelpMessage="First part of the url, e.g. http://mydomain/path")]
	[string]
	[ValidateNotNullOrEmpty()]
	$url1, 
	[parameter(HelpMessage="Second part of the url, e.g. path2/myfile.zip")]
	[string]
	$url2,
	[parameter(HelpMessage="Trim ending slash, default=true")]
	[switch]
	$trimEndSlash
)
{
	$url = $url1
	$url2 = $url2.TrimStart('/')
	if ($url2)
	{
		$url = $url.TrimEnd('/') + '/' + $url2
	}

	if ($trimEndSlash) { $url = $url.TrimEnd('/') }
	return $url
}

function Split-FolderName([Parameter(Mandatory=$true, HelpMessage='Folder name including list identity')] [string] $Folder)
{
	$Folder = $Folder.Replace('\', '/').Trim('/')
	$parts = $Folder -Split '/'
	$listIdentity = $parts[0]
	$fileName = ($parts | Select -Skip 1) -Join '/'
	return New-Object PSObject -Property @{ List = $listIdentity; File = $fileName }
}

function Iif($val1, $val2)
{
	if (($val1 -ne $null) -and ($val1 -ne '')) { return $val1 }
	return $val2
}

function Format-Date([datetime] $date)
{
	if (-not $date) { return $date }
	return [Xml.XmlConvert]::ToString($date, [Xml.XmlDateTimeSerializationMode]::Utc)
}

function Parse-Date($date)
{
	if ($date -is [datetime]) { return $date }
	if ($date -isnot [string]) { return $null }
	
	$d = New-Object DateTime
	if ([datetime]::TryParse($date, [ref]$d)) { return $d }

	if ($date -match '^\\/Date\((?<num>\d{13})\)\\/$')
	{
		return (([datetime]'1/1/1970').AddMilliseconds($Matches.num)).ToLocalTime()
	}

	return $null
}

function Get-ValueFromObject($obj)
{
	if ($obj -is [System.Management.Automation.PSCustomObject])
	{
		$res = @{}
		$obj.PSObject.Properties |% {
			$res[$_.Name] = Get-ValueFromObject $_.Value
		}		
		return $res
	}
	elseif ($obj -is [Object[]])
	{
		$res = @()
		$obj |% { $res += Get-ValueFromObject $_ }		
		return $res
	}
	elseIf ($obj -eq 'null') { return $null }
	elseif ($obj -eq 'false') { return $false }
	elseif ($obj -eq 'true') { return $true }

	return $obj
}

function Get-HashtableFromJson([string] $par)
{
	if (-not $par) { return @{} }
	return (Get-ValueFromObject (ConvertFrom-Json -InputObject $par))
}

function Get-ServerUrl([string] $url)
{
	if ((-not $url) -or ($url.Length -le 9)) { return $url }
	$pos = $url.IndexOf('/', 8)
	if ($pos -eq -1) { return $url }
	return $url.Substring(0, $pos)
}

function Get-TenantForOrga([string] $OrgaName)
{
	return (Invoke-WebRequest "https://login.windows.net/$OrgaName.onmicrosoft.com/.well-known/openid-configuration"|ConvertFrom-Json).token_endpoint.Split('/')[3]
}


function Get-EncodedString([string] $s)
{
	if ($s)
	{
		return ([System.Web.HttpUtility]::Urlencode($s))
	}
	else
	{
		return ''
	}
}

function Get-DecodedString([string] $s)
{
	if ($s)
	{
		return ([System.Web.HttpUtility]::Urldecode($s))
	}
	else
	{
		return ''
	}
}

function Get-DBValue($v)
{
	if ($v -is [System.DBNull])
	{
		return $null
	}
	else
	{
		return $v
	}
}


Export-ModuleMember -Function LwPerform, Add-OptionalParam, Join-URL, Split-FolderName, Iif, Format-Date, Get-HashtableFromJson, Get-ServerUrl, Get-TenantForOrga, Get-EncodedString, Get-DecodedString, Get-DBValue