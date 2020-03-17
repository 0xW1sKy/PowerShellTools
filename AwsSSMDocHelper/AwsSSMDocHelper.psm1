Function ConvertTo-SSMDocument{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
            [string]$ScriptPath,
        [Parameter(Mandatory=$True)]
            [string]$Description
    )
    $Prefix = @"
{
    "schemaVersion":"2.2",
    "description":"$description",
    "mainSteps":[
        {
            "action":"aws:runPowerShellScript",
            "name":"RemediateIISLogFields",
            "precondition":{
            "StringEquals":[
                "platformType",
                "Windows"
            ]
            },
            "inputs":{
            "runCommand":
"@
    $Suffix = @"
        }
    }
    ]
}

"@
    If ((Test-Path $ScriptPath)) {
    
        $JsonCode = Get-Content $($ScriptPath) -Encoding UTF8 | ForEach-Object { "$($_)".ToString() } | ConvertTo-Json | ForEach-Object{
        [Regex]::Replace($_, 
            "\\u(?<Value>[a-zA-Z0-9]{4})", {
                param($m) ([char]([int]::Parse($m.Groups['Value'].Value,
                    [System.Globalization.NumberStyles]::HexNumber))).ToString() } )}
        $json = $Prefix + $JsonCode + $Suffix
    }
    $json | Out-String
}
Export-ModuleMember -Function ConvertTo-SSMDocument