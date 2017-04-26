function Get-DnsIPV4Address {
[CmdletBinding()]
param ( [string]$Machine)
process{ Write-Output "$([System.Net.Dns]::GetHostEntry("$Machine").addresslist | where-object {$_.AddressFamily -eq "InterNetwork" })" }
}

function Get-DnsIPV6Address {
[CmdletBinding()]
param ( [string]$Machine)
process{ Write-Output "$([System.Net.Dns]::GetHostEntry("$Machine").addresslist | where-object {$_.AddressFamily -eq "InterNetworkV6" })" }
}

function Get-DnsHostName {
[CmdletBinding()]
param ( [string]$Machine )
process{ Write-Output "$([System.Net.Dns]::GetHostEntry("$Machine").HostName)" }
}

function Get-DnsEntry {
[CmdletBinding()]
param ( [string]$Machine )
process{$([System.Net.Dns]::GetHostEntry("$Machine"))}
}
