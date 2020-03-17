Function Get-NetworkScope
{ 
    [CmdletBinding()]
    param([String]$IPAddress)
    #Input IP Address or CIDR address. 
    #Evaluates input to determine if it is a private or public address
    if($IPAddress -ne $null) {
        try {
            $errorActionPreference = 'SilentlyContinue'
            $BinaryIP = $([System.Net.IPAddress]::Parse($IPAddress.split('/')[0]).GetAddressBytes() |ForEach-Object{[System.Convert]::ToString($_, 2).PadLeft(8, '0') }) -join '.'
            $errorActionPreference = 'Continue'
        }catch{
            $errorActionPreference = 'Continue'
            Write-Error "Invalid IP Address Provided"
            Write-Output "Invalid IP Address"
            break
        }
        If( $BinaryIP -Match "^00001010.[0-1]{8}.[0-1]{8}.[0-1]{8}$" <#10.0.0.0/8#> `
        -OR $BinaryIP -Match "^10101100.0001[0-1]{4}.[0-1]{8}.[0-1]{8}$" <#172.16.0.0/12#> `
        -OR $BinaryIP -Match "^11000000.10101000.[0-1]{8}.[0-1]{8}$" <#192.168.0.0/16#> `
        -OR $BinaryIP -Match "^10101001.11111110.[0-1]{8}.[0-1]{8}$" <#169.254.0.0/16#> `
        -OR $BinaryIP -Match "^01111111.00000000.[0-1]{8}.[0-1]{8}$" <#127.0.0.0/16#> `
        -OR $BinaryIP -Match "^11111111.11111111.11111111.11111111$"){
            Write-Output "Private"
        }else{
            Write-Output "Public"
        }
    }else{
        Write-Output "No IP Address Provided"
    }
}