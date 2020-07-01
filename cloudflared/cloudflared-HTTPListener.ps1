# Copyright (c) 2014 Microsoft Corp.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


Function Start-HTTPListener {
    <#
    .Synopsis
        Creates a new HTTP Listener accepting PowerShell command line to execute
    .Description
        Creates a new HTTP Listener enabling a remote client to execute PowerShell command lines using a simple REST API.
        This function requires running from an elevated administrator prompt to open a port.

        Use Ctrl-C to stop the listener.  You'll need to send another web request to allow the listener to stop since
        it will be blocked waiting for a request.
    .Parameter Port
        Port to listen, default is 8888
    .Parameter URL
        URL to listen, default is /
    .Parameter Auth
        Authentication Schemes to use, default is IntegratedWindowsAuthentication
    .Example
        Start-HTTPListener -Port 8080 -Url cloudflared
        Open a web browser and go to: "http://localhost:8888/cloudflared?hostname=example.com&protocol=rdp"
    #>

    Param (
        [Parameter()]
        [Int] $Port = 8888,

        [Parameter()]
        [String] $Url = "",

        [Parameter()]
        [System.Net.AuthenticationSchemes] $Auth = [System.Net.AuthenticationSchemes]::IntegratedWindowsAuthentication
        )

    Process {
#        $ErrorActionPreference = "Stop"

        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if ( -not ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))) {
            Write-Error "This script must be executed from an elevated PowerShell session" -ErrorAction Stop
        }

        if ($Url.Length -gt 0 -and -not $Url.EndsWith('/')) {
            $Url += "/"
        }

        $listener = New-Object System.Net.HttpListener
        $prefix = "http://*:$Port/$Url"
        $listener.Prefixes.Add($prefix)
        $listener.AuthenticationSchemes = $Auth
        try {
            $listener.Start()
            while ($true) {
                $statusCode = 200
                Write-Warning "Note that thread is blocked waiting for a request.  After using Ctrl-C to stop listening, you need to send a valid HTTP request to stop the listener cleanly."
                Write-Warning "Sending '?exit=true' command will cause listener to stop immediately"
                Write-Verbose "Listening on $port..."
                $context = $listener.GetContext()
                $request = $context.Request
                if ($request.QueryString.Keys -contains 'exit'){
                    $listener.stop()
                    break
                }
                if (!$request.IsAuthenticated) {
                    Write-Warning "Rejected request as user was not authenticated"
                    $statusCode = 403
                    $commandOutput = "Unauthorized"
                } else {
                    $identity = $context.User.Identity
                    Write-Verbose "Received request $(get-date) from $($identity.Name):"
                    $request | fl * | Out-String | Write-Verbose

                    # only allow requests that are the same identity as the one who started the listener
                    if ($identity.Name -ne $CurrentPrincipal.Identity.Name) {
                        Write-Warning "Rejected request as user doesn't match current security principal of listener"
                        $statusCode = 403
                        $commandOutput = "Unauthorized"
                    } else {
                        if (-not $request.QueryString.HasKeys()) {
                            $commandOutput = "SYNTAX: hostname=<string> protocol=[rdp|ssh|tcp]"
                            $Format = "TEXT"
                        } else {

                            $hostname = $request.QueryString.Item("hostname")

                            $protocol = $request.QueryString.Item("protocol")


                            #Find an open local ip
                            $iplist = Get-NetTCPConnection | where { $_.localaddress -like '127.*' } | select -ExpandProperty LocalAddress | sort | unique
                            $ipfound = $false
                            while (!($ipfound)) {
                                $o1 = '127'
                                $o2 = Get-Random -Minimum 1 -Maximum 254 # avoid use of 127.0.0.0/24
                                $o3 = Get-Random -Minimum 0 -Maximum 254
                                $o4 = Get-Random -Minimum 1 -Maximum 254 # avoid use of 127.x.x.0 or 127.x.x.255
                                $testip = @($o1, $o2, $o3, $o4) | Join-String -Separator '.'
                                if ($testip -notin $iplist) {
                                    $linkip = $testip
                                    $ipfound = $true
                                    break
                                }
                            }
                            # the above method could be used to allow the original domain name to work
                            # with cloudflared if we set the DNS locally.
                            switch ($protocol){
                                    rdp {$dport = 3389 }
                                    ssh {$dport = 22 }
                                }
                            $durl = "$linkip`:$dport"
                            try {
                                $cloudflared = Start-Process -FilePath 'C:\cloudflared.exe' -ArgumentList "access $protocol --hostname $hostname --url $durl" -WindowStyle Hidden
                                switch ($protocol){
                                    rdp {Start-Process mstsc -ArgumentList "/v:$durl /prompt" }
                                    ssh {Start-Process ssh -ArgumentList "$hostname -p $dport" }
                                }

                            } catch {
                                $commandOutput = "Error in URL Listener"
                                $statusCode = 500
                            }
                        }
                        write-output $commandOutput | ConvertTo-JSON
                        }
                    }
                }

                Write-Verbose "Response:"
                if (!$commandOutput) {
                    $commandOutput = [string]::Empty
                }
                Write-Verbose $commandOutput

                $response = $context.Response
                $response.StatusCode = $statusCode
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($commandOutput)
                $response.ContentLength64 = $buffer.Length
                $output = $response.OutputStream
                $output.Write($buffer,0,$buffer.Length)
                $output.Close()

        } catch {
            $listener.Stop()
        }
    }
    End {
        $listener.Stop()
    }
}

Start-HTTPListener -Url cloudflared -Verbose
