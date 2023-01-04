[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
if([IO.Path]::PathSeparator -eq ":"){
  if( $(uname) -eq "Darwin"){
    $env:hostname = $(hostname)
  }
}else{
  $env:hostname = $env:computername
}
# Universal Time
# (Get-Date).ToUniversalTime().ToString("o")

function global:prompt {
  # Multiple Write-Host commands with color
  Write-Host(Get-Date -UFormat '+%Y-%m-%d|%H:%M:%S') -nonewline -foregroundcolor Red
  Write-Host("[") -nonewline
  Write-Host($env:hostname) -nonewline -foregroundcolor Green
  Write-Host("] ") -nonewline
  Write-Host("$(Split-Path $pwd -Leaf)/") -foregroundcolor Blue
  return "🔰`: "
}
