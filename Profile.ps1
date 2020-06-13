function global:prompt {
  # Multiple Write-Host commands with color
  Write-Host("[") -nonewline
  Write-Host($env:computername) -nonewline -foregroundcolor Green
  Write-Host("] ") -nonewline
  Write-Host("$(Split-Path $pwd -Leaf)/") -nonewline -foregroundcolor Blue
  return " $ "
}
Invoke-RestMethod -uri https://raw.githubusercontent.com/0xW1sKy/PowerShellTools/master/rebellogo | % { $_.split("`n") | % { Write-Host $_ -ForegroundColor red -BackgroundColor black; Start-Sleep .05 }}
