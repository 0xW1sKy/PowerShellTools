# How To Install
```powershell
$url = 'https://github.com/0xW1sKy/PowerShellTools/zipball/master/'
$desktop =  $([Environment]::GetFolderPath('DesktopDirectory'))
$zipFileName = $($([system.uri]$url).absolutepath.split('/')[2]) + '.zip'
$ZipFile = Join-Path $desktop $zipFileName
$Destination = "$Home\Documents\WindowsPowerShell\Modules"
#Download the File and place on desktop
Invoke-WebRequest -Uri $Url -OutFile $ZipFile
#Open the Zip Archive and place on desktop
Expand-Archive -LiteralPath $zipFile -DestinationPath $desktop
#Select the folder you just created
$ExtractPath = get-childitem $desktop `
                    | Select-Object `
                    | Where-Object {$_.name -like '0xW1sKy-PowerShellTools-*'} `
                    | Sort-Object -Property LastWriteTime -Descending `
                    | Select-Object -First 1 -ExpandProperty FullName
#Get Path of each file that is in the extracted folder path and move them to your Modules Location
Get-ChildItem $ExtractPath | ForEach-Object{ 
    Move-Item $_.FullName "$Destination\$($_.name)"
    }
#Clean Up Artifacts
Remove-Item -Path $ExtractPath
Remove-Item -Path $zipfile
```