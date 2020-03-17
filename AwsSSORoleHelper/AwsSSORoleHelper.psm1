#Requires -Modules AWSPowerShell 
<#
.SYNOPSIS
This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.  
Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script (this is similar behaviour to aws cli v2).
.DESCRIPTION
This is a simple utility script that allows you to retrieve credentials for AWS accounts that are secured using AWS SSO.  
Access tokens are cached locally to prevent the need to be pushed to a web browser each time you invoke the script (this is similar behaviour to aws cli v2).
Main usability enhancement compared to aws cli 2 is the abillity to retrieve all credentials for all accounts that you have access to.  
You can optionally specify a rolename with the -RoleName parameter and retrieve all credentials for that rolename across all of your accounts.
Alternatively you can specify an AccountID by using the -AccountID parameter and retrieve all credentials for that AccountID.
Additionally, you can use this script to configure all available or explicitly selected credentials into your AWS Credentials store using the -GenerateProfiles switch.
.EXAMPLE
    #Generate credential profile for all accounts and role names.
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -GenerateProfiles
.EXAMPLE
    #Generate credential profile for all accounts where role name is 'My_Role_Name'
    Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -RoleName 'My_Role_Name' -GenerateProfiles
.EXAMPLE
    #Get credentials for specific account and rolename, then use those to retrieve S3 bucket.
    $RoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AccountID 0123456789 -RoleName S3_Reader -Passthru
    Get-S3Bucket -AccessKey $RoleCredentials.AccessKey -SecretKey $RoleCredentials.SecretKey -SessionToken $RoleCredentials.SessionToken
.INPUTS
    StartUrl (Mandatory)
.OUTPUTS
    AccountName, AccountId, RoleName, AccessKey, Expiration, SecretKey, SessionToken
#>
function Get-AWSSSORoleCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$StartUrl,
        [string]$AccountId,
        [string]$RoleName,
        [string]$ClientName = "default",
        [ValidateSet('public')][string]$ClientType = "public",
        [int]$TimeoutInSeconds = 60,
        [string]$Path = (Join-Path $Home ".awsssohelper"),
        [string]$Region,
        [switch]$PassThru,
        [switch]$RefreshAccessToken,
        [switch]$GenerateProfiles,
        [switch]$SaveToCredFile

    )

    Function get-epochDate ($epochDate) { [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($epochDate)) }

    if([string]::IsNullOrEmpty($Region)){
        if (($null -eq (Get-DefaultAWSRegion).Region)) {
            Write-Host "No region specified, using default region us-east-1." 
            $Region = 'us-east-1'
        }
        else {
            $Region = (Get-DefaultAWSRegion).Region
        }
    }
    $urlSubDomain = ([system.uri]$starturl).host.split('.')[0]
    $CachePath = Join-Path $Path $urlSubDomain
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }

    if (Test-Path $CachePath) {
        $AccessToken = Get-Content $CachePath | ConvertFrom-Json
    }

    if (!$AccessToken) {
        $RefreshAccessToken = $true
    }
    else{ 
        if($accesstoken.loggedat.gettype().name -eq 'DateTime'){
            if($(New-timespan $accesstoken.loggedat (get-date).ToUniversalTime()).totalseconds -gt $AccessToken.ExpiresIn) {
                $RefreshAccessToken = $true
            }
        }else{
            if($(New-TimeSpan (get-epochDate $accesstoken.loggedat.split("(").split(")")[1]) (Get-Date).touniversaltime()).TotalSeconds -gt $AccessToken.ExpiresIn) {
                $RefreshAccessToken = $true
            }
        }
    }

    if(!($RefreshAccessToken)){
        try{
            $AWSAccounts = Get-SSOAccountList -AccessToken $AccessToken.AccessToken -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Region $region
        }catch{
            $RefreshAccessToken = $true
        }
    }
    if ($RefreshAccessToken) {

        $Client = Register-SSOOIDCClient -ClientName $ClientName -ClientType $ClientType -Region $Region -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
        $DeviceAuth = Start-SSOOIDCDeviceAuthorization -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret -StartUrl $StartUrl -Region $Region -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) 

        try {
            $Process = Start-Process $DeviceAuth.VerificationUriComplete -PassThru
        }
        catch {
            continue
        }

        if (!$Process.Id) {
            Write-Host "`r`nVisit the following URL to authorise this session:`r`n"
            Write-Host -ForegroundColor White "$($DeviceAuth.VerificationUriComplete)`r`n"
        }
        
        Clear-Variable AccessToken -Force -ErrorAction SilentlyContinue
        Write-Host "Waiting for SSO login via browser..."
        $SSOStart = (Get-Date).ToUniversalTime()
        
        while (!$AccessToken -and ((New-TimeSpan $SSOStart (Get-Date).ToUniversalTime()).TotalSeconds -lt $TimeoutInSeconds)) {
            try {
                $AccessToken = New-SSOOIDCToken -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret -Code $DeviceAuth.Code -DeviceCode $DeviceAuth.DeviceCode  -Region $Region -GrantType "urn:ietf:params:oauth:grant-type:device_code" -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
            }
            catch {
                Start-Sleep -Seconds 5
            }
        }
        if (!$AccessToken) {
            throw 'No Access Token obtained.'
        }
        Write-Host "Login Successful. Access Token obtained."
        $AccessToken | ConvertTo-Json | Set-Content $CachePath
        $AWSAccounts = Get-SSOAccountList -AccessToken $AccessToken.AccessToken -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Region $region
    }

    if (!$AccountId) {
        $AccountId = $AWSAccounts | Select-Object -ExpandProperty AccountId
    }

    $Credentials = @()

    foreach ($Id in ($AccountId -split ' ')) {
        if (!$RoleName) {
            $SSORoles = Get-SSOAccountRoleList -AccessToken $AccessToken.AccessToken -AccountId $Id -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Region $region | Select-Object -ExpandProperty RoleName
        }
        else{
            $SSORoles = $RoleName
        }
        $SSORoles | ForEach-Object {
            $SSORoleCredential = Get-SSORoleCredential -AccessToken $AccessToken.AccessToken -AccountId $Id -RoleName $_ -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new()) -Region $region
            $Credentials += [pscustomobject][ordered]@{
                AccountName = $AWSAccounts | Where-Object {$_.AccountId -like $Id} | Select-Object -Expandproperty AccountName
                AccountId = $Id;
                RoleName = $_;
                AccessKey = $SSORoleCredential.AccessKeyId;
                Expiration = $SSORoleCredential.Expiration;
                SecretKey = $SSORoleCredential.SecretAccessKey;
                SessionToken = $SSORoleCredential.SessionToken
            }           
        }
           
    }
    $output = $credentials
    if($GenerateProfiles) {
        $CredentialPath = Join-Path $(Join-path $Home -ChildPath ".aws") "credentials"
        $Credentials | ForEach-Object {
            if(!$SaveToCredFile){
                Set-AWSCredential -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken -StoreAs $($_.AccountName + '_' + $_.RoleName)
            }else{
                Set-AWSCredential -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken -StoreAs $($_.AccountName + '_' + $_.RoleName) -ProfileLocation $CredentialPath
            }

        }
        Write-host $Credentials.Count "AWS Credentials have been added to your credential store."
        $output = Get-AWSCredential -ListProfileDetail | Sort-Object -Property ProfileLocation,ProfileName
    }

    if ($PassThru) {
        $output = $Credentials | Select-Object @{N="ProfileName";E={$_.AccountName + '_' + $_.RoleName}},AccessKey,SecretKey,SessionToken | Sort-Object
    }
    $output
}
Export-ModuleMember -Function Get-AWSSSORoleCredential