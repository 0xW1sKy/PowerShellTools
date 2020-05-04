function Get-AWSSSORoleCredential {
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

        Region is set to US-East-1 by default as this is the only region that currently supports AWS SSO.
        .PARAMETER StartUrl
        The AWS SSO URL that you use to login. Example: https://mycompany.awsapps.com/start
        .PARAMETER AccountId
        Specify an AccountID to filter results to a specific account.
        .PARAMETER RoleName
        Specify a RoleName to filter results to a specific set of roles.
        .PARAMETER PassThru
        Returns AccountName, AccountId, RoleName, AccessKey, SecretKey, SessionToken, Expiration for all credentials based on filter.
        Pair with -AccountId and -RoleName to select a single set of credentials.
        .PARAMETER RefreshAccessToken
        Use this switch to manually refresh access token. Usually not needed, but included due to some inconsistencies with AWS SSO.
        .PARAMETER UseSharedCredentialsFile
        Use this switch to save profiles to the AWS Credentials file configured in the global environment variable 'AWS_SHARED_CREDENTIALS_FILE'
        .EXAMPLE
        #Generate credential profile for all accounts and role names, auto save to credential file.
        Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start"
        .EXAMPLE
        #Generate credential profile for all accounts where role name is 'My_Role_Name', auto save to credential file.
        Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -RoleName 'My_Role_Name'
        .EXAMPLE
        #Get credentials for specific account and rolename, then use those to retrieve S3 bucket.
        $RoleCredentials = Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -AccountID 0123456789 -RoleName S3_Reader -Passthru
        Get-S3Bucket -AccessKey $RoleCredentials.AccessKey -SecretKey $RoleCredentials.SecretKey -SessionToken $RoleCredentials.SessionToken
        .EXAMPLE
        #Generate credential profile for all accounts and role names, save to shared credentials file.
        Get-AWSSSORoleCredential -StartUrl "https://mycompany.awsapps.com/start" -UseSharedCredentialFile
        .INPUTS
        StartUrl (Mandatory)
        .OUTPUTS
        Default Outputs:
        ProfileName, StoreTypeName, ProfileLocation
        PassThru Outputs:
        AccountName, AccountId, RoleName, AccessKey, SecretKey, SessionToken, Expiration
    #>
    [CmdletBinding()]


    param(
        [Parameter(Mandatory=$true)][string]$StartUrl,
        [string]$AccountId,
        [string]$RoleName,
        [switch]$PassThru,
        [switch]$RefreshAccessToken,
        [switch]$UseSharedCredentialsFile
    )

    Function convertfrom-EpochTime ($epochdate) {
        if (("$epochdate").length -gt 10 ){
                (Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)
        }
        else {
            (Get-Date -Date "01/01/1970").AddSeconds($epochdate)
        }
    }
    if(!($UseSharedCredentialsFile)){
        $CredentialPath = Join-Path $(Join-path $Home -ChildPath ".aws") "credentials"
    }else{
        $CredentialPath = [Environment]::GetEnvironmentVariable('AWS_SHARED_CREDENTIALS_FILE')
    }
    
    # Required Defaults for OIDC Connection
    $ClientName = "default"
    $ClientType = "public"
    
    # Set a location to save AccessTokens
    $Path = (Join-Path $Home ".awsssohelper")
    
    # Hardcoding region as only us-east-1 currently supports SSO OIDC connection.
    $Region = 'us-east-1'

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
    }else{ 
        if($accesstoken.loggedat.gettype().name -eq 'DateTime'){
            if($(New-timespan $accesstoken.loggedat (get-date).ToUniversalTime()).totalseconds -gt $AccessToken.ExpiresIn) {
                $RefreshAccessToken = $true
            }
        }else{
            if($(New-TimeSpan (ConvertFrom-EpochTime $accesstoken.loggedat.split("(").split(")")[1]) (Get-Date).touniversaltime()).TotalSeconds -gt $AccessToken.ExpiresIn) {
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

        $SSOStart = (Get-Date).ToUniversalTime()
        $TimeoutInSeconds = $DeviceAuth.ExpiresIn
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
        
        
        while (!$AccessToken -and ((New-TimeSpan $SSOStart (Get-Date).ToUniversalTime()).TotalSeconds -lt $TimeoutInSeconds)) {
            try {
                $AccessToken = New-SSOOIDCToken -ClientId $Client.ClientId -ClientSecret $Client.ClientSecret -Code $DeviceAuth.Code -DeviceCode $DeviceAuth.DeviceCode  -Region $Region -GrantType "urn:ietf:params:oauth:grant-type:device_code" -Credential ([Amazon.Runtime.AnonymousAWSCredentials]::new())
            }
            catch {
                Start-Sleep -Seconds 5
            }
        }
        if (!$AccessToken) {
            if(($(New-TimeSpan $SSOStart (Get-Date).ToUniversalTime()).TotalSeconds) -ge $timeoutinseconds){
                throw 'Access Token Request Timed out. Please attempt to run the script again.'
            }
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
    if ($PassThru) {
        $output = $Credentials | Select-Object AccountName,AccountId,RoleName,AccessKey,SecretKey,SessionToken,Expiration | Sort-Object
    }else{

        $Credentials | ForEach-Object {
                Set-AWSCredential -AccessKey $_.AccessKey -SecretKey $_.SecretKey -SessionToken $_.SessionToken -StoreAs $($_.AccountName + '_' + $_.RoleName) -ProfileLocation $CredentialPath

        }
        Write-host $Credentials.Count "AWS Credentials have been added to your credential store."
        $output = Get-AWSCredential -ListProfileDetail | Sort-Object -Property ProfileLocation,ProfileName
    }

    $output
}
Export-ModuleMember -Function Get-AWSSSORoleCredential