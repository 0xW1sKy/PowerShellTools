import boto3
import os
import subprocess
import sys
import getopt
import json
import datetime
import re
import webbrowser
import time
import configparser


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class awsRoleCredential:
  def __init__(self, accountName, accountId, roleName, accessKey, secretKey, sessionToken, expiration):
    self.accountName = accountName
    self.accountId = accountId
    self.roleName = roleName
    self.accessKey = accessKey
    self.secretKey = secretKey
    self.sessionToken = sessionToken
    self.expiration = expiration

#Add cross compatibility with the powershell version of this script. 
#Allows conversion of dict object to be case insensitive
#Why aws responses in python have different capitalization than aws responses in powershell? dumb.
class CaseInsensitiveDict(dict):
    class Key(str):
        def __init__(self, key):
            str.__init__(key)
        def __hash__(self):
            return hash(self.lower())
        def __eq__(self, other):
            return self.lower() == other.lower()
    def __init__(self, data=None):
        super(CaseInsensitiveDict, self).__init__()
        if data is None:
            data = {}
        for key, val in data.items():
            self[key] = val
    def __contains__(self, key):
        key = self.Key(key)
        return super(CaseInsensitiveDict, self).__contains__(key)
    def __setitem__(self, key, value):
        key = self.Key(key)
        super(CaseInsensitiveDict, self).__setitem__(key, value)
    def __getitem__(self, key):
        key = self.Key(key)
        return super(CaseInsensitiveDict, self).__getitem__(key)

def urlCheck(string): 
    # findall() has been used  
    # with valid conditions for urls in string 
    url = re.match('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string) 
    return url

def update_credentials_file(credential, profileLocation):
    config = configparser.ConfigParser()
    config.read(profileLocation)
    profile_name = credential.accountName + "_" + credential.roleName
    if profile_name not in config.sections():
        config.add_section(profile_name)
    assert profile_name in config.sections()
    config[profile_name]["aws_access_key_id"] = str(credential.accessKey)
    config[profile_name]["aws_secret_access_key"] = str(credential.secretKey)
    config[profile_name]["aws_session_token"] = str(credential.sessionToken)
    config.write(open(profileLocation, "w"), space_around_delimiters=False)



currentSession = boto3.session.Session()
defaultRegion = currentSession.region_name

newAccessToken = False
generateProfiles = False
startUrl = ''
accountId = ''
roleName = ''
passThru = ''
timeoutInSeconds = 60
clientName = 'default'
clientType = 'public'
path = os.path.join(os.environ['userprofile'],'.awsssohelper')
region = ''
accessToken = ''

try:
    opts, args = getopt.getopt(
        sys.argv[1:],
        "argos:",
        [
            "accountId=",
            "roleName=",
            "generateProfiles",
            "startUrl=",
            "clientName=",
            "clientType=",
            "path=",
            "newAccessToken",
            "region="
        ])
except getopt.GetoptError:
    print('ERROR: Unable to parseOptions')
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-h', "--help"):
        print('Usage: Get-AWSSSORoleCredential.py -s "https://mycompany.awsapps.com/start/" --generateProfiles')
        sys.exit()
    elif opt in ("-s", "--startUrl"):
        startUrl = arg
    elif opt in ("-a", "--accountId"):
        accountId = arg
    elif opt in ("-r", "--roleName"):
        roleName = arg
    elif opt in ("-p", "--passThru"):
        passThru = True
    elif opt in ("-g", "--generateProfiles"):
        generateProfiles = True
    elif opt in ("-o", "--outputToCredFile"):
        outputToCredFile = True
    elif opt == '--clientName':
        clientName = arg
    elif opt == '--clientType':
        clientType = arg
    elif opt == '--path':
        path = arg
    elif opt == '--newAccessToken':
        newAccessToken = True
    elif opt == '--region':
        region = arg

if not urlCheck(startUrl):
    print(bcolors.FAIL, 'ERROR: No startUrl provided. (--startUrl "https://mycompany.awsapps.com/start")', bcolors.ENDC)
    sys.exit(2)

if not region:
    if not defaultRegion:
        print(bcolors.OKBLUE, "INFORMATION: No region specified, and no default region configured. Using recommended region us-east-1.", bcolors.ENDC) 
        region = 'us-east-1'
    else:
        if defaultRegion != 'us-east-1':
            print(
                bcolors.WARNING, 
                "WARNING: Current session default region is: ", 
                "\r\n",
                defaultRegion,
                "\r\n", 
                "For this script we recommend using us-east-1 as your defined region.",
                "\r\n",
                "At the time of writing this script, us-east-1 is the only functional region for AWS SSO.",
                "\r\n",
                bcolors.ENDC
                )
            if input('Would you like to set the region for this script to us-east-1? (y/n): ') != 'y':
                region = defaultRegion
            else:
                region = 'us-east-1'
        else:
            region = defaultRegion

urlSubDomain = re.search("(https?://)?([^:^/]*)(:\\d*)?(.*)?", startUrl).group(2).split('.')[0]

cachePath = os.path.join(path,urlSubDomain)

ssooidc = boto3.client(
    'sso-oidc',
    region_name=region
)


if not os.path.isdir(path):
    try:
        os.mkdir(path)
    except OSError:
        print (bcolors.FAIL, "ERROR: Creation of the directory %s failed" % path, bcolors.ENDC)
        sys.exit(2)
    else:
        print (bcolors.OKGREEN, "SUCCESS: Successfully created the directory %s " % path, bcolors.ENDC)



if os.path.isfile(cachePath):
    with open(cachePath) as json_file:
        accessToken = json.load(json_file)
    accessToken = CaseInsensitiveDict(accessToken)

if not accessToken:
    newAccessToken = True
else:
    sessionLength = round((datetime.datetime.utcfromtimestamp(int(re.split('\(|\)', accessToken['loggedAt'])[1][:10])) - datetime.datetime.utcnow() ).total_seconds()/60)
    if sessionLength >= accessToken['expiresIn']:
        newAccessToken = True


if newAccessToken:
    client = ssooidc.register_client(
        clientName=clientName,
        clientType=clientType
    )
    deviceAuth = ssooidc.start_device_authorization(
        clientId=client['clientId'],
        clientSecret=client['clientSecret'],
        startUrl=startUrl
    )
    try:
        webbrowser.open(deviceAuth['verificationUriComplete'], new=0, autoraise=True)
    except OSError:
        print(bcolors.OKBLUE, "\r\n","Visit the following URL to authorise this session:", "\r\n", deviceAuth['verificationUriComplete'], "\r\n", bcolors.ENDC)
    accessToken = ''
    print(bcolors.OKBLUE,'Waiting for SSO login via browser...',bcolors.ENDC)
    ssoStart = datetime.datetime.utcnow()
    while not accessToken and (datetime.datetime.utcnow() - ssoStart).total_seconds() < deviceAuth['expiresIn']:
        try:
            accessToken = ssooidc.create_token(
                clientId=client['clientId'],
                clientSecret=client['clientSecret'],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=deviceAuth['deviceCode']
            )
            #add dumb formating for datetime to match the .Net JavaScript Deserialization format...
            #helps with compatibility between python and powershell version of this script.
            LoggedAt = '/Date(' + str(datetime.datetime.timestamp(datetime.datetime.strptime(accessToken['ResponseMetadata']['HTTPHeaders']['date'], '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc)))[0:10] + ')/'
            accessToken['LoggedAt']=LoggedAt
            accessToken['startUrl']=startUrl
        except:
            time.sleep(deviceAuth['interval'])


if not accessToken:
    print(bcolors.FAIL, 'ERROR: No access token obtianed.', bcolors.ENDC)
    sys.exit(2)
else:     
    print(bcolors.OKGREEN, "\r\n", "Login Successful. Access Token Obtained", bcolors.ENDC)


with open(cachePath, 'w') as file:
    file.write(json.dumps(accessToken))


sso = boto3.client(
    'sso',
    region_name=region
)

awsAccounts = sso.list_accounts(
    maxResults = 123,
    accessToken = accessToken['accessToken']
)

if not accountId :
    accountId = [o['accountId'] for o in awsAccounts['accountList']]

credentials = []

for aId in accountId :
    if not roleName :
        ssoRoles = sso.list_account_roles(
            accessToken = accessToken['accessToken'],
            accountId = aId
        )['roleList']
    else :
        ssoRoles = roleName
    for role in ssoRoles :
        ssoRoleCredential = sso.get_role_credentials(
            roleName = role['roleName'],
            accountId = role['accountId'],
            accessToken = accessToken['accessToken']
        ).get('roleCredentials')
        
        credentials.append(awsRoleCredential([o['accountName'] for o in awsAccounts['accountList'] if o['accountId'] == aId][0], 
            aId, 
            role['roleName'], 
            ssoRoleCredential['accessKeyId'], 
            ssoRoleCredential['secretAccessKey'], 
            ssoRoleCredential['sessionToken'], 
            ssoRoleCredential['expiration'])
        )



if generateProfiles :
    credentialPath = os.path.join(os.environ['userprofile'],".aws","credentials")
    for credential in credentials :
        update_credentials_file(credential, credentialPath)
    print(bcolors.OKGREEN, len(credentials), " AWS Credentials have been added to your credential store.", bcolors.ENDC)
    sys.exit()


credentials