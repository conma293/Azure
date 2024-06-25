*_Got creds for a test user by password spray._

TLDR:
- Use [AzureAD](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azuread-module)/[MG Module](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---mg-module) for basic AAD/Entra ID Directory enumeration (i.e., users, groups, devices)
  - This will require an access token for AAD or MS Graph
- Use [az powershell](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration----az-powershell) or [az cli](https://github.com/conma293/Azure/blob/main/2.1_Enumeration.md#enumeration---azure-cli-az-cli) for other enumeration - resources, roles, vms, apps etc
  - This will require ARM access token (default token)
    

Using tools like ROADTools or Azurehound is going to be our best bet anyhow (and enum isnt logged so who cares right!?)
 
    


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
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneC@nGu355ForT3stUs3r" -AsPlainText -Force 
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
roadrecon plugin policies
```
