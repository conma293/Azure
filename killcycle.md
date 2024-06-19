*_Got creds for a test user by password spray._
#### AzureAD
Compromised a user "Test", so first thing lets see what **user permissions** we have - in Azure this will be groups and roles:
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

- Now should we check if we are the **owner of a device** (and therefore localadmin)? ```Get-AzureADUserOwnedDevice -ObjectId test@defcorphq.onmicrosoft.com```
- lets see what **devices** are ACTUALLY being **used** (i.e., active): ```Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}```
- OK now lets see if there are any **custom roles**? ```Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False}``` (May need to use preview module)
- And lets see the **users who have Global admin** role: ```Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember```

#### az powershell

- Ok now lets enumerate all **resources** visible to the current user:
```Get-AzResource```

- And enumerate all **Azure RBAC role assignments** for all the resources the current user has read access to (NOT just the users role assignments):
```Get-AzRoleAssignment```

- lets output that to a table for ease of use:
```
Get-AzRoleAssignment | select DisplayName, RoleDefinitionName, ObjectType, CanDelegate
```
#### az cli
a good one to use from az cli is the **whoami** equivalent:-
```az ad signed-in-user show```
