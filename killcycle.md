Target environment through password spray.

Compromised a user "Test", so first thing lets see what permissions we have - in Azure this will be groups and roles:
```
Get-AzureADUser -SearchString 'test'
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
```

We could also look at the admin user:
```
Get-AzureADUser -SearchString 'admin' | Get-AzureADUserMembership
Get-AzureADUserMembership -ObjectId admin@defcorphq.onmicrosoft.com
```
I wonder who else is in the Global Admins group?
```
Get-AzureADGroupMember -ObjectId 9240b75e-823c-4c02-8868-a00ddbeb3fa1
```
Or we could just look this way:
```
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
```

_in normal environments we would expect to see some Service Principals (that is an application) running as Global Administrator - if we were to compromise that object, or a user that is the owner of that object, we could get GA!_


Now should we check if we are the owner of a device (and therefore localadmin)?
```
Get-AzureADUserOwnedDevice -ObjectId test@defcorphq.onmicrosoft.com
```

lets see what devices are ACTUALLY being used (i.e., active):

```
Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}
```


ok we get a random GUID for the group, but what roles doe we have?
