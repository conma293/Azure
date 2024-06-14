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





ok we get a random GUID for the group, but what roles doe we have?

