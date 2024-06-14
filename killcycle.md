Target environment through password spray.

Compromised a user "Test", so first thing lets see what permissions we have - in Azure this will be groups and roles:
```
Get-AzureADUser -SearchString 'test'
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
```

ok we get a random GUID for the group, but what roles doe we have?

