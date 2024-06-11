# Recce

# External Discovery
- Get if Azure tenant is in use, tenant name and Federation
```
https://login.microsoftonline.com/getuserrealm.srf?login==[USERNAME@ DOMAIN]&xml=1
```

- Get the Tenant ID (first GUID of returned url - used by OAuth)
```
https://login.microsoftonline.com/[DOMAIN]/.well-known/openid configuration
```

- Validate Email ID by sending requests to
```
https://login.microsoftonline.com/common/GetCredentialType
```

* * *

OR we could just use AADInternals

https://github.com/Gerenios/AADInternals 

```Import-Module C:\AzAD Tools\AADInternals\AADInternals.psd1 -Verbose```

Get tenant name, authentication, brand name (usually same as directory name) and domain name:
```
Get-AADIntLoginInformation UserName root@defcorphq.onmicrosoft.com
```

Get tenant ID:
```
Get-AADIntTenantID Domain defcorphq.onmicrosoft.com
```

-Get tenant domains:
```
Get-AADIntTenantDomains Domain defcorphq.onmicrosoft.com
Get-AADIntTenantDomains Domain deffin.onmicrosoft.com
Get-AADIntTenantDomains Domain microsoft.com
```

Get all the information:
```
Invoke-AADIntReconAsOutsider DomainName defcorphq.onmicrosoft.com
```
