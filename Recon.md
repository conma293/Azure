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

OR we could just use AADInternals

https://github.com/Gerenios/AADInternals 

```Import-Module C:\AzAD Tools\AADInternals\AADInternals.psd1 -Verbose```
