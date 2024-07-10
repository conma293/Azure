# Tools
-AzAD
MG
Azure
Az CLI

# API Call
```
$token=''
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

URIs:
```

```
