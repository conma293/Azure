# Azure AD - Authentication and APIs

## TLDR - Tokens == OAuth Credentials (and we want to steal them!)


- Microsoft identity platform uses OpenID Connect (OIDC) for authentication and OAuth 2.0 for authorization.
- Azure AD supports multiple types of authentication like SAML 2.0, OIDC, OAuth 2.0 and Legacy authentication protocols for synchronization like - Header based, LDAP, Kerberos Constrained Delegation etc.
- An application (OAuth Client - web app, mobile apps, cli apps) can sign in to the Authorization server, get bearer tokens to access Resource server (Microsoft Graph and other APIs).


- In this case the Web Server/Web App needs to access a Web API on behalf of the user.
- This is achieved by acquisition of tokens using the Oauth authorization code flow.


- OAuth 2.0 and OIDC use bearer tokens which are JSON Web Tokens.
- A bearer token, as the name suggests, grants the bearer access to a protected resource.
- There are three types of tokens used in OIDC:
  - Access Tokens - The client presents this token to the resource server to access resources. It can be used only for a specific combination of user, client, and resource and cannot be revoked until expiry - that is 1 hour by default.
  - ID Tokens - The client receives this token from the authorization server. It contains basic information about the user. It is bound to a specific combination of user and client.
  - Refresh Tokens - Provided to the client with access token. Used to get new access and ID tokens. It is bound to a specific combination of user and client and can be revoked. Default expiry is 90 days for inactive refresh tokens and no expiry for active tokens.

There is a transaction flow for basic auth and token auth (later needed for webapp to access resources on users behalf):

- ```/oauth2/v2.0/authorize``` - Authentication
  - User signs in, enters credentials & consents to permissions to [Identity Provider]
  - [Identity Provider] returns ```id_token``` AND ```authorization_code``` to browser
  - Browser redirects ```id_token``` AND ```authorization_code``` to Redirect URI
  - Web Server Validates ```id_token``` and sets session cookie

- ```/oauth2/v2.0/token``` - Authorization
  - Web Server Requests Oauth bearer token, providing ```authorization_code```, apps client_id, creds etc
  - Token endpoint of the Identity Platform returns new ```access token``` AND ```refresh token``` to Web Server
  - Web Server now can call web API with ```access_token``` in authorization header
  - Web API Validates ```access token``` and returns secure data to web server app
 
Conditional access policy is a real issue


 

Note for Access Token - if user is deleted it is still valid because there is no check on the token, only whats inside (i.e., is there a role assignment for this user to this resource - if yes then grant access, whether the user still exists or not) .. (just like a TGT/TGS in AD)

## 
Logon:
```
$passwd= ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneCr4ckTh!sP@ssw0rd" -AsPlainText -Force
$creds= New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
```

and then get token:
```
Get-AzAccessToken
(Get-AzAccessToken).token
```

- can decrypt with base64 on commandline or with website like https://jwt.io/
  - Aud = Audience = the API that the Token is meant for
  - app.displayname = requesting process/app (detection possibility?)

#### Using Tokens with CLI tools - Az PowerShell

- Both Az PowerShell and AzureAD modules allow the use of Access tokens for authentication.
- Usually, tokens contain all the claims (including that for MFA and Conditional Access etc.) so they are useful in bypassing such security controls.
- If you are already connected to a tenant, request an access token for resource manager (ARM)
```
Get-AzAccessToken
(Get-AzAccessToken).Token
```
we can then look at resources (ARM token) but not users, for that we need ADgraph or MSgraph token:

- Request an access token for AAD Graph to access Azure AD. Supported tokens - AadGraph, AnalysisServices, Arm, Attestation, Batch, DataLake, KeyVault, MSGraph, OperationalInsights, ResourceManager, Storage, Synapse
```
Get-AzAccessToken -ResourceTypeName MSGraph
```
- From older versions of Az PowerShell, get a token for Microsoft Graph: ```(Get-AzAccessToken -Resource "https://graph.microsoft.com").Token```


•  Use the access token:
```
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken eyJ0eXA...
```

OR:
```
$token='eyJ0eXA...'
Connect-AzAccount -AccessToken $token -AccountId test@defcorphq.onmicrosoft.com
```


•  Use other access tokens. In the below command, use the one for MSGraph (access token is still required) for accessing Azure AD:
```
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken eyJ0eXA... -MicrosoftGraphAccessToken eyJ0eXA...
```


#### Using Tokens with CLI tools - az cli


•  az cli can request a token but cannot use it! (Actually you can, see the next slide)

•  Request an access token (ARM): ```az account get-access-token```

•  Request an access token for aad-graph. Supported tokens - aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms:
```
az account get-access-token --resource-type ms-graph
```

#### Stealing Tokens from az cli


•  az cli (before 2.30.0 – January 2022) stores access tokens in clear text in accessTokens.json in the directory C:\Users\[username]\.Azure

•  We can read tokens from the file, use them and request new ones too!

•  azureProfile.json in the same directory contains information about subscriptions.

•  You can modify accessTokens.json to use access tokens with az cli but better to use with Az PowerShell or the Azure AD module.

•  To clear the access tokens, always use az logout



•  Az PowerShell (older versions) stores access tokens in clear text in ```TokenCache.dat``` in the directory ```C:\Users\[username]\.Azure```

•  It also stores ```ServicePrincipalSecret``` in clear-text in ```AzureRmContext.json``` if a service principal secret is used to authenticate.

•  Another interesting method is to take a process dump of PowerShell and looking for tokens in it!

•  Users can save tokens using Save-AzContext, look out for them! Search for Save-AzContext in PowerShell console history!

•  Always use Disconnect-AzAccount!!


#### Using Tokens with CLI tools - AzureAD module

•  AzureAD module cannot request a token but can use one for AADGraph or Microsoft Graph!

•  Use the AAD Graph token:
```
Connect-AzureAD -AccountId test@defcorphq.onmicrosoft.com -AadAccessToken eyJ0eXA...
```


### Using Tokens with APIs - Management

- The two REST APIs endpoints that are most widely used are:
  - Azure Resource Manager - management.azure.com
  - Microsoft Graph - graph.microsoft.com (Azure AD Graph which is deprecated is graph.windows.net)

•  Let's have a look at super simple PowerShell codes for using the APIs


#### Using Tokens with APIs - ARM

•  Get an access token and use it with ARM API. For example, list all the subscriptions
```
$Token = 'eyJ0eXAi..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{ Method  = 'GET' Uri    = $URI Headers = @{'Authorization' = "Bearer $Token"}}
(Invoke-RestMethod @RequestParams).value
```

#### Using Tokens with APIs - Mg

•  Get an access token for MS Graph. For example, list all the users
```
$Token = 'eyJ0eXAi..'
$URI = 'https://graph.microsoft.com/v1.0/users'
$RequestParams = @{ Method = 'GET' Uri     = $URI Headers = @{'Authorization' = "Bearer $Token"}}
(Invoke-RestMethod @RequestParams).value
```

### Continuous Access Evaluation (CAE)
•  CAE can help in invalidating access tokens before their expiry time (default 1 hour).

- Useful in cases like:
  - User termination or password change enforced in near real time
  - Blocks use of access token outside trusted locations when location
based conditional access is present

•  In CAE sessions, the access token lifetime is increased up to 28 hours.

#### CAE – Claims Challenge

•  CAE needs the client (Browser/App/CLI) to be CAE-capable – the client must understand that the token has not expired but cannot be used.

•  Outlook, Teams, Office (other than web) and OneDrive web apps and apps support CAE.

•  “The xms_cc claim with a value of “CP1" in the access token is the authoritative way to identify a client application is capable of handling a claims challenge.”

•  In case the client is not CAE-capable, a normal access token with 1 hour expiry is issued.

•  We can find xms_cc claim in MSGraph token for testuser that was requested using Az PowerShell.

•  Access tokens issued for managed identities by Azure IMDS are not CAE-enabled.


#### CAE – Critical Event Evaluation

•  CAE works in two scenarios:

1.   Critical event evaluation

• User account is deleted or disabled

• Password change or reset for a user

• MFA enabled for a user

• Refresh token is revoked

• High user risk detected by Azure AD identity Protection (not supported by
Sharepoint online)

• Only Exchange Online, Sharepoint online and Teams are supported.

#### CAE – Conditional Access Policy Evaluation

•  CAE works in two scenarios:

2.   Conditional Access policy evaluation

• Only IP-based (both IPv4 and IPv6) named locations are supported. Other location conditions like MFA trusted IPs or country-based locations are not supported.

• Exchange Online, SharePoint online, Teams and MS Graph are supported.



### Enumeration - ROADTools

•  RoadRecon (https://github.com/dirkjanm/ROADtools) is a tool for enumerating Azure AD environments!

•  RoadRecon uses a different version '1.61-internal' of Azure AD Graph API that provides more information.

- Enumeration using RoadRecon includes three steps
  - Authentication
  - Data Gathering
  - Data Exploration

•  Roadrecon is already setup on your student VM.

•  roadrecon supports username/password, access and refresh tokens, device code flow (sign-in from another device) and PRT cookie.
```
cd C:\AzAD\Tools\ROADTools .\venv\Scripts\activate roadrecon auth -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234
```

•  Once authentication is done, use the below command to gather data (ignore the errors): ```roadrecon gather```

•  Use roadrecon GUI to analyse the gathered information (starts a web server on port 5000): ```roadrecon gui```

