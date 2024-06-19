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
 

Note for Access Token - if user is deleted it is still valid because there is no check on the token, only whats inside (i.e., is there a role assignment for this user to this resource - if yes then grant access, whether the user still exists or not) .. (just like a TGT/TGS in AD)


