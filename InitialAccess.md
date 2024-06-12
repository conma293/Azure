# Initial Access
#### Password Spray/Brute Force
- We will use a single password against multiple users that we have enumerated.
- This is definitely noisy and may lead to detection!
- For Azure, password spray attack can be done against different API endpoints like Azure AD Graph, Microsoft Graph, Office 365 Reporting webservice etc


MSOLSpray 
https://github.com/dafthack/MSOLSpray

for password spray against the accounts that we discovered.
-The tool supports fireprox to rotate source IP address on auth request.
https://github.com/ustayready/fireprox

```
C:\AzAD\Tools\MSOLSpray\MSOLSPray.ps1
Invoke-MSOLSpray -UserList C:\AzAD\Tools\validemails.txt -Password P@ssword01 -Verbose
```
