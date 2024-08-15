$passwd = ConvertTo-SecureString "StudXPassword@123" -AsPlainText -Force


New-LocalUser -Name studentX -Password $passwd 
Add-LocalGroupMember -Group Administrators -Member studentX
