$passwd = ConvertTo-SecureString "Stud213Password@123" -AsPlainText -Force


New-LocalUser -Name student213 -Password $passwd 
Add-LocalGroupMember -Group Administrators -Member student213
