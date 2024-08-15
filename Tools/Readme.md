https://github.com/mgeeky/AzureRT

Install-Module Az -Force -Confirm -AllowClobber -Scope AllUsers
Install-Module AzureAD -Force -Confirm -AllowClobber -Scope AllUsers
Install-Module Microsoft.Graph -Force -Confirm -AllowClobber -Scope AllUsers # OPTIONAL
Install-Module MSOnline -Force -Confirm -AllowClobber -Scope AllUsers        # OPTIONAL
Install-Module AzureADPreview -Force -Confirm -AllowClobber -Scope AllUsers  # OPTIONAL
Install-Module AADInternals -Force -Confirm -AllowClobber -Scope AllUsers    # OPTIONAL

Import-Module Az
Import-Module AzureAD
