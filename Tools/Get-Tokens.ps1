Function Get-Tokens
{
<#
    .SYNOPSIS
        Request new ID,Access,Refresh token using the existing Refresh token and the Client ID, Client Secrets

    .PARAMETER client_id
        Pass the application id that is generated once we register the application.

    .PARAMETER scope
        Define the Scope for the tokens.

    .PARAMETER refresh_token
        Pass the exisiting refresh token.

    .PARAMETER redirect_uri
        Pass the redirect uri entered while registering the application.

    .PARAMETER client_secret
        Pass the client secret entered while registering the application.

    .EXAMPLE
        PS C:\> Get-Tokens -client_id "987f176a-c29b-4699-8a41-d1b59ca3d790" -scope "https://graph.microsoft.com/.default openid offline_access" -refresh_token "0.AXEAUOJSlHFvAU-Lh1qyqKr8o2oXT4SbwZlGikHRs5yj1zBxABo" -redirect_uri "https://localhost/" -client_secret "_0As0tE8-Gr_6g.85j8ydP1dKf27oQ-8Ll"

    .EXAMPLE
        PS C:\> Get-Tokens -client_id "987f176a-c29b-4699-8a41-d1b59ca3d790" -scope "https://graph.microsoft.com/.default openid offline_access" -refresh_token "0.AXEAUOJSlHFvAU-Lh1qyqKr8o2oXT4SbwZlGikHRs5yj1zBxABo" -client_secret "_0As0tE8-Gr_6g.85j8ydP1dKf27oQ-8Ll"

    .LINK
        https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#refresh-the-access-token
#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$True)]
    [String]
    $client_id = $null,
    [Parameter(Mandatory=$True)]
    [String]
    $scope = $null,
    [Parameter(Mandatory=$True)]
    [String]
    $refresh_token = $null,
    [Parameter(Mandatory=$false)]
    [String]
    $redirect_uri = $null,
    [Parameter(Mandatory=$True)]
    [String]
    $client_secret = $null
    )

    $psobj = New-Object PSObject

    $Params = @{
    "URI"     = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    "Method"  = "POST"
    "Headers" = @{
        "Content-Type"  = "application/x-www-form-urlencoded"
        }
    }

    $Body = @{client_id=$client_id;
    scope=$scope;
    refresh_token=$refresh_token;
    redirect_uri=$redirect_uri;
    grant_type="refresh_token";
    client_secret=$client_secret;
    }

    $Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body

    Add-Member -InputObject $psobj -NotePropertyName "token_type" -NotePropertyValue $Result.token_type
    Add-Member -InputObject $psobj -NotePropertyName "scope" -NotePropertyValue $Result.scope
    Add-Member -InputObject $psobj -NotePropertyName "access_token" -NotePropertyValue $Result.access_token
    Add-Member -InputObject $psobj -NotePropertyName "refresh_token" -NotePropertyValue $Result.refresh_token
    Add-Member -InputObject $psobj -NotePropertyName "id_token" -NotePropertyValue $Result.id_token
    Write-Output $psobj
}