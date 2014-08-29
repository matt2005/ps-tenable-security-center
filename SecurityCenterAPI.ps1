##########################################################
#          Security Center PowerShell Connector          #
#                                                        #
#     For use with Tenable Network Security Center 4     #
#                                                        #
##########################################################
function global:Invoke-SecurityCenterRequest{
<#
    .SYNOPSIS
    This Cmdlet allows you to quickly and easily interact with Tennable's Network Security Center Product. 
 
    .DESCRIPTION
    This module allows you to quickly and easily interact with Tennable's Network Security Center Product. The product's API does some weird things that aren't very well documented- requires a mixmatch of JSON and URL-encoded parameters in different locations, as well as having some pretty random parameters.
 
    .EXAMPLE
    Invoke-SecurityCenterRequest -Endpoint https://myseccenter.local/request.php -User admin -Password admin -module asset -action init
    Returns a result object, containing a results hashtable containing assets as stored in Security Center

    .NOTES
    Be sure to be using a HTTPS endpoint- basic authentication is used.

    .LINK
    https://github.com/antmldr/ps-tenable-security-center
#>
[CmdletBinding()]
param(
    [parameter(Mandatory=$True, HelpMessage="http(s) endpoint (typically https://host.example/request.php)")]
    [string]$Endpoint,
    
    [parameter(Mandatory=$True, HelpMessage="SC API username, passed in using basic auth. Endpoint must support https for this to be encrypted!")] 
    [string]$User,

    [parameter(Mandatory=$True, HelpMessage="SC API password. Endpoint must support https for this to be encrypted!")]
    [string]$Password,

    [parameter(Mandatory=$True, HelpMessage="SC API Module")]
    [string]$Module,

    [parameter(Mandatory=$True, HelpMessage="SC API Action")]
    [string]$Action,

    [parameter(Mandatory=$False, HelpMessage="SC API Input, to be provided in a [System.Collectable.Hashtable]")]
    $Input
    )

    Begin
    {
        # $Params = @{ module (string), action (string), input (@{}) (Optnl),}
        function runCommand($params)
        {
            # Check that we were passed the correct parameters
            if (!$params.module){ write-error "Please provide a module name"; return; }
            if (!$params.action){ write-error "Please provide an action name"; return; }
    
            # If we're not logged in, perform login function
            if (!$session) { $session = loginToAPI }

            # Generate random request ID as not to conflict with a previous session
            $requestId = Get-Random -Minimum 10000 -Maximum 19999

            # Generate the request string
            $request = "request_id=" + $requestId + "&module=" + $params.module + "&action=" + $params.action + "&token=" + $session.token

            # If there is input for the command, convert the input into URL encoded JSON and concatenate
            if ($params.input)
            {
                $jsonInput = $params.input | ConvertTo-Json
                $encodedinput = [System.Web.HttpUtility]::UrlEncode($jsonInput)
                $request += ("&input=" + $encodedinput)
            }

            write-debug ("Performing API action: " + $request)
    
            # POST against the API
            $response = Invoke-RestMethod -Uri $Endpoint -Method Post -Body $request -WebSession $session.webSession

            # If the response code didn't equal zero, echo out the error the API provided
            if ($response.error_code -ne 0) 
                { Write-Warning ("Executing failed on " + $params.module+"::" + $params.action+" - " + $response.error_msg) }
            else
            { 
                write-debug ("Successfully executed " + $params.module+"::" + $params.action) 
                write-debug ("API responded with " + $response.response)
                return $response
            }
        }

        #Encode Credentials for API
        $credentials = @{ username = $user; password = $password } | ConvertTo-Json
        $encodedcreds = [System.Web.HttpUtility]::UrlEncode($credentials)
    
        $request = 'module=auth&action=login&input=' + $encodedcreds+'&request_id=1'
        write-debug ("Executing login request " + $request)

        $response = Invoke-RestMethod -Uri $Endpoint -Method Post -Body $request -SessionVariable webSession
        write-debug ("API Response from login request :" + $response)

        if ($response.error_code -eq 0) 
            { $session = @{ webSession = $webSession; token = $response.response.token } }
    }

    Process
    {
        $params = @{ module = $Module; action = $Action; input = $Input }
        return runCommand($params)
    }
}