# Enable strict mode for best practices
Set-StrictMode -Version Latest

# Powershell version check
if ($PSVersionTable.PSVersion.Major -ge 7){
    Write-Verbose "PowerShell version is 7 or higher"
    Write-Verbose "$PSVersionTable"
}
else{
    Write-Host -ForegroundColor DarkYellow "PowerShell version is lower than 7. Module requires PowerShell 7 or higher hence some of the modules won't work till you upgrade to Powershell 7 or higher"
}

function Get-HCSAccessToken {
    <#
        .NOTES
        .SYNOPSIS
            Generates the Access Token 
        .DESCRIPTION
            Generates Access token to run Cloud Service next-gen APIs, which can be generated from Omnissa Cloud Services Console(https://connect.omnissa.com/) My Account --> API Tokens
        .PARAMETER RefreshToken
            Copy refresh token previously generated from Cloud Services Console - https://connect.omnissa.com/
        .EXAMPLE
            Get-HCSAccessToken -RefreshToken $refreshToken
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$refreshToken
    )

    $body = @{
        refresh_token = $refreshToken
        grant_type    = 'refresh_token'
    }

    try {
        $results = Invoke-RestMethod -Uri "https://connect.omnissa.com/csp/gateway/am/api/auth/api-tokens/authorize" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"

        # Extract and store the access token
        $env:HCSAccessToken = $results.access_token

        $timeNow = Get-Date
        Write-Host "AccessToken generated successfully at $timeNow and saved to `$env:HCSAccessToken"
        Write-Host -ForegroundColor Yellow "AccessToken will expire in 30 minutes. Please re-run the command if expired."
    }
    catch {
        Write-Host -ForegroundColor Red "Failed to retrieve Cloud Service Access Token. Error: $($_.Exception.Message)"
    }
}

function Get-HCSAccessTokenValidity {
    <#
        .NOTES
        .SYNOPSIS  
            Checks the validity of the HCSAccessToken.  
        .DESCRIPTION  
            This command provides detailed information regarding the validity of the HCSAccessToken.  
        .PARAMETER token  
            You should copy the token generated from the Get-HCSAccessToken cmdlet, which is typically saved in the variable $env:HCSAccessToken.  
        .EXAMPLE  
            Get-HCSAccessTokenValidity -Token "$env:HCSAccessToken"
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$Token
    )
    #$token="$env:HCSAccessToken"
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { 
        Write-Error "Invalid token" -ErrorAction Stop 
    }

    # Token formatting
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }

    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json 

    # Convert Expiry time using epoch time
    $epochTime = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $tokenExpInUtc = $epochTime.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes 
    $expInUtc = $tokenExpInUtc.AddMinutes($offset)    
    $timeToExpire = $expInUtc - (Get-Date)
    # Print only below values in output
    $dataObj = New-Object -TypeName PSObject 
    $dataObj | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $expInUtc
    $dataObj | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpire

    return $dataObj
}

function Get-HCSEdge {
    <#  
        .SYNOPSIS  
            Retrieves Edge details for the specified OrgId.  
        .DESCRIPTION  
            This cmdlet fetches information about the edges deployed in a next-gen environment.  
            It may also provide additional insights regarding edge properties and their current status based on the `reportedStatus` parameter.
            When the orgId isn't mentioned , accesstoken orgId will be considered to provide the information
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER reportedStatus  
            A Boolean value. When set to $true, it retrieves the current status of the Edge.  
        .EXAMPLE  
            Get-HCSEdge  
        .EXAMPLE  
            Get-HCSEdge -OrgId f9b98412-658b-45db-a06b-000000000000  
        .EXAMPLE  
            Get-HCSEdge -OrgId f9b98412-658b-45db-a06b-000000000000 -reportedStatus $true
        .EXAMPLE
            # Get Overall Status of Edges in the specific Org

            Get-HCSEdge -OrgId f9b98412-658b-45db-a06b-000000000000 -reportedStatus $true| select Name,@{N="OverAll Status";E={$_.status}},@{N="Environment";E={$_.providerLabel}},@{N="Cloud Connectivity";E={$_.reportedStatus.deviceConnectionDetails.deviceStatus}}

            # Get Edge Module Status

            Get-HCSEdge -OrgId f9b98412-658b-45db-a06b-000000000000 -reportedStatus $true | select name,@{n='ADModuleStatus';e={foreach ($rs in $_.reportedStatus.moduleConnectionDetails){if($rs.moduleName -like "ad-module"){$rs.moduleStatus}}}},@{n='UAGModuleStatus';e={foreach ($rs in $_.reportedStatus.moduleConnectionDetails){if($rs.moduleName -like "sg-uag-module"){$rs.moduleStatus}}}},@{n='AVModuleStatus';e={foreach ($rs in $_.reportedStatus.moduleConnectionDetails){if($rs.moduleName -like "av-azure-module"){$rs.moduleStatus}}}},@{n='InfraAzureModuleStatus';e={foreach ($rs in $_.reportedStatus.moduleConnectionDetails){if($rs.moduleName -like "infra-azure-module"){$rs.moduleStatus}}}},@{n='AgentModuleStatus';e={foreach ($rs in $_.reportedStatus.moduleConnectionDetails){if($rs.moduleName -like "agent-module"){$rs.moduleStatus}}}} | ft

            # Get SSO Status

            Get-HCSEdge -OrgId f9b98412-658b-45db-a06b-002a5ed2db92 -reportedStatus $true | Select Name,@{N="SSOName";E={$_.ssoConfigurations.name}},@{N="SSOcaMode";E={$_.ssoConfigurations.caMode}},@{N="SSOcaType";E={$_.ssoConfigurations.caType}},@{N="SSO Status";E={$_.ssoConfigurations.status.message}} | ft



    #>
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = 'OrgId')]
        [String]$OrgId,

        [Parameter(Mandatory = $false)]
        [bool]$reportedStatus = $false
    )

    # Ensure access token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)
    
    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Renew the token using Get-HCSAccessToken and run the command again."
        return
    } else {
        Write-Verbose "Token is valid"
    }

    # Build base URL
    $baseUri = "https://cloud.omnissahorizon.com/admin/v2/edge-deployments"
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Prepare query parameters
    $queryParams = @{
        "size" = 200
        "sort" = "asc"
    }

    if ($OrgId) {
        $queryParams["org_id"] = $OrgId
        $queryParams["include_reported_status"] = $reportedStatus
    }

    # Construct the final URI with parameters
    $uri = $baseUri + "?" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
    Write-Verbose " URL - $uri "

    # Make the API call
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
        return $response.content
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSEdge: Unable to retrieve Edge details with the given search parameters"
        Write-Host -ForegroundColor Red ($_ | Out-String)
        return
    }
}

function Get-HCSUag {
    <#
    .SYNOPSIS
        Retrieves UAG details.
    .DESCRIPTION
        The Get-HCSUag cmdlet retrieves information about UAGs deployed in the next-gen environment.
        When the orgId isn't mentioned , accesstoken orgId will be considered to provide the information
    .PARAMETER OrgId
        The long OrgId for the organization. Copy and input the OrgId to this parameter.
    .EXAMPLE
        Get-HCSUag
    .EXAMPLE
        Get-HCSUag -OrgId f9b98412-658b-45db-a06b-000000000000
    .EXAMPLE
        # Get UAG Baisc / limited details

        Get-HCSUag -OrgId f9b98412-658b-45db-a06b-000000000000 | Select Name,@{N="Deployment Type";E={$_.type}},@{N="Enivronment";E={$_.providerLabel}},status,@{N="UAG URL";E={$_.fqdn}},@{N="UAGCert ExpiryDate";E={$_.sslCertificateTo.expiryDate}} | ft

        # Get the UAG Health Status

        $uag=Get-HCSUag -OrgId f9b98412-658b-45db-a06b-000000000000

          # LB Status

          $uag.reportedProperties | select uagDeploymentId,reportedLoadBalancerDetails

          # Each gateway Health details 

          $uag.reportedProperties.reportedGatewayDetails
    
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$OrgId
    )

    # Validate token
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)

    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Please renew the token using Get-HCSAccessToken and run the command again."
        return
    }

    Write-Verbose "Token is valid."

    # Base URI and headers
    $baseUri = "https://cloud.omnissahorizon.com/admin/v2/uag-deployments"
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Build URI based on OrgId presence
    $queryParams = @{
        "size" = 200
        "sort" = "asc"
    }

    if ($OrgId) {
        $queryParams["OrgId"] = $OrgId
    }

    # Construct the final URI with parameters
    $uri = $baseUri + "?" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
    Write-Verbose " URL - $uri "

    # Perform the API call
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
        return $response.content
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSUag: UAG details are not available with the given search parameters"
        Write-Host -ForegroundColor Red ($_ | Out-String)
        return
    }
}

function Get-HCSAD {
    <#
        .SYNOPSIS
            Gets the Active Directory details.
        .DESCRIPTION
            Retrieves information about the Active Directory configured with next-gen.
            Provides additional details about the Active Directory, Bind accounts, Join account, and its current status when using the reportedStatus parameter.
        .PARAMETER OrgId
            The long OrgId of the organization. Input this value to filter results by organization.
        .PARAMETER reportedStatus
            Boolean to indicate if the expanded Active Directory status should be reported. Defaults to $false.
        .EXAMPLE
            Get-HCSAD
        .EXAMPLE
            Get-HCSAD -OrgId f9b98412-658b-45db-a06b-000000000000
        .EXAMPLE
            Get-HCSAD -OrgId f9b98412-658b-45db-a06b-000000000000 -reportedStatus $true 
        .EXAMPLE
            # Get the current status of multiple Active Directory Domains

                $ADStatus=(Get-HCSAD -OrgId f9b98412-658b-45db-a06b-000000000000 -reportedStatus $true).reportedStatus

                $ADStatus

                $ADStatus."6450eb6b5d91f6xxxxxx"
        
    
     #>
     [CmdletBinding()]
     param(
         [ValidateNotNullOrEmpty()]
         [Parameter(Mandatory = $false)]
         [string]$OrgId,
 
         [Parameter(Mandatory = $false)]
         [bool]$reportedStatus = $false
     )
 
     $headers = @{
         'Authorization' = "Bearer $env:HCSAccessToken"
         'Accept'        = "*/*"
     }
 
     # Check token validity
     $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
     if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
         Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
         return
     }
     Write-Verbose "Token is valid"
 
     # Build base URL
     $urlBase = "https://cloud.omnissahorizon.com/admin/v2/active-directories"
 
     # Add query parameters based on input
     $queryParams = @{}
     if ($OrgId) {
         $queryParams['OrgId'] = $OrgId
     }
     if ($reportedStatus) {
         $queryParams['expanded'] = 'true'
     } else {
         $queryParams['expanded'] = 'false'
     }
     $queryParams['size'] = 200
     $queryParams['sort'] = 'asc'
 
     # Construct the URL with query parameters
     $uri = "$urlBase" + "?" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
     Write-Verbose " URL - $uri "

     # Invoke REST API and return results
     try {
         $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
         return $response.content
     } catch {
         Write-Host -ForegroundColor Red "Get-HCSAD: Unable to retrieve Active Directory details for OrgId $OrgId"
     }
}
 
function Get-HCSPool {
    <#
    .SYNOPSIS
        Gets the Horizon next-gen Pool details.
    .DESCRIPTION
        Retrieves information about the pools created in the next-gen system with configured properties.
        It can fetch all pools or specific pool details based on PoolId .
    .PARAMETER OrgId
        Organization ID (long OrgId).
    .PARAMETER PoolId
        Pool ID for a specific pool.
    .EXAMPLE
        Get-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000
    .EXAMPLE
        Get-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx
    .EXAMPLE

        # Get limited / basic details of All Pools

            Get-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 | select id,name,vmNamePattern,templateType

        # Get Pool subnets & available Ip's

            Get-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 | select Name,templateType,@{N="Subnet";E={$_.networks.data.name}},@{N="Available IPs";E={$_.networks.data.availableIpAddresses}}|ft


    #>
    
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolId
    )
    
    # Authorization header
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }
    
    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/admin/v2/templates"

    # Add query parameters based on input
    $queryParams = @{}
    $queryParams['size'] = 1000
    $queryParams['sort'] = 'asc'
    $queryParams['org_id'] = $OrgId

    if ($PoolId) {
        $queryParams['expanded'] = "all"

        # Construct the URL with query parameters
        $uri = "$baseUrl" + "/$PoolId" + "?" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
        Write-Verbose " URL - $uri "
    } else{
        # Construct the URL with query parameters
        $uri = "$baseUrl" + "?" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
        Write-Verbose " URL - $uri "
    }


    try{
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
        write-verbose $response
        #check if response has the content key
        if ($response.PSObject.Properties.Name -contains "content"){
            return $response.content
        } else{
            return $response
        }
        
    } catch {
        Write-Host -ForegroundColor Red "Get-HCSPool: Unable to retrieve Pool details"
        Write-Host ($_ | Out-String)
        return
    }
}

function Get-HCSPoolGroup {
    <#
    .SYNOPSIS
        Gets the Horizon next-gen Pool Group details.
    .DESCRIPTION
        Retrieves information about the pool groups created in the next-gen system with configured properties.
        It can fetch all pool groups details or specific pool group details based on PoolGroup Id .
    .PARAMETER OrgId
        Organization ID (long OrgId).
    .PARAMETER PoolGroupId
        PoolGroupID for a specific pool group.
    .EXAMPLE
        Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000
    .EXAMPLE
        Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolGroupId 66a2334g33xxxx
    .EXAMPLE

        # Get limited / basic details of All Pool Groups

            Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 | select Name,id,Type,@{N="PoolGroup Type";E={$_.templateType}},@{N="Pool Name";E={$_.templates.name}} | ft -AutoSize

        # Get Pool Group Details with PowerPolicy Modes

            Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 | select Name,id,Type,@{N="PoolGroup Type";E={$_.templateType}},@{N="Pool Name";E={$_.templates.name}},@{N="PowerPolicy Mode";E={$mode=$_.powerPolicy.occupancyPresetMode;if($mode -eq "DISABLED"){"Non-Occupancy"}else{"Occupancy"}}} | ft -AutoSize
        
        # Get Pool Group sessions details

            Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 | select Name,id,Type,@{N="PoolGroup Type";E={$_.templateType}},@{N="Total Possible Sessions";E={$_.reportedCapacity.provisionedSessions}},@{N="Total Assigned Sessions";E={$_.reportedCapacity.usedSessions}},@{N="Current Active Sessions(Connected+Disconnected)";E={$_.reportedCapacity.consumedSessions}} | ft -AutoSize
    #> 
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = 'OrgId')]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$IncludeInternalPools,
        [String]$IncludeDisabledPools,
        [String]$PoolGroupId,
        [String]$PoolGroupName
    )

    # Authorization header
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }
    
    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Build base API URL
    $baseUrl = "https://cloud.omnissahorizon.com/portal/v3/pools" + "?" + "size=1000&org_id=$OrgId"
    
    # Modify query params based on user input
    $queryParams = @{}
    $queryParams["exclude_disabled_pools"] = $IncludeDisabledPools -eq $false
    $queryParams["include_internal_pools"] = $IncludeInternalPools -eq $true

    # Add specific PoolGroup by Name or PoolGroupId
    if ($PSBoundParameters.ContainsKey('PoolGroupId')) {
        $baseUrl = "https://cloud.omnissahorizon.com/portal/v3/pools/$PoolGroupId" + "?" + "org_id=$OrgId"
    } elseif ($PSBoundParameters.ContainsKey('PoolGroupName')) {
        try {
            # Find PoolGroup Id based on PoolGroupName
            $responsePoolGroup = (Invoke-RestMethod -Uri "$baseUrl&exclude_disabled_pools=false&include_internal_pools=true" -Method Get -Headers $headers -ErrorAction Stop).content
            $PGId = ($responsePoolGroup | Where-Object { $_.name -like $PoolGroupName }).id
            Write-Verbose " $PoolGroupId is $PGId"
            $baseUrl = "https://cloud.omnissahorizon.com/portal/v3/pools/$PGId" + "?" + "org_id=$OrgId"
        } catch {
            Write-Host -ForegroundColor Red "Unable to retrieve PoolGroup Id for the provided PoolGroupName."
            return
        }
    }

    # Send the API request
    try {
        Write-Verbose " Fianl queryParams -  $queryParams.GetEnumerator() "
        $finalUrl = $baseUrl + "&" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
        Write-Verbose "Final constructed URL - $finalUrl"
        $finalResponse = (Invoke-RestMethod -Uri $finalUrl -Method Get -Headers $headers -ErrorAction Stop)
        if ($finalResponse.PSObject.Properties.Name -contains "content"){
            return $finalResponse.content
        } else{
            return $finalResponse
        }
    } catch {
        Write-Host -ForegroundColor Red "Unable to retrieve Pool Group details"
        $errorDetails = $_ | Out-String
        Write-Host $errorDetails
    }
}

function Get-HCSPoolVM {
    <#
    .SYNOPSIS
        Fetch all provisioned VM details in a specific pool of the Horizon next-gen environment.
    .DESCRIPTION
        Retrievesinformation about the virtual machines (VMs) created in the next-gen system, along with their configured properties. 
        It can fetch the details of all provisioned VMs based on the specified PoolId.
    .PARAMETER OrgId
        Organization ID (long OrgId).
    .PARAMETER PoolId
        Pool ID for a specific pool.
    .PARAMETER SessionDetails
        By including this parameter, the Get-HCSPoolVM command will display session details for all pool VMs or for a specific VM. 
        By default, this value is set to true.
    .PARAMETER ExcludeAssignedVM
        By default, ExcludeAssignedVM is set to false. If this parameter is added to Get-HCSPoolVM and set to true, the output will include VM details for those that are not assigned to any user.
    .PARAMETER VMId
       This is an optional parameter. If you need to fetch the details of a specific VM, provide the VM name here.
    .PARAMETER PoolName
        This parameter is not mandatory if PoolId is provided
    .EXAMPLE
        Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx
    .EXAMPLE
        Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId test-vm-001
    .EXAMPLE

        # Get limited / basic details of vm's in a specific pool 

            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66axxxxx | select id,powerState,lifecycleStatus,agentStatus,sessionPlacementStatus | ft -AutoSize

        # List all the vm's in a pool(s) with their image 'version'

            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000  -PoolName PoolA | select id,lifecycleStatus,powerState,haiAgentVersion,@{N="Image - Version";E={$imagedetails=($_.image);$pos=$imagedetails.IndexOf("/images/");$parts=(($imagedetails.SubString($pos+1)).Split("/"));$parts[1,3]}} | Format-Table

        # Listing Vm's in specific lifecycleStatus or powerstate and get the number of vm's count in that state

            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000  -PoolName PoolA | ?{$_.lifecycleStatus -eq "PROVISIONED"}).count
            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000  -PoolName PoolA | ?{$_.powerstate -eq "poweredOn" -and $_.lifecycleStatus -eq "PROVISIONED"}).count
            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000  -PoolName PoolA | ?{$_.powerstate -eq "poweredOff" -and $_.lifecycleStatus -eq "PROVISIONED"}).count
            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000  -PoolName PoolA | ?{$_.lifecycleStatus -eq "PROVISIONING"}).count
            Get-HCSPoolVM -OrgId f9b98412-658b-45db-a06b-000000000000  -PoolName PoolA | ?{$_.lifecycleStatus -eq "CUSTOMIZING"}).count

    #> 
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$SessionDetails,
        [String]$ExcludeAssignedVM,
        [String]$VMId,
        [String]$PoolId,
        [String]$PoolName
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Ensure PoolId & PoolName parameters are valid
    if ( !$PSBoundParameters.ContainsKey('PoolId') -and !$PSBoundParameters.ContainsKey('PoolName')) {
        Write-Host -ForegroundColor Red "Get-HCSPoolVM: Missing required parameters, Please Pass one of PoolId or PoolName"
        return
    }

    # Get Pool ID if not provided
    if (-not $PSBoundParameters.ContainsKey('PoolId') -and $PSBoundParameters.ContainsKey('PoolName')) {
        try {
            $PoolId = (Get-HCSPool -OrgId $OrgId | Where-Object { $_.name -like $PoolName }).id
            Write-Verbose "Pool ID: $PoolId"
        } catch {
            Write-Host -ForegroundColor Red "Error retrieving Pool ID for $PoolName"
            Write-Host ($_ | Out-String)
            return
        }
    }

    # Construct the base URL dynamically
    $url = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms?org_id=$OrgId"

    # Add query parameters based on input flags
    if ($SessionDetails -eq $true) {
        $url += "&include_sessions=true"
    } else {
        $url += "&include_sessions=false"
    }

    if ($ExcludeAssignedVM -eq $true) {
        $url += "&exclude_vms_with_no_available_sessions=true"
    } else {
        $url += "&exclude_vms_with_no_available_sessions=false"
    }

    # If VMId is provided, adjust the URL
    if ($PSBoundParameters.ContainsKey('VMId')) {
        $url = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId?org_id=$OrgId"
    }

    Write-Verbose " Final URL - $url"

    try {
        # Initial API call to get total pages
        $firstPage = Invoke-RestMethod -Uri "$url&size=1000" -Method Get -Headers $headers -ErrorAction Stop
        $totalPages = $firstPage.totalPages
        $allResults = $firstPage.content

        # Pagination: Fetch all pages
        for ($page = 1; $page -lt $totalPages; $page++) {
            $pagedUrl = "$url&page=$page&size=1000"
            Write-Verbose " Pagination URL - $pagedUrl "
            $pagedResults = Invoke-RestMethod -Uri $pagedUrl -Method Get -Headers $headers -ErrorAction Stop
            $allResults += $pagedResults.content
        }
        return $allResults
    } catch {
        Write-Host -ForegroundColor Red "Get-HCSPoolVM: Error retrieving Pool VM details."
        Write-Host ($_ | Out-String)
        return
    }
}

function Get-HCSProvider {
    <#
    .SYNOPSIS
        Gets the Horizon next-gen provider details 
    .DESCRIPTION
        Get-HCSProvider cmdlet retrieves all the providers configured 
        A capacity provider is the supported hypervisors and cloud platforms that provide the necessary resource capacity to provision and deliver desktops and applications to end-users.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER Environment
        Environment Parameter accepts azure or view or vsphere or aws or gcp or nutanix or WINDOWS_365
    .PARAMETER reportedStatus
        reportedStatus parameter accepts a boolean value of $true or $false as input. When set to $true, it retrieves the current status of Provider. 
    .EXAMPLE
        Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure
    .EXAMPLE
        Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure -reportedStatus $true
    .EXAMPLE
        # Get each provider health details

            Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure -reportedStatus $true | Select Name,Id,@{N="Status";E={if($_.healthStatusDetails){$_.healthStatusDetails.providerInstanceHealthStatus}else{"NotInUse"}}}

        # Get the Subscription , application id details 
            Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure | select Name,id,@{N="SubscriptionId";E={$_.providerDetails.data.subscriptionId}},@{N="DirectoryId";E={$_.providerDetails.data.directoryId}},@{N="ApplicationId";E={$_.providerDetails.data.applicationId}},@{N="Azure Region";E={$_.providerDetails.data.region}} | ft -AutoSize

        # Get the Health & Datacenter details

            Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure -reportedStatus $true | Select Name,Id,@{N="Status";E={if($_.healthStatusDetails){$_.healthStatusDetails.providerInstanceHealthStatus}else{"NotInUse"}}},@{N="HDC Name";E={$_.hdc.name}},@{N="HDC Url";E={$_.hdc.url}},@{N="HDC vmHub Url";E={$_.hdc.vmHubURL}},@{N="HDC vmHub Name";E={$_.hdc.vmHub.name}} | ft -AutoSize
    #>
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$reportedStatus,
        [String]$Id,
        [String]$Environment = "Azure"

    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"
    
    # Base URL for the API Call
    $baseUrl = "https://cloud.omnissahorizon.com/admin/v2/providers/$Environment/instances?OrgId=$OrgId&size=200&sort=asc"

    # Append Parameters Based on reportedStatus
    if ($reportedStatus -eq $true -and !$Id) {
        $baseUrl += "&include_health_details=true"
    } elseif (!$reportedStatus -eq $true -and $Id) {
        $baseUrl = "https://cloud.omnissahorizon.com/admin/v3/providers/instances/$id" + "?include_health_details=true&org_id=$OrgId"
    } elseif (!$reportedStatus -eq $true -and !$Id) {
        $baseUrl += "&include_health_details=false"
    } else {
        $baseUrl += "&include_health_details=false"
    }
    write-Verbose $baseUrl

    # Perform API Call
    try {
        $response = (Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop)
        write-Verbose $response
        if($response.psobject.properties | Where-Object {$_.Name -eq "content"}){
            return $response.content
        } else{
            return $response
        }
        
    } catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSProvider: Error retrieving Provider details with given search parameters"
        Write-Host ($_ | Out-String)
    }
}

function Get-HCSNetworks {
    <#
    .SYNOPSIS
        Gets VNET details of a specirfic provider 
    .DESCRIPTION
        Get-HCSNetworks cmdlet returns all azure networks (VNET) associated to specific provider.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER Environment
        Environment Parameter accepts azure or view or vsphere or aws or gcp or nutanix or WINDOWS_365
    .PARAMETER ProviderId
        Every provider name is associated with a unique ID, and this information can be retrieved from the Get-HCSProvider cmdlet.
    .PARAMETER Preffered
        The parameter accepts a boolean value of $true or $false as input. When set to $true, the output will include only the networks that have been selected in the provider.   
    .EXAMPLE
        Get-HCSNetworks -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure -ProviderId 60009e8c0e2493ed4bf600 -Preffered $true
    .EXAMPLE
        Get-HCSNetworks -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure -ProviderId 60009e8c0e2493ed4bf600 -Preffered $false
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [String]$Environment = "azure",
        [String]$ProviderId,
        [System.Boolean]$Preffered,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$ProviderName
    )

    # Set Authorization Headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "application/json"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    } 
    Write-Verbose "Token is valid"

    # Convert Environment to Lowercase
    try {
        $Environment = $Environment.ToLower()
    } catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSNetworks: Unable to convert the Environment info to lowercase"
        Write-Host ($_ | Out-String)
        return
    }


    # Determine Base URL
    $baseUrl = if ($Preffered -eq $true) {
        "https://cloud.omnissahorizon.com/admin/v2/providers/$Environment/instances/$ProviderId/preferences/networks"
    } else {
        "https://cloud.omnissahorizon.com/admin/v2/providers/$Environment/instances/$ProviderId/networks?OrgId=$OrgId&size=200&sort=asc"
    }

    # Try to Fetch the Data
    try {
        $response = (Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop)
        if ($Preffered -eq $false) { return $response.content } else { return $response }
    } catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSNetworks: Unable to fetch network details"
        Write-Host ($_ | Out-String)
        return
    }
}

function Get-HCSSubnets {
    <#
    .SYNOPSIS
        Gets Subnets information of a vnet 
    .DESCRIPTION
        Get-HCSSubnets cmdlet returns subnets details for a provided VnetId.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER Environment
        Environment Parameter accepts azure or view or vsphere or aws or gcp or nutanix or WINDOWS_365
    .PARAMETER ProviderId
        Every provider name is associated with a unique ID, and this information can be retrieved from the Get-HCSProvider cmdlet.
    .PARAMETER VnetId
        vnet id can be retrieved from Get-HCSNetworks   
    .EXAMPLE
        Get-HCSSubnets -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure -ProviderId 60009e8c0e2493ed4bf600 -VnetId ""
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$Environment,
        [String]$ProviderId,
        [String]$VnetId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$ProviderName
    )

    # Convert Environment to Lowercase
    try {
        $Environment = $Environment.ToLower()
    } catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSSubnets: Unable to convert the Environment info to lowercase"
        Write-Host ($_ | Out-String)
        return
    }

    # Set Authorization Headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "application/json"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Subnet info from the Azure for the above provider instanse
    try {
        $subnetData = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/admin/v2/providers/$Environment/instances/$ProviderId/networks/subnets?network_id=$VnetId&OrgId=$OrgId&size=200&sort=asc") -Method Get -Headers $headers -ErrorAction Stop).content
        return $subnetData    
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSSubnets: Unable fetch Network Details "
        Write-Host ($_ | Out-String)
        return
    }


}

function Start-HCSVM {
    <#
    .SYNOPSIS
        Start a Single VM
    .DESCRIPTION
        This cmdlet helps in powering on the vm if it's in the powered-off state
        if the vm in a state other than powered-off then it will skip executing the command
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER PoolId
        Please provide the poolid for a specific pool
    .PARAMETER VMId
        Please provide the VMName
    .PARAMETER PoolName
        PoolName is an optional parameter , provide the poolname for a specific pool if needed
    .EXAMPLE
        Start-HCSVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId "vdi001"
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$PoolId,
        [String]$VMId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolName
    )

    # Ensure access token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)
    
    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Renew the token using Get-HCSAccessToken and run the command again."
        return
    } else {
        Write-Verbose "Token is valid"
    }
    

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Check if OrgId, PoolId, and VMId are provided
    if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolId') -and $PSBoundParameters.ContainsKey('VMId'))) {
        Write-Host -ForegroundColor Red "Start-HCSVM: Please check the provided search parameters"
        return
    }

    # Check if PoolId exists in the OrgId
    try {
        $PoolIdExistsCheck = (Get-HCSPool -OrgId $OrgId -PoolId $PoolId).id
        Write-Verbose "Pool Details - $PoolIdExistsCheck"
        if ($PoolId -ne $PoolIdExistsCheck) {
            Write-Host -ForegroundColor Red "Start-HCSVM: PoolId not found"
            return
        }
    } catch {
        Write-Host -ForegroundColor Red "Start-HCSVM: Error retrieving PoolId details"
        Write-Host ($_ | Out-String)
        return
    }

    # Check if the VM exists and is valid
    try {
        $urlVMInfo = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "org_id=$OrgId"
        $dataVMInfo = (Invoke-RestMethod -Uri $urlVMInfo -Method Get -Headers $headers -ErrorAction Stop)
        Write-Verbose "VM Details - $dataVMInfo"
        if ($VMId -ne $dataVMInfo.id) {
            Write-Host -ForegroundColor Red "Start-HCSVM: Invalid VMId"
            return
        }

        Write-Verbose "$VMId is Valid"
    } catch {
        Write-Host -ForegroundColor Red "Start-HCSVM: Unable to find VM details, please check VMId"
        Write-Host ($_ | Out-String)
        return
    }

    # Start the VM if it's powered off
    try {
        if ($dataVMInfo.powerState -eq "PoweredOff") {
            $urlVMPowerOn = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "action=powerOn&org_id=$OrgId"
            Write-Verbose "URL for PowerOn: $urlVMPowerOn"

            $datavmPowerOn = (Invoke-WebRequest -Uri $urlVMPowerOn -Method Post -Headers $headers -ErrorAction Stop)
            Write-Verbose "PowerOn details - $datavmPowerOn"
            if ($datavmPowerOn.StatusCode -eq "202" -and $datavmPowerOn.StatusDescription -eq "Accepted") {
                Write-Host "Start-HCSVM: PowerON request for $VMId is accepted"
            }
        } else {
            Write-Verbose "$VMId is already in $($dataVMInfo.powerState) state"
            Write-Host "$VMId is in $($dataVMInfo.powerState) state, hence PowerON not issued"
        }
    } catch {
        Write-Host -ForegroundColor Red "Start-HCSVM: Unable to PowerON VM, please check the error"
        Write-Host ($_ | Out-String)
    }
}

function Stop-HCSVM {
    <#
    .SYNOPSIS
        Stop a Single VM
    .DESCRIPTION
        This cmdlet helps in power-off the vm 
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER PoolId
        Please provide the poolid for a specific pool
    .PARAMETER VMId
        Please provide the VMName
    .PARAMETER PoolName
        Please provide the poolname for a specific pool
    .EXAMPLE
        Stop-HCSVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId "vdi001"
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$PoolId,
        [String]$VMId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolName
    )

    # Ensure access token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)
    
    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Renew the token using Get-HCSAccessToken and run the command again."
        return
    } else {
        Write-Verbose "Token is valid"
    }
    

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Check if OrgId, PoolId, and VMId are provided
    if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolId') -and $PSBoundParameters.ContainsKey('VMId'))) {
        Write-Host -ForegroundColor Red "Stop-HCSVM: Please check the provided search parameters"
        return
    }

    # Check if PoolId exists in the OrgId
    try {
        $PoolIdExistsCheck = (Get-HCSPool -OrgId $OrgId -PoolId $PoolId).id
        Write-Verbose "Pool Details - $PoolIdExistsCheck"
        if ($PoolId -ne $PoolIdExistsCheck) {
            Write-Host -ForegroundColor Red "Stop-HCSVM: PoolId not found"
            return
        }
    } catch {
        Write-Host -ForegroundColor Red "Stop-HCSVM: Error retrieving PoolId details"
        Write-Host ($_ | Out-String)
        return
    }

    # Check if the VM exists and is valid
    try {
        $urlVMInfo = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "org_id=$OrgId"
        $dataVMInfo = (Invoke-RestMethod -Uri $urlVMInfo -Method Get -Headers $headers -ErrorAction Stop)
        Write-Verbose "VM Details - $dataVMInfo"
        if ($VMId -ne $dataVMInfo.id) {
            Write-Host -ForegroundColor Red "Stop-HCSVM: Invalid VMId"
            return
        }

        Write-Verbose "$VMId is Valid"
    } catch {
        Write-Host -ForegroundColor Red "Stop-HCSVM: Unable to find VM details, please check VMId"
        Write-Host ($_ | Out-String)
        return
    }

    # Stop the VM if it's powered ON
    try {
        if ($dataVMInfo.powerState -eq "PoweredOn") {
            $urlvmpowerOff = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "action=powerOff&org_id=$OrgId"
            Write-Verbose "URL for PowerOff: $urlvmpowerOff"

            $datavmpowerOff = (Invoke-WebRequest -Uri $urlvmpowerOff -Method Post -Headers $headers -ErrorAction Stop)
            Write-Verbose "PowerOff details - $datavmpowerOff"
            if ($datavmpowerOff.StatusCode -eq "202" -and $datavmpowerOff.StatusDescription -eq "Accepted") {
                Write-Host "Stop-HCSVM: PowerOff request for $VMId is accepted"
            }
        } else {
            Write-Verbose "$VMId is already in $($dataVMInfo.powerState) state"
            Write-Host "$VMId is in $($dataVMInfo.powerState) state, hence PowerOff not issued"
        }
    } catch {
        Write-Host -ForegroundColor Red "Stop-HCSVM: Unable to PowerOff VM, please check the error"
        Write-Host ($_ | Out-String)
    }
}

function Restart-HCSVM {
    <#
    .SYNOPSIS
        Restart a Single VM
    .DESCRIPTION
        This cmdlet helps in restarting a vm 
        Restart will be issued when the vm power states are PoweredOn / PoweredOff
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER PoolId
        Please provide the poolid for a specific pool
    .PARAMETER VMId
        Please provide the VMName
    .PARAMETER PoolName
        Please provide the poolname for a specific pool
    .EXAMPLE
        Restart-HCSVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId "vdi001"
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$PoolId,
        [String]$VMId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolName
    )

    # Ensure access token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)
    
    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Renew the token using Get-HCSAccessToken and run the command again."
        return
    } else {
        Write-Verbose "Token is valid"
    }
    

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Check if OrgId, PoolId, and VMId are provided
    if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolId') -and $PSBoundParameters.ContainsKey('VMId'))) {
        Write-Host -ForegroundColor Red "Restart-HCSVM: Please check the provided search parameters"
        return
    }

    # Check if PoolId exists in the OrgId
    try {
        $PoolIdExistsCheck = (Get-HCSPool -OrgId $OrgId -PoolId $PoolId).id
        Write-Verbose "Pool Details - $PoolIdExistsCheck"
        if ($PoolId -ne $PoolIdExistsCheck) {
            Write-Host -ForegroundColor Red "Restart-HCSVM: PoolId not found"
            return
        }
    } catch {
        Write-Host -ForegroundColor Red "Stop-HCSVM: Error retrieving PoolId details"
        Write-Host ($_ | Out-String)
        return
    }

    # Check if the VM exists and is valid
    try {
        $urlVMInfo = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "org_id=$OrgId"
        $dataVMInfo = Invoke-RestMethod -Uri $urlVMInfo -Method Get -Headers $headers -ErrorAction Stop
        Write-Verbose "VM Details - $dataVMInfo"
        if ($VMId -ne $dataVMInfo.id) {
            Write-Host -ForegroundColor Red "Restart-HCSVM: Invalid VMId"
            return
        }
        Write-Verbose "$VMId is Valid"
    } catch {
        Write-Host -ForegroundColor Red "Restart-HCSVM: Unable to find VM details, please check VMId"
        Write-Host ($_ | Out-String)
        return
    }

    # Restart a vm if  it's in PoweredOn / PoweredOff state
    try {
        if ($dataVMInfo.powerState -eq "PoweredOn" -or $dataVMInfo.powerState -eq "PoweredOff") {
            $urlvmrestart = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "action=restart&org_id=$OrgId"
            Write-Verbose "URL for restart: $urlvmrestart"

            $datavmrestart = (Invoke-WebRequest -Uri $urlvmrestart -Method Post -Headers $headers -ErrorAction Stop)
            Write-Verbose "Restart details - $datavmrestart"
            if ($datavmrestart.StatusCode -eq "202" -and $datavmrestart.StatusDescription -eq "Accepted") {
                Write-Host "Restart-HCSVM: Restart request for $VMId is accepted"
            }
        } else {
            Write-Verbose "$VMId is already in $($dataVMInfo.powerState) state"
            Write-Host "$VMId is in $($dataVMInfo.powerState) state, hence Restart not issued"
        }
    } catch {
        Write-Host -ForegroundColor Red "Restart-HCSVM: Unable to Restart VM, please check the error"
        Write-Host ($_ | Out-String)
    }
}

function Remove-HCSVM {
    <#
    .SYNOPSIS
        Deletes a VM
    .DESCRIPTION
       The Remove-HCSVM cmdlet removes the virtual machine (VM) from a Pool. 
       When the ignore_warnings parameter is set to $true, all warning messages are disregarded, allowing for the forced deletion of the VM.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER VMId
        Please provide the VMID which is the VM Name
    .PARAMETER ignore_warnings
        parameter accepts a boolean value of $true or $false as input. When set to $true, all warning messages are disregarded, allowing for the forced deletion of the VM
    .PARAMETER PoolName
        Please provide the poolname for a specific pool and it's an optional parameter
    .EXAMPLE
        Remove-HCSVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId NexgenVM1
    .EXAMPLE
        emove-HCSVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId NexgenVM1 -ignore_warnings $true
    .EXAMPLE
        Remove-HCSVM -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 66a2334g33xxxx -VMId NexgenVM1 -ignore_warnings $false
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$PoolId,
        [String]$VMId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$ignore_warnings = "false"
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "*/*"
    }

    # Ensure access token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)
    
    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Renew the token using Get-HCSAccessToken and run the command again."
        return
    } else {
        Write-Verbose "Token is valid"
    }

    # Check if PoolId exists in the OrgId
    try {
        $PoolIdExistsCheck = (Get-HCSPool -OrgId $OrgId -PoolId $PoolId).id
        Write-Verbose "Pool Details - $PoolIdExistsCheck"
        if ($PoolId -ne $PoolIdExistsCheck) {
            Write-Host -ForegroundColor Red "Remove-HCSVM: PoolId not found"
            return
        }
    } catch {
        Write-Host -ForegroundColor Red "Remove-HCSVM: Error retrieving PoolId details"
        Write-Host ($_ | Out-String)
        return
    }

    # Check if the VM exists and is valid
    try {
        $urlVMInfo = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId/vms/$VMId" + "?" + "org_id=$OrgId"
        $dataVMInfo = (Invoke-RestMethod -Uri $urlVMInfo -Method Get -Headers $headers -ErrorAction Stop)
        Write-Verbose "VM Details - $dataVMInfo"
        if ($VMId -ne $dataVMInfo.id) {
            Write-Host -ForegroundColor Red "Remove-HCSVM: Invalid VMId"
            return
        }

        Write-Verbose "$VMId is Valid"
    } catch {
        Write-Host -ForegroundColor Red "Remove-HCSVM: Unable to find VM details, please check VMId"
        Write-Host ($_ | Out-String)
        return
    }

    # Ensure all parameters are valid
    if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolName') -and $PSBoundParameters.ContainsKey('VMId'))) {
        Write-Host -ForegroundColor Red "Remove-HCSVM: Missing required parameters"
        return
    }

    if ($null -ne $dataVMInfo) {
        $vmPowerState = $dataVMInfo.powerState

        # Proceed with deletion if the VM is powered on or off
        if ($vmPowerState -in @("PoweredOff", "PoweredOn")) {
            try {
                $urlDeleteVM = "https://cloud.com/admin/v2/templates/$PoolId/vms/$VMId?org_id=$OrgId&ignore_warnings=$ignore_warnings"
                $deleteResponse = (Invoke-WebRequest -Uri $urlDeleteVM -Method DELETE -Headers $headers -ErrorAction Stop)

                if ($deleteResponse.StatusCode -eq "202" -and $deleteResponse.StatusDescription -eq "Accepted") {
                    Write-Host "Remove-HCSVM: Deletion request for $VMId is accepted"
                } else {
                    Write-Host -ForegroundColor Red "Remove-HCSVM: Deletion request failed for $VMId"
                    Write-Host ($_ | ConvertFrom-Json | Out-String)
                    return
                }
            } catch {
                Write-Host -ForegroundColor Red "Remove-HCSVM: Unable to delete VM $VMId"
                Write-Host ($_ | ConvertFrom-Json | Out-String)
                return
            }
        } else {
            Write-Host -ForegroundColor Yellow "Remove-HCSVM: VM $VMId is in $vmPowerState state, hence DELETE isn't issued"
        }
    } else {
        Write-Host -ForegroundColor Yellow "Remove-HCSVM: VM $VMId does not exist"
    }
}

function Remove-HCSPoolGroup {
    <#
    .SYNOPSIS
        Deletes a PoolGroup
    .DESCRIPTION
       The Remove-HCSPoolGroup cmdlet removes the specific PoolGroup. 
       When the force parameter is set to $true, all warning messages are disregarded, allowing for the forced deletion of the PoolGroup.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER PoolGroupName
        Please provide the PoolGroup Name for a specific pool
    .PARAMETER force
        parameter accepts a boolean value of $true or $false as input. When set to $true, all warning messages are disregarded, allowing for the forced deletion of the PoolGroup
    .EXAMPLE
        Remove-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolGroupName NextgenPoolGroup1 
    .EXAMPLE
        Remove-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolGroupName NextgenPoolGroup1 -force $true
    .EXAMPLE
        Remove-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolGroupName NextgenPoolGroup1 -force $false
    .EXAMPLE
        Remove-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolGroupId 6624xxxxxxx -force $false
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolGroupName,
        [String]$PoolGroupId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$force = "false"
    )

    # Ensure access token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currentTime = (Get-Date).AddMinutes(5)
    
    if ($currentTime -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired. Renew the token using Get-HCSAccessToken and run the command again."
        return
    } else {
        Write-Verbose "Token is valid"
    }

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Ensure PoolGroupId & PoolGroupName parameters are valid
    if (!$PSBoundParameters.ContainsKey('PoolGroupId') -and !$PSBoundParameters.ContainsKey('PoolGroupName')) {
        Write-Host -ForegroundColor Red "Remove-HCSPoolGroup: Missing required parameters, Please pass one of PoolGroupId or PoolGroupName"
        return
    }

    # Function to handle DELETE requests
    function Invoke-DeleteRequest {
        param (
            [String]$PoolGroupId,
            [String]$disassociateAction = 'FORCEFUL',
            [String]$deleteFlag = 'false'
        )

        $urlpg = "https://cloud.omnissahorizon.com/portal/v3/pools/$PoolGroupId" + "?" + "delete=$deleteFlag&org_id=$OrgId&disassociateAction=$disassociateAction"
        try {
            $dataPGDel = Invoke-WebRequest -Uri $urlpg -Method DELETE -Headers $headers -ErrorAction Stop
            if ($dataPGDel.StatusCode -eq "202" -and $dataPGDel.StatusDescription -eq "Accepted") {
                Write-Host "Remove-HCSPoolGroup: Deletion request for $PoolGroupName is accepted"
            } else {
                Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPoolGroup: Deletion request for $PoolGroupName failed"
                return $dataPGDel
            }
        } catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPoolGroup: Unable to delete $PoolGroupName"
            Write-Host ($_.Exception.Message)
        }
    }

    # Retrieve PoolGroup ID
    if (-not $PSBoundParameters.ContainsKey('PoolGroupId') -and $PSBoundParameters.ContainsKey('PoolGroupName')) {
        try{
            $PoolGroup = (Get-HCSPoolGroup -OrgId $OrgId -PoolGroupName $PoolGroupName)
            Write-Verbose "PoolGroup Details - $PoolGroup"
            if ($PoolGroupName -ne $PoolGroup.name) {
                Write-Host "Remove-HCSPoolGroup: $PoolGroupName does not seem to exist, please check for any trialing spaces in the name"
                return
            }
            $PoolGroupId = $PoolGroup.id
            Write-Verbose " Pool Group Id is - $PoolGroupId "
        } catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPoolGroup: Error retrieving PoolGroup Details , Please check the PoolGroup Name"
            Write-Host ($_.Exception.Message)
            return
        }
    }

    # Retrieve Existing Sessions
    try {
        $existingSessions = $PoolGroup.reportedCapacity.consumedSessions
        Write-Verbose "$PoolGroupName has $existingSessions sessions"
    } catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPoolGroup: Error retrieving PoolGroup session details"
        Write-Host ($_.Exception.Message)
        return
    }

    # Main Logic for Deletion
    if ($existingSessions -eq 0) {
        Invoke-DeleteRequest -PoolGroupId $PoolGroupId -deleteFlag $force
    } else {
        Write-Host -ForegroundColor Red "Active User Count on the PoolGroup: $existingSessions"
        Write-Host "Log off active users:"
        Write-Host "1. Immediately"
        Write-Host "2. After active sessions end"
        $choice = Read-Host "Enter your choice (1 or 2)"

        if ($choice -eq '1') {
            Invoke-DeleteRequest -PoolGroupId $PoolGroupId -disassociateAction 'FORCEFUL'
        } elseif ($choice -eq '2') {
            Invoke-DeleteRequest -PoolGroupId $PoolGroupId -disassociateAction 'GRACEFUL'
        } else {
            Write-Host -ForegroundColor Red "Invalid input, please enter 1 or 2"
        }
    }
}

function Remove-HCSPool {
    <#
    .SYNOPSIS
        Deletes a Pool
    .DESCRIPTION
       The Remove-HCSPool cmdlet removes the specific Pool. 
       When the force parameter is set to $true, all warning messages are disregarded, allowing for the forced deletion of the Pool.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER PoolName
        Please provide the Pool Name for a specific pool
    .PARAMETER force
        parameter accepts a boolean value of $true or $false as input. When set to $true, all warning messages are disregarded, allowing for the forced deletion of the Pool
        By default the force is false
    .EXAMPLE
        Remove-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolName NextgenPool1 
    .EXAMPLE
        Remove-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 666axxxxxxxx
    .EXAMPLE
        Remove-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolName NextgenPool1 -force $true
    .EXAMPLE
        Remove-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 666axxxxxxxx -force $true
    .EXAMPLE
        Remove-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 666axxxxxxxx -force $false
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [String]$PoolName,
        [String]$PoolId,
        [String]$force = $false
    )
    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "application/json"
    }

    # Ensure all parameters are valid
    if (!$PSBoundParameters.ContainsKey('PoolId') -and !$PSBoundParameters.ContainsKey('PoolName')) {
        Write-Host -ForegroundColor Red "Remove-HCSPool: Missing required parameters, Please pass one of PoolId or PoolName"
        return
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Retrieve Pool ID
    if (-not $PSBoundParameters.ContainsKey('PoolId') -and $PSBoundParameters.ContainsKey('PoolName')) {
        try{
            $Pool = (Get-HCSPool -OrgId $OrgId | Where-Object { $_.name -like $PoolName })
            Write-Verbose "Pool Details - $Pool"
            if ($PoolName -ne $Pool.name) {
                Write-Host "Remove-HCSPool: $PoolName does not seem to exist, please check for any trialing spaces in the name"
                return
            }
            $PoolId = $Pool.id
            Write-Verbose " Pool Id is - $PoolId "
        } catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPool: Error retrieving Pool Details , Please check the Pool Name"
            Write-Host ($_.Exception.Message)
            return
        }
    }
    # Helper function to handle DELETE requests
    function Invoke-PoolDeleteRequest {
        param (
            [String]$PoolId,
            [String]$force = $false
        )

        $urlPoolDetails = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId" + "?" + "org_id=$OrgId&force=$force"
        try {
            $dataPoolDelete = Invoke-WebRequest -Uri $urlPoolDetails -Method DELETE -Headers $headers -ErrorAction Stop
            if ($dataPoolDelete.StatusCode -eq "202" -and $dataPoolDelete.StatusDescription -eq "Accepted") {
                Write-Host "Remove-HCSPool: Deletion request for $PoolName is accepted"
            } else {
                Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPool: Deletion request for $PoolName failed"
                Write-Host ($_.Exception.Message)
                return
            }
        } catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Remove-HCSPool: Unable to delete $PoolName"
            Write-Host ($_.Exception.Message)
            return
        }
    }

    # Pool Deletion Logic
    Invoke-PoolDeleteRequest -PoolId $PoolId -force $force
}

function Get-HCSImage {
    <#
    .SYNOPSIS
        Retrieves Image details in a specific org
    .DESCRIPTION
        The Get-HCSImage cmdlet is utilized to retrieve information about the Images created in next-gen . 
        When the Get-HCSImage cmdlet is used with OrgID, it will provide details of all the images created in that Org.
        Furthermore, when the cmdlet is used with OrgID and ImageID, it retrieves the configured properties of a specific image. 
        Similarly, when used with OrgID and ImageName, it retrieves the  properties of a specific image.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageId
        Please provide the ImageId for a specific pool
    .PARAMETER ImageName
        Please provide the ImageName for a specific pool
    .EXAMPLE
        Get-HCSImage
    .EXAMPLE
        Get-HCSImage -OrgId f9b98412-658b-45db-a06b-000000000000
    .EXAMPLE
        Get-HCSImage -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 667500dd39d000023f7d5fd    
    .EXAMPLE
        Get-HCSImage -OrgId f9b98412-658b-45db-a06b-000000000000 | select id,name,os,multiSession
        
        Get-HCSImage -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageName "NextGenImage1"
    #>
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = 'OrgId')]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$ImageId,
        [String]$ImageName
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images?org_id=$OrgId"

    # Fetch images based on parameters
    try {
        if ($ImageId) {
            # Fetch by ImageId
            $imageUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images/$ImageId" + "?" + "org_id=$OrgId"
            return (Invoke-RestMethod -Uri $imageUrl -Method Get -Headers $headers -ErrorAction Stop)
        }
        elseif ($ImageName) {
            # Fetch all images and search by ImageName
            $imageData = (Invoke-RestMethod -Uri "$baseUrl&size=1000" -Method Get -Headers $headers -ErrorAction Stop).content
            Write-Verbose "All Images Information - $imageData"
            $image = $imageData | Where-Object { $_.name -eq $ImageName }
            if ($image) {
                $imageUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images/$($image.id)" + "?" + "org_id=$OrgId"
                return (Invoke-RestMethod -Uri $imageUrl -Method Get -Headers $headers -ErrorAction Stop)
            } else {
                Write-Host -ForegroundColor Red "Get-HCSImage: Image with name $ImageName not found"
                Write-Host $_.Exception.Message
            }
        }
        else {
            # Return all images if no specific ImageId or ImageName provided
            return (Invoke-RestMethod -Uri "$baseUrl&size=1000" -Method Get -Headers $headers -ErrorAction Stop).content
        }
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSImage: Error retrieving image details, Please check provided parameters"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSImageId {
    <#
    .SYNOPSIS
        Retrieves ImageID of a specific image
    .DESCRIPTION
        The Get-HCSImageId cmdlet is used to retrieve the ImageId of a particular image 
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageName
        Please specify the ImageName for which you need to retrieve the ImageId.
    .EXAMPLE
        Get-HCSImageId -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageName W10-Image-01
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$ImageName
    )  
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 'Accept' = "*/*";
    }
    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry) {
        Write-Verbose "Token is valid"
    }
    else {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        break
    }

    #Find the ImageId
    try {
        $imageUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images?size=1000&org_id=$OrgId"
        $images_info_complete = (Invoke-RestMethod -Uri $imageUrl -Method Get -Headers $headers -ErrorAction Stop).content

        # Use Where-Object to find the image by name
        $image = $images_info_complete | Where-Object { $_.name -eq $ImageName }

        if ($image) {
            return $image.id
        } else {
            Write-Host -ForegroundColor Red "Get-HCSImageId: Image with name $ImageName not found"
            return
        }
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSImageId: Unable to retrieve ImageId with given ImageName"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSImageVersion {
    <#
    .SYNOPSIS
        Retrieves ImageVersion details ofa  particular image
    .DESCRIPTION
        The Get-HCSImageVersion cmdlet is used to retrieve the ImageVersion of a particular image 
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageId
        Please specify the ImageId for which you need to retrieve the ImageVersions.
    .PARAMETER VersionId
        Please specify the VersionId for which you need to retrieve the ImageVersions.
    .EXAMPLE
        Get-HCSImageVersion -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65
    .EXAMPLE
        Get-HCSImageVersion -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65

        Get-HCSImageVersion -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65 -VersionId 67h67y089f3c5

        Get-HCSImageVersion -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 675xxxxa7929 | Select @{N="Version Name";E={$_.name}},@{N="Versionid";E={$_.id}},@{N="ImageId";E={$_.streamId}},State,Status | ft

        Get-HCSImageVersion -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 67583aa939727a6247ea7929 | Select @{N="Version Name";E={$_.name}},@{N="VersionId";E={$_.id}},State,@{N="MarkerId";E={$_.markers.id}},@{N="MarkerName";E={$_.markers.name}} | ft


    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$ImageId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$VersionId
    )  

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Accept' = "*/*";
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    Write-Verbose "Token is valid"

    # Base URL
    $baseUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images/$ImageId/versions"

    # Build the URL based on parameters
    $url = if ($VersionId) {
        "$baseUrl/$VersionId" + "?" + "org_id=$OrgId"
    } else {
        "$baseUrl" + "?" + "org_id=$OrgId&size=1000"
    }

    # Execute the request
    try {
        $response = (Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop)

        if ($VersionId) {
            return $response
        } else {
            return $response.content
        }
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSImageVersion: Unable to retrieve Image Version details"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSImageCopies {
    <#
    .SYNOPSIS
        Retrieves ImageCopies details of specific or all the images in a specific org
    .DESCRIPTION
        The Get-HCSImageCopies cmdlet is used to retrieve the ImageCopies details of specific or all the images in a specific org
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageId
        Please specify the ImageId for which you need to retrieve the ImageCopies.
    .PARAMETER VersionId
        Please specify the VersionId for which you need to retrieve the ImageCopies.
    .PARAMETER CopyId
        Please specify the CopyId for which you need to retrieve the ImageCopies.
    .PARAMETER ProviderId
        Please specify the ProviderId for which you need to retrieve the ImageCopies.
    .PARAMETER LimitedOutput
         parameter accepts a boolean value of $true or $false as input. When set to $true, limited output will be provided 
    .EXAMPLE
        Get-HCSImageCopies -OrgId f9b98412-658b-45db-a06b-000000000000 
    .EXAMPLE
        Get-HCSImageCopies -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65 
    .EXAMPLE
        Get-HCSImageCopies -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65 -VersionId 67h67y089f3c5
    .EXAMPLE
        Get-HCSImageCopies -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65 -VersionId 67h67y089f3c5 -LimitedOutput $true
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$ImageId,
        [String]$VersionId,
        [String]$CopyId,
        [String]$ProviderId,
        [bool]$LimitedOutput
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Accept' = "application/json";
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    Write-Verbose "Token is valid"

    # Base URL for API
    $baseUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1"

    # Build the URL based on parameters
    $url = if ($ImageId -and $VersionId) {
        if ($CopyId) {
            "$baseUrl/images/$ImageId/versions/$VersionId/copies/$CopyId" + "?" + "org_id=$OrgId"
        } elseif ($ProviderId) {
            "$baseUrl/images/$ImageId/versions/$VersionId/copies?org_id=$OrgId&provider_instance_id=$ProviderId&page=0&size=200&sort=asc"
        } elseif ($LimitedOutput) {
            "$baseUrl/images/$ImageId/versions/$VersionId/copies?org_id=$OrgId&page=0&size=1&sort=asc"
        } else {
            "$baseUrl/images/$ImageId/versions/$VersionId/copies?org_id=$OrgId&page=0&size=200&sort=asc"
        }
    } else {
        "$baseUrl/image-copies?org_id=$OrgId&size=200&sort=asc"
    }
    Write-Verbose "$url"
    # Execute the request
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
        if ($response.PSObject.Properties.Name -contains "content"){
            return $response.content
        } else{
            return $response
        }
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSImageCopies: Unable to retrieve Image Copy details"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSImageMarkers {
    <#
    .SYNOPSIS
        Retrieves ImageMaker details of a specific Image
    .DESCRIPTION
        The Get-HCSImageMarkers cmdlet is used to retrieve the ImageMaker details of a specific image
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageId
        Please specify the ImageId for which you need to retrieve the Image Maker Information.
    .PARAMETER MarkerId
        Please specify the MarkerId for which you need to retrieve check the image details.
    .EXAMPLE
        Get-HCSImageMarkers -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65 
    .EXAMPLE
        Get-HCSImageMarkers -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 6c879d8988ds65 -MarkerId 67h67y089f3c5
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,
        [String]$ImageId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$MarkerId
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken";
        'Accept' = "application/json";
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    Write-Verbose "Token is valid"

    # Base URL for API
    $baseUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images/$ImageId/markers"

    # Build the URL based on parameters
    $url = if ($MarkerId) {
        "$baseUrl/$MarkerId" + "?" + "org_id=$OrgId"
    } else {
        "$baseUrl" + "?" + "org_id=$OrgId&include_template_info=include_template_info&page=0&size=1000&sort=asc"
    }

    # Execute the request
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
        if ($response.PSObject.Properties.Name -contains "content"){
            return $response.content
        } else{
            return $response
        }    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCImageMarkers: Unable to retrieve Marker details"
        Write-Host $_.Exception.Message
    }
}

function New-HCSImageCopy { 
    <#
    .SYNOPSIS
        Create a New Image copy
    .DESCRIPTION
        The New-HCSImageCopy cmdlet is used to create a new image copy from an Image or version of the image
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageName
        Please specify the ImageName form where you would like to initiate the copy - it's an optional parameter if the clone parameter is mentioned as version
    .PARAMETER ImageId
        Please provide the ImageId of the image needs to copied / cloned
    .PARAMETER VersionId
        Please provide the VersionId of the image version needs to copied / cloned
    .PARAMETER Clone
        Please specify the clone action - allowed values are Image or Version
        choose this option based on ImageId parameter
    .PARAMETER Vnet
        Provide the vNet complete path
    .PARAMETER Subnet
        Provide the Subnet complete path
    .PARAMETER PublicIp
        By default PublicIp is set to false and it's an optional parameter, by adding this parameter as true the new image vm gets the publicIp assigned
    .PARAMETER Description
        Please specify the description of the image copy - it's an optional parameter
    .PARAMETER VersionType
        Please specify the VersionType - allowed values are Major or Major
        By default the versionType set as True if not specified
    .EXAMPLE

        # Clone from a version

        New-HCSImageCopy -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 660ab3000000ed06c06c -VersionId 660ab000005ed06cf0d -Clone Version -Vnet "/subscriptions/n72df38e-20n2-5b23-67fc-84616e84dbf4/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_W2_VNET_01" -Subnet "/subscriptions/n72df38e-20n2-5b23-67fc-84616e84dbf4/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_W2_VNET_01/subnets/VM_01"

        #Clone from an Image

        New-HCSImageCopy -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageName W10-Image-01 -ImageId 660ab3000000ed06c06c -VersionId 660ab000005ed06cf0d -Clone Version -Vnet "/subscriptions/n72df38e-20n2-5b23-67fc-84616e84dbf4/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_W2_VNET_01" -Subnet "/subscriptions/n72df38e-20n2-5b23-67fc-84616e84dbf4/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_W2_VNET_01/subnets/VM_01"

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [String]$OrgId,
        [String]$ImageId,
        [String]$VersionId,
        [String]$Vnet,
        [String]$Subnet,

        [Parameter(Mandatory)]
        [ValidateSet("Image", "Version")]
        [String]$Clone,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$ImageName,
        [String]$PublicIp = "false",
        [String]$Description = "",

        [ValidateSet("Major", "Minor")]
        [String]$VersionType = "Major"
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Accept'        = "application/json"; 
        'Content-Type'  = "application/json";
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    Write-Verbose "Token is valid"
    if($Clone -eq "Image") {
        if (-not ($PSBoundParameters.ContainsKey('ImageName'))) {
            Write-Host -ForegroundColor Red "New-HCSImageCopy: ImageName is Mandatory parameter if the clone is set to Image"
            return
        }
    }

    # Set clone action
    switch ($Clone.ToLower()) {
        "image"   { $action = "clone-image" }
        "version" { $action = "clone-version" }
        default {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCImageCopy: Invalid clone action. Use 'Image' or 'Version'."
            return
        }
    }

    # Public IP handling
    $PublicIp = if ($PublicIp.ToLower() -eq "true") { "true" } else { "false" }

    # Construct payload
    $payload = @{
        orgId = $OrgId
        assetDetails = @{
            data = @{
                subNet = $Subnet
                vNet = $Vnet
            }
            options = @{
                createPublicIp = $PublicIp
            }
            type = "AZURE_NETWORK_RESOURCE"
        }
        markers = @()
    }

    if ($Clone -eq "Version") {
        $payload.versionDescription = $Description
        $payload.versionType = $VersionType
    }
    elseif ($Clone -eq "Image") {
        $payload.imageName = $ImageName
        $payload.imageDescription = ""
        $payload.versionDescription = ""
        $payload.versionType = $VersionType
        $payload.markers = @( @{ name = "default" } )
    }

    # Convert payload to JSON
    $jsonPayload = $payload | ConvertTo-Json -Depth 4
    Write-Verbose "Image Copy payload - $jsonPayload"

    # API URL
    $cloneUrl = "https://cloud.omnissahorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId/clone?action=$action"

    # Invoke API
    try {
        $response = Invoke-RestMethod -Uri $cloneUrl -Method Post -Body $jsonPayload -Headers $headers -ErrorAction Stop
        return $response
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCImageCopy: Unable to clone image or version."
        Write-Host $_.Exception.Message
    }
}

function New-HCSImagePublish {
    <#
    .SYNOPSIS
        Publish the Image copy
    .DESCRIPTION
        The New-HCSImagePublish cmdlet is used to publish an image copy which is already exists and optimized
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER ImageId
        Please provide the ImageId of the image copy needs to be published
    .PARAMETER VersionId
        Please provide the VersionId of the image copy needs to be published
    .PARAMETER Resiliency
        It's an optional parameter and accepts boolean value true / false , if we pass this parameter with value as $true then a VM will be preserved in the Azure if publish fails for any reason
    .PARAMETER Replicas
        By default the publish will be replicated to all the providers associated with edge deployment , if we set it to $false then we have to manually trigger and it's limited to one provider
    .PARAMETER ApplicationScan
        It's an optional parameter and accepts boolean value true / false , This will not be available for Single Session Images (MuitiSession and RDSH only)
    .PARAMETER ValidateImage
        It's an optinal parameter and accepts boolean value true / false , By passing this parameter as $true , a temporary (studio) pool will be created in the one of preffered subnets and  waits for Agent to become available then gets deleted
    .PARAMETER Description
        Please specify the description of the image that's published - it's an optional parameter
    .NOTES
        By default below agent features hard coded for the cmdlet , this will be improved in the next versions
        ("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
    .EXAMPLE

        # Clone from a version

            New-HCSImagePublish -OrgId f9b98412-658b-45db-a06b-000000000000 -ImageId 660ab00d00d000d06cf00 -VersionId 66660010000009537c00   

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [String]$OrgId,
        [String]$ImageId,
        [String]$VersionId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [bool]$Resiliency,
        [String]$Description,
        [bool]$Replicas,
        [bool]$ApplicationScan,
        [bool]$ValidateImage
        
    )
    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 'Accept' = "application/json"; 'Content-Type' = "application/json";
    }

    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry) {
        Write-Verbose "Token is valid"
    }
    else {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        break
    }
    #Get the image version name
    try {
        $imageversiondetails = Get-HCSImageVersion -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId
        $imageversionname = $imageversiondetails.name
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Unable to retrieve image version name"
        $string_err = $_ | Out-String
        Write-Host $string_err
        Break
    }

    if ($PSBoundParameters.ContainsKey('Replicas')) {
        if ($Replicas -eq "$true") {
            #Get the imageCopyProviderId and exclude it from the replica providers
            try {
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $providerwithedgeexists = Get-HCSProvider -OrgId $OrgId -Environment Azure | Where-Object { $null -ne $_.edgeDeploymentId -and $_.id -ne $imageCopyProviderId }
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Unable to retrieve provider details for generating hash for replicas"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }

            $replicasjson = @()
            foreach ($providerwithedge in $providerwithedgeexists) {
                $replicasjson += @{
                    edgeDeploymentId   = $providerwithedge.edgeDeploymentId
                    providerInstanceId = $providerwithedge.id
                    providerLabel      = $providerwithedge.providerLabel
                }
            }                
            
        }
        elseif ($Replicas -eq "$false") {
            $replicasjson = ""
        }        
    }
    else {
        #Get the imageCopyProviderId and exclude it from the replica providers
        try {
            $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
            $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
            $providerwithedgeexists = Get-HCSProvider -OrgId $OrgId -Environment Azure | Where-Object { $null -ne $_.edgeDeploymentId -and $_.id -ne $imageCopyProviderId }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Unable to retrieve provider details for generating hash for replicas"
            $string_err = $_ | Out-String
            Write-Host $string_err
            Break
        }

        $replicasjson = @()
        foreach ($providerwithedge in $providerwithedgeexists) {
            $replicasjson += @{
                edgeDeploymentId   = $providerwithedge.edgeDeploymentId
                providerInstanceId = $providerwithedge.id
                providerLabel      = $providerwithedge.providerLabel
            }
        }    
    }

    if ($PSBoundParameters.ContainsKey('OrgId')) {
        if ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and !$PSBoundParameters.ContainsKey('ValidateImage')) {
            try {
                $hashtable_imageid_versionid_default = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = "false"
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = "false"
                        appScanDetails = @{
                            infrastructureResourceList = @()
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = @()
                    }
                    replicas                       = $replicasjson  
                } 

                $payload_imageid_versionid_default = $hashtable_imageid_versionid_default | ConvertTo-Json -Depth 4
                $payload_imageid_versionid_default
                $publishwithdefaultUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_default_Info = (Invoke-RestMethod -Uri "$publishwithdefaultUrl" -Method Post -Body $payload_imageid_versionid_default -Headers $headers -ErrorAction Stop)
                return $publish_default_Info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Resiliency')) {
            try {
                $hashtable_imageid_versionid_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = "false"
                        appScanDetails = @{
                            infrastructureResourceList = @()
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = @()
                    }
                    replicas                       = $replicasjson
            
                } 

                $payload_imageid_versionid_resiliency = $hashtable_imageid_versionid_resiliency | ConvertTo-Json -Depth 4
                $publishwithresiliencyUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_resiliency_Info = (Invoke-RestMethod -Uri "$publishwithresiliencyUrl" -Method Post -Body $payload_imageid_versionid_resiliency -Headers $headers -ErrorAction Stop)
                return $publish_with_resiliency_Info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('ApplicationScan')) {
            try {         
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $appScanStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_appscan = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = $appScanStudioDeployNetwork
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = @()
                    }
                    replicas                       = $replicasjson
            
                } 

                $payload_imageid_versionid_appscan = $hashtable_imageid_versionid_appscan | ConvertTo-Json -Depth 4
                $publishwithappscanUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_appscan_Info = (Invoke-RestMethod -Uri "$publishwithappscanUrl" -Method Post -Body $payload_imageid_versionid_appscan -Headers $headers -ErrorAction Stop)
                return $publish_with_appscan_Info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('ValidateImage')) {
            try {
                    
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $validateImageStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = @()
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = $validateImageStudioDeployNetwork
                    }
                    replicas                       = $replicasjson
                
                } 
    
                $payload_imageid_versionid_validation = $validateImageStudioDeployNetwork | ConvertTo-Json -Depth 4
                $publishwithvalidationUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_validation_info = (Invoke-RestMethod -Uri "$publishwithvalidationUrl" -Method Post -Body $payload_imageid_versionid_validation -Headers $headers -ErrorAction Stop)
                return $publish_with_validation_info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Replicas')) {
            try {
                $hashtable_imageid_versionid_replica = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = @()
                        }
                    }
                    validateImage                  = $ValidateImage
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = @()
                    }
                    replicas                       = $replicasjson
                } 

                $payload_imageid_versionid_replica = $hashtable_imageid_versionid_replica | ConvertTo-Json -Depth 4
                $publishwithreplicaUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_replica_Info = (Invoke-RestMethod -Uri "$publishwithreplicaUrl" -Method Post -Body $payload_imageid_versionid_replica -Headers $headers -ErrorAction Stop)
                return $publish_with_replica_Info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Replicas') -and $PSBoundParameters.ContainsKey('Resiliency')) {
            try {
                $hashtable_imageid_versionid_replica_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = @()
                        }
                    }
                    validateImage                  = $ValidateImage
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = @()
                    }
                    replicas                       = $replicasjson
                } 

                $payload_imageid_versionid_replica = $hashtable_imageid_versionid_replica_resiliency | ConvertTo-Json -Depth 4
                $publishwithreplicaUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_replica_Info = (Invoke-RestMethod -Uri "$publishwithreplicaUrl" -Method Post -Body $payload_imageid_versionid_replica -Headers $headers -ErrorAction Stop)
                return $publish_with_replica_Info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Replicas') -and $PSBoundParameters.ContainsKey('ApplicationScan')) {
            try {
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $appScanStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_replica_appScan = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = $appScanStudioDeployNetwork
                        }
                    }
                    validateImage                  = $ValidateImage
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = @()
                    }
                    replicas                       = $replicasjson
                } 

                $payload_imageid_versionid_replica = $hashtable_imageid_versionid_replica_appScan | ConvertTo-Json -Depth 4
                $publishwithreplicaUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_replica_Info = (Invoke-RestMethod -Uri "$publishwithreplicaUrl" -Method Post -Body $payload_imageid_versionid_replica -Headers $headers -ErrorAction Stop)
                return $publish_with_replica_Info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Replicas') -and $PSBoundParameters.ContainsKey('ValidateImage')) {
            try {
                    
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $validateImageStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = @()
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = $validateImageStudioDeployNetwork
                    }
                    replicas                       = $replicasjson
                
                } 
    
                $payload_imageid_versionid_validation = $validateImageStudioDeployNetwork | ConvertTo-Json -Depth 4
                $publishwithvalidationUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_validation_info = (Invoke-RestMethod -Uri "$publishwithvalidationUrl" -Method Post -Body $payload_imageid_versionid_validation -Headers $headers -ErrorAction Stop)
                return $publish_with_validation_info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Replicas') -and $PSBoundParameters.ContainsKey('ValidateImage') -and $PSBoundParameters.ContainsKey('ApplicationScan') ) {
            try {
                    
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $validateImageAppScanStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = $validateImageAppScanStudioDeployNetwork
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = $validateImageAppScanStudioDeployNetwork
                    }
                    replicas                       = $replicasjson
                } 
    
                $payload_imageid_versionid_appscan_validation = $validateImageStudioDeployNetwork | ConvertTo-Json -Depth 4
                $publishwithappscanvalidationUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_appscan_validation_info = (Invoke-RestMethod -Uri "$publishwithappscanvalidationUrl" -Method Post -Body $payload_imageid_versionid_appscan_validation -Headers $headers -ErrorAction Stop)
                return $publish_with_appscan_validation_info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('ValidateImage') -and $PSBoundParameters.ContainsKey('ApplicationScan') ) {
            try {        
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $validateImageAppScanStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = $validateImageAppScanStudioDeployNetwork
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = $validateImageAppScanStudioDeployNetwork
                    }
                    replicas                       = $replicasjson
                } 
    
                $payload_imageid_versionid_appscan_validation = $validateImageStudioDeployNetwork | ConvertTo-Json -Depth 4
                $publishwithappscanvalidationUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_appscan_validation_info = (Invoke-RestMethod -Uri "$publishwithappscanvalidationUrl" -Method Post -Body $payload_imageid_versionid_appscan_validation -Headers $headers -ErrorAction Stop)
                return $publish_with_appscan_validation_info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('VersionId') -and $PSBoundParameters.ContainsKey('Replicas') -and $PSBoundParameters.ContainsKey('ValidateImage') -and $PSBoundParameters.ContainsKey('ApplicationScan') -and $PSBoundParameters.ContainsKey('Resiliency') ) {
            try {     
                $imagecopylimitedoutput = Get-HCSImageCopies -OrgId $OrgId -ImageId $ImageId -VersionId $VersionId -LimitedOutput $true
                $imageCopyProviderId = $imagecopylimitedoutput.providerInstanceId
                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $imageCopyProviderId -Environment Azure -Preffered $true).desktop
                $validateImageAppScanStudioDeployNetwork = $PrefferedNetworks[(Get-Random -Maximum ([array]$PrefferedNetworks).count)]
                $hashtable_imageid_versionid_resiliency = @{
                    orgId                          = $OrgId
                    description                    = $Description
                    versionName                    = $imageversionname
                    providerLabel                  = "Azure"
                    publishWithResiliency          = $Resiliency
                    osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                    options                        = @{
                        horizonAgent = @{
                            installHorizonAgent = "True"
                            features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                        }
                    }
                    applicationScan                = @{
                        enableAppScan  = $ApplicationScan
                        appScanDetails = @{
                            infrastructureResourceList = $validateImageAppScanStudioDeployNetwork
                        }
                    }
                    validateImage                  = "false"
                    validationInfraResourceDetails = @{
                        infrastructureResourceList = $validateImageAppScanStudioDeployNetwork
                    }
                    replicas                       = $replicasjson
                } 
    
                $payload_imageid_versionid_appscan_validation = $validateImageStudioDeployNetwork | ConvertTo-Json -Depth 4
                $publishwithappscanvalidationUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
                $publish_with_appscan_validation_info = (Invoke-RestMethod -Uri "$publishwithappscanvalidationUrl" -Method Post -Body $payload_imageid_versionid_appscan_validation -Headers $headers -ErrorAction Stop)
                return $publish_with_appscan_validation_info
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
                $string_err = $_ | Out-String
                Write-Host $string_err
                Break
            }
        }
    }
    else {
        try {
            $hashtable_imageid_versionid_default = @{
                orgId                          = $OrgId
                description                    = $Description
                versionName                    = $imageversionname
                providerLabel                  = "Azure"
                publishWithResiliency          = "false"
                osCustomizations               = @("DisableWindowsUpdate", "RemoveAppXPackages")
                options                        = @{
                    horizonAgent = @{
                        installHorizonAgent = "True"
                        features            = @("DEM", "ClientDriveRedirection", "PerfTracker", "HelpDesk", "RTAV", "PrintRedir")
                    }
                }
                applicationScan                = @{
                    enableAppScan  = $ApplicationScan
                    appScanDetails = @{
                        infrastructureResourceList = @()
                    }
                }
                validateImage                  = $ValidateImage
                validationInfraResourceDetails = @{
                    infrastructureResourceList = @()
                }
                replicas                       = $replicasjson   
            } 

            $payload_imageid_versionid_default = $hashtable_imageid_versionid_default | ConvertTo-Json -Depth 4
            $publishwithdefaultUrl = "https://cloud.vmwarehorizon.com/imagemgmt/v1/images/$ImageId/versions/$VersionId" + "?" + "action=publish"
            $publish_default_Info = (Invoke-RestMethod -Uri "$publishwithdefaultUrl" -Method Post -Body $payload_imageid_versionid_default -Headers $headers -ErrorAction Stop)
            return $publish_default_Info
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSImagePublish: Image Publish failed"
            $string_err = $_ | Out-String
            Write-Host $string_err
            Break
        }
    }
}

function Get-RetrieveByPage {
    <#
    .SYNOPSIS
        if the response has more than 1 page, this cmdlet helps in retriving the information
    .DESCRIPTION
        if the response has more than 1 page, this cmdlet helps in retriving the information,
        Written to use inside one or more cmdlets and not available to use/export
    .PARAMETER url
        Provided the request url
    .PARAMETER Method
        Which method to be called , GET / POST - defaulted to GET always
    .PARAMETER Body
        Provide the body for the request
    .EXAMPLE
        Get-RetrieveByPage -url https://connect.omnissa.com/xxxxx -Method GET -Body {}
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$url,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [switch]$Body
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "application/json"
        'Content-Type' = "application/json"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    Write-Verbose "Token is valid"

    try {
        # Fetch initial data to get page count
        $data = Invoke-RestMethod -Uri $url -Method $Method -Headers $headers -ErrorAction Stop
        $pageCount = $data.totalPages
        Write-Verbose "PageCount - $pageCount"

        # If no paging, return data directly
        if ($pageCount -eq 0) {
            return $data
        }

        # Initialize variables
        $dataArray = @()
        $pageNumber = 0
        $urlWithPageParam = $url + "&page="

        # Process pages
        do {
            $pagedUrl = "$urlWithPageParam$pageNumber"
            Write-Verbose "Fetching page: $pagedUrl"

            $pagedData = if ($Body.IsPresent) {
                Invoke-RestMethod -Uri $pagedUrl -Method $Method -Body $Body -Headers $headers -ErrorAction Stop
            } else {
                Invoke-RestMethod -Uri $pagedUrl -Method $Method -Headers $headers -ErrorAction Stop
            }

            $dataArray += $pagedData.content
            $pageNumber++

        } while ($pageNumber -lt $pageCount)

        return $dataArray

    } catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Get-RetrieveByPage: Error while retrieving page count number"
        Write-Host $_.Exception.Message
        return
    }
}

function Get-HCSPublishedApps {
    <#
    .SYNOPSIS
        Retrieves All published app details for a specific org
    .DESCRIPTION
        The Get-HCSPublishedApps cmdlet is utilized to retrieve information about the published apps created in next-gen with its configured properties. 
        When the Get-HCSPublishedApps cmdlet is used with OrgID, it will provide details on all the published apps created.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .EXAMPLE
        Get-HCSPublishedApps -OrgId f9b98412-658b-45db-a06b-000000000000
    .EXAMPLE
        Get-HCSPublishedApps -OrgId f9b98412-658b-45db-a06b-000000000000 | select AppName,@{N="PoolGroupName";E={$_.poolName}}
    .EXAMPLE
        $appinfo=Get-HCSPublishedApps -OrgId f9b98412-658b-45db-a06b-000000000000
        $appinfo|Select AppName,@{N="AppPath";E={$_.applications.path}},@{N="AppVersion";E={$_.applications.version}},@{N="AppPublisher";E={$_.applications.publisher}},@{N="PoolGroup Name";E={$_.poolName}}
    #>
   [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId
    )
    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "application/json"
        'Content-Type' = "application/json"
    }

    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry){
        Write-Verbose "Token is valid"
    }
    else{
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        break
    }

    try {
        $urlapp = "https://cloud.omnissahorizon.com/portal/v4/pools/apps" + "?" + "org_id=$OrgId&search=type%20%24in%20APPLICATION%2CDESKTOP_APPLICATION%20AND%20templateType%20%24in%20MULTI_SESSION&sort=desc&size=1000"
        $dataPublishedApp = Get-RetrieveByPage -url $urlapp -Method POST
        return $dataPublishedApp
    }
    catch {
        Write-Host -ForegroundColor Red  "Get-HCSPublishedApps: Unable to retrieve Published App details"
        $string_err = $_ | Out-String
        Write-Host $string_err
        Break
    }
}

function Get-HCSAvApps {
    <#
    .SYNOPSIS
        Retrieves all AV applications for a specific org.
    .DESCRIPTION
        Retrieves AV applications and optionally includes their app versions if specified.
    .PARAMETER OrgId
        Long OrgId of the organization.
    .PARAMETER Include_AppVersion
        Specifies whether to include app version details.
    .EXAMPLE
        Get-HCSAvApps -OrgId f9b98412-658b-45db-a06b-000000000000
        Get-HCSAvApps -OrgId f9b98412-658b-45db-a06b-000000000000 -Include_AppVersion $true
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [Parameter(Mandatory = $false)]
        [bool]$Include_AppVersion = $false
    )

    # Set headers for API calls
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "application/json"
    }

    # Token validation
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Build the URL based on Include_AppVersion
    $url = "https://cloud.omnissahorizon.com/av-appies/v1/applications?org_id=$OrgId&include_complete=$($Include_AppVersion)&sort=asc&size=1000"

    # Fetch data using Get-RetrieveByPage
    try {
        $dataPublishedApp = Get-RetrieveByPage -url $url -Method GET
        return $dataPublishedApp
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSAvApps: Unable to retrieve AV Apps"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSAvAppVersions {
    <#
    .SYNOPSIS
        Retrieves all AV Versions with applications for a specific org
    .DESCRIPTION
        The Get-HCSAvAppVersions cmdlet is utilized to retrieve information about the appvolume versions created in next-gen with its configured properties. 
        When the Get-HCSAvAppVersions cmdlet is used with OrgID and Include_Applicaion enabled, it will provide details of all the appvolumes applications with appversions.
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .EXAMPLE
        Get-HCSAvAppVersions -OrgId f9b98412-658b-45db-a06b-000000000000
    .EXAMPLE
        Get-HCSAvAppVersions -OrgId f9b98412-658b-45db-a06b-000000000000 -$Include_AppVersion $true
    .EXAMPLE
        Get-HCSAvAppVersions -OrgId f9b98412-658b-45db-a06b-000000000000 | select Name,version,lifecycleStage,deliveryMode
    .EXAMPLE
        $avinfo=Get-HCSAvApps -OrgId f9b98412-658b-45db-a06b-000000000000
        $avinfo|select Name,version,lifecycleStage,deliveryMode,@{N="Package FilesharePath";E={$_.packages.sourceUri}},@{N="ProviderInstance";E={$_.packages.providerInstanceIds}},@{N="PackageName";E={$_.packages.filename}},@{N="PackageSizeInMB";E={[math]::Round(($_.packages.fileSize)/1MB,2)}} | Format-Table
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [Parameter(Mandatory = $false)]
        [bool]$Include_Applicaion = $false
    )

    # Set headers for API calls
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "application/json"
    }

    # Token validation
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Build the URL based on Include_AppVersion
    $url = "https://cloud.omnissahorizon.com/av-appies/v1/app-versions?org_id=$OrgId&include_complete=$($Include_Applicaion)&sort=asc&size=1000"

    # Fetch data using Get-RetrieveByPage
    try {
        $dataPublishedApp = Get-RetrieveByPage -url $url -Method GET
        return $dataPublishedApp
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSAvApps: Unable to retrieve AV Apps"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSAvAppShortcuts {
    <#
    .SYNOPSIS
        Retrieves all AV App Shortcuts for a specific org.
    .DESCRIPTION
        Retrieves all AV App Shortcuts for a specific org.
    .PARAMETER OrgId
        Long OrgId of the organization.
    .PARAMETER Include_AppVersion
        Specifies whether to include app version details.
    .EXAMPLE
        Get-HCSAvAppsShortcuts -OrgId f9b98412-658b-45db-a06b-000000000000
        Get-HCSAvAppsShortcuts -OrgId f9b98412-658b-45db-a06b-000000000000 -Include_Application $true
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [Parameter(Mandatory = $false)]
        [bool]$Include_Application = $false
    )

    # Set headers for API calls
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "application/json"
    }

    # Token validation
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Build the URL based on Include_AppVersion
    
    $url = "https://cloud.omnissahorizon.com/av-appies/v1/app-shortcuts?hide_duplicates=false&include_application=true&org_id=$OrgId&page=0&size=1000&sort=asc"

    # Fetch data using Get-RetrieveByPage
    try {
        $dataPublishedApp = Get-RetrieveByPage -url $url -Method GET
        return $dataPublishedApp
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSAvAppShortcuts: Unable to retrieve AV Apps Shortcuts"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSAzureVmSkus {
    <#
    .SYNOPSIS
        Retrieves the Supported Azure VM SKUs details for a specific Provider.
    .DESCRIPTION
        Retrieves the Supported Azure VM SKUs details for a specific Provider.
        This information will be needed in various places like creating a new pool and etc
    .PARAMETER OrgId
        Long OrgId of the organization.
    .PARAMETER providerId
        Provide the Edge provider id
    .PARAMETER VmSize
        Provide the VMSize to retrieve the details. Example : Standard_D16s_v4
    .EXAMPLE
        # Retrieves all the vmSKU's supported in next-gen and also provides the information if a specific SKU not available for pool creation 
        Get-HCSAzureVmSkus -OrgId f9b98412-658b-45db-a06b-000000000000 -providerId 6450e940000cd2d3ded

        # Retrieves the details for a specific SKU
        Get-HCSAvAppsShortcuts -OrgId f9b98412-658b-45db-a06b-000000000000 -providerId 6450e94c5d91f671cd2d3ded -VmSize Standard_A4_v2
    #>
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$providerId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [ValidatePattern("[Standard][_][0-9a-z]")]
        [String]$VmSize
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "application/json"
        'Content-Type'  = "application/json"
    }

    # Token validation
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    try {
        # Construct the base URL
        $baseUrl = "https://cloud.omnissahorizon.com/admin/v2/providers/azure/instances/$providerId/compute-vm-skus?org_id=$OrgId&sort=desc&size=1000"
        
        # Check if VmSize is provided
        if ($VmSize) {
            $urlSpecificVmSku = "$baseUrl&search=name%20%24eq%20$VmSize"
            $dataSpecificVmSku = Get-RetrieveByPage -url $urlSpecificVmSku -Method GET
            Write-Verbose $dataSpecificVmSku

            if ($dataSpecificVmSku.id -eq $VmSize) {
                return $dataSpecificVmSku
            }
            else {
                Write-Host -ForegroundColor Yellow "Get-HCSAzureVmSkus: Provided VM Size doesn't exist, please recheck and try again"
            }
        }
        else {
            $dataAllVmSkus = Get-RetrieveByPage -url $baseUrl -Method GET
            return $dataAllVmSkus
        }
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSAzureVmSkus: Unable to retrieve Azure VM Skus info"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSAzureDiskSkus { 
    <#
        .SYNOPSIS
            Retrieves the Supported Azure Disk SKUs details for a specific Provider.
        .DESCRIPTION
            Retrieves the Supported Azure VM Disk SKUs details for a specific Provider.
            This information will be needed in various places like creating a new pool and etc
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER providerId
            Provide the Edge provider id
        .PARAMETER VmSize
            Provide the VMSize to retrieve the supported Disk SKUIdetails. Example : Standard_D16s_v4
        .EXAMPLE
            # Retrieves the Disk SKU details for a specific VM SKU
            Get-HCSAvAppsShortcuts -OrgId f9b98412-658b-45db-a06b-000000000000 -providerId 6450e94c5d90001cd2d3ded -VmSize Standard_A4_v2
        #>
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$providerId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [ValidatePattern("[Standard][_][0-9a-z]")]
        [String]$VmSize
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept'        = "application/json"
        'Content-Type'  = "application/json"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Retrieve VM SKU capabilities
    $vmSku = Get-HCSAzureVmSkus -OrgId $OrgId -providerId $providerId -VmSize $VmSize

    try {
        # Determine URL based on capabilities
        $premiumFlag = if ($vmSku.data.capabilities) { "true" } else { "false" }
        $urlDiskSkus = "https://cloud.omnissahorizon.com/admin/v2/providers/azure/instances/$providerId/disk-skus?org_id=$OrgId&include_premium=$premiumFlag&sort=desc&size=1000"

        # Retrieve Disk SKUs based on VM capabilities
        $dataAllDiskSkus = Get-RetrieveByPage -url $urlDiskSkus -Method GET
        return $dataAllDiskSkus
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSAzureDiskSkus: Unable to retrieve Disk Skus information for the specified VM Size"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSUserActivity { 
    <#
        .SYNOPSIS
            Retrieves the User Activity details of a specific Org.
        .DESCRIPTION
            Retrieves the User Activity details of a specific Org. This data is fetch from Workspace ONE Intelligence 
            We can filter the information by UserId / VM / PoolName and also can be exported to a CSV
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER StartDate
            It's an optional parameter and if not specified last 6 hours of activities will be displayed
            Provide the startDate for Activites filtering 
            Provide the dateformat as "yyyy-MM-ddTHH:mm:ss.fff" , if not provided then cmdlet will convert it
            Example:: Get-Date "03/05/2024 06:16:18" -Format "yyyy-MM-ddTHH:mm:ss.fff"
        .PARAMETER EndDate
            It's an optional parameter and if not specified last 6 hours of activities will be displayed
            Provide the endtDate for Activites filtering 
            Provide the dateformat as "yyyy-MM-ddTHH:mm:ss.fff" , if not provided then cmdlet will convert it
            Example:: Get-Gate "03/08/2024 04:51:00" -Format "yyyy-MM-ddTHH:mm:ss.fff"
        .PARAMETER UserName
            Filter the output based on a specific UserId
        .PARAMETER VmName
            Filter the output based on a specific VmName
        .PARAMETER PoolName
            Filter the output based on a specific Pool
        .PARAMETER Filter
            For More filter check https://cloud.omnissahorizon.com/data-query-service/swagger-ui/index.html#/Data%20Query%20Service/getAll
        .EXAMPLE
            # Retrieves the User Activities for a specific Org
                Get-HCSUserActivity -OrgId f9b98412-658b-45db-a06b-000000000000
            
            # Retrieves the User Activities for a specific time range
                Get-HCSUserActivity -OrgId f9b98412-658b-45db-a06b-000000000000 -StartDate "2024-11-25" -EndDate "2024-12-01"

            # Retrieves the User Activities for a specific User
                Get-HCSUserActivity -OrgId f9b98412-658b-45db-a06b-000000000000 -StartDate "2024-11-25" -EndDate "2024-12-01" -UserName User01
            
            # Retrieves the User Activities for a specific VmName
                Get-HCSUserActivity -OrgId f9b98412-658b-45db-a06b-000000000000 -StartDate "2024-11-25" -EndDate "2024-12-01" -VmName User01
            
            # Retrieves the User Activities for a specific PoolName
                Get-HCSUserActivity -OrgId f9b98412-658b-45db-a06b-000000000000 -StartDate "2024-11-25" -EndDate "2024-12-01" -PoolName Dedicated01            

    #>
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [datetime]$StartDate,
        [datetime]$EndDate,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$Filter,
        [String]$UserName,
        [String]$VmName,
        [String]$PoolName
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken";
        'Accept'        = "*/*";
    }

    # Token validation
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Default to last 6 hours if no date range is provided
    if (-not $PSBoundParameters.ContainsKey('StartDate') -and -not $PSBoundParameters.ContainsKey('EndDate')) {
        $StartDate = (Get-Date).AddHours(-6)
        $EndDate = Get-Date
        $startDateFormatted = [datetime]::Parse($StartDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        $endDateFormatted = [datetime]::Parse($EndDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        
    } elseif($PSBoundParameters.ContainsKey('StartDate') -and -not $PSBoundParameters.ContainsKey('EndDate')){
        $EndDate = Get-Date
        $startDateFormatted = [datetime]::Parse($StartDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        $endDateFormatted = [datetime]::Parse($EndDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")

    } elseif(-not $PSBoundParameters.ContainsKey('StartDate') -and $PSBoundParameters.ContainsKey('EndDate')){
        Write-Host -ForegroundColor Red "Please provide StartDate"
        return
    } else{
        # Date formatting
        $startDateFormatted = [datetime]::Parse($StartDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        $endDateFormatted = [datetime]::Parse($EndDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
    }

    # Base URL
    $url = "https://cloud.omnissahorizon.com/data-query-service/v1/user-activities?end_date=$endDateFormatted&start_date=$startDateFormatted&org_id=$OrgId"

    # Add filters dynamically
    if ($UserName) {
        $url += "&search=endUser%20%24eq%20$UserName"
    }
    elseif ($VmName) {
        $url += "&search=vmName%20%24eq%20$VmName"
    }
    elseif ($PoolName) {
        $url += "&search=templateName%20%24eq%20$PoolName"
    }
    elseif ($Filter) {
        $FilterFormatted = $Filter -replace ' ', '%20' -replace '-eq', '%24eq'
        $url += "&search=$FilterFormatted"
    }
    else{
        $url = $url
    }



    try {
        Write-Verbose "$url"

        # Initial API call to get total pages
        $dataUAPC = Invoke-RestMethod -Uri "$url&size=250" -Method Get -Headers $headers -ErrorAction Stop
        $pageCount = $dataUAPC.totalPages
        $dataArray = @()
        $pageNumber = 0

        # Paginate and collect data
        while ($pageNumber -lt $pageCount) {
            $urlPageNumber = "$url&page=$pageNumber&size=250"
            Write-Verbose "Fetching page $pageNumber"
            $resultsByPage = Invoke-RestMethod -Uri $urlPageNumber -Method Get -Headers $headers -ErrorAction Stop
            $dataArray += $resultsByPage.content
            $pageNumber++
        }
        Write-Verbose "$dataArray"
        return $dataArray
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSUserActivity: Error while retrieving user activities"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSAdminActivity { 
    <#
        .SYNOPSIS
            Retrieves the Admin Activity details of a specific Org.
        .DESCRIPTION
            Retrieves the Admin Activity details of a specific Org. This data is fetch from Horizon itself 
            We can filter the information and also can be exported to a CSV
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER StartDate
            It's an optional parameter and if not specified last 24 hours of activities will be displayed
            Provide the startDate for Activites filtering 
            Provide the dateformat as "yyyy-MM-ddTHH:mm:ss.fff" , if not provided then cmdlet will convert it
            Example:: Get-Date "03/05/2024 06:16:18" -Format "yyyy-MM-ddTHH:mm:ss.fff"
        .PARAMETER EndDate
            It's an optional parameter and if not specified last 24 hours of activities will be displayed
            Provide the endtDate for Activites filtering 
            Provide the dateformat as "yyyy-MM-ddTHH:mm:ss.fff" , if not provided then cmdlet will convert it
            Example:: Get-Gate "03/08/2024 04:51:00" -Format "yyyy-MM-ddTHH:mm:ss.fff"
        .EXAMPLE
            # Retrieves the Admin Activities for a specific Org
                Get-HCSAdminActivity -OrgId f9b98412-658b-45db-a06b-000000000000
            
            # Retrieves the Admin Activities for a specific time range
                Get-HCSAdminActivity -OrgId f9b98412-658b-45db-a06b-000000000000 -StartDate "2024-11-25" -EndDate "2024-12-01"      

    #>
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [datetime]$StartDate,
        [datetime]$EndDate
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken";
        'Accept'        = "*/*";
    }

    # Token validation
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    Write-Verbose "Token is valid"

    # Default to last 6 hours if no date range is provided
    if (-not $PSBoundParameters.ContainsKey('StartDate') -and -not $PSBoundParameters.ContainsKey('EndDate')) {
        $StartDate = (Get-Date).AddHours(-24)
        $EndDate = Get-Date
        $startDateFormatted = [datetime]::Parse($StartDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        $endDateFormatted = [datetime]::Parse($EndDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        write-Verbose "StartDate - $startDateFormatted & EndDate - $endDateFormatted"   
    } elseif($PSBoundParameters.ContainsKey('StartDate') -and -not $PSBoundParameters.ContainsKey('EndDate')){
        $EndDate = Get-Date
        $startDateFormatted = [datetime]::Parse($StartDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        $endDateFormatted = [datetime]::Parse($EndDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
        write-Verbose "StartDate - $startDateFormatted & EndDate - $endDateFormatted"

    } elseif(-not $PSBoundParameters.ContainsKey('StartDate') -and $PSBoundParameters.ContainsKey('EndDate')){
        Write-Host -ForegroundColor Red "Please provide StartDate"
        return
    } elseif( $PSBoundParameters.ContainsKey('StartDate') -and $PSBoundParameters.ContainsKey('EndDate')){
         $startDateFormatted = $startDate
          $endDateFormatted = $EndDate
    } 
    #else{
    #    # Date formatting
    #    $startDateFormatted = [datetime]::Parse($StartDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
    #    $endDateFormatted = [datetime]::Parse($EndDate).ToString("yyyy-MM-ddTHH:mm:ss.fff")
    #    write-Verbose "StartDate - $startDateFormatted & EndDate - $endDateFormatted"
    #}

    # Base URL
    $url = "https://cloud.omnissahorizon.com/activity-manager/v1/activities?end_date=$endDateFormatted&start_date=$startDateFormatted&org_id=$OrgId&search=externalParentId%20%24isnull%20true"


    try {
        Write-Verbose "$url"

        # Initial API call to get total pages
        $dataUAPC = Invoke-RestMethod -Uri "$url&size=250" -Method Get -Headers $headers -ErrorAction Stop
        $pageCount = $dataUAPC.totalPages
        $dataArray = @()
        $pageNumber = 0

        # Paginate and collect data
        while ($pageNumber -lt $pageCount) {
            $urlPageNumber = "$url&page=$pageNumber&size=250"
            Write-Verbose "Fetching page $pageNumber"
            $resultsByPage = Invoke-RestMethod -Uri $urlPageNumber -Method Get -Headers $headers -ErrorAction Stop
            $dataArray += $resultsByPage.content
            $pageNumber++
        }
        Write-Verbose "$dataArray"
        return $dataArray
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSAdminActivity: Error while retrieving user activities"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSSessionCount {
    <#
        .SYNOPSIS
            Retrieves the Existing session count details 
        .DESCRIPTION
            Retrieves the Session count details per org or per pool or per poolGroup
        .PARAMETER OrgId
            Long OrgId of the organization. retrives the sessions count details for all the pools
        .PARAMETER poolId
            optional parameter , Provide the pool id to retrive the Connected & Disconnected count for the specific pool
        .PARAMETER poolGroupId
            optional parameter , Provide the poolGroup id to retrive the Connected & Disconnected count for the specific poolGroup
        .PARAMETER PoolName
            optional parameter , Provide the poolName to retrive the Connected & Disconnected count for the specific pool
        .EXAMPLE
            # Retrieves the Session Count details for all the pools
                Get-HCSSessionCount -OrgId f9b98412-658b-45db-a06b-000000000000

            # Retrieves the Session Count details for specific pool
                Get-HCSSessionCount -OrgId f9b98412-658b-45db-a06b-000000000000 -poolid 6718c5ee0000003100

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$poolId,
        [string]$poolGroupId,
        [string]$PoolName
    )
    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 'Content-Type' = "application/json";
    }
    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry){
        Write-Verbose "Token is valid"
    }
    else{
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        break
    }


    if($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolId')){
        try{
                
            $GraphQLBody = "{`"query`":`"query HorizonSessionOverview {`\n    horizonSessionOverview(`\n        orgId: `\`"$orgId`\`"`\n        templateId: `\`"$poolId`\`"`\n    ) {`\n        data {`\n            category`\n            count`\n            percentage`\n            level`\n            subCategories {`\n                state`\n                count`\n            }`\n        }`\n    }`\n}`\n`",`"variables`":{}}"
            
            $response = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLBody
            $sessionDetails = [PSCustomObject]@{
                Connected       = $response.data.horizonSessionOverview.data| ? {$_.category -eq "CONNECTED"} | Select-Object -ExpandProperty count
                Disconnected    = $response.data.horizonSessionOverview.data| ? {$_.category -eq "DISCONNECTED"} | Select-Object -ExpandProperty count
            }
            return $sessionDetails
        }
        catch{
            Write-Host -ForegroundColor Red  "Get-HCSSessionCount: Error while retriving Session details"
            $string_err = $_ | Out-String
            Write-Host $string_err
            break
        }
    }
   elseif($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId')){
        try{
        
            $GraphQLBody = "{`"query`":`"query HorizonSessionOverview {`\n    horizonSessionOverview(`\n        orgId: `\`"$orgId`\`"`\n        poolGroupId: `\`"$poolGroupId`\`"`\n    ) {`\n        data {`\n            category`\n            count`\n            percentage`\n            level`\n            subCategories {`\n                state`\n                count`\n            }`\n        }`\n    }`\n}`\n`",`"variables`":{}}"

            $response = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLBody
            $sessionDetails = [PSCustomObject]@{
                Connected       = $response.data.horizonSessionOverview.data| ? {$_.category -eq "CONNECTED"} | Select-Object -ExpandProperty count
                Disconnected    = $response.data.horizonSessionOverview.data| ? {$_.category -eq "DISCONNECTED"} | Select-Object -ExpandProperty count
            }
            return $sessionDetails
        }
        catch{
            Write-Host -ForegroundColor Red  "Get-HCSSessionCount: Error while retriving Session details"
            $string_err = $_ | Out-String
            Write-Host $string_err
            break
        }
    }
    elseif($PSBoundParameters.ContainsKey('OrgId') -and !$PSBoundParameters.ContainsKey('PoolGroupId') -and !$PSBoundParameters.ContainsKey('PoolId')){
        try{
            $perPoolSessionDetails = @()
            $PoolDetails = Get-HCSPool -OrgId $orgId
            foreach($PoolD in $PoolDetails){
                $poolId = $PoolD.id
                $GraphQLBody = "{`"query`":`"query HorizonSessionOverview {`\n    horizonSessionOverview(`\n        orgId: `\`"$orgId`\`"`\n        templateId: `\`"$poolId`\`"`\n    ) {`\n        data {`\n            category`\n            count`\n            percentage`\n            level`\n            subCategories {`\n                state`\n                count`\n            }`\n        }`\n    }`\n}`\n`",`"variables`":{}}"
                $response = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLBody
                $sessionDetails = $response.data.horizonSessionOverview.data
                $connectedCount = $response.data.horizonSessionOverview.data| ? {$_.category -eq "CONNECTED"} | Select-Object -ExpandProperty count
                $disConnectedCount = $response.data.horizonSessionOverview.data| ? {$_.category -eq "DISCONNECTED"} | Select-Object -ExpandProperty count
                $perPoolSessionDetail = [PSCustomObject]@{
                    PoolName        = $PoolD.name
                    PoolId          = $poolId
                    Connected       = $connectedCount
                    Disconnected    = $disConnectedCount
                }
                $perPoolSessionDetails += $perPoolSessionDetail   
            }
            return $perPoolSessionDetails
        }
        catch{
            Write-Host -ForegroundColor Red  "Get-HCSSessionCount: Get-HCSSessionCount: Error while retriving Session details"
            $string_err = $_ | Out-String
            Write-Host $string_err
            break
        }
    }
    elseif($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId') -and $PSBoundParameters.ContainsKey('PoolId')){
        Write-Host -ForegroundColor Yello  "Get-HCSSessionCount: Please verify the parameters; only one of PoolId or PoolGroupId is allowed with OrgId"
    }
}

function Get-HCSSession {
    <#
        .SYNOPSIS
            Retrieves the Existing sessions details 
        .DESCRIPTION
            Retrieves the Session details per org or per pool or per poolGroup
            The output contains vmName, Userd, UserName,  poolid, poolType, loginTime, SessionState and etc
        .PARAMETER OrgId
            Long OrgId of the organization. retrives the sessions details for all the pools
        .PARAMETER poolId
            optional parameter , Provide the pool id to retrive session details for the specific pool
        .PARAMETER poolGroupId
            optional parameter , Provide the poolGroup id to retrive session details for the specific poolGroup
        .PARAMETER PoolName
            optional parameter , Provide the poolName to retrive session details for the specific pool
        .EXAMPLE
            # Retrieves the Session  details for all the pools
                Get-HCSSession -OrgId f9b98412-658b-45db-a06b-000000000000

            # Retrieves the Session  details for specific pool
                Get-HCSSession -OrgId f9b98412-658b-45db-a06b-000000000000 -poolid 6718c5ee0000003100

            # Retrieves the Basic Session  details
                Get-HCSSession -orgId f9b98412-658b-45db-a06b-000000000000 | select vmName,userId,username,sessionType,sessionStatus,@{N="SessionStateDuration-Days";E={ New-TimeSpan -Seconds $_.sessionStateDuration}}

                Get-HCSSession -orgId f9b98412-658b-45db-a06b-000000000000 -poolId 6718xxxxxxx0xx | select vmName,userId,username,sessionType,sessionStatus,@{N="SessionStateDuration-Days";E={ New-TimeSpan -Seconds $_.sessionStateDuration}}

                Get-HCSSession -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 6718cxxx7426f5xxxa | select vmName,userId,username,sessionType,sessionStatus,@{N="SessionStateDuration-Days";E={ New-TimeSpan -Seconds $_.sessionStateDuration}}

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$poolId,
        [string]$poolGroupId,
        [string]$PoolName
    )
    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 'Content-Type' = "application/json";
    }
    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry){
        Write-Verbose "Token is valid"
    }
    else{
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        break
    }


    if($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolId') -and !$PSBoundParameters.ContainsKey('PoolGroupId')){
        try{
                
            $GraphQLBody = "{`"query`":`"query HorizonSessions {`\n    horizonSessions(`\n        orgId: `\`"$orgId`\`"`\n        templateId: `\`"$poolId`\`"`\n    size: 1000\n) {`\n        orgId`\n        templateId`\n        poolGroupId`\n        sessionStatus`\n        size`\n        totalElements`\n        totalPages`\n        content {`\n            vmId`\n            vmName`\n            userId`\n            dspecId`\n            agentSessionGuid`\n            agentSessionId`\n            sessionType`\n            templateType`\n            templateId`\n            clientId`\n            sessionStatus`\n            lastAssignedTime`\n            lastLoginTime`\n            username`\n            releaseSessionOnDeassign`\n            entitlementId`\n            orgId`\n            sessionStateDuration`\n            viewClientProtocol`\n        }`\n    }`\n}`",`"variables`":{}}"
            
            $response = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLBody -ErrorAction Stop
            $pagecount = $response.data.horizonSessions.totalPages
            if($pagecount -eq "1"){
                $sessionDetails = $response.data.horizonSessions.content
                return $sessionDetails
            }
            else{
                try{
                    $pagenumbers = -1
                    $dataarray = @()
                    Do {
                        [int]$pagenumbers += 1      
                        $GraphQLMorePagesBody = "{`"query`":`"query HorizonSessions {`\n    horizonSessions(`\n        orgId: `\`"$orgId`\`"`\n        templateId: `\`"$poolId`\`"`\n    size: 1000\n    page: `\`"$pagenumbers`\`"`\n) {`\n        orgId`\n        templateId`\n        poolGroupId`\n        sessionStatus`\n        size`\n        totalElements`\n        totalPages`\n        content {`\n            vmId`\n            vmName`\n            userId`\n            dspecId`\n            agentSessionGuid`\n            agentSessionId`\n            sessionType`\n            templateType`\n            templateId`\n            clientId`\n            sessionStatus`\n            lastAssignedTime`\n            lastLoginTime`\n            username`\n            releaseSessionOnDeassign`\n            entitlementId`\n            orgId`\n            sessionStateDuration`\n            viewClientProtocol`\n        }`\n    }`\n}`",`"variables`":{}}"
                        Write-Verbose "$GraphQLMorePagesBody"     
                        $resultsbypage = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLMorePagesBody -ErrorAction Stop
                        Write-Verbose $resultsbypage
                        $dataarray += $resultsbypage.data.horizonSessions.content
                        $pagecount -= 1
                    } while ($pagecount -gt 0)
                    return $dataarray
                }
                catch{
                    Write-Host -ForegroundColor Red  "Get-HCSSession: Error while retriving Session details using Pool Id"
                    $string_err = $_ | Out-String
                    Write-Host $string_err
                    break
                }
            }
        }
        catch{
            Write-Host -ForegroundColor Red  "Get-HCSSession: Error while retriving Session details using Pool Id"
            $string_err = $_ | Out-String
            Write-Host $string_err
            break
        }
   }
   elseif($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId') -and !$PSBoundParameters.ContainsKey('PoolId')){
        try{
        
            $GraphQLBody = "{`"query`":`"query HorizonSessions {`\n    horizonSessions(`\n        orgId: `\`"$orgId`\`"`\n        poolGroupId: `\`"$poolGroupId`\`"`\n    size: 1000\n) {`\n        orgId`\n        templateId`\n        poolGroupId`\n        sessionStatus`\n        size`\n        totalElements`\n        totalPages`\n        content {`\n            vmId`\n            vmName`\n            userId`\n            dspecId`\n            agentSessionGuid`\n            agentSessionId`\n            sessionType`\n            templateType`\n            templateId`\n            clientId`\n            sessionStatus`\n            lastAssignedTime`\n            lastLoginTime`\n            username`\n            releaseSessionOnDeassign`\n            entitlementId`\n            orgId`\n            sessionStateDuration`\n            viewClientProtocol`\n        }`\n    }`\n}`",`"variables`":{}}"

            $response = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLBody -ErrorAction Stop
            $pagecount = $response.data.horizonSessions.totalPages
            if($pagecount -eq "1"){
                $sessionDetails = $response.data.horizonSessions.content
                return $sessionDetails
            }
            else{
                try{
                    $pagenumbers = -1
                    $dataarray = @()
                    Do {
                        [int]$pagenumbers += 1
                        $GraphQLMorePagesBody = "{`"query`":`"query HorizonSessions {`\n    horizonSessions(`\n        orgId: `\`"$orgId`\`"`\n        poolGroupId: `\`"$poolGroupId`\`"`\n    size: 1000\n    page: `\`"$pagenumbers`\`"`\n) {`\n        orgId`\n        templateId`\n        poolGroupId`\n        sessionStatus`\n        size`\n        totalElements`\n        totalPages`\n        content {`\n            vmId`\n            vmName`\n            userId`\n            dspecId`\n            agentSessionGuid`\n            agentSessionId`\n            sessionType`\n            templateType`\n            templateId`\n            clientId`\n            sessionStatus`\n            lastAssignedTime`\n            lastLoginTime`\n            username`\n            releaseSessionOnDeassign`\n            entitlementId`\n            orgId`\n            sessionStateDuration`\n            viewClientProtocol`\n        }`\n    }`\n}`",`"variables`":{}}"
                        Write-Verbose "$GraphQLMorePagesBody"     
                        $resultsbypage = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLMorePagesBody -ErrorAction Stop
                        Write-Verbose $resultsbypage
                        $dataarray += $resultsbypage.data.horizonSessions.content
                        $pagecount -= 1
                    } while ($pagecount -gt 0)
                    return $dataarray
                }
                catch{
                    Write-Host -ForegroundColor Red  "Get-HCSSession: Error while retriving Session details using PoolGroup Id"
                    $string_err = $_ | Out-String
                    Write-Host $string_err
                    break
                }
            }
        }
        catch{
            Write-Host -ForegroundColor Red  "Get-HCSSession: Error while retriving Session details using PoolGroup Id"
            $string_err = $_ | Out-String
            Write-Host $string_err
            break
        }
    }
    elseif($PSBoundParameters.ContainsKey('OrgId') -and !$PSBoundParameters.ContainsKey('PoolGroupId') -and !$PSBoundParameters.ContainsKey('PoolId')){
        Write-Host -ForegroundColor Yellow  "Get-HCSSession: Please verify the parameters; When specifying the OrgId, either the PoolId or PoolGroupId must be provided"
    }
    elseif($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId') -and $PSBoundParameters.ContainsKey('PoolId')){
        Write-Host -ForegroundColor Yellow  "Get-HCSSession: Please verify the parameters; only one of PoolId or PoolGroupId is allowed"
    }
}

function Get-HCSEntitlements {
    <#
        .SYNOPSIS
            Retrieves the per PoolGroup entitlments.
        .DESCRIPTION
            Retrieves the per PoolGroup entitlments.
            OrgId & PoolGroupId's are mandatory to get the infromation
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER poolGroupId
            Provide the poolGroup id
        .PARAMETER appIdentifier
            It's am optional parameter , used to find published apps on demand with app volumes
        .EXAMPLE
            # Retrieves the eititlements 
                Get-HCSEntitlements -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 672bxxxxxx4exxd

                Get-HCSEntitlements -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 672bxxxxxx4exxd | Select entitlementId,entitlementType,Name,Id,DomainName,TotalDesktops,TotalApplications | ft -AutoSize
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$poolGroupId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$appIdentifier
    )
    
    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }


    # Helper function to perform GraphQL requests
    function Invoke-GraphQLRequest {
        param (
            [string]$body,
            [int]$pageCount
        )

        $dataArray = @()
        $pageNumber = 0

        # Loop for handling multiple pages
        do {
            $pagedBody = $body -replace 'page: `"\d+`"', "page: `"$pageNumber`""
            $responseGraphQL = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $pagedBody -ErrorAction Stop
            Write-Verbose "Invoke-GraphQLRequest response is $responseGraphQL"
            $dataArray += $responseGraphQL.data.horizonSessions.content
            $pageCount--
            $pageNumber++
        } while ($pageCount -gt 0)

        return $dataArray
        Write-Verbose "multiple pages response - $dataArray"
    }

    # Construct GraphQL query body
    if($appIdentifier){
        $GraphQLBody = "{`"query`":`"query HorizonPoolEntitlements {`\n    horizonPoolEntitlements(`\n        poolId: `\`"$poolGroupId`\`"`\n        appIdentifier: `\`"$appIdentifier`\`"`\n        orgId: `\`"$orgId`\`"`\n        page: 0`\n        size: 1000`\n    ) {`\n        orgId`\n        size`\n        totalElements`\n        totalPages`\n        content {`\n            orgId`\n            location`\n            entitlementId`\n            entitlementType`\n            id`\n            name`\n            domainName`\n            totalDesktops`\n            totalApplications`\n            poolIds`\n            assignmentType`\n        }`\n    }`\n}`",`"variables`":{}}"

    }else{
        $GraphQLBody = "{`"query`":`"query HorizonPoolEntitlements {`\n    horizonPoolEntitlements(`\n        poolId: `\`"$poolGroupId`\`"`\n        orgId: `\`"$orgId`\`"`\n        page: 0`\n        size: 1000`\n    ) {`\n        orgId`\n        size`\n        totalElements`\n        totalPages`\n        content {`\n            orgId`\n            location`\n            entitlementId`\n            entitlementType`\n            id`\n            name`\n            domainName`\n            totalDesktops`\n            totalApplications`\n            poolIds`\n            assignmentType`\n        }`\n    }`\n}`",`"variables`":{}}"
    }
    Write-Verbose $GraphQLBody

    try {
        $response = Invoke-RestMethod 'https://cloud-sg.horizon.omnissa.com/graphql/' -Method 'POST' -Headers $headers -Body $GraphQLBody -ErrorAction Stop
        $pageCount = $response.data.horizonPoolEntitlements.totalPages
        Write-Verbose "GraphQL API response in try statement - $response"

        if ($pageCount -eq 1) {
            return $response.data.horizonPoolEntitlements.content
        }elseif ($pageCount -eq 0) {
            Write-Verbose "Response is null - please check the PoolGroupId & appIdentifier information"
            return $response.data.horizonPoolEntitlements.content
        }else{
            return Invoke-GraphQLRequest -body $GraphQLBody -pageCount $pageCount
        }
    }
    catch {
        Write-Host -ForegroundColor Red "Error retrieving Entitlement details: $_"
    }
}

function Get-HCSUsers {
    <#
    .SYNOPSIS
        Retrieves the user information from the associated identity provider (Azure Entra / WorkSpace ONE). 
    .DESCRIPTION
        Get-HCSUsers cmdlet retrieves information of users synced to associated identity provider (Azure Entra / WorkSpace ONE)
        When the cmdlet is executed with the OrgId, it retrieves all the users synchronized to the identity provider.    
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER domain
        It's an optional parmeter , Please provide fully qualified domain name Ex: hcsops.com 
    .PARAMETER userName
        It's an optional parmeter , please provide Username to filter the output
    .PARAMETER firstName
        It's an optional parmeter , Once FirstName is provider output data filter out based on the FirstName
    .PARAMETER lastName
        It's an optional parmeter , Once LastName is provider output data filter out based on the LastName
    .PARAMETER userId
        It's an optional parmeter , Once userId is provider output data filter out based on the userId
    .EXAMPLE
        Get-HCSUsers -OrgId f9b98412-658b-45db-a06b-000000000000 
    .EXAMPLE
        Get-HCSUsers -OrgId f9b98412-658b-45db-a06b-000000000000 -domain hcsops.com
    .EXAMPLE
        Get-HCSUsers -OrgId f9b98412-658b-45db-a06b-000000000000  -UserName John

        Get-HCSUsers -OrgId f9b98412-658b-45db-a06b-000000000000 -domain hcsops.com -UserName John
    .EXAMPLE
        Get-HCSUsers -OrgId f9b98412-658b-45db-a06b-000000000000 -UserId axx59xxxx2-2xx6d-4cxx-a095-18xxxxrb0fb4    
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$userName,
        [string]$firstName,
        [string]$lastName,
        [string]$domain,
        [string]$userId
    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type'  = "application/json";
        'Accept'        = "*/*";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    # Ensure only one identifier parameter is provided
    $providedParams = @(@($userName, $firstName, $lastName, $userId)| Where-Object { $_ -ne $null -and $_ -ne '' })
    Write-Verbose " Provided Parameters : $providedParams"
    Write-Verbose " Provider Parameters count : $($providedParams.Count) "
    if (($providedParams).Count -gt 1) {
        Write-Host -ForegroundColor Yellow "Please provide only one parameter among userName, firstName, lastName, and userId."
        return
    }

    # Generate JSON payload for the request body
    $commonPayload = @{}
    if ($userName) {
        $commonPayload.userName = $userName
    } elseif ($firstName) {
        $commonPayload.firstName = $firstName
    } elseif ($lastName) {
        $commonPayload.lastName = $lastName
    } elseif ($userId) {
        $commonPayload.userIds = @($userId)
    }

    # Add domain if provided
    if ($domain) {
        $commonPayload.domain = $domain
    }

    # Convert the payload to JSON
    $payloadJson = $commonPayload | ConvertTo-Json -Depth 4
    Write-Verbose "JSON Payload: $payloadJson"

    # Make the REST API call
    try {
        $uri = "https://cloud.omnissahorizon.com/auth/v2/admin/users/search?org_id=$orgId"
        Write-Verbose "POST URL: $uri"
        $userDetails = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payloadJson -ErrorAction Stop
        return $userDetails.users
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSUsers: Error while retrieving user details"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSGroups {
    <#
    .SYNOPSIS
        Retrieves the user information from the associated identity provider (Azure Entra / WorkSpace ONE). 
    .DESCRIPTION
        Get-HCSGroups cmdlet retrieves information of users synced to associated identity provider (Azure Entra / WorkSpace ONE)
        When the cmdlet is executed with the OrgId, it retrieves all the users synchronized to the identity provider.    
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER groupName
        It's an optional parmeter , Please provide groupName
    .PARAMETER groupId
        It's an optional parmeter , please provide groupId
    .PARAMETER onPremSid
        It's an optional parmeter , please provide onPremSid
    .EXAMPLE
        Get-HCSGroups -OrgId f9b98412-658b-45db-a06b-000000000000 
    .EXAMPLE
        Get-HCSGroups -OrgId f9b98412-658b-45db-a06b-000000000000 -groupName John
        
        Get-HCSGroups -OrgId f9b98412-658b-45db-a06b-000000000000 -groupId John
    .EXAMPLE
        Get-HCSGroups -OrgId f9b98412-658b-45db-a06b-000000000000 -onPremSid axx59xxxx2-2xx6d-4cxx-a095-18xxxxrb0fb4    
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$groupName,
        [string]$groupId,
        [string]$onPremSid
    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type'  = "application/json";
        'Accept'        = "*/*";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    # Ensure only one identifier parameter is provided
    $providedParams = @(@($groupName, $groupId, $onPremSid)| Where-Object { $_ -ne $null -and $_ -ne '' })
    Write-Verbose " Provided Parameters : $providedParams"
    Write-Verbose " Provider Parameters count : $($providedParams.Count) "
    if ($providedParams.count -gt 1) {
        Write-Host -ForegroundColor Yellow "Please provide only one parameter among groupName, groupId and onPremSid."
        return
    }

    # Generate JSON payload for the request body
    $commonPayload = @{}
    if ($groupName) {
        $commonPayload.displayName = $groupName
    } elseif ($groupId) {
        $commonPayload.groupIds = @($groupId)
    } elseif ($onPremSid) {
        $commonPayload.onPremSid = $onPremSid
    }

    # Convert the payload to JSON
    $payloadJson = $commonPayload | ConvertTo-Json -Depth 4
    Write-Verbose "JSON Payload: $payloadJson"

    # Make the REST API call
    try {
        $uri = "https://cloud.omnissahorizon.com/auth/v2/admin/groups/search?org_id=$orgId"
        Write-Verbose "POST URL: $uri"
        $userDetails = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payloadJson -ErrorAction Stop
        return $userDetails.groups
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSGroups: Error while retrieving user details"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSGroupUsers {
    <#
    .SYNOPSIS
        Retrieves the users who are part of a specific group synced to the Identity provider. 
    .DESCRIPTION
       Get-HCSGroupUsers cmdlet retrieves users list who are part of a group synchronized with the Identity provider..   
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER groupId
        Please provide the groupId, which can be retrieved from Get-HCSGroups.
    .EXAMPLE
        Get-HCSGroupUsers -OrgId f9b98412-658b-45db-a06b-000000000000 -groupIdId 691c3dx8-7c9c-442e-b282-be117v71646
    .EXAMPLE
        Get-HCSGroupUsers -OrgId f9b98412-658b-45db-a06b-000000000000 -groupIdId 691c3dx8-7c9c-442e-b282-be117v71646 -transitive $true
    .EXAMPLE
        Get-HCSGroupUsers -OrgId f9b98412-658b-45db-a06b-000000000000 -groupIdId 691c3dx8-7c9c-442e-b282-be117v71646 -transitive $false
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter( Mandatory = $true)]
        [String]$OrgId,
        [String]$groupId,

        [ValidateNotNullOrEmpty()]
        [Parameter( Mandatory = $false)]
        [String]$transitive
    )
    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 'Accept' = "*/*";
    }
    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry) {
        Write-Verbose "Token is valid"
    }
    else {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        $string_err = $_ | Out-String
        Write-Host -ForegroundColor Red $string_err
        break
    }
    if ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('groupId')) {
        if ($transitive -eq $true) {
            try {
                $dataUGT = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/auth/v1/admin/groups/$groupId/users?org_id=$OrgId&transitive=true") -Method Get -Headers $headers -ErrorAction Stop).users
                return $dataUGT
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black " Get-HCSGroupUsers: Error while retriving users details with given search parameters "
                $string_err = $_ | Out-String
                Write-Host -ForegroundColor Red $string_err
                Break
            }
        }
        elseif ($transitive -eq $false) {
            try {
                $dataUGT = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/auth/v1/admin/groups/$groupId/users?org_id=$OrgId&transitive=false") -Method Get -Headers $headers -ErrorAction Stop).users
                return $dataUGT
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black " Get-HCSGroupUsers: Error while retriving users details with given search parameters "
                $string_err = $_ | Out-String
                Write-Host -ForegroundColor Red $string_err
                Break
            }
        }
        else {
            try {
                $dataUGT = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/auth/v1/admin/groups/$groupId/users?org_id=$OrgId") -Method Get -Headers $headers -ErrorAction Stop).users
                return $dataUGT
            }
            catch {
                Write-Host -ForegroundColor Red -BackgroundColor Black " Get-HCSGroupUsers: Error while retriving users details with given search parameters "
                $string_err = $_ | Out-String
                Write-Host -ForegroundColor Red $string_err
                Break
            }
        }
    }
    else {
        try {
            $dataUGT = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/auth/v1/admin/groups/$groupId/users?org_id=$OrgId") -Method Get -Headers $headers -ErrorAction Stop).users
            return $dataUGT
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black " Get-HCSGroupUsers: Error while retriving users details with given search parameters "
            $string_err = $_ | Out-String
            Write-Host -ForegroundColor Red $string_err
            Break
        }
    }  
}

function Get-HCSUserGroups {
    <#
    .SYNOPSIS
        Retrieves the user information from the associated identity provider. 
    .DESCRIPTION
       Get-HCSUserGroups cmdlet retrieves the associated user groups' details from the linked identity provider.   
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER UserId
        Please provide UserId ,can be retrieved from Get-HCSUsers
    .EXAMPLE
        Get-HCSUserGroups -OrgId f9b98412-658b-45db-a06b-000000000000 -UserId a8667622-216d-4v1a-a095-188ndd4rb0f54
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter( Mandatory = $true)]
        [String]$OrgId,
        [String]$UserId
    )    
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 'Accept' = "*/*";
    }
    #check token validity
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    $currenttime = (Get-Date).AddMinutes(5)
    if ($currenttime -lt $tokenexpiry) {
        Write-Verbose "Token is valid"
    }
    else {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        break
    }
    if ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('UserId')) {
        try {
            $dataUGT = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/auth/v1/admin/user/$UserId/groups?org_id=$OrgId") -Method Get -Headers $headers -ErrorAction Stop).groups
            return $dataUGT
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSUserGroups: Error while retriving nested Users details with given search parameters "
            $string_err = $_ | Out-String
            Write-Host -ForegroundColor Red $string_err
            Break
        }
         
    }
    else {
        try {
            $dataUGF = (Invoke-RestMethod -Uri $("https://cloud.vmwarehorizon.com/auth/v1/admin/user/$UserId/groups?org_id=$OrgId") -Method Get -Headers $headers -ErrorAction Stop).groups
            return $dataUGF
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Get-HCSUserGroups: Error while retriving nested Users details with given search parameters "
            $string_err = $_ | Out-String
            Write-Host -ForegroundColor Red $string_err
            break
        }
    }    
}

function New-HCSPool {
    <#  
        .SYNOPSIS  
            Creates a New Pool with provided parameters in next-gen Org  
        .DESCRIPTION  
            Creates a New Pool with provided parameters in next-gen Org    
            If a JSON payload exists, there is no need to pass any parameters, as the cmdlet will read the information from the JSON file and create the pool accordingly.
            However, if the JSON parameters are not provided, you must pass the following mandatory parameters:
                OrgId,PoolName,PoolType,ImageId,MarkerId,VmModelSku,DiskSku,ActiveDirectoryId,uagDeploymentId,providerId,DesktopAdminUsername,DesktopAdminPassword,ComputerOU
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER PoolName
            Name of the pool.
        .PARAMETER PoolType
            Provide the poolType - allowed values are 'FLOATING', 'DEDICATED', 'MULTI_SESSION'
        .PARAMETER ProvisioningType
            Provide the ProvisioningType - allowed values are 'ON_DEMAND', 'UP_FRONT'
        .PARAMETER Description
            It's an optional parameter . provide a description for the pool if necessary 
        .PARAMETER ImageId
            provide the mageId from which pool VMs needs to be created . Get-HCSImage will help 
        .PARAMETER MarkerId
            provide the MarkerId of the ImageId from which pool VMs needs to be created . Get-HCSImage will help 
        .PARAMETER AvailabilityZone
            The Boolean value defaults to $false. Set it to $true to enable the AvailabilityZone.
        .PARAMETER VmModelSku
            Provide the VmModel - Ex: Standard_A4_v2
        .PARAMETER DiskSku
            Provide the DiskSku - allowed values are 'Premium_LRS', 'Premium_ZRS', 'PremiumV2_LRS', 'Standard_LRS', 'StandardSSD_LRS', 'StandardSSD_ZRS', 'UltraSSD_LRS'
        .PARAMETER ComputerOU
            Provide the computerOU where the VM's will join the domain - Ex: "OU=Computers,OU=Horizon,DC=domain,DC=com"
        .PARAMETER SubnetId
            Provide the SubnetId Ex: "/subscriptions/xxx-34a2-4a23-x9f7-254xxxfb3/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_CENTRAL_VNET_01/subnets/VDI01"
            (Get-HCSNetworks -OrgId $OrgId -ProviderId $ProviderId -Environment Azure -Preffered $true).desktop can help in getting the information
            if the SubnetId not provided then cmdlet take the preffered networks on the provider as input
        .PARAMETER providerId
            Provide the providerID 
        .PARAMETER ActiveDirectoryId
            Provide the ActiveDirectoryId
            Get-HCSAD cmdlet will be useful to get this information
        .PARAMETER uagDeploymentId
            Provide the UagDeploymentId
            Get-HCSUAG cmdlet will be useful to get this information
        .PARAMETER VmNamePrefix
            Provide the VMNamePattern , if not provided then from the poolName the cmdlet autogenerates
        .PARAMETER ReuseVmId
            The Boolean value defaults to $true. Set it to $false if new vmName needed
        .PARAMETER DesktopAdminUsername
            Image Vm administrator user name
        .PARAMETER DesktopAdminPassword
            Image Vm administrator password
            since the parameter is a securestring - convert the password to securestring and pass as a variable
            Example:
                $password="P@s$W0rd123#" | ConvertTo-SecureString -AsPlainText -Force
            
                To check the above converted password is correct then execute -> ConvertFrom-SecureString $password -AsPlainText
        .PARAMETER DiskEncryption
            The Boolean value defaults to $false. Set it to $true to enable the DiskEncryption.
        .PARAMETER MinSpareVm
            Minimum number of spare/unassigned VM's to be always available in a pool
            Default value is set to 1 and can be modified after pool creation
        .PARAMETER MaximumSpareVm
            Maximum number of spare/unassigned VM's can be possible in a pool
            Default value is set to 1 and can be modified after pool creation
        .PARAMETER MaximumVm
            Maximum number of VM's can be provisioned in the pool
            Default value is set to 1 and can be modified after pool creation
        .PARAMETER SessionsPerVm
            Default to 1 and configurable 
            How many sessions can be possible in a VM , For Muiltisession Pools this parameter can be configurable and if not provided for any reason this input is editable from the pool
            For Dedicated & Floating pools this values shoubde set to 1
        .PARAMETER ProxyServer
            proxy server IP / Hostname for agent to Horizon Cloud ControlPlane communication
        .PARAMETER ProxyPort
            proxy servver port
        .PARAMETER DEMId
            if DEM is configured , provide the DEM ID
            if the DEM ID is passwed ,DEM uses NOAD mode hence if DEM is delivered through group polices then don't specify this parameter
        .PARAMETER JsonFilePath
            Provide the path to JSON file
        .EXAMPLE
            # Pool creation by providing JSON file

                New-HCSPool -JsonFilePath "C:\temp\new-pool-01.json" -Verbose

            # Pool Creation with Mandatory parameters

                New-HCSPool -PoolName "P01-Shell-Pool" -PoolType FLOATING -ImageId 660axxdf3dxxxd06cxxc -MarkerId 660ab3xxxx0882xx02 -OrgId "f9b98412-658b-45db-a06b-000000000000" -VmModelSku Standard_F2s -DiskSku StandardSSD_LRS -ComputerOU "OU=Computers,OU=Horizon,DC=domain,DC=com" -ActiveDirectoryId 6451f755xxxx72dd5xxx52 -uagDeploymentId 64ae68xxxx09a38xx1 -providerId 6450e94xxxfxxcxxxd3dx -DesktopAdminUsername "localadmin" -DesktopAdminPassword $password -Verbose

            # Pool Creation with proxy

                New-HCSPool -PoolName "P02-Shell-Pool" -PoolType FLOATING -ImageId 660axxdf3dxxxd06cxxc -MarkerId 660ab3xxxx0882xx02 -OrgId "f9b98412-658b-45db-a06b-000000000000" -VmModelSku Standard_F2s -DiskSku StandardSSD_LRS -ComputerOU "OU=Computers,OU=Horizon,DC=domain,DC=com" -ActiveDirectoryId 6451f755xxxx72dd5xxx52 -uagDeploymentId 64ae68xxxx09a38xx1 -providerId 6450e94xxxfxxcxxxd3dx -DesktopAdminUsername "localadmin" -DesktopAdminPassword $password -ProxyServer "10.0.0.4" -ProxyPort 3128 -Verbose

            # Pool creation with provision type as OnDemand , SpareVMs,specific Subnet & sessionperVM for a MultiSession Pool

                New-HCSPool -PoolName "P03-Shell-Pool" -PoolType FLOATING -ImageId 660axxdf3dxxxd06cxxc -MarkerId 660ab3xxxx0882xx02 -OrgId "f9b98412-658b-45db-a06b-000000000000" -VmModelSku Standard_F2s -DiskSku StandardSSD_LRS -ComputerOU "OU=Computers,OU=Horizon,DC=domain,DC=com" -ActiveDirectoryId 6451f755xxxx72dd5xxx52 -uagDeploymentId 64ae68xxxx09a38xx1 -providerId 6450e94xxxfxxcxxxd3dx -DesktopAdminUsername "localadmin" -DesktopAdminPassword $password -SubnetId "/subscriptions/xxxxe-2xx2-xxx-8xxx-xx61xxxxf4/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_W2_VNET_01/subnets/VM_02" -ProvisioningType ON_DEMAND -MinSpareVm 2 -MaximumSpareVm 3 -MaximumVm 10 -SessionsPerVm 7 -Verbose                

    #>
    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'JsonInput')]
        [ValidateNotNullOrEmpty()]
        [String]$JsonFilePath,

        [Parameter(Mandatory = $false)]
        [string]$PoolName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('FLOATING', 'DEDICATED', 'MULTI_SESSION')]
        [string]$PoolType,

        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string]$ImageId,

        [Parameter(Mandatory = $false)]
        [string]$MarkerId,

        [Parameter(Mandatory = $false)]
        [string]$OrgId,

        [bool]$AvailabilityZone = $false,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("[Standard][_][0-9a-z]")]
        [string]$VmModelSku,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Premium_LRS', 'Premium_ZRS', 'PremiumV2_LRS', 'Standard_LRS', 'StandardSSD_LRS', 'StandardSSD_ZRS', 'UltraSSD_LRS')]
        [string]$DiskSku,

        [string]$SubnetId,
        [string]$ComputerOU,

        [Parameter(Mandatory = $false)]
        [string]$ActiveDirectoryId,

        [Parameter(Mandatory = $false)]
        [string]$uagDeploymentId,

        [Parameter(Mandatory = $false)]
        [string]$providerId,

        [ValidateSet('ON_DEMAND', 'UP_FRONT')]
        [string]$ProvisioningType = "UP_FRONT",

        [int]$MinSpareVm = 1,
        [int]$MaximumSpareVm = 1,
        [int]$MaximumVm = 1,
        [int]$SessionsPerVm = 1,
        [string]$VmNamePrefix,

        [Boolean]$ReuseVmId = $true,

        [Parameter(Mandatory = $false)]
        [string]$DesktopAdminUsername,

        [Parameter(Mandatory = $false)]
        [SecureString]$DesktopAdminPassword,

        [bool]$DiskEncryption = $false,
        [string]$DEMId,

        [ValidateNotNullOrEmpty()]
        [string]$ProxyServer,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [int]$ProxyPort
    )

    Process {
        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"; 
            'content-type'  = "application/json"; 
            'Accept'        = "application/json";
        }

        # Check token validity
        $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        if ((Get-Date).AddMinutes(5) -lt $tokenexpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        
        try {
            if ($JsonFilePath) {
                # Check if the JSON file exists
                if (-not (Test-Path -Path $JsonFilePath)) {
                    Throw "The specified JSON file '$JsonFilePath' does not exist."
                }
                # Read and parse the JSON file
                $jsonPayload = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
                # Convert the JSON object back to a string for the payload
                $payloadJson = $jsonPayload | ConvertTo-Json -Depth 10
                Write-Verbose "JsonInput provided is - $payloadJson"
            }
            else {
                # Check if Mandatory parameters are provided
                if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolName') -and $PSBoundParameters.ContainsKey('PoolType') -and $PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('MarkerId') -and $PSBoundParameters.ContainsKey('VmModelSku') -and $PSBoundParameters.ContainsKey('DiskSku') -and $PSBoundParameters.ContainsKey('ActiveDirectoryId') -and $PSBoundParameters.ContainsKey('uagDeploymentId') -and $PSBoundParameters.ContainsKey('providerId') -and $PSBoundParameters.ContainsKey('DesktopAdminUsername') -and $PSBoundParameters.ContainsKey('DesktopAdminPassword') -and $PSBoundParameters.ContainsKey('ComputerOU'))) {
                    Write-Host -ForegroundColor Red "New-HCSPool: Mandatory parameters missing - please check if one of OrgId,PoolName,PoolType,ImageId,MarkerId,VmModelSku,DiskSku,ActiveDirectoryId,uagDeploymentId,providerId,DesktopAdminUsername,DesktopAdminPassword,ComputerOU is missing"
                    return
                }

                $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $ProviderId -Environment Azure -Preffered $true).desktop
        
                # Disk Encryption JSON
                $diskEncryptionhash = @{ enabled = $DiskEncryption }
                $diskEncryptionJson = $diskEncryptionhash | ConvertTo-Json -Depth 4

                Write-Verbose "Disk encryption JSON: $diskEncryptionJson"

                # Reuse VM ID
                $ReuseVmId = $ReuseVmId.ToString().ToLower()

                # Availability Zone
                $AvailabilityZone = $AvailabilityZone.ToString().ToLower()

                # VM Size SKU
                try {
                    $VmsizeSkuJson = Get-HCSAzureVmSkus -OrgId $OrgId -providerId $providerId -VmSize $VmModelSku
                    if ($VmsizeSkuJson.id -ne $VmModelSku) {
                        Write-Host -ForegroundColor Red "Get-HCSAzureVmSkus : Unable to retrieve VMSize details, please recheck the VM Size and try again"
                        return
                    }
                }
                catch {
                    Write-Host -ForegroundColor Red "Get-HCSAzureVmSkus : Unable to retrieve VMSize details, please recheck the VM Size and try again"
                    return
                }

                Write-Verbose "VM Size SKU JSON: $VmsizeSkuJson"

                # Disk SKU
                try {
                    $DiskSizeSkus = Get-HCSAzureDiskSkus -OrgId $OrgId -providerId $ProviderId -VmSize $VmModelSku
                    if ($null -eq $DiskSizeSkus) {
                        Write-Host -ForegroundColor Red "New-HCSPool: Unable to retrieve DiskSku details, please check provided DiskSku and try again"
                        return
                    }
                    $DiskSizeSkuJson = $DiskSizeSkus | Where-Object { $_.id -eq $DiskSku }
                }
                catch {
                    Write-Host -ForegroundColor Red "New-HCSPool: Unable to retrieve DiskSku details, please check provided DiskSku and try again"
                    return
                }

                Write-Verbose "Disk SKU JSON: $DiskSizeSkuJson"

                # Spare Policy
                $sparePolicyHash = if ($ProvisioningType -eq "UP_FRONT") {
                    @{ description = ""; limit = $MaximumVm; max = $MaximumVm; min = $MaximumVm }
                }
                else {
                    @{ description = ""; limit = $MaximumVm; max = $MaximumSpareVm; min = $MinSpareVm }
                }
                $sparePolicyJson = $sparePolicyHash | ConvertTo-Json -Depth 4

                Write-Verbose "Spare policy JSON: $sparePolicyJson"

                # Decrypt Password
                $decryptPassArray = (ConvertFrom-SecureString $DesktopAdminPassword -AsPlainText).ToCharArray()
                $decryptPassJson = $decryptPassArray | ConvertTo-Json -Depth 4

                Write-Verbose "Decrypted password JSON: $decryptPassJson"

                # Validate Image and Marker IDs
                try {
                    $Imagevalidation = Get-HCSImageMarkers -OrgId $OrgId -ImageId $ImageId -MarkerId $MarkerId
                    if ($Imagevalidation.imageId -ne $ImageId) {
                        Write-Host -ForegroundColor Red "New-HCSPool : Please validate ImageId & MarkerId details"
                        return
                    }
                }
                catch {
                    Write-Host -ForegroundColor Red "New-HCSPool : Please validate ImageId & MarkerId details"
                    return
                }

                # Set VM Name Pattern
                $vmNamePattern = if ($PSBoundParameters.ContainsKey('VmNamePrefix')) {
                    $VmNamePrefix
                }
                else {
                    $name = $PoolName -replace '^[^a-zA-Z]+', '' -replace '[^a-zA-Z0-9-]', ''
                    $trimmedName = $name.Substring(0, [Math]::Min($name.Length, 10))
                    "$trimmedName-"
                }

                Write-Verbose "VM Name Pattern: $vmNamePattern"

                # Proxy Handling
                if ($PSBoundParameters.ContainsKey('ProxyServer') -and $PSBoundParameters.ContainsKey('ProxyPort')) {
                    $proxyhttp = "http://$ProxyServer" + ":" + "$ProxyPort"
                    $ProxyInfoHash = @{ bypass = ""; server = $proxyhttp }
                    $ProxyInfoJson = $ProxyInfoHash | ConvertTo-Json -Depth 4
                    Write-Verbose "Proxy Info JSON: $ProxyInfoJson"
                    $agentCustomizationHash = @{ DEMId = $DEMId; proxyInfo = $ProxyInfoHash }

                }
                elseif (!$PSBoundParameters.ContainsKey('ProxyServer') -and $PSBoundParameters.ContainsKey('ProxyPort')) {
                    Write-Host -ForegroundColor Red "New-HCSPool : ProxyServer is a mandatory parameter when ProxyPort is specified"
                    return

                }
                elseif ($PSBoundParameters.ContainsKey('ProxyServer') -and !$PSBoundParameters.ContainsKey('ProxyPort')) {
                    Write-Host -ForegroundColor Red "New-HCSPool : New-HCSPool : ProxyPort is a mandatory parameter when ProxyServer is specified"
                    return

                }
                else {
                    $agentCustomizationHash = @{ DEMId = $DEMId }
                }
        
                $agentCustomizationJson = $agentCustomizationHash | ConvertTo-Json -Depth 4

                Write-Verbose "Agent Customization JSON: $agentCustomizationJson"

                # Networks
                if ($PSBoundParameters.ContainsKey('SubnetId')) {
                    try {
                        $networksJson = $PrefferedNetworks | Where-Object { $SubnetId -contains $_.id }
                    }
                    catch {
                        Write-Host -ForegroundColor Red "New-HCSPool: Unable to retrieve Preffered networks"
                        return
                    }
                }
                else {
                    $networksJson = $PrefferedNetworks
                }
        
                $networksJsonHash = $networksJson | ConvertTo-Json -Depth 6 | ConvertFrom-Json -AsHashtable
                Write-Verbose "Networks JSON Hash: $networksJsonHash"

                # Payload Creation
                $commonPayload = @{
                    availabilityZoneEnabled = $AvailabilityZone
                    description             = $Description
                    imageReference          = @{ streamId = $ImageId; markerId = $MarkerId }
                    agentCustomization      = $agentCustomizationHash
                    name                    = $PoolName
                    networks                = @($networksJsonHash)
                    diskSizeInGB            = "127"
                    diskEncryption          = $diskEncryptionhash
                    sparePolicy             = $sparePolicyHash
                    vmLicenseType           = "WINDOWS_CLIENT"
                    infrastructure          = @{
                        vmSkus   = @($VmsizeSkuJson)
                        diskSkus = @($DiskSizeSkuJson)
                    }
                    reuseVmId               = $ReuseVmId
                    computerAccountOU       = $ComputerOU
                    activeDirectoryId       = $ActiveDirectoryId
                    uagDeploymentId         = $uagDeploymentId
                    orgId                   = $OrgId
                    providerInstanceId      = $providerId
                    resourceTags            = @{}
                    licenseProvided         = $true
                    vmNamePattern           = $vmNamePattern
                    desktopAdminUsername    = $DesktopAdminUsername
                    desktopAdminPassword    = $decryptPassArray
                    templateType            = $PoolType
                }

                if ($PoolType -eq 'MULTI_SESSION') {
                    $commonPayload.sessionsPerVm = $sessionsPerVm
                }
                else {
                    $commonPayload.sessionsPerVm = 1
                }
                $payloadJson = $commonPayload | ConvertTo-Json -Depth 6
                Write-Verbose "Final Payload JSON: $payloadJson"

            }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSPool: Pool Creation Request for $PoolName failed for JsonInput generation"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }


        try {
            $urlPool = "https://cloud.omnissahorizon.com/admin/v2/templates?ignore_warnings=true"
            Write-Verbose "(Invoke-RestMethod -Uri $urlPool -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop)"
            $dataCreatePool = Invoke-WebRequest -Uri $urlPool -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop

            if ($dataCreatePool.StatusCode -eq 201 -and $dataCreatePool.StatusDescription -eq "Created") {
                Write-Host "New-HCSPool: $PoolName Creation Request is accepted"
                return $dataCreatePool.Content
            }
            else {
                Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSPool: Pool Creation Request for $PoolName failed"
                Write-Host -ForegroundColor Red ($dataCreatePool | Out-String)
                return
            }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSPool: Pool Creation Request for $PoolName failed"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }
    }
}

function New-HCSPoolGroup {
    <#  
        .SYNOPSIS  
            Creates a New PoolGroup with provided parameters in next-gen Org  
        .DESCRIPTION  
            Creates a New PoolGroup with provided parameters in next-gen Org    
            If a JSON payload exists, there is no need to pass any parameters, as the cmdlet will read the information from the JSON file and create the pool accordingly.
            However, if the JSON parameters are not provided, you must pass the following mandatory parameters:
                rgId,Name,PoolGroupType,PoolType,PoolId,PowerManagementType,PowerManagementMode,AlwaysPoweredOnVMPercent,LogoffDisconnectedSessions
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER Name
            Name of the PoolGroup.
        .PARAMETER PoolGroupType
            Provide the PoolGroupType - allowed values are 'DESKTOP', 'APPLICATION', 'DESKTOP_APPLICATION'
        .PARAMETER PoolType
            Provide the poolType - allowed values are 'FLOATING', 'DEDICATED', 'MULTI_SESSION'
        .PARAMETER PoolId
            Provide the poolID of the pool to be associated with this poolGroup
        .PARAMETER DisplayName
            DisplayName of the PoolGroup , Name & displayname can be different
        .PARAMETER Description
            It's an optional parameter . provide a description for the pool if necessary 
        .PARAMETER edgeDeploymentId
            Provide the edgeDeploymentId
            Get-HCSEdge cmdlet will be useful to get this information 
        .PARAMETER edgeDeploymentName
            Provide the edgeDeploymentName of the  edgeDeploymentId
        .PARAMETER DataCenterId
            Provide the datacenter ID - it's an optional parameter since we will get this info from the pool id parameter
        .PARAMETER EnableSSO
            Optional paramter - The Boolean value defaults to $true , if SSO not required on the specific poolgroup set it as $false
        .PARAMETER PowerManagementType
            Provide the PowerManagementType - allowed values are 'Occupancy', 'NonOccupancy'.
        .PARAMETER PowerManagementMode
            Provide the PowerManagementMode - allowed values are 'Performence', 'Balanced', 'Cost'.
            Performence - Optimized for Performence , Cost - Optimized for Cost and Balanced.
        .PARAMETER AlwaysPoweredOnVMPercent
            Provide the a value so that AlwaysPoweredOnVMPercent vm's will be always poweredON
        .PARAMETER PowerProtect
            Optional paramter - Provide the PowerProtect values - Maximum allowed value is 60 mins
            Default value is set to 30 mins.
        .PARAMETER PreferredClientType
            Optional paramter - Provide the PreferredClientType, allowed values are 'HORIZON_CLIENT', 'BROWSER'
            Default value is set to 'HORIZON_CLIENT'
        .PARAMETER SupportedDisplayProtocols
            Optional paramter and defaut to BLAST
        .PARAMETER Scope
            Optional paramter - Provide the Scope , allowed values are 'ALL_SITES', 'ONE_SITE'
            Default value is set to 'ALL_SITES'
        .PARAMETER connectionAffinity
            Optional paramter - Provide the connectionAffinity fro user logins . allowed values are 'NEAREST_SITE', 'HOME_SITE'
            Default value is set to 'NEAREST_SITE'
        .PARAMETER directConnect
            Optional paramter, The Boolean value defaults to $false. Set it to $true if UAG needs to be bypassed
        .PARAMETER ShowMachineName
            Optional paramter,The Boolean value defaults to $false. Set it to $true if Dedicated desktop name to be shown for user
            Applicable for Dedicated poolgroups
        .PARAMETER IdleSessionTimeout
            Optional paramter,Provide IdleSessionTimeout for the poolgroup
            Default value is set to '10080'
        .PARAMETER LogoffDisconnectedSessions
            Provide LogoffDisconnectedSessions, allowed values are 'IMMEDIATELY', 'NEVER', 'AFTER'
            If the parameter set to AFTER then "AutomaticLogoffMinutes" needs to be set
        .PARAMETER AutomaticLogoffMinutes
            Optional paramter,Provide AutomaticLogoffMinutes for the poolgroup
            Default value is set to '120'
        .PARAMETER MaximumSessionLifetime
            Optional paramter,Provide MaximumSessionLifetime for the poolgroup
            Default value is set to '10080'
        .PARAMETER JsonFilePath
            Provide the path to JSON file
        .EXAMPLE
            # PoolGroup creation by providing JSON file

                New-HCSPoolGroup -JsonFilePath "C:/temp/new-poolgroup-01.json" -Verbose

            # PoolGroup Creation with Mandatory parameters

                New-HCSPoolGroup -Name P02 -PoolGroupType DESKTOP -PoolType FLOATING -PoolId 675040dxxx645774xxe -PowerManagementType NonOccupancy -AlwaysPoweredOnVMPercent 10 -LogoffDisconnectedSessions AFTER -OrgId f9b98412-658b-45db-a06b-000000000000 -Verbose

    #>
    param(

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'JsonInput')]
        [ValidateNotNullOrEmpty()]
        [String]$JsonFilePath,

        [Parameter(Mandatory = $false)]
        [string]$PoolId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('FLOATING', 'DEDICATED', 'MULTI_SESSION')]
        [string]$PoolType,

        [Parameter(Mandatory = $false)]
        [ValidateSet('DESKTOP', 'APPLICATION', 'DESKTOP_APPLICATION')]
        [string]$PoolGroupType,

        [Parameter(Mandatory = $false)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName = "",

        [string]$edgeDeploymentId,
        [string]$edgeDeploymentName,
        [string]$DataCenterId,
        
        [Parameter(Mandatory = $false)]
        [string]$OrgId,

        [bool]$EnableSSO = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Occupancy', 'NonOccupancy')]
        [string]$PowerManagementType,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Performence', 'Balanced', 'Cost')]
        [string]$PowerManagementMode = "Balanced",

        [Parameter(Mandatory = $false)]
        [int]$AlwaysPoweredOnVMPercent,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IMMEDIATELY', 'NEVER', 'AFTER')]
        [string]$LogoffDisconnectedSessions,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$AutomaticLogoffMinutes = 120,

        [Parameter(Mandatory = $false)]
        [int]$MaximumSessionLifetime = 10080,

        [Parameter(Mandatory = $false)]
        [int]$IdleSessionTimeout = 10080,

        [bool]$ShowMachineName = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet('BLAST')]
        [string]$SupportedDisplayProtocols = "BLAST",

        [ValidateSet('HORIZON_CLIENT', 'BROWSER')]
        [string]$PreferredClientType = "HORIZON_CLIENT",

        [ValidateSet('ALL_SITES', 'ONE_SITE')]
        [string]$Scope = "ALL_SITES",

        [ValidateSet('NEAREST_SITE', 'HOME_SITE')]
        [string]$connectionAffinity = "NEAREST_SITE",

        [int]$PowerProtect = 30,

        [Boolean]$directConnect = $false
    )

    Process {
        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        try {
            if ($JsonFilePath) {
                # Check if the JSON file exists
                if (-not (Test-Path -Path $JsonFilePath)) {
                    Throw "The specified JSON file '$JsonFilePath' does not exist."
                }
                # Read and parse the JSON file
                $jsonPayload = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
                # Convert the JSON object back to a string for the payload
                $payloadJson = $jsonPayload | ConvertTo-Json -Depth 10
                Write-Verbose "JsonInput provided is - $payloadJson"
            }
            else {
                # Check if Mandatory parameters are provided
                if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('Name') -and $PSBoundParameters.ContainsKey('PoolGroupType') -and $PSBoundParameters.ContainsKey('PoolType') -and $PSBoundParameters.ContainsKey('PoolId') -and $PSBoundParameters.ContainsKey('PowerManagementType') -and $PSBoundParameters.ContainsKey('AlwaysPoweredOnVMPercent') -and $PSBoundParameters.ContainsKey('LogoffDisconnectedSessions'))) {
                    Write-Host -ForegroundColor Red "New-HCSPoolGroup: Mandatory parameters missing - please check if one of OrgId,Name,PoolGroupType,PoolType,PoolId,PowerManagementType,PowerManagementMode,AlwaysPoweredOnVMPercent,LogoffDisconnectedSessions is missing"
                    return
                }

                # Validation for poolId , PoolType and etc
                try {
                    $validatePoolId = Get-HCSPool -OrgId $OrgId -PoolId $PoolId
                    Write-Verbose "Pool details for provided $PoolId"
                    Write-Verbose "$validatePoolId"
                    if ($PoolId -ne $validatePoolId.id) {
                        Write-Host -ForegroundColor Red "Invalid PoolId: $PoolId"
                        return
                    }
                    if ($PoolType -ne $validatePoolId.templateType) {
                        Write-Host -ForegroundColor Red "Invalid PoolType for provided $PoolId"
                        return
                    }
                    if ($PowerManagementType -eq "Occupancy") {
                        if (!$PSBoundParameters.ContainsKey('PowerManagementMode')) {
                            Write-Host -ForegroundColor Red "Add the PowerManagementMode parameter as the PowerManagementType setting is configured to Occupancy"
                            return
                        }
                        if (!$PSBoundParameters.ContainsKey('AlwaysPoweredOnVMPercent')) {
                            Write-Host -ForegroundColor Red "Add the AlwaysPoweredOnVMPercent parameter as the PowerManagementType setting is configured to Occupancy"
                            return
                        }
                    }
                    if ($PowerManagementType -eq "NonOccupancy") {
                        if ($PSBoundParameters.ContainsKey('PowerManagementMode')) {
                            Write-Host -ForegroundColor Red "Given that the PowerManagementType is NonOccupancy, there is no requirement for the PowerManagementMode to be utilized."
                            return
                        }
                        if (!$PSBoundParameters.ContainsKey('AlwaysPoweredOnVMPercent')) {
                            Write-Host -ForegroundColor Red "Add the AlwaysPoweredOnVMPercent parameter as the PowerManagementType setting is configured to NOccupancy"
                            return
                        }
                    }
                }
                catch {
                    Write-Host -ForegroundColor Red "Error validating PoolId: $_"
                    return
                }

                # Resolve edge deployment and data center information
                $edgeDeploymentId = if ($PSBoundParameters.ContainsKey('edgeDeploymentId')) {
                    $edgeDeploymentId
                }
                else {
                    $validatePoolId.edgeDeployment.id
                }
        
                $edgeDeploymentName = if ($PSBoundParameters.ContainsKey('edgeDeploymentName')) {
                    $edgeDeploymentName
                }
                else {
                    $validatePoolId.edgeDeployment.name
                }
        
                $DataCenterId = if ($PSBoundParameters.ContainsKey('DataCenterId')) {
                    $DataCenterId
                }
                else {
                    $validatePoolId.edgeDeployment.hdc.id
                }

                # Prepare JSON payload
                $templateHash = @{
                    id               = $PoolId
                    edgeDeploymentId = $edgeDeploymentId
                    dataCenterId     = $DataCenterId
                    edgeDeployment   = @{ name = $edgeDeploymentName }
                }
                $protocolHash = @{
                    name            = $SupportedDisplayProtocols
                    defaultProtocol = $true
                }

                $presetMode = switch ($PowerManagementMode) {
                    "Performence" { "OPTIMIZED_FOR_PERFORMANCE" }
                    "Balanced" { "BALANCED" }
                    "Cost" { "OPTIMIZED_FOR_COST" }
                    default { "OPTIMIZED_FOR_COST" }
                }

                $powerPolicyHash = if ($PowerManagementType -eq "Occupancy") {
                    @{
                        enabled                 = $true
                        min                     = $AlwaysPoweredOnVMPercent
                        minUnit                 = "PERCENTAGE"
                        powerOffProtectTimeMins = $PowerProtect
                        occupancyPresetMode     = $presetMode
                        powerSchedules          = @()
                    }
                }
                else {
                    @{
                        enabled                 = $true
                        min                     = $AlwaysPoweredOnVMPercent
                        minUnit                 = "PERCENTAGE"
                        powerOffProtectTimeMins = $PowerProtect
                        powerSchedules          = @()
                    }
                }

                $logoffTimer = switch ($LogoffDisconnectedSessions) {
                    "NEVER" { 0 }
                    "IMMEDIATELY" { -1 }
                    "AFTER" { $AutomaticLogoffMinutes }
                    default { 0 }
                }

                $agentCustomizationHash = switch ($PoolType) {
                    "MULTI_SESSION" {
                        @{
                            disconnectSessionTimeoutMins = $logoffTimer
                            idleTimeoutMins              = $IdleSessionTimeout
                            sessionLoadBalancingSettings = @{
                                LBCPUTHRESHOLD              = 90
                                LBDISKQUEUELENTHRESHOLD     = 0
                                LBDISKREADLATENCYTHRESHOLD  = 0
                                LBDISKWRITELATENCYTHRESHOLD = 0
                                LBMEMTHRESHOLD              = 90
                                loadIndexThresholdPercent   = 90
                            }
                        }
                    }
                    default {   
                        @{
                            disconnectSessionTimeoutMins = $logoffTimer
                            idleTimeoutMins              = $IdleSessionTimeout
                        }
                    }
                }

                $agentCustomizationHash = @{
                    disconnectSessionTimeoutMins = $logoffTimer
                    idleTimeoutMins              = $IdleSessionTimeout
                }
                $sessionLifeTimeHash = @{
                    maxSessionLifeTime = $MaximumSessionLifetime
                }

                # Build common payload
                $commonPayload = @{
                    type                 = $PoolGroupType
                    templateType         = $PoolType
                    applications         = @()
                    templates            = @($templateHash)
                    name                 = $Name
                    displayName          = $DisplayName
                    protocols            = @($protocolHash)
                    enableSSO            = $EnableSSO
                    preferredClientType  = $PreferredClientType
                    scope                = $Scope
                    connectionAffinity   = $connectionAffinity
                    powerPolicy          = $powerPolicyHash
                    orgId                = $OrgId
                    agentCustomization   = $agentCustomizationHash
                    startSessionSettings = $sessionLifeTimeHash
                    directConnect        = $directConnect
                }

                if ($PoolType -eq 'MULTI_SESSION') {
                    $commonPayload.vmMaintenancePolicy = $null
                    $commonPayload.transientLoadThresholdSecs = 10

                }
                elseif ($PoolType -eq 'DEDICATED') {
                    $commonPayload.showAssignedMachineName = $ShowMachineName
                }
                else {
                    $commonPayload
                }

                $payloadJson = $commonPayload | ConvertTo-Json -Depth 10

                Write-Verbose "Final Payload JSON: $payloadJson"
            
            }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSPoolGroup: PoolGroup Creation Request for $Name failed for JsonInput generation"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }

        try {
            $urlpg = "https://cloud.omnissahorizon.com/portal/v2/pools"
            $dataCreatePoolGroup = Invoke-WebRequest -Uri $urlpg -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop

            if ($dataCreatePoolGroup.StatusCode -eq 201) {
                Write-Host "New-HCSPoolGroup: $Name Creation Request is accepted"
                return $dataCreatePoolGroup.Content
            }
            else {
                Write-Host -ForegroundColor Red "New-HCSPoolGroup: Pool creation failed for $Name"
                Write-Host ($dataCreatePoolGroup | Out-String)
            }
        }
        catch {
            Write-Host -ForegroundColor Red "Error creating Pool Group: $_"
        }
    }
}

function New-HCSEntitlement {
    <#
        .SYNOPSIS
            Creates new entitlments.
        .DESCRIPTION
            Creates new entitlments. Entitlments can be added to poolGroups or per desktop/application or appVolumes
            OrgId & PoolGroupId's are mandatory to get the infromation
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER poolGroupId
            Provide the poolGroup id.
            PoolGroupId can be found using "Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000| select Name,id,Type,@{N="PoolGroup Type";E={$_.templateType}}"
        .PARAMETER userId
            Enter the userId to add the enitlement
            userId can be found using "Get-HCSUsers -orgId f9b98412-658b-45db-a06b-000000000000 -userName user01"
        .PARAMETER groupId
            Enter the groupId to add the enitlement
            groupId can be found using "Get-HCSGroups -orgId f9b98412-658b-45db-a06b-000000000000"
        .EXAMPLE
            # Create new  eititlements 
                New-HCSEntitlement -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 672bxxxxxx4exxd -userId 680xxx-42xxb-4xxc-bxx0a-3xfbxxxx3xb5
                
                New-HCSEntitlement -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 672bxxxxxx4exxd -groupId 002x1xxa-c5x9-4x12-xxx-fxxxx8xxdxx4

                New-HCSEntitlement -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 672bxxxxxx4exxd -userId 680xxx-42xxb-4xxc-bxx0a-3xfbxxxx3xb5 -groupId 002x1xxa-c5x9-4x12-xxx-fxxxx8xxdxx4

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$poolGroupId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$userId,
        [string]$groupId
    )
    
    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    # Check if Mandatory parameters are provided
    if (-not ($PSBoundParameters.ContainsKey('userId') -or $PSBoundParameters.ContainsKey('groupId'))) {
        Write-Host -ForegroundColor Red "New-HCSEntitlement: Mandatory parameters missing - provide one of userId or groupId"
        return
    }

    # Resource Details Hash 
    $resourceDetailsHash = @{poolId = $poolGroupId; launchId = $poolGroupId}

    #construct json
    $commonPayload = @{
        orgId   = $OrgId
        poolIds = @($poolGroupId)
        resourceDetails = @( $resourceDetailsHash )
    }

    if($userId -and !$groupId){
        $commonPayload.userIds = @($userId)
    }
    elseif($groupId -and !$userId){
        $commonPayload.groupIds = @($groupId)
    }
    elseif($userId -and $groupId){
        $commonPayload.userIds = @($userId)
        $commonPayload.groupIds = @($groupId)
    }
    else{
        Write-Host -ForegroundColor Red "New-HCSEntitlement: provide one of userId or groupId"
    }
    $payloadJson = $commonPayload | ConvertTo-Json -Depth 4
    Write-Verbose "Final Payload JSON: $payloadJson"

            
    try {
        $urlEntitlement = "https://cloud.omnissahorizon.com/portal/v3/entitlements"
        Write-Verbose "(Invoke-RestMethod -Uri $urlEntitlement -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop)"
        $dataEntitlement = Invoke-RestMethod 'https://cloud.omnissahorizon.com/portal/v3/entitlements' -Method 'POST' -Headers $headers -body $payloadJson
        return $dataEntitlement
    }
    catch {
        Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSEntitlement: Entitlement Creation Request for $poolGroupId failed"
        Write-Host -ForegroundColor Red ($_ | Out-String)
        return
    }


}

function Remove-HCSEntitlement {
    <#
        .SYNOPSIS
            Removes HCS entitlments.
        .DESCRIPTION
            Removes HCS entitlments. Remove the entitlement for a specific user or group from a poolGroup
            OrgId & EntitlementId's are mandatory 
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER entitlementId
            Provide the entitlementId. This parameter accepts one entitlement removal at a time 
            entitlementId can be found using " Get-HCSEntitlements -orgId f9b98412-658b-45db-a06b-000000000000 -poolGroupId 672bxxxxxx4exxd | select entitlementId,entitlementType,id,name,domainName | ft "
        .EXAMPLE
            # Remove the eititlement 
                Remove-HCSEntitlement -orgId f9b98412-658b-45db-a06b-000000000000 -entitlementId 672bxxxxxx4exxd 

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$entitlementId

    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    try {
        $urlDeleteEN = "https://cloud.omnissahorizon.com/portal/v3/entitlements/$entitlementId" + "?" + "org_id=$OrgId"
        $deleteResponse = (Invoke-WebRequest -Uri $urlDeleteEN -Method DELETE -Headers $headers -ErrorAction Stop)
        write-Verbose $deleteResponse

        if ($deleteResponse.StatusCode -eq "204") {
            Write-Host "Remove-HCSEntitlement: Deletion request for Entitlement with id $entitlementId is accepted"
        } else {
            Write-Host -ForegroundColor Red "Remove-HCSEntitlement: Deletion request for Entitlement with id $entitlementId is failed"
            Write-Host ($_ | Out-String)
            return
        }
    }
    catch{
        Write-Host -ForegroundColor Red "Remove-HCSEntitlement: Entitlement Deletion failed"
        Write-Host ($_ | Out-String)
        return
    }


}

function Get-HCSAVEntitlement {
    <#
        .SYNOPSIS
            Retrieves the per PoolGroup entitlments.
        .DESCRIPTION
            Retrieves the per PoolGroup entitlments.
            OrgId & PoolGroupId's are mandatory to get the infromation
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER Id
            Provide the poolGroup id
        .PARAMETER appIdentifier
            It's am optional parameter , used to find published apps on demand with app volumes
        .EXAMPLE
            # Retrieves the App Volumes eititlements 
                Get-HCSAVEntitlement -orgId f9b98412-658b-45db-a06b-000000000000

                Get-HCSAVEntitlement -orgId f9b98412-658b-45db-a06b-000000000000 -Id 672bxxxxxx4exxd
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$id
    )
    
    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }


    # Construct GraphQL query body
    if($id){
        $urlAVEN = "https://cloud.omnissahorizon.com/av-entitlements/v1/app-entitlements/$id"
    }else{
        $urlAVEN = "https://cloud.omnissahorizon.com/av-entitlements/v1/app-entitlements?org_id=$orgId&page=0&size=1000&sort=asc"
    }
    write-Verbose "AV Entitlements URl - $urlAVEN"

    try {
        $response = Invoke-RestMethod "$urlAVEN" -Method 'GET' -Headers $headers -ErrorAction Stop
        $pageCount = $response.totalPages
        Write-Verbose "API response in try statement - $response"

        if ($pageCount -eq 1) {
            return $response.content
        }elseif ($pageCount -eq 0) {
            Write-Verbose "Response is null -  Check the orgId and token is valid"
            return $response
        }else{
            Get-RetrieveByPage -url $urlAVEN -Method GET
        }
    }
    catch {
        Write-Host -ForegroundColor Red "Error retrieving AV Entitlement details: $_"
    }
}

function Remove-HCSAVEntitlement {
    <#
        .SYNOPSIS
            Removes App Volumes HCS entitlments.
        .DESCRIPTION
            Removes App Volumes HCS entitlments. Remove the entitlement for a specific user or group from a poolGroup
            OrgId & EntitlementId's are mandatory 
        .PARAMETER OrgId
            Long OrgId of the organization.
        .PARAMETER AVEntitlementId
            Provide the entitlementId. This parameter accepts one entitlement removal at a time 
            AVentitlementId can be found using " Get-HCSAVEntitlement -orgId f9b98412-658b-45db-a06b-000000000000| select id,entityId,entityType,entitlementType | ft "
            In the above GET command output , ID is AVEntitlementId , entityId is User / Group ID , entityType is user or group entitlement
        .EXAMPLE
            # Remove the eititlement 
                Remove-HCSAVEntitlement -orgId f9b98412-658b-45db-a06b-000000000000 -AVEntitlementId 672bxxxxxx4exxd 

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$AVEntitlementId

    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    try {
        $urlDeleteAVEN = "https://cloud.omnissahorizon.com/av-entitlements/v1/app-entitlements/$AVEntitlementId" + "?" + "skipResolutionUpdate=true"
        $deleteResponse = (Invoke-WebRequest -Uri $urlDeleteAVEN -Method DELETE -Headers $headers -ErrorAction Stop)
        write-Verbose $deleteResponse

        if ($deleteResponse.StatusCode -eq "204") {
            Write-Host "Remove-HCSAVEntitlement: Deletion request for Entitlement with id $entitlementId is accepted"
        } else {
            Write-Host -ForegroundColor Red "Remove-HCSAVEntitlement: Deletion request for Entitlement with id $entitlementId is failed"
            Write-Host ($_ | Out-String)
            return
        }
    }
    catch{
        Write-Host -ForegroundColor Red "Remove-HCSAVEntitlement: Entitlement Deletion failed"
        Write-Host ($_ | Out-String)
        return
    }


}

function Get-HCSLicenseConsumption {
    <#
        .SYNOPSIS
            Retrieves License used in last 3 months.
        .DESCRIPTION
            Retrieves License used in last 3 months.
        .PARAMETER OrgId
            Optinal Parameter, Org ID will be retrieved from the token itself
        .PARAMETER Filter
            Allowed values are TRENDS or AGGREGATE . 
            if the Filter is not passed with the cmdlet then default it to AGGREGATE
        .EXAMPLE
            # Retrieves the App Volumes eititlements 
                Get-HCSLicenseConsumption

                Get-HCSLicenseConsumption -Filter TRENDS
    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$orgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [ValidateSet('TRENDS','AGGREGATE')]
        [string]$Filter = 'AGGREGATE'
    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }


    # Construct GraphQL query body
    if($Filter -eq "TRENDS"){
        $urlLC = "https://cloud.omnissahorizon.com/data-query-service/v1/license-usage-trends/CCU?frequency=ENTIRERANGE"
        write-Verbose "License Consumption URL - $urlLC"
        try {
            $response = Invoke-RestMethod "$urlLC" -Method 'GET' -Headers $headers -ErrorAction Stop
            return $response.results
        }
        catch {
            Write-Host -ForegroundColor Red "Error retrieving License Consumption details: $_"
        }
    }else{
        $urlLC = "https://cloud.omnissahorizon.com/data-query-service/v1/license-usage-aggregate/CCU?total=true"
        try {
            $response = Invoke-RestMethod "$urlLC" -Method 'GET' -Headers $headers -ErrorAction Stop
            return $response
        }
        catch {
            Write-Host -ForegroundColor Red "Error retrieving License Consumption details: $_"
        }
    }
}

function Get-HCSAVFileShares {
    <#
        .SYNOPSIS
            Retrieves APP VOLUMES File Share details.
        .DESCRIPTION
            Retrieves APP VOLUMES File Share details
            OrgId & EntitlementId's are mandatory 
        .PARAMETER OrgId
            Optinal Parameter, Org ID will be retrieved from the token itself
        .PARAMETER ProviderId
            Provide the ProviderId to retrieve the file shares
        .EXAMPLE
            # Remove the eititlement 
                Get-HCSAVFileShares -ProviderId 672bxxxxxx4exxd 

    #>
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$ProviderId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$OrgId

    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    try {
        $urlAVFileShares = "https://cloud.omnissahorizon.com/av-fileshare/v1/storage-accounts?size=100&page=0&search=infraProviderInstanceId%20%24eq%20" + "$ProviderId"
        $deleteResponse = (Invoke-WebRequest -Uri $urlAVFileShares -Method GET -Headers $headers -ErrorAction Stop)
        return $deleteResponse.content

    }
    catch{
        Write-Host -ForegroundColor Red "Get-HCSAVFileShares: Failed to retrieve the AV FileShares"
        Write-Host ($_ | Out-String)
        return
    }


}

function Get-HCSUserAssignedIdentities {
    <#
        .SYNOPSIS
            Retrieves User assigned identitites created in the Azure in the specific provider region.
        .DESCRIPTION
            Retrieves User assigned identitites created in the Azure in the specific provider region.     
        .PARAMETER OrgId
            Provide the long orgId
        .PARAMETER ProviderId
            Provide the ProviderId to retrieve the User Assigned Identities
        .EXAMPLE
            # Remove the eititlement 
                Get-HCSUserAssignedIdentities -orgId f9b98412-658b-45db-a06b-000000000000 -ProviderId 672bxxxxxx4exxd 

    #>
    [CmdletBinding()]
    Param(

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]$ProviderId


    )

    # Common headers
    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"; 
        'Content-Type' = "application/json";
    }

    # Token validity check
    $tokenexpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    Write-Verbose $tokenexpiry
    if ((Get-Date).AddMinutes(5) -ge $tokenexpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }

    try {
        $urlUserIdentity = "https://cloud.omnissahorizon.com/admin/v2/providers/azure/instances/$ProviderId/user-assigned-identities?org_id=$OrgId&page=0&size=100&sort=asc"
        $response = Invoke-RestMethod -Uri $urlUserIdentity -Method GET -Headers $headers -ErrorAction Stop
        return $response.content

    }
    catch{
        Write-Host -ForegroundColor Red "Get-HCSUserAssignedIdentities: Failed to retrieve the User Assigned Identities from Azure "
        Write-Host ($_ | Out-String)
        return
    }


}

function New-HCSEdge {
    <#  
        .SYNOPSIS  
            Creates a New Edge with provided parameters in next-gen Org  
        .DESCRIPTION  
            Creates a New Edge with provided parameters in next-gen Org   
            If a JSON payload exists, there is no need to pass any parameters, as the cmdlet will read the information from the JSON file and create the pool accordingly.
            However, if the JSON parameters are not provided, you must pass the following mandatory parameters:
                OrgId,EdgeName,PoolGroupType,EdgeType,ProviderId,Subnet,UserAssignedIdentity,EdgeOutboundType,LogoffDisconnectedSessions,podCIDR,serviceCIDR
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER EdgeName
            Name of the Edge.
        .PARAMETER EdgeType
            Provide the EdgeType - allowed values are 'AKS', 'VM'
        .PARAMETER ProviderId
            Provide the ProviderId, Get-HCSProvider can help getting this information
            Example: 
            Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure | select Name,id,@{N="SubscriptionId";E={$_.providerDetails.data.subscriptionId}},@{N="DirectoryId";E={$_.providerDetails.data.directoryId}},@{N="ApplicationId";E={$_.providerDetails.data.applicationId}},@{N="Azure Region";E={$_.providerDetails.data.region}} | ft -AutoSize
        .PARAMETER Subnet
            Provide the Management subnet details for deploying edge
            Example : 
            $subnet01=Get-HCSSubnets -OrgId f9b98412-658b-45db-a06b-000000000000 -ProviderId 6450e94c5dxxxxxx3ded -Environment azure -VnetId "/subscriptions/axxxx-2xx2-4xx3-xxfc-8xxxxxdxx/resourceGroups/HCS_DEV_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEV_VNET_01" | ? {$_.id -match  "Management"}
            if there are more subnets with the name of Management then pick one in random
            $randomManagementSubnet = $subnet01[(Get-Random -Maximum ([array]$subnet01).count)]
        .PARAMETER UserAssignedIdentity
            Provide UserAssignedIdentity complete ID
            Example:
            Get-HCSUserAssignedIdentities -ProviderId 6450xxxxxxxxd -OrgId f9b98412-658b-45db-a06b-000000000000 
            Copy the complete ID
        .PARAMETER EdgeOutboundType
            provide EdgeOutboundType - allowed values are NAT_GATEWAY , USER_DEFINED_ROUTES
        .PARAMETER podCIDR
            Provide the podCIDR
            provide the CIDR range with minimum /21
        .PARAMETER serviceCIDR
            Provide the serviceCIDR
            provide the CIDR range with minimum /27
        .PARAMETER resourceTags
            Provide the resourceTags for resource groups , this parameter accept multiple  values and specify them as comma separated
        .PARAMETER enablePrivateEndpoint
            PrivateLink support for VDI's to Horizon control plane connectivity - default enabled
        .PARAMETER proxyName
            Optional paramter - Provide proxyName . this name will be used to identify the proxy configuration    
        .PARAMETER proxyHost
            Optional paramter - Provide the proxy server IP or FQDN
        .PARAMETER proxyPort
            optional paramter - Provide proxyPort
        .PARAMETER proxyUsername
            optional paramter - Provide proxyUsername
        .PARAMETER proxyPassword
            Optional paramter - Provide proxyPassword.
        .PARAMETER proxySSLEnabled
            Optional paramter - Provide proxySSLEnabled
        .PARAMETER proxyCertificate
            Optional paramter - Provide proxyCertificate
        .PARAMETER JsonFilePath
            Provide the path to JSON file
        .EXAMPLE
            # Edge creation by providing JSON file

                New-HCSEdge -JsonFilePath "C:/temp/new-edge-01.json" -Verbose

            # Edge Creation with Mandatory parameters

                New-HCSEdge -OrgId f9b98412-658b-45db-a06b-000000000000 -EdgeName "Power-Edge-01" -EdgeType AKS -ProviderId 63200xxxxxxxxbf65xx -Subnet $subnet -UserAssignedIdentity "/subscriptions/2xxx5-3xx-4axx-9xx7-2xxxxxfb3/resourcegroups/HCS_DEVOPS_RG_1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/hcsdevops-03-aks-identity" -EdgeOutboundType NAT_GATEWAY -podCIDR "10.251.8.0/21" -serviceCIDR "10.251.0.0/27" -Verbose

    #>
    param(

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'JsonInput')]
        [ValidateNotNullOrEmpty()]
        [String]$JsonFilePath,

        [Parameter(Mandatory = $false)]
        [string]$EdgeName,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet('AKS', 'VM')]
        [string]$EdgeType,

        [Parameter(Mandatory = $false)]
        [string]$ProviderId,

        [Parameter(Mandatory = $false)]
        [pscustomobject]$Subnet,

        [Parameter(Mandatory = $false)]
        [string]$UserAssignedIdentity,

        [Parameter(Mandatory = $false)]
        [ValidateSet('NAT_GATEWAY', 'USER_DEFINED_ROUTES')]
        [string]$EdgeOutboundType,
        
        [Parameter(Mandatory = $false)]
        [string]$OrgId,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                # validate CIDR format
                if ($_ -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[01])$') {
                    $subnet = [int]($_ -split '/')[1]
                    if ($subnet -le 21) {
                        $true
                    }
                    else {
                        Throw "The value '$_' has a subnet mask larger than /21. Please provide a CIDR like '10.251.8.0/21' or smaller."
                    }
                }
                else {
                    Throw "The value '$_' is not a valid CIDR format. Please provide a value like '10.251.250.8/21'."
                }
            })]
        [string]$podCIDR,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                # validate CIDR format
                if ($_ -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[01])$') {
                    $subnetMask = [int]($_ -split '/')[1]
                    if ($subnetMask -le 27) {
                        $true 
                    }
                    else {
                        Throw "The value '$_' has a subnet mask larger than /27. Please provide a CIDR like '10.251.0.0/27' or smaller."
                    }
                }
                else {
                    Throw "The value '$_' is not a valid CIDR format. Please provide a value like '10.251.0.0/27'."
                }
            })]
        [string]$serviceCIDR,

        [Parameter(Mandatory = $false)]
        [String[]]$resourceTags = @(),

        [Parameter(Mandatory = $false)]
        [string]$enablePrivateEndpoint = $true,

        [Parameter(Mandatory = $false)]
        [string]$proxyName,

        [Parameter(Mandatory = $false)]
        [string]$proxyHost,

        [Parameter(Mandatory = $false)]
        [int]$proxyPort,

        [Parameter(Mandatory = $false)]
        [ValidateSet('HTTP', 'HTTPS')]
        [string]$proxyType = "HTTP",

        [Parameter(Mandatory = $false)]
        [string]$proxyUsername,
        [string]$proxyPassword,

        [Parameter(Mandatory = $false)]
        [Boolean]$proxySSLEnabled = $false,

        [Parameter(Mandatory = $false)]
        [string]$proxyCertificate 
    )

    Process {
        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }
        try {
            if ($JsonFilePath) {
                # Check if the JSON file exists
                if (-not (Test-Path -Path $JsonFilePath)) {
                    Throw "The specified JSON file '$JsonFilePath' does not exist."
                }
                # Read and parse the JSON file
                $jsonPayload = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
                # Convert the JSON object back to a string for the payload
                $payloadJson = $jsonPayload | ConvertTo-Json -Depth 10
                Write-Verbose "JsonInput provided is - $payloadJson"
            }
            else {
                # Check if Mandatory parameters are provided
                if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('EdgeName') -and $PSBoundParameters.ContainsKey('EdgeType') -and $PSBoundParameters.ContainsKey('ProviderId') -and $PSBoundParameters.ContainsKey('Subnet') -and $PSBoundParameters.ContainsKey('UserAssignedIdentity') -and $PSBoundParameters.ContainsKey('EdgeOutboundType') -and $PSBoundParameters.ContainsKey('podCIDR') -and $PSBoundParameters.ContainsKey('serviceCIDR'))) {
                    Write-Host -ForegroundColor Red "New-HCSEdge: Mandatory parameters missing - please check if one of OrgId,EdgeName,PoolGroupType,EdgeType,ProviderId,Subnet,UserAssignedIdentity,EdgeOutboundType,LogoffDisconnectedSessions,podCIDR,serviceCIDR is missing"
                    return
                }

                # Change the value based on EdgeOutboundtype
                if($EdgeOutboundType -eq "NAT_GATEWAY"){
                    $OutboundType = "USER_ASSIGNED_NAT_GATEWAY"
                } elseif ($EdgeOutboundType -eq "USER_DEFINED_ROUTES") {
                    $OutboundType = "USER_DEFINED_ROUTING"
                }


                # Convert Subnet details to Hashtable
                $subnetHash = @{
                    kind = $Subnet.kind
                    id = $Subnet.id 
                    data =$Subnet.data
                }
                Write-Verbose "Subnet hashTable - $subnetHash"

                # Validate ProviderID
                $ProviderIdCheck = Get-HCSProvider -orgId $OrgId -Environment Azure -Id $providerId
                write-verbose "$ProviderIdCheck"
                if ($providerId -eq $ProviderIdCheck.id) {
                    write-verbose "ProviderId with $ProviderId exists"
                }
                else {
                    Write-Host -ForegroundColor Red " ProviderId $ProviderId doesn't seems to be exist , please check "
                    return
                }

                # Validate Subnet
                #write-verbose "provided subnet id - '$Subnet.id'"
                #write-verbose "provided subnet VNET id - '$Subnet.data.parent'"
                #$networks = Get-HCSSubnets -OrgId $OrgId -ProviderId $providerId -Environment azure -VnetId "$Subnet.data.parent"
                #write-verbose $networks
                #foreach ($Snet in $networks){
                #    write-verbose $Snet
                #    if($Snet.id -eq $Subnet.id){
                #        write-verbose "Provided Subnet exists"
                #    }
                #}

                # Validate UserAssignedIdentity
                $identityCheck = Get-HCSUserAssignedIdentities -ProviderId $providerId -OrgId $OrgId | ? { $_.id -eq "$UserAssignedIdentity" }
                write-verbose "$identityCheck"
                if ($UserAssignedIdentity -eq $identityCheck.id) {
                    write-verbose "UserAssignedIdentity with $UserAssignedIdentity exists"
                }
                else {
                    Write-Host -ForegroundColor Red " UserAssignedIdentity $UserAssignedIdentity doesn't seems to be exist , please check "
                    return
                }

                # Trim EdgeName not more than 64 characters
                $edgeNameTrim = $EdgeName.substring(0, [System.Math]::Min(64, $EdgeName.Length))
                Write-Verbose "Trimmed edge name - $edgeNameTrim"

                # Trim EdgeName not more than 46 characters for AKS Cluster DNS Prefix
                $edgeNameTrimAKSDNS = $EdgeName.substring(0, [System.Math]::Min(46, $EdgeName.Length))
                Write-Verbose "Trimmed edge name - $edgeNameTrimAKSDNS"

                # Resource Tags Hash if present
                if ($resourceTags){
                    $resourceTagsHash["KeyName"] = $resourceTags
                    $rTags = $resourceTagsHash["KeyName"]
                    
                } else {
                    $rTags = @{}
                }
                Write-Verbose "resourceTags are $rTags"
            
                # Build common payload
                $commonPayload = @{
                    name                  = $edgeNameTrim
                    description           = $Description
                    orgId                 = $OrgId
                    providerInstanceId    = $providerId
                    ssoConfigurations     = @()
                    infrastructure        = @{
                        managementNetwork = $subnetHash
                    }
                    resourceTags          = $rTags
                    enablePrivateEndpoint = $enablePrivateEndpoint
                }

                if ($EdgeType -eq 'AKS') {
                    $commonPayload.deploymentModeDetails = @{
                        type       = "CLUSTER"
                        attributes = @{
                            numNodes      = "4"
                            identityId    = $UserAssignedIdentity
                            dnsNamePrefix = "$edgeNameTrimAKSDNS-k8s-dns"
                            podCidr       = $podCIDR
                            serviceCidr   = $serviceCIDR
                            outboundType  = $OutboundType
                        }
                    } 
                }
                elseif ($EdgeType -eq 'VM') {
                    $commonPayload.deploymentModeDetails = @{
                        type       = "VM"
                        attributes = @{}
                    }
                }

                if ($proxyName) {
                    $commonPayload.proxyConfiguration = @{
                        enabled    = $true
                        proxyName  = $proxyName
                        proxyHost  = $proxyHost
                        proxyPort  = $proxyPort
                        proxyType  = $proxyType
                        sslEnabled = $proxySSLEnabled
                    }
                }

                if ($proxyUsername) {
                    $commonPayload.username = $proxyUsername
                    $commonPayload.password = $proxyPassword
                }
                

                $payloadJson = $commonPayload | ConvertTo-Json -Depth 20
                Write-Verbose "Final Payload JSON: $payloadJson"
            }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSEdge: Edge Creation Request for $Name failed for JsonInput generation"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }

        try {
            $urlEdge = "https://cloud.omnissahorizon.com/admin/v2/edge-deployments"
            $dataCreateEdge = Invoke-WebRequest -Uri $urlEdge -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop

            if ($dataCreateEdge.StatusCode -eq 201) {
                Write-Verbose "New-HCSEdge: $Name Creation Request is accepted"
                $returnData = $dataCreateEdge.Content | ConvertTo-Json -Depth 6
                return $returnData
            }
            else {
                Write-Host -ForegroundColor Red "New-HCSEdge: Edge creation failed for $Name"
                Write-Host ($dataCreateEdge | Out-String)
            }
        }
        catch {
            Write-Host -ForegroundColor Red "New-HCSEdge - Error creating Edge: $_"
        }
    }
}

function New-HCSUAG {
    <#  
        .SYNOPSIS  
            Creates a New UAG with provided parameters in next-gen Org  
        .DESCRIPTION  
            Creates a New UAG with provided parameters in next-gen Org   
            If a JSON payload exists, there is no need to pass any parameters, as the cmdlet will read the information from the JSON file and create the pool accordingly.
            However, if the JSON parameters are not provided, you must pass the following mandatory parameters:
                OrgId,EdgeName,PoolGroupType,EdgeType,ProviderId,Subnet,UserAssignedIdentity,EdgeOutboundType,LogoffDisconnectedSessions,podCIDR,serviceCIDR
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER UagName
            Name of the UAG. you can copy the same name as EdgeName
        .PARAMETER UagType
            Provide the UAGType - allowed values are 'EXTERNAL', 'INTERNAL' or "INTERNAL_AND_EXTERNAL"
        .PARAMETER ProviderId
            Provide the ProviderId, Get-HCSProvider can help getting this information
            Example: 
            Get-HCSProvider -OrgId f9b98412-658b-45db-a06b-000000000000 -Environment azure | select Name,id,@{N="SubscriptionId";E={$_.providerDetails.data.subscriptionId}},@{N="DirectoryId";E={$_.providerDetails.data.directoryId}},@{N="ApplicationId";E={$_.providerDetails.data.applicationId}},@{N="Azure Region";E={$_.providerDetails.data.region}} | ft -AutoSize
        .PARAMETER DMZSubnet
            Provide the DMZ subnet details for deploying UAG
            Example : 
            $subnet01=Get-HCSSubnets -OrgId f9b98412-658b-45db-a06b-000000000000 -ProviderId 6450e94c5dxxxxxx3ded -Environment azure -VnetId "/subscriptions/axxxx-2xx2-4xx3-xxfc-8xxxxxdxx/resourceGroups/HCS_DEV_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEV_VNET_01" | ? {$_.id -match  "DMZ"}
            if there are more subnets with the name of DMZ then pick one in random
            $randomManagementSubnet = $subnet01[(Get-Random -Maximum ([array]$subnet01).count)]\
        .PARAMETER ManagementSubnet
            Provide the Management subnet details for deploying UAG
            Example : 
            $subnet01=Get-HCSSubnets -OrgId f9b98412-658b-45db-a06b-000000000000 -ProviderId 6450e94c5dxxxxxx3ded -Environment azure -VnetId "/subscriptions/axxxx-2xx2-4xx3-xxfc-8xxxxxdxx/resourceGroups/HCS_DEV_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEV_VNET_01" | ? {$_.id -match  "Management"}
            if there are more subnets with the name of Management then pick one in random
            $randomManagementSubnet = $subnet01[(Get-Random -Maximum ([array]$subnet01).count)]
        .PARAMETER VMSubnet
            Provide the VM subnet details for deploying UAG
            Example : 
            $subnet01=Get-HCSSubnets -OrgId f9b98412-658b-45db-a06b-000000000000 -ProviderId 6450e94c5dxxxxxx3ded -Environment azure -VnetId "/subscriptions/axxxx-2xx2-4xx3-xxfc-8xxxxxdxx/resourceGroups/HCS_DEV_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEV_VNET_01" | ? {$_.id -match  "VM"}
            if there are more subnets with the name of VM then pick one in random 
            $randomManagementSubnet = $subnet01[(Get-Random -Maximum ([array]$subnet01).count)]
        .PARAMETER ExternalFQDN
            provide External FQDN to Access the UAG
            If UAGType is selected as INTERNAL then ExternalFQDN will not be considered
        .PARAMETER InternalFQDN
            provide Internal FQDN to Access the UAG
            If UAGType is selected as EXTERNAL then InternalFQDN will not be considered
        .PARAMETER BlastPort
            Provide the BlastPort - default value is 8443 , if this parameter is set to 443 then BlastPort will use 443 for the deployment
        .PARAMETER NumberOfGateways
            Provide the Count of UAG's required . default it to 2 and maximum can be provisined is 10
        .PARAMETER CertificateType
            Provide the Certificate Type , allowed values are "PEM" or "PFX"
        .PARAMETER Certficate
            Provide the certificate in the format using https://docs.omnissa.com/bundle/UnifiedAccessGatewayDeployandConfigureV2406/page/ConvertCertificateFilestoOne-LinePEMFormat.html
        .PARAMETER CertficatePassword
            Provide the certificate password if the the certificate format is PFX
        .PARAMETER ManualPublicIP
            optional paramter - Provide when you are using firewall as the public Ip else publicIP will be created automatically
        .PARAMETER proxyName
            Optional paramter - Provide proxyName . this name will be used to identify the proxy configuration    
        .PARAMETER proxyHost
            Optional paramter - Provide the proxy server IP or FQDN      
        .PARAMETER proxyType
            Optional paramter - Provide proxytype , Allowed values are "HTTPS" or "HTTPS"
        .PARAMETER proxyCertificate
            Optional paramter - Provide proxyCertificate
        .PARAMETER JsonFilePath
            Provide the path to JSON file
        .EXAMPLE
            # UAG creation by providing JSON file

                New-HCSUAG -JsonFilePath "C:/temp/new-uag-01.json" -Verbose

            # UAG Creation with Mandatory parameters

                New-HCSUAG -OrgId f9b98412-658b-45db-a06b-000000000000 -EdgeName "Power-Edge-01" -EdgeType AKS -ProviderId 63200xxxxxxxxbf65xx -Subnet $subnet -UserAssignedIdentity "/subscriptions/2xxx5-3xx-4axx-9xx7-2xxxxxfb3/resourcegroups/HCS_DEVOPS_RG_1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/hcsdevops-03-aks-identity" -EdgeOutboundType NAT_GATEWAY -podCIDR "10.251.8.0/21" -serviceCIDR "10.251.0.0/27" -Verbose

    #>

    param(

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'JsonInput')]
        [ValidateNotNullOrEmpty()]
        [String]$JsonFilePath,

        [Parameter(Mandatory = $false)]
        [string]$UagName,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet('EXTERNAL', 'INTERNAL', "INTERNAL_AND_EXTERNAL")]
        [string]$UagType,

        [Parameter(Mandatory = $false)]
        [string]$ProviderId,

        [Parameter(Mandatory = $false)]
        [string]$CertificateType,

        [Parameter(Mandatory = $false)]
        [string]$Certificate,

        [Parameter(Mandatory = $false)]
        [string]$CertficatePassword,

        [Parameter(Mandatory = $false)]
        [pscustomobject]$DmzSubnet,

        [Parameter(Mandatory = $false)]
        [pscustomobject]$ManagementSubnet,

        [Parameter(Mandatory = $false)]
        [pscustomobject]$VMSubnet,

        [Parameter(Mandatory = $false)]
        [ValidateSet('2', '3', "4", "5", "6", "7", "8", "9", "10")]
        [int]$NumberOfGateways = "2",

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                # Regular expression for a valid FQDN
                if ($_ -match '^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$') {
                    $true
                }
                else {
                    Throw "The value '$_' is not a valid Fully Qualified Domain Name (FQDN)."
                } })]
        [string]$InternalFQDN,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                # Regular expression for a valid FQDN
                if ($_ -match '^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$') {
                    $true
                }
                else {
                    Throw "The value '$_' is not a valid Fully Qualified Domain Name (FQDN)."
                } })]
        [string]$ExternalFQDN,

        [Parameter(Mandatory = $false)]
        [ValidateSet('443', '8443')]
        [int]$BlastPort = "8443",
    
        [Parameter(Mandatory = $false)]
        [string]$OrgId,


        [Parameter(Mandatory = $false)]
        [string]$VMSku = "Standard_A4_v2",

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                # Regular expression for IPv4 or IPv6
                if ($_ -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
                    $true
                }
                else {
                    Throw "The value '$_' is not a valid IP address."
                } })]
        [string]$ManualPublicIP,

        [Parameter(Mandatory = $false)]
        [string]$proxyName,

        [Parameter(Mandatory = $false)]
        [string]$proxyHost,

        [Parameter(Mandatory = $false)]
        [int]$proxyPort,

        [Parameter(Mandatory = $false)]
        [String[]]$resourceTags = @(),

        [Parameter(Mandatory = $false)]
        [ValidateSet('HTTP', 'HTTPS')]
        [string]$proxyType = "HTTP",

        [Parameter(Mandatory = $false)]
        [string]$proxyCertificate 
    )

    Process {
        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        try {
            if ($JsonFilePath) {
                # Check if the JSON file exists
                if (-not (Test-Path -Path $JsonFilePath)) {
                    Throw "The specified JSON file '$JsonFilePath' does not exist."
                }
                # Read and parse the JSON file
                $jsonPayload = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
                # Convert the JSON object back to a string for the payload
                $payloadJson = $jsonPayload | ConvertTo-Json -Depth 10
                Write-Verbose "JsonInput provided is - $payloadJson"
            }
            else {
                # Check if Mandatory parameters are provided
                if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('UagType') -and $PSBoundParameters.ContainsKey('UagName') -and $PSBoundParameters.ContainsKey('ProviderId') -and $PSBoundParameters.ContainsKey('ManagementSubnet') -and $PSBoundParameters.ContainsKey('VMSubnet') -and $PSBoundParameters.ContainsKey('DmzSubnet') -and $PSBoundParameters.ContainsKey('CertificateType') -and $PSBoundParameters.ContainsKey('Certificate'))) {
                    Write-Host -ForegroundColor Red "New-HCSEdge: Mandatory parameters missing - please check if one of OrgId,UagType,UagName,ProviderId,DmzSubnet,VMSubnet,ManagementSubnet,CertificateType,Certificate is missing"
                    return
                }

                if ($UagType -eq "INTERNAL" -and $PSBoundParameters.ContainsKey('DmzSubnet') -and $PSBoundParameters.ContainsKey('ExternalFQDN')) {
                    Write-Host -ForegroundColor Red "New-HCSUAG : When UagType selected as INTERNAL, ExternalFQDN & DmzSubnet not allowed "
                    return
                }
                elseif ($UagType -eq "INTERNAL"  -and !$PSBoundParameters.ContainsKey('DmzSubnet') -and $PSBoundParameters.ContainsKey('ExternalFQDN')) {
                    Write-Host -ForegroundColor Red "New-HCSUAG : When UagType selected as INTERNAL, ExternalFQDN is not allowed "
                    return
                }
                elseif ($UagType -eq "INTERNAL"  -and $PSBoundParameters.ContainsKey('DmzSubnet') -and !$PSBoundParameters.ContainsKey('ExternalFQDN')) {
                    Write-Host -ForegroundColor Red "New-HCSUAG : When UagType selected as INTERNAL, DmzSubnet is not allowed "
                    return
                }

                if ($UagType -eq "EXTERNAL" -and $PSBoundParameters.ContainsKey('InternalFQDN')) {
                    Write-Host -ForegroundColor Red "New-HCSUAG : When UagType selected as INTERNAL, InternalFQDN is not allowed "
                    return
                }

                if ($UagType -eq "INTERNAL_AND_EXTERNAL" -and !$PSBoundParameters.ContainsKey('InternalFQDN') -and !$PSBoundParameters.ContainsKey('ExternalFQDN')) {
                    Write-Host -ForegroundColor Red "New-HCSUAG : When UagType selected as INTERNAL_AND_EXTERNAL, InternalFQDN or ExternalFQDN is Mandatory "
                    return
                }
                elseif ($UagType -eq "INTERNAL_AND_EXTERNAL" -and !$PSBoundParameters.ContainsKey('InternalFQDN') -and $PSBoundParameters.ContainsKey('ExternalFQDN')) {
                    $InternalFQDN = $ExternalFQDN
                    Write-Verbose "Since the UAG type is INTERNAL_AND_EXTERNAL - Internal FQDn is $InternalFQDN"
                }
                elseif ($UagType -eq "INTERNAL_AND_EXTERNAL" -and $PSBoundParameters.ContainsKey('InternalFQDN') -and !$PSBoundParameters.ContainsKey('ExternalFQDN')) {
                    $ExternalFQDN = $InternalFQDN
                    Write-Verbose "Since the UAG type is INTERNAL_AND_EXTERNAL - External FQDn is $ExternalFQDN"
                }

                # Print input certificate details in verbose
                Write-Verbose "$Certificate"
                # Print input certificate by removing extra \
                $UpdatedCert = $Certificate -replace '\\n', "`n"
                Write-Verbose "$UpdatedCert"


                # Validate ProviderID
                $ProviderIdCheck = Get-HCSProvider -orgId $OrgId -Environment Azure -Id $providerId
                write-verbose "$ProviderIdCheck"
                if ($providerId -eq $ProviderIdCheck.id) {
                    write-verbose "ProviderId with $ProviderId exists"
                }
                else {
                    Write-Host -ForegroundColor Red " ProviderId $ProviderId doesn't seems to be exist , please check "
                    return
                }


                # Convert Subnet details to Hashtable
                $dmzSubnetHash = @{
                    kind = $DMZSubnet.kind
                    id   = $DMZSubnet.id 
                    data = $DMZSubnet.data
                }
                $dmzSubnetJson = $dmzSubnetHash | ConvertTo-Json -Depth 4
                Write-Verbose "DMZ Subnet JSON - $dmzSubnetJson "

                # Convert Subnet details to Hashtable
                $managementSubnetHash = @{
                    kind = $ManagementSubnet.kind
                    id   = $ManagementSubnet.id 
                    data = $ManagementSubnet.data
                }
                $managementSubnetJson = $managementSubnetHash | ConvertTo-Json -Depth 4
                Write-Verbose "Management Subnet JSON - $managementSubnetJson"

                # Convert Subnet details to Hashtable
                $vmSubnetHash = @{
                    kind = $VMSubnet.kind
                    id   = $VMSubnet.id 
                    data = $VMSubnet.data
                }
                $vmSubnetJson = $vmSubnetHash | ConvertTo-Json -Depth 4
                Write-Verbose "Desktop Subnet JSON - $vmSubnetJson"

                # Trim EdgeName not more than 64 characters
                $uagNameTrim = $UagName.substring(0, [System.Math]::Min(64, $UagName.Length))
                Write-Verbose "Trimmed UAG name - $uagNameTrim"

                # Resource Tags Hash if present
                if ($resourceTags) {
                    $resourceTagsHash["KeyName"] = $resourceTags
                    $rTags = $resourceTagsHash["KeyName"]   
                }
                else {
                    $rTags = @{}
                }
                $resourceTagsJson = $rTags | ConvertTo-Json -Depth 4
                Write-Verbose "resourceTags are $resourceTagsJson"

                # VM Size SKU
                try {
                    $VmsizeSkuJson = Get-HCSAzureVmSkus -OrgId $OrgId -providerId $providerId -VmSize $VmSku
                    Write-Verbose "VMSKU details - $VmsizeSkuJson"
                    if ($VmsizeSkuJson.id -ne $VmSku) {
                        Write-Host -ForegroundColor Red "Get-HCSAzureVmSkus : Unable to retrieve VMSize details, please recheck the VM Size and try again"
                        return
                    }
                }
                catch {
                    Write-Host -ForegroundColor Red "Get-HCSAzureVmSkus : Unable to retrieve VMSize details, please recheck the VM Size and try again"
                    return
                }
            

                # Build common payload
                $commonPayload = @{
                    cluster            = @{ min = "$NumberOfGateways"; max = "$NumberOfGateways" }
                    name               = $uagNameTrim
                    description        = $Description
                    orgId              = $OrgId
                    providerInstanceId = $providerId
                    numberOfGateways   = $NumberOfGateways
                    type               = $UagType
                    resourceTags       = $rTags
                    blastTcpPort       = $BlastPort

                }

                if ($UagType -eq "INTERNAL") {
                    $commonPayload.fqdn = $InternalFQDN
                    $commonPayload.infrastructure = @{
                        managementNetwork = $managementSubnetHash;
                        desktopNetwork    = $vmSubnetHash;
                        vmSkus            = $VmsizeSkuJson
                    }
                }


                if ($UagType -eq "EXTERNAL") {
                    $commonPayload.fqdn = $ExternalFQDN
                    $commonPayload.infrastructure = @{
                        dmzNetwork        = $dmzSubnetHash;
                        managementNetwork = $managementSubnetHash;
                        desktopNetwork    = $vmSubnetHash;
                        vmSkus            = $VmsizeSkuJson
                    }
                }


                if ($UagType -eq "INTERNAL_AND_EXTERNAL") {
                    $commonPayload.fqdn = $ExternalFQDN
                    $commonPayload.internalFqdn = $InternalFQDN
                    $commonPayload.infrastructure = @{
                        dmzNetwork        = $dmzSubnetHash;
                        managementNetwork = $managementSubnetHash;
                        desktopNetwork    = $vmSubnetHash;
                        vmSkus            = $VmsizeSkuJson
                    }
                }

                if ($CertificateType -eq "PEM") {
                    $commonPayload.sslCertificate = @{
                        data                = @{
                            certificate         = $UpdatedCert
                            certificatePassword = ""
                        }
                        type = "PEM"
                    }
                }

                if ($CertificateType -eq "PFX") {
                    $commonPayload.sslCertificate = @{
                        data                = @{
                            certificate         = $UpdatedCert
                            certificatePassword = $CertficatePassword
                        }
                        type = "PFX"
                    }
                }

                if ($ManualPublicIP) {
                    $commonPayload.customIpConfiguration = @{
                        customIpType         = "STATIC_IP_ADDRESS"
                        assignToLoadBalancer = $false
                        ipDetails            = @{
                            address = $ManualPublicIP
                        }
                    }
                }
            
                if ($PSBoundParameters.ContainsKey($proxyHost) -or $PSBoundParameters.ContainsKey($proxyName)) {
                    $commonPayload.enabled = $true
                    $commonPayload.proxyHost = $proxyHost
                    $commonPayload.proxyName = $proxyName
                    $commonPayload.proxyPort = $proxyPort
                    $commonPayload.proxyType = $proxyType
                    if ($PSBoundParameters.ContainsKey($proxyCertificate)) {
                        $commonPayload.trustedCertificate = $proxyCertificate
                    }
                }

                $payloadJson = $commonPayload | ConvertTo-Json -Depth 20
                Write-Verbose "Final Payload JSON: $payloadJson"
            }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "New-HCSUAG: UAG Creation Request for $Name failed for JsonInput generation"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }

        try {
            $urlUag = "https://cloud.omnissahorizon.com/admin/v2/uag-deployments"
            $dataCreateUag = Invoke-WebRequest -Uri $urlUag -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop

            if ($dataCreateUag.StatusCode -eq 201) {
                Write-Verbose "New-HCSUAG: $Name Creation Request is accepted"
                #convert output to JSON
                $returnData = $dataCreateUag.Content | ConvertTo-Json -Depth 6
                return $returnData
            }
            else {
                Write-Host -ForegroundColor Red "New-HCSUAG: Edge creation failed for $Name"
                Write-Host ($dataCreateUag | Out-String)
            }
        }
        catch {
            Write-Host -ForegroundColor Red "New-HCSUAG - Error creating Edge: $_"
        }


    }

}

function New-HCSSite {
    <#  
        .SYNOPSIS  
            Creates a New Site with provided parameters in next-gen Org  
        .DESCRIPTION  
            sites associate a user or user group with a specific site. Assign home sites to manage resources for end-user connection requests.
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER SiteName
            Name of the Site
        .PARAMETER Description
            Optional parameter - add a description to the site
    #>

    param(

        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [Parameter(Mandatory = $true)]
        [string]$SiteName,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    process{

        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        # Payload Json Creation
        $siteCreatehash = @{
            name = $SiteName;
            orgId = $OrgId
            description = $Description
        }
        $payloadJson = $siteCreatehash | ConvertTo-Json -Depth 4
        Write-Verbose "Site Creation payload - $payloadJson"

        try{
            $siteCreateUrl = "https://cloud.omnissahorizon.com/portal/v2/sites"
            $dataCreateSite = Invoke-RestMethod -Uri $siteCreateUrl -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop
            return $dataCreateSite

        }
        catch{
            Write-Host -ForegroundColor Red "New-HCSSite - Error creating Site: $_"
        }
    }

}

function Get-HCSSite {
    <#  
        .SYNOPSIS  
            Creates a New Site with provided parameters in next-gen Org  
        .DESCRIPTION  
            sites associate a user or user group with a specific site. Assign home sites to manage resources for end-user connection requests.
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER Siteid
            Name of the Site
        .EXAMPLE
            Get-HCSSite -OrgId f9b98412-658b-45db-a06b-000000000000
    #>

    param(

        [Parameter(Mandatory = $true)]
        [string]$OrgId
    )

    process{

        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        try{
            $siteGetUrl = "https://cloud.omnissahorizon.com/portal/v2/sites"
            $dataGetSite = Invoke-RestMethod -Uri $siteGetUrl -Method Get -Headers $headers -ErrorAction Stop
            return $dataGetSite
        }
        catch{
            Write-Host -ForegroundColor Red "Get-HCSSite - Error fetching Site details: $_"
        }
    }

}

function Set-HCSSite {
    <#  
        .SYNOPSIS  
            Updates the Edge with a site mapping 
        .DESCRIPTION  
            Updates the Edge with a site mapping . 
            This cmdlet helps to associate a site with existing edge.
            if the Edge is already tied with a site - this cmdlet will fail 
        .PARAMETER SiteId
            provide the SiteId -> Get-HCSSite will help you with sites information
        .PARAMETER EdgeDeploymentId
            provide the EdgeId -> get-HCSEdge will help with Edge Deployment Id 
    #>

    param(

        [Parameter(Mandatory = $true)]
        [string]$OrgId,

        [Parameter(Mandatory = $true)]
        [string]$SiteId,

        [Parameter(Mandatory = $true)]
        [string]$EdgeDeploymentId
    )

    process {

        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        # Put call to update the Edge to Site mapping 
        try {
            $edgeSiteMapUrl = "https://cloud.omnissahorizon.com/portal/v2/sites/$SiteId/edge/$EdgeDeploymentId" + "?" + "org_id=$OrgId"
            Write-Verbose "Site map URL - $edgeSiteMapUrl"
            $dataSiteMapping = Invoke-RestMethod -Uri $edgeSiteMapUrl -Method PUT -Headers $headers -ErrorAction Stop
            Write-Verbose "Site mapping results - $dataSiteMapping"
            return $dataSiteMapping
        }
        catch {
            Write-Host -ForegroundColor Red "Set-HCSSite - Error Update Sitemapping : $_"
        }
    }
    
}

function Set-HCSPool {
    <#  
        .SYNOPSIS  
            patch the pool with provided properties
        .DESCRIPTION  
            patch the pool with provided properties
            This cmdlet helps to updating below details 
             - SessionperVM in MULTI_SESSION pools
             - Increase or Decrease the count vm's based on Provisioning Type
             - Update the image & marker
             - Add the new resource tags
        .PARAMETER OrgId
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER PoolId
            poolId of the pool -  Get-HCSPool will help              
        .PARAMETER PoolType
            Provide the poolType - allowed values are 'FLOATING', 'DEDICATED', 'MULTI_SESSION'
        .PARAMETER SessionsPerVm
            How many sessions can be possible in a VM , For Muiltisession Pools this parameter can be configurable
            For Dedicated & Floating pools this values shoubde set to 1
        .PARAMETER ProxyServer
            proxy server IP / Hostname for agent to Horizon Cloud ControlPlane communication
        .PARAMETER ProxyPort
            proxy servver port
        .PARAMETER Description
            Pool description
        .PARAMETER ImageId
            provide the mageId from which pool VMs needs to be created . Get-HCSImage will help 
        .PARAMETER MarkerId
            provide the MarkerId of the ImageId from which pool VMs needs to be created . Get-HCSImage will help 
        .PARAMETER VmModelSku
            Provide the VmModel - Ex: Standard_A4_v2
        .PARAMETER DiskSku
            Provide the DiskSku - allowed values are 'Premium_LRS', 'Premium_ZRS', 'PremiumV2_LRS', 'Standard_LRS', 'StandardSSD_LRS', 'StandardSSD_ZRS', 'UltraSSD_LRS'
        .PARAMETER SubnetId
            Provide the SubnetId Ex: "/subscriptions/xxx-34a2-4a23-x9f7-254xxxfb3/resourceGroups/HCS_DEVOPS_RG_01/providers/Microsoft.Network/virtualNetworks/HCS_DEVOPS_CENTRAL_VNET_01/subnets/VDI01"
            (Get-HCSNetworks -OrgId $OrgId -ProviderId $ProviderId -Environment Azure -Preffered $true).desktop can help in getting the information
            if the SubnetId not provided then cmdlet take the preffered networks on the provider as input
        .PARAMETER ProvisioningType
            Provide the ProvisioningType - allowed values are 'ON_DEMAND', 'UP_FRONT'
        .PARAMETER MinSpareVm
            Minimum number of spare/unassigned VM's to be always available in a pool
            Default value is set to 1 and can be modified after pool creation
        .PARAMETER MaximumSpareVm
            Maximum number of spare/unassigned VM's can be possible in a pool
            Default value is set to 1 and can be modified after pool creation
        .PARAMETER MaximumVm
            Maximum number of VM's can be provisioned in the pool
            Default value is set to 1 and can be modified after pool creation
        .PARAMETER DiskEncryption
            The Boolean value defaults to $false. Set it to $true to enable the DiskEncryption.
        .PARAMETER AvailabilityZone
            The Boolean value defaults to $false. Set it to $true to enable the AvailabilityZone.
        .PARAMETER DEMId
            if DEM is configured , provide the DEM ID
            if the DEM ID is passwed ,DEM uses NOAD mode hence if DEM is delivered through group polices then don't specify this parameter
        .EXAMPLE
            # Update SessionsPerVM
                set-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 6718c5ee3ff7ef2d0a4f313b -PoolType MULTI_SESSION -SessionsPerVm 10
            # Update Description
                Set-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 6718c5ee3ff7ef2d0a4f313b  -Description "updated using powershell"
            # Update VMSku & DiskSku
                Set-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 6718c5ee3ff7ef2d0a4f313b -PoolType MULTI_SESSION -VmModelSku "Standard_F2s_v2" -DiskSku StandardSSD_LRS
            # Update Spare policy
                set-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 6718c5ee3ff7ef2d0a4f313b -PoolType MULTI_SESSION -MinSpareVm 1 -MaximumVm 3 -MaximumSpareVm 2 -ProvisioningType ON_DEMAND
            # using in pipleline , select Object is mandatory since Get-HCSPool output json not having poolId paramter rather it has Id , hence we need to explicitly provide
                Get-HCSPool -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolId 666a66a9fa7cdf1fbf6618be|Select-Object @{Name="PoolId";E={$_.Id}},OrgId | Set-HCSPool -MaximumVm 4 -ProvisioningType ON_DEMAND -MinSpareVm 1 -MaximumSpareVm 2


    #>

    param(

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$OrgId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$PoolId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('FLOATING', 'DEDICATED', 'MULTI_SESSION')]
        [string]$PoolType,

        [Parameter(Mandatory = $false)]
        [string]$SessionsPerVm,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]$ProxyServer,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [int]$ProxyPort,

        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$ImageId,

        [Parameter(Mandatory = $false)]
        [string]$MarkerId,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('ON_DEMAND', 'UP_FRONT')]
        [string]$ProvisioningType = "UP_FRONT",

        [Parameter(Mandatory = $false)]
        [ValidateSet('Premium_LRS', 'Premium_ZRS', 'PremiumV2_LRS', 'Standard_LRS', 'StandardSSD_LRS', 'StandardSSD_ZRS', 'UltraSSD_LRS')]
        [string]$DiskSku,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("[Standard][_][0-9a-z]")]
        [string]$VmModelSku,

        [Parameter(Mandatory = $false)]
        [string]$SubnetId,

        [Parameter(Mandatory = $false)]
        [bool]$DiskEncryption,
        [bool]$AvailabilityZone,
        [string]$DEMId,

        [Parameter(Mandatory = $false)]
        [int]$MinSpareVm,
        [int]$MaximumSpareVm,
        [int]$MaximumVm


    )

    process {

        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }
        
        if ($input) {
                Write-Verbose "Value from pipeline: $_"
            } else {
                Write-Verbose "No pipeline input" 
        }
     

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        # Payload Creation
        $commonPayload = @{}

        #find the pool information
        $poolInfo = Get-HCSPool -OrgId $OrgId -poolId $PoolId
        Write-Verbose "Pool Information - $poolInfo "

        # Proxy Handling
        if ($PSBoundParameters.ContainsKey('ProxyServer') -and $PSBoundParameters.ContainsKey('ProxyPort')) {
            $proxyhttp = "http://$ProxyServer" + ":" + "$ProxyPort"
            $ProxyInfoHash = @{ bypass = ""; server = $proxyhttp }
            $ProxyInfoJson = $ProxyInfoHash | ConvertTo-Json -Depth 4
            Write-Verbose "Proxy Info JSON: $ProxyInfoJson"
            $agentCustomizationHash = @{ DEMId = $DEMId; proxyInfo = $ProxyInfoHash }

        }
        elseif (!$PSBoundParameters.ContainsKey('ProxyServer') -and $PSBoundParameters.ContainsKey('ProxyPort')) {
            Write-Host -ForegroundColor Red "Set-HCSPool : ProxyServer is a mandatory parameter when ProxyPort is specified"
            return

        }
        elseif ($PSBoundParameters.ContainsKey('ProxyServer') -and !$PSBoundParameters.ContainsKey('ProxyPort')) {
            Write-Host -ForegroundColor Red "Set-HCSPool : ProxyPort is a mandatory parameter when ProxyServer is specified"
            return

        }
        else {
            $agentCustomizationHash = @{ DEMId = $DEMId }
        }

        # Disk Encryption
        if ($PSBoundParameters.ContainsKey('DiskEncryption')) {
            $diskEncryptionhash = @{ enabled = $DiskEncryption }
            $diskEncryptionJson = $diskEncryptionhash | ConvertTo-Json -Depth 4
            Write-Verbose "$diskEncryptionJson"
        }

        # VmModel & DiskSku change
        if ($PSBoundParameters.ContainsKey('VmModelSku') -and $PSBoundParameters.ContainsKey('DiskSku')) {
            $providerId = $poolInfo.providerInstanceId
            Write-Verbose "Pool ProviderId - $providerId "
            # VM Size SKU
            try {
                $VmsizeSkuJson = Get-HCSAzureVmSkus -OrgId $OrgId -providerId $providerId -VmSize $VmModelSku
                if ($VmsizeSkuJson.id -ne $VmModelSku) {
                    Write-Host -ForegroundColor Red "Set-HCSPool : Unable to retrieve VMSize details, please recheck the VM Size and try again"
                    return
                }
            }
            catch {
                Write-Host -ForegroundColor Red "Set-HCSPool : Unable to retrieve VMSize details, please recheck the VM Size and try again"
                return
            }
            Write-Verbose "VM Size SKU JSON: $VmsizeSkuJson"
            # Disk SKU
            try {
                $DiskSizeSkus = Get-HCSAzureDiskSkus -OrgId $OrgId -providerId $ProviderId -VmSize $VmModelSku
                if ($null -eq $DiskSizeSkus) {
                    Write-Host -ForegroundColor Red "Set-HCSPool: Unable to retrieve DiskSku details, please check provided DiskSku and try again"
                    return
                }
                $DiskSizeSkuJson = $DiskSizeSkus | Where-Object { $_.id -eq $DiskSku }
            }
            catch {
                Write-Host -ForegroundColor Red "Set-HCSPool: Unable to retrieve DiskSku details, please check provided DiskSku and try again"
                return
            }
            Write-Verbose "Disk SKU JSON: $DiskSizeSkuJson"
        }
        elseif (!$PSBoundParameters.ContainsKey('VmModelSku') -and $PSBoundParameters.ContainsKey('DiskSku')) {
            Write-Host -ForegroundColor Red "Set-HCSPool : VmModelSku is mandatory with DiskSku"
            return
        }
        elseif ($PSBoundParameters.ContainsKey('VmModelSku') -and !$PSBoundParameters.ContainsKey('DiskSku')) {
            Write-Host -ForegroundColor Red "Set-HCSPool : DiskSku is mandatory with VmModelSku"
            return
        }

        # Spare Policy
        if (!$PSBoundParameters.ContainsKey('ProvisioningType')) {
            if ($PSBoundParameters.ContainsKey('MinSpareVm') -or $PSBoundParameters.ContainsKey('MaximumSpareVm') -or $PSBoundParameters.ContainsKey('MaximumVm')) {
                Write-Host -ForegroundColor Red "Set-HCSPool: For Spare Policy update, ProvisioningType is a mandatory parameter."
                return
            }
        }

        if ($PSBoundParameters.ContainsKey('ProvisioningType')) {
            switch ($ProvisioningType) {
                "UP_FRONT" {
                    if ($PSBoundParameters.ContainsKey('MaximumVm') -and -not ($PSBoundParameters.ContainsKey('MinSpareVm') -or $PSBoundParameters.ContainsKey('MaximumSpareVm'))) {
                        $sparePolicyHash = @{
                            description = ""
                            limit       = $MaximumVm
                            max         = $MaximumVm
                            min         = $MaximumVm
                        }
                    }
                    else {
                        Write-Host -ForegroundColor Red "Set-HCSPool: When ProvisioningType is 'UP_FRONT', only MaximumVm is an allowed parameter."
                        return
                    }
                }
                "ON_DEMAND" {
                    if ($PSBoundParameters.ContainsKey('MaximumVm') -and $PSBoundParameters.ContainsKey('MinSpareVm') -and $PSBoundParameters.ContainsKey('MaximumSpareVm')) {
                        $sparePolicyHash = @{
                            description = ""
                            limit       = $MaximumVm
                            max         = $MaximumSpareVm
                            min         = $MinSpareVm
                        }
                    }
                    else {
                        Write-Host -ForegroundColor Red "Set-HCSPool: When ProvisioningType is 'ON_DEMAND', MinSpareVm, MaximumSpareVm, and MaximumVm are mandatory parameters."
                        return
                    }
                }
                default {
                    Write-Host -ForegroundColor Red "Set-HCSPool: Invalid ProvisioningType. Supported values are 'UP_FRONT' and 'ON_DEMAND'."
                    return
                }
            }
            $commonPayload.sparePolicy = $sparePolicyHash                    
            $sparePolicyJson = $sparePolicyHash | ConvertTo-Json -Depth 4
            Write-Verbose "Spare policy JSON: $sparePolicyJson"
        }


        # Validate Image and Marker IDs
        if ($PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('MarkerId')) {
            try {
                $Imagevalidation = Get-HCSImageMarkers -OrgId $OrgId -ImageId $ImageId -MarkerId $MarkerId
                if ($Imagevalidation.imageId -ne $ImageId) {
                    Write-Host -ForegroundColor Red "Set-HCSPool : Please validate ImageId & MarkerId details"
                    return
                }
            }
            catch {
                Write-Host -ForegroundColor Red "Set-HCSPool : Please validate ImageId & MarkerId details"
                return
            }    
        }
        elseif (!$PSBoundParameters.ContainsKey('ImageId') -and $PSBoundParameters.ContainsKey('MarkerId')) {
            Write-Host -ForegroundColor Red "Set-HCSPool : Please provide ImageId"
            return
        }
        elseif ($PSBoundParameters.ContainsKey('ImageId') -and !$PSBoundParameters.ContainsKey('MarkerId')) {
            Write-Host -ForegroundColor Red "Set-HCSPool : Please provide MarkerId"
            return
        }

        # Networks
        if ($PSBoundParameters.ContainsKey('SubnetId')) {
            $ProviderIdVal = $poolInfo.providerInstanceId
            Write-Verbose "Pool ProviderId - $ProviderIdVal"
            $PrefferedNetworks = (Get-HCSNetworks -OrgId $OrgId -ProviderId $ProviderIdVal -Environment Azure -Preffered $true).desktop
            Write-Verbose "preffered networks - $PrefferedNetworks"
            try {
                $networksJson = $PrefferedNetworks | Where-Object { $SubnetId -contains $_.id }
            }
            catch {
                Write-Host -ForegroundColor Red "Set-HCSPool: Unable to retrieve Preffered networks"
                return
            }
            $networksJsonHash = $networksJson | ConvertTo-Json -Depth 6 | ConvertFrom-Json -AsHashtable
            Write-Verbose "Networks JSON Hash: $networksJsonHash"
        }
        

        # Actual payload creation for PATCH call

        if($PSBoundParameters.ContainsKey('SessionsPerVm')){
            if ($poolInfo.templateType -eq 'MULTI_SESSION') {
                $commonPayload.sessionsPerVm = $sessionsPerVm
            } else {
                $commonPayload.sessionsPerVm = 1
            }
        }
        
        if ($ProxyServer) {
            $commonPayload.agentCustomization = $agentCustomizationHash
        }

        if ($Description) {
            $commonPayload.description = $Description
        }
        
        if ($ImageId -or $MarkerId) {
            $commonPayload.imageReference = @{ streamId = $ImageId; markerId = $MarkerId }
        }

        if ($VmModelSku -or $DiskSku) {
            $commonPayload.infrastructure = @{
                vmSkus   = @($VmsizeSkuJson)
                diskSkus = @($DiskSizeSkuJson)
            }
        }

        if ($DiskEncryption) {
            $commonPayload.diskEncryption = $diskEncryptionhash
        }

        if ($SubnetId) {
            $commonPayload.networks = @($networksJsonHash)
        }

        if ($AvailabilityZone) {
            $commonPayload.availabilityZoneEnabled = $AvailabilityZone
        }
        
        $payloadJson = $commonPayload | ConvertTo-Json -Depth 6
        Write-Verbose "Final Payload JSON: $payloadJson"

        # Trigger API call with above constructed payload based on selection
        try {
            $urlPool = "https://cloud.omnissahorizon.com/admin/v2/templates/$PoolId" + "?" + "ignore_warnings=true&org_id=$OrgId"
            Write-Verbose " Patch URL --> (Invoke-RestMethod -Uri $urlPool -Method PATCH -Headers $headers -Body $payloadJson -ErrorAction Stop) "
            $dataPatchPool = Invoke-RestMethod -Uri $urlPool -Method PATCH -Headers $headers -Body $payloadJson -ErrorAction Stop
            return $dataPatchPool
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Set-HCSPool: Pool Update Request failed"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }
    }

}

function Set-HCSPoolGroup {
    <#  
        .SYNOPSIS  
            Creates a New PoolGroup with provided parameters in next-gen Org  
        .DESCRIPTION  
            Creates a New PoolGroup with provided parameters in next-gen Org    
            If a JSON payload exists, there is no need to pass any parameters, as the cmdlet will read the information from the JSON file and create the pool accordingly.
            However, if the JSON parameters are not provided, you must pass the following mandatory parameters:
                rgId,Name,PoolGroupType,PoolType,PoolId,PowerManagementType,PowerManagementMode,AlwaysPoweredOnVMPercent,LogoffDisconnectedSessions
        .PARAMETER OrgId  
            The long OrgId for the organization. Please copy and input the OrgId into this parameter.  
        .PARAMETER PoolGroupName
            Name of the PoolGroup.
        .PARAMETER PoolId
            Provide the poolID of the pool to be associated with this poolGroup
        .PARAMETER DisplayName
            DisplayName of the PoolGroup , Name & displayname can be different
        .PARAMETER Description
            It's an optional parameter . provide a description for the pool if necessary 
        .PARAMETER EnableSSO
            Optional paramter - The Boolean value defaults to $true , if SSO not required on the specific poolgroup set it as $false
        .PARAMETER PowerManagementType
            Provide the PowerManagementType - allowed values are 'Occupancy', 'NonOccupancy'.
        .PARAMETER PowerManagementMode
            Provide the PowerManagementMode - allowed values are 'Performence', 'Balanced', 'Cost'.
            Performence - Optimized for Performence , Cost - Optimized for Cost and Balanced.
        .PARAMETER AlwaysPoweredOnVMPercent
            Provide the a value so that AlwaysPoweredOnVMPercent vm's will be always poweredON
        .PARAMETER PowerOffProtectMins
            Optional paramter - Provide the PowerOffProtectMins values - Maximum allowed value is 60 mins
            Default value is set to 30 mins.
        .PARAMETER PreferredClientType
            Optional paramter - Provide the PreferredClientType, allowed values are 'HORIZON_CLIENT', 'BROWSER'
            Default value is set to 'HORIZON_CLIENT'
        .PARAMETER SupportedDisplayProtocols
            Optional paramter and defaut to BLAST
        .PARAMETER Scope
            Optional paramter - Provide the Scope , allowed values are 'ALL_SITES', 'ONE_SITE'
            Default value is set to 'ALL_SITES'
        .PARAMETER connectionAffinity
            Optional paramter - Provide the connectionAffinity fro user logins . allowed values are 'NEAREST_SITE', 'HOME_SITE'
            Default value is set to 'NEAREST_SITE'
        .PARAMETER directConnect
            Optional paramter, The Boolean value defaults to $false. Set it to $true if UAG needs to be bypassed
        .PARAMETER ShowMachineName
            Optional paramter,The Boolean value defaults to $false. Set it to $true if Dedicated desktop name to be shown for user
            Applicable for Dedicated poolgroups
        .PARAMETER IdleSessionTimeout
            Optional paramter,Provide IdleSessionTimeout for the poolgroup
            Default value is set to '10080'
        .PARAMETER LogoffDisconnectedSessions
            Provide LogoffDisconnectedSessions, allowed values are 'IMMEDIATELY', 'NEVER', 'AFTER'
            If the parameter set to AFTER then "AutomaticLogoffMinutes" needs to be set
        .PARAMETER AutomaticLogoffMinutes
            Optional paramter,Provide AutomaticLogoffMinutes for the poolgroup
            Default value is set to '120'
        .PARAMETER MaximumSessionLifetime
            Optional paramter,Provide MaximumSessionLifetime for the poolgroup
            Default value is set to '10080'
        .PARAMETER PoolGroupId
            provide poolGroupID
        .PARAMETER EmptyApplicationSessionTimeoutMinutes
            provide EmptyApplicationSessionTimeoutMinutes
        .PARAMETER EmptyApplicationSessionLogoffType
            provide EmptyApplicationSessionLogoffType
        .PARAMETER ConsecutiveSessionAllocationTime
            provide ConsecutiveSessionAllocationTime , default is 10 Seconds
        .PARAMETER VMMaintenancePolicy 
        .PARAMETER VMMaintenanceType
        .PARAMETER VMMaintenanceRecurrence
        .PARAMETER VMMaintenanceRecurrenceDay
        .PARAMETER VMMaintenanceTimezone
        .PARAMETER VMMaintenanceScheduledHour
        .PARAMETER VMMaintenanceQuiescingVMs
        .PARAMETER VMMaintenanceAction
        .PARAMETER JsonFilePath
            Provide the path to JSON file
        .EXAMPLE
            # PoolGroup creation by providing JSON file

                Set-HCSPoolGroup -JsonFilePath "C:/temp/update-poolgroup-01.json" -Verbose

            # PoolGroup Creation with Mandatory parameters

                Set-HCSPoolGroup -Name P02 -PoolGroupType DESKTOP -PoolType FLOATING -PoolId 675040dxxx645774xxe -PowerManagementType NonOccupancy -AlwaysPoweredOnVMPercent 10 -LogoffDisconnectedSessions AFTER -OrgId f9b98412-658b-45db-a06b-000000000000 -Verbose

            # using in pipleline , select Object is mandatory since Get-HCSPoolGroup output json not having poolGroupId paramter rather it has Id , hence we need to explicitly provide
                Get-HCSPoolGroup -OrgId f9b98412-658b-45db-a06b-000000000000 -PoolGroupId 666a66a9fa7cdf1fbf6618be|Select-Object @{Name="PoolGroupId";E={$_.Id}},OrgId | Set-HCSPoolGroup -PowerManagementType NonOccupancy -AlwaysPoweredOnVMPercent 10

    #>
    
    param(

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'JsonInput')]
        [ValidateNotNullOrEmpty()]
        [String]$JsonFilePath,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$PoolGroupId,

        [Parameter(Mandatory = $false)]
        [string]$PoolGroupName,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName,
        [string]$Description,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$OrgId,

        [bool]$EnableSSO,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Occupancy', 'NonOccupancy')]
        [string]$PowerManagementType,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Performence', 'Balanced', 'Cost')]
        [string]$PowerManagementMode = "Balanced",

        [Parameter(Mandatory = $false)]
        [int]$AlwaysPoweredOnVMPercent,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IMMEDIATELY', 'NEVER', 'AFTER')]
        [string]$LogoffDisconnectedSessions,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$AutomaticLogoffMinutes = 120,

        [Parameter(Mandatory = $false)]
        [int]$MaximumSessionLifetime,

        [Parameter(Mandatory = $false)]
        [int]$IdleSessionTimeout,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$EmptyApplicationSessionTimeoutMinutes = 60,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LOGOFF', 'DISCONNECT')]
        [string]$EmptyApplicationSessionLogoffType,
        

        [Parameter(Mandatory = $false)]
        [int]$ConsecutiveSessionAllocationTime,

        [bool]$ShowMachineName,

        [ValidateSet('HORIZON_CLIENT', 'BROWSER')]
        [string]$PreferredClientType ,

        [ValidateSet('ALL_SITES', 'ONE_SITE')]
        [string]$Scope,

        [ValidateSet('NEAREST_SITE', 'HOME_SITE')]
        [string]$connectionAffinity,

        [Parameter(Mandatory = $false)]
        [int]$PowerOffProtectMins,

        [Parameter(Mandatory = $false)]
        [Boolean]$DirectConnect,

        [Parameter(Mandatory = $false)]
        [Boolean]$VMMaintenancePolicy,

        [ValidateSet('SCHEDULED', 'SESSION')]
        [string]$VMMaintenanceType = "SCHEDULED",

        [ValidateSet('WEEKLY', 'DAILY')]
        [string]$VMMaintenanceRecurrence = "WEEKLY",

        [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
        [string]$VMMaintenanceRecurrenceDay = "Sunday",

        [string]$VMMaintenanceTimezone = "UTC",

        [ValidateRange(1, 24)]
        [int]$VMMaintenanceScheduledHour = "0",

        [int]$VMMaintenanceQuiescingVMs = "1",

        [ValidateSet('RESTART', 'REBUILD')]
        [string]$VMMaintenanceAction = "RESTART"

    )
    process {

        $headers = @{
            'Authorization' = "Bearer $env:HCSAccessToken"
            'content-type'  = "application/json"
            'Accept'        = "application/json"
        }

        # Check token validity
        $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
        Write-Verbose "$tokenExpiry"
        if ((Get-Date).AddMinutes(5) -lt $tokenExpiry) {
            Write-Verbose "Token is valid"
        }
        else {
            Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
            return
        }

        try {
            if ($JsonFilePath) {
                # Check if the JSON file exists
                if (-not (Test-Path -Path $JsonFilePath)) {
                    Throw "The specified JSON file '$JsonFilePath' does not exist."
                }
                # Read and parse the JSON file
                $jsonPayload = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
                # Convert the JSON object back to a string for the payload
                $payloadJson = $jsonPayload | ConvertTo-Json -Depth 10
                Write-Verbose "JsonInput provided is - $payloadJson"
            }
            else {
                # Retrive poolGroup Details 
                $poolGroupData = Get-HCSPoolGroup -OrgId $OrgId -PoolGroupId $PoolGroupId
                Write-Verbose "PoolGroup Details - $poolGroupData"

                # Get the Pool Type
                $PoolType = $poolGroupData.templateType

                if ($EmptyApplicationSessionLogoffType -eq "LOGOFF") { $AppSessionLogoffType = $null}
                if ($EmptyApplicationSessionLogoffType -eq "DISCONNECT") {$AppSessionLogoffType = "DISCONNECT"}

                # Check if Mandatory parameters are provided
                if (-not ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId'))) {
                    Write-Host -ForegroundColor Red "Set-HCSPoolGroup: Mandatory parameters missing - please check if one of OrgId,PoolGroupId is missing"
                    return
                }

                #Check Provided timezone is valid
                function Set-TimeZone {
                    [CmdletBinding()]
                    Param(
                        [Parameter(Mandatory = $true, HelpMessage = "Enter a valid IANA time zone like 'Asia/Kolkata' or 'UTC'.")]
                        [ValidateScript({
                                try {
                                    # Validate using TimeZoneConverter module
                                    $null = [TimeZoneConverter.TZConvert]::GetTimeZoneInfo($_)
                                    return $true
                                }
                                catch {
                                    retun "InValid"
                                }
                            })]
                        [string]$TimeZone
                    )
                
                    return "Valid"
                }

                # Initialize common payload Hash
                $commonPayload = @{}

                # Handle Power Policy
                if ($PSBoundParameters.ContainsKey('PowerManagementType')) {
                    $powerPolicyData = $poolGroupData.powerPolicy
                    Write-Verbose "Existing Power Policy details - $powerPolicyData"
                    try {
                        if ($PowerManagementType -eq "Occupancy") {
                            if (!$PSBoundParameters.ContainsKey('PowerManagementMode')) {
                                Write-Host -ForegroundColor Red "Add the PowerManagementMode parameter as the PowerManagementType setting is configured to Occupancy"
                                return
                            }
                            if (!$PSBoundParameters.ContainsKey('AlwaysPoweredOnVMPercent')) {
                                Write-Host -ForegroundColor Red "Add the AlwaysPoweredOnVMPercent parameter as the PowerManagementType setting is configured to Occupancy"
                                return
                            }
                        }
                        if ($PowerManagementType -eq "NonOccupancy") {
                            if ($PSBoundParameters.ContainsKey('PowerManagementMode')) {
                                Write-Host -ForegroundColor Red "Given that the PowerManagementType is NonOccupancy, there is no requirement for the PowerManagementMode to be utilized."
                                return
                            }
                            if (!$PSBoundParameters.ContainsKey('AlwaysPoweredOnVMPercent')) {
                                Write-Host -ForegroundColor Red "Add the AlwaysPoweredOnVMPercent parameter as the PowerManagementType setting is configured to NoOccupancy"
                                return
                            }
                        }
                    }
                    catch {
                        Write-Host -ForegroundColor Red "Error validating PoolId: $_"
                        return
                    }
                    # Prepare JSON payload
                    $presetMode = switch ($PowerManagementMode) {
                        "Performence" { "OPTIMIZED_FOR_PERFORMANCE" }
                        "Balanced" { "BALANCED" }
                        "Cost" { "OPTIMIZED_FOR_COST" }
                        default { "OPTIMIZED_FOR_COST" }
                    }

                    if ($PSBoundParameters.ContainsKey('PowerOffProtectMins')){
                        $PowerOffProtectValue = $PowerOffProtectMins
                    } else{
                        $PowerOffProtectValue = $powerPolicyData.powerOffProtectTimeMins
                    }
                
                    $powerPolicyHash = if ($PowerManagementType -eq "Occupancy") {
                        @{
                            enabled                 = $true
                            min                     = $AlwaysPoweredOnVMPercent
                            minUnit                 = "PERCENTAGE"
                            powerOffProtectTimeMins = $PowerOffProtectValue
                            occupancyPresetMode     = $presetMode
                            powerSchedules          = @()
                        }
                    }
                    else {
                        @{
                            enabled                 = $true
                            min                     = $AlwaysPoweredOnVMPercent
                            minUnit                 = "PERCENTAGE"
                            powerOffProtectTimeMins = $PowerOffProtectValue
                            powerSchedules          = @()
                        }
                    }
                    # PowerPolicy Payload
                    $commonPayload.powerPolicy = $powerPolicyHash
                }
                
                $SessionLBSettings = $poolGroupData.agentCustomization.sessionLoadBalancingSettings
                Write-Verbose "sessionLoadBalancingSettings - $SessionLBSettings"

                # Handle LogoffDisconnectedSessions & AutomaticLogoffMinutes Update
                if ($PSBoundParameters.ContainsKey('LogoffDisconnectedSessions') -and $PSBoundParameters.ContainsKey('AutomaticLogoffMinutes')) {
                        $emptySessionTimeoutMins = $poolGroupData.agentCustomization.emptySessionTimeoutMins
                        $IdleSessionTimeout = $poolGroupData.agentCustomization.idleTimeoutMins
                        $logoffTimer = switch ($LogoffDisconnectedSessions) {
                            "NEVER" { 0 }
                            "IMMEDIATELY" { -1 }
                            "AFTER" { $AutomaticLogoffMinutes }
                            default { 0 }
                        }
                        $agentCustomizationHash = switch ($PoolType) {
                            "MULTI_SESSION" {
                                @{
                                    disconnectSessionTimeoutMins = $logoffTimer
                                    idleTimeoutMins              = $IdleSessionTimeout
                                    emptySessionTimeoutMins      =  $emptySessionTimeoutMins
                                    emptySessionLogoffType       = $null
                                    sessionLoadBalancingSettings = @{
                                        LBCPUTHRESHOLD              = $SessionLBSettings.LBCPUTHRESHOLD
                                        LBDISKQUEUELENTHRESHOLD     = $SessionLBSettings.LBDISKQUEUELENTHRESHOLD
                                        LBDISKREADLATENCYTHRESHOLD  = $SessionLBSettings.LBDISKREADLATENCYTHRESHOLD
                                        LBDISKWRITELATENCYTHRESHOLD = $SessionLBSettings.LBDISKWRITELATENCYTHRESHOLD
                                        LBMEMTHRESHOLD              = $SessionLBSettings.LBMEMTHRESHOLD
                                        loadIndexThresholdPercent   = $SessionLBSettings.loadIndexThresholdPercent
                                    }
                                }
                            }
                            default {   
                                @{
                                    disconnectSessionTimeoutMins = $logoffTimer
                                    idleTimeoutMins              = $IdleSessionTimeout
                                }
                            }
                        }
                        # Payload
                        $commonPayload.agentCustomization = $agentCustomizationHash
                } elseif ($PSBoundParameters.ContainsKey('LogoffDisconnectedSessions') -and !$PSBoundParameters.ContainsKey('AutomaticLogoffMinutes')) {
                    $emptySessionTimeoutMins = $poolGroupData.agentCustomization.emptySessionTimeoutMins
                    $IdleSessionTimeout = $poolGroupData.agentCustomization.idleTimeoutMins
                    $logoffTimer = switch ($LogoffDisconnectedSessions) {
                        "NEVER" { 0 }
                        "IMMEDIATELY" { -1 }
                        "AFTER" { $AutomaticLogoffMinutes }
                        default { 0 }
                    }
                    $agentCustomizationHash = switch ($PoolType) {
                        "MULTI_SESSION" {
                            @{
                                disconnectSessionTimeoutMins = $logoffTimer
                                idleTimeoutMins              = $IdleSessionTimeout
                                emptySessionTimeoutMins      = $emptySessionTimeoutMins
                                emptySessionLogoffType       = $AppSessionLogoffType
                                sessionLoadBalancingSettings = @{
                                    LBCPUTHRESHOLD              = $SessionLBSettings.LBCPUTHRESHOLD
                                    LBDISKQUEUELENTHRESHOLD     = $SessionLBSettings.LBDISKQUEUELENTHRESHOLD
                                    LBDISKREADLATENCYTHRESHOLD  = $SessionLBSettings.LBDISKREADLATENCYTHRESHOLD
                                    LBDISKWRITELATENCYTHRESHOLD = $SessionLBSettings.LBDISKWRITELATENCYTHRESHOLD
                                    LBMEMTHRESHOLD              = $SessionLBSettings.LBMEMTHRESHOLD
                                    loadIndexThresholdPercent   = $SessionLBSettings.loadIndexThresholdPercent
                                }
                            }
                        }
                        default {   
                            @{
                                disconnectSessionTimeoutMins = $logoffTimer
                                idleTimeoutMins              = $IdleSessionTimeout
                            }
                        }
                    }
                    # Payload
                    $commonPayload.agentCustomization = $agentCustomizationHash
                } elseif (!$PSBoundParameters.ContainsKey('LogoffDisconnectedSessions') -and $PSBoundParameters.ContainsKey('AutomaticLogoffMinutes')) {
                    Write-Host -ForegroundColor RED "LogoffDisconnectedSessions is a mandatory parameter while AutomaticLogoffMinutes is specified"
                }

                # Handle Empty application session timeout
                if ($PSBoundParameters.ContainsKey('EmptyApplicationSessionTimeoutMinutes') -and $PSBoundParameters.ContainsKey('EmptyApplicationSessionLogoffType') ){
                    if($EmptyApplicationSessionTimeoutMinutes -eq 0){
                        $emptySessionTimeoutMins = 0
                        $AppSessionLogoffType = $null
                    } else{
                        $emptySessionTimeoutMins = $EmptyApplicationSessionTimeoutMinutes
                    }
                    $logoffTimer = $poolGroupData.agentCustomization.disconnectSessionTimeoutMins
                    $IdleSessionTimeout = $poolGroupData.agentCustomization.idleTimeoutMins
                    $agentCustomizationHash = switch ($PoolType) {
                        "MULTI_SESSION" {
                            @{
                                disconnectSessionTimeoutMins = $logoffTimer
                                idleTimeoutMins              = $IdleSessionTimeout
                                emptySessionTimeoutMins      = $emptySessionTimeoutMins
                                emptySessionLogoffType       = $AppSessionLogoffType
                                sessionLoadBalancingSettings = @{
                                        LBCPUTHRESHOLD              = $SessionLBSettings.LBCPUTHRESHOLD
                                        LBDISKQUEUELENTHRESHOLD     = $SessionLBSettings.LBDISKQUEUELENTHRESHOLD
                                        LBDISKREADLATENCYTHRESHOLD  = $SessionLBSettings.LBDISKREADLATENCYTHRESHOLD
                                        LBDISKWRITELATENCYTHRESHOLD = $SessionLBSettings.LBDISKWRITELATENCYTHRESHOLD
                                        LBMEMTHRESHOLD              = $SessionLBSettings.LBMEMTHRESHOLD
                                        loadIndexThresholdPercent   = $SessionLBSettings.loadIndexThresholdPercent
                                }
                            }
                        }
                        default {   
                            @{
                                disconnectSessionTimeoutMins = $logoffTimer
                                idleTimeoutMins              = $IdleSessionTimeout
                            }
                        }
                    }
                    # Payload
                    $commonPayload.agentCustomization = $agentCustomizationHash
                } elseif (!$PSBoundParameters.ContainsKey('EmptyApplicationSessionTimeoutMinutes') -and $PSBoundParameters.ContainsKey('EmptyApplicationSessionLogoffType') ){
                    Write-Host -ForegroundColor RED "EmptyApplicationSessionTimeoutMinutes is a mandatory parameter while EmptyApplicationSessionLogoffType is specified"
                }  elseif ($PSBoundParameters.ContainsKey('EmptyApplicationSessionTimeoutMinutes') -and !$PSBoundParameters.ContainsKey('EmptyApplicationSessionLogoffType') ){
                    Write-Host -ForegroundColor RED "EmptyApplicationSessionLogoffType is a mandatory parameter while EmptyApplicationSessionTimeoutMinutes is specified"
                }
                
                # Handle MaximumSessionLifetime update
                if ($PSBoundParameters.ContainsKey('MaximumSessionLifetime')) {
                    $sessionLifeTimeHash = @{
                        maxSessionLifeTime = $MaximumSessionLifetime
                    }
                    # Payload
                    $commonPayload.startSessionSettings = $sessionLifeTimeHash
                }

                # Handle SSO Enable / Disable
                if ($PSBoundParameters.ContainsKey('EnableSSO')) {
                    # payload
                    $commonPayload.enableSSO = $EnableSSO
                }

                # Handle PoolGroupName update
                if ($PSBoundParameters.ContainsKey('PoolGroupName')) {
                    # payload
                    $commonPayload.name = $PoolGroupName
                }

                # Handle PoolGroup DisplayName Update
                if ($PSBoundParameters.ContainsKey('DisplayName')) {
                    # payload
                    $commonPayload.displayName = $DisplayName
                }

                # Handle PoolGroup Description update
                if ($PSBoundParameters.ContainsKey('Description')) {
                    # payload
                    $commonPayload.description = $Description
                }

                # Handle Direct Connect update
                if ($PSBoundParameters.ContainsKey('DirectConnect')) {
                    # payload
                    $commonPayload.directConnect = $directConnect
                }

                # Handle ConnectionAffinity update
                if ($PSBoundParameters.ContainsKey('connectionAffinity')) {
                    # payload
                    $commonPayload.connectionAffinity = $connectionAffinity
                }

                # Handle PrefferedClient type update with Broweser / Horizon Client
                if ($PSBoundParameters.ContainsKey('PreferredClientType')) {
                    # payload
                    $commonPayload.preferredClientType = $PreferredClientType
                }

                # Handle the Site Scope
                if ($PSBoundParameters.ContainsKey('Scope')) {
                    # payload
                    $commonPayload.scope = $Scope
                }
                if ($PSBoundParameters.ContainsKey('$ConsecutiveSessionAllocationTime')) {
                    $commonPayload.transientLoadThresholdSecs = $ConsecutiveSessionAllocationTime
                }

                # Handle Rolling Maintenance update
                if ($PoolType -eq 'MULTI_SESSION' -and $PSBoundParameters.ContainsKey('VMMaintenancePolicy')) {
                    # Get the VM Maintenace Policy
                    $MaintPolicy = $poolGroupData.vmMaintenancePolicy
                    Write-Verbose "VM Maintenance Policy - $MaintPolicy"
                    if ($null -eq $MaintPolicy -and $VMMaintenancePolicy -eq $false){
                        Write-Host -ForegroundColor Yellow "vmMaintenancePolicy is not yet configured on the poolGroup"
                    } elseif ($null -eq $MaintPolicy -and $VMMaintenancePolicy -eq $true) {
                        $MaintenanceRecurrenceDay = switch ($VMMaintenanceRecurrenceDay) {
                            "SUNDAY"    { 1 }
                            "MONDAY"    { 2 }
                            "TUESDAY"   { 3 }
                            "WEDNESDAY" { 4 }
                            "THURSDAY"  { 5 }
                            "FRIDAY"    { 6 }
                            "SATURDAY"  { 7 }
                            default     { 1 }
                        }

                        $commonPayload.vmMaintenancePolicy = @{
                            enabled = $true ;
                            vmMaintenancePolicyType = $VMMaintenanceType ;
                            maxQuiescingVMs = $VMMaintenanceQuiescingVMs ;
                            vmAction = $VMMaintenanceAction ;
                            recurrenceType = $MaintenanceRecurrenceDay ;
                            dayOfWeek = $VMMaintenanceRecurrenceDay ;
                            hourOfDay = $VMMaintenanceScheduledHour ;
                            timeZone = $VMMaintenanceTimezone ;
                            numOfSessionsPerVM = $null
                        }
                    }
                    $MaintPolicyStatus = $poolGroupData.vmMaintenancePolicy.enabled
                    Write-Verbose "vmMaintenancePolicy Status - $MaintPolicyStatus"

                    if($MaintPolicyStatus -eq $false -and $VMMaintenancePolicy -eq $false){
                        Write-Host -ForegroundColor Yellow "VM Maintenace Policy is already Disabled"
                    } elseif($MaintPolicyStatus -eq $true -and $VMMaintenancePolicy -eq $false){
                        $commonPayload.vmMaintenancePolicy = @{
                            enabled = $false ;
                            vmMaintenancePolicyType = $MaintPolicy.vmMaintenancePolicyType ;
                            maxQuiescingVMs = $MaintPolicy.maxQuiescingVMs ;
                            vmAction = $MaintPolicy.vmAction ;
                            recurrenceType = $MaintPolicy.recurrenceType ;
                            dayOfWeek = $MaintPolicy.dayOfWeek ;
                            hourOfDay = $MaintPolicy.hourOfDay ;
                            timeZone = $MaintPolicy.timeZone ;
                            numOfSessionsPerVM = $null
                        }
                    } elseif($MaintPolicyStatus -eq $false -and $VMMaintenancePolicy -eq $true){
                        $commonPayload.vmMaintenancePolicy = @{
                            enabled = $true ;
                            vmMaintenancePolicyType = $MaintPolicy.vmMaintenancePolicyType ;
                            maxQuiescingVMs = $MaintPolicy.maxQuiescingVMs ;
                            vmAction = $MaintPolicy.vmAction ;
                            recurrenceType = $MaintPolicy.recurrenceType ;
                            dayOfWeek = $MaintPolicy.dayOfWeek ;
                            hourOfDay = $MaintPolicy.hourOfDay ;
                            timeZone = $MaintPolicy.timeZone ;
                            numOfSessionsPerVM = $null
                        }
                    } elseif($MaintPolicyStatus -eq $true -and $VMMaintenancePolicy -eq $true){
                        Write-Host -ForegroundColor Yellow "VM Maintenace Policy is already Enabled"
                    }
                }

                # Handle ShowMachineName update for Dedicated pools only
                if ($PoolType -eq 'DEDICATED' -and $PSBoundParameters.ContainsKey('ShowMachineName')) {
                    $commonPayload.showAssignedMachineName = $ShowMachineName
                }

                $payloadJson = $commonPayload | ConvertTo-Json -Depth 10
                Write-Verbose "Final Payload JSON: $payloadJson"

               # Trigger API call with above constructed payload based on selection
                try {
                    $urlPoolGroup = "https://cloud.omnissahorizon.com/portal/v4/pools/$PoolGroupId" + "?" + "org_id=$OrgId&delete=false"
                    Write-Verbose "(Invoke-RestMethod -Uri $urlPoolGroup -Method PATCH -Headers $headers -Body $payloadJson -ErrorAction Stop)"
                    $dataPatchPoolGroup = Invoke-RestMethod -Uri $urlPoolGroup -Method PATCH -Headers $headers -Body $payloadJson -ErrorAction Stop
                    return $dataPatchPoolGroup
                }
                catch {
                    Write-Host -ForegroundColor Red -BackgroundColor Black "Set-HCSPoolGroup: Pool Group Creation Request for $PoolGroupName failed"
                    Write-Host -ForegroundColor Red ($_ | Out-String)
                    return
                }
            }
        }
        catch {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Set-HCSPoolGroup: PoolGroup Creation Request for $Name failed for JsonInput generation"
            Write-Host -ForegroundColor Red ($_ | Out-String)
            return
        }

    }
    
}

function Get-HCSCustomClientSubDomain {
    <#
    .SYNOPSIS
        Retrieves Identity provider details of a specific org
    .DESCRIPTION
        The Get-HCSCustomClientSubDomain cmdlet is utilized to retrieve information about the Customer Client Access Subdomain URL configured in next-gen . 
        When the Get-HCSCustomClientSubDomain cmdlet is used , information is retrieved based on the access token orgId

    .EXAMPLE
       Get-HCSCustomClientSubDomain
    #>

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/rx-service/v1/tenant/vanity"

    # Fetch images based on parameters
    try {
        return (Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop)
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSCustomClientSubDomain: Error retrieving Client Subdomain URL details, Please check the accessToken"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSCustomClientURL {
    <#
    .SYNOPSIS
        Retrieves Identity provider details of a specific org
    .DESCRIPTION
        The Get-HCSCustomClientURL cmdlet is utilized to retrieve information about the Custom Client  URL configured in next-gen . 
        When the Get-HCSCustomClientURL cmdlet is used , information is retrieved based on the access token orgId

    .EXAMPLE
       Get-HCSCustomClientURL
    #>

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/rx-service/v1/tenant/custom-domain"

    # Fetch images based on parameters
    try {
        return (Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop)
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSCustomClientURL: Error retrieving Custom Client URL details, Please check the accessToken"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSIdentityProvider {
    <#
    .SYNOPSIS
        Retrieves Identity provider details of a specific org
    .DESCRIPTION
        The Get-HCSIdentityProvider cmdlet is utilized to retrieve information about the Identity provider configured in next-gen . 
        When the Get-HCSIdentityProvider cmdlet is used with OrgID
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .EXAMPLE
        Get-HCSIdentityProvider -OrgId f9b98412-658b-45db-a06b-000000000000
    #>
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = 'OrgId')]
        [String]$OrgId
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/auth/v1/admin/org-idp-map?org_id=$OrgId"

    # Fetch images based on parameters
    try {
        return (Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop)
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSIdentityProvider: Error retrieving IDP details, Please check the OrgId"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSInternalNetworks {
    <#
    .SYNOPSIS
        Retrieves Identity provider details of a specific org
    .DESCRIPTION
        The Get-HCSInternalNetworks cmdlet is utilized to retrieve information about the  public IP address ranges of the networks your internal end users will connect from configured in next-gen . 
        When the Get-HCSInternalNetworks cmdlet is used with OrgID
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .EXAMPLE
        Get-HCSInternalNetworks -OrgId f9b98412-658b-45db-a06b-000000000000
    #>
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true, ParameterSetName = 'OrgId')]
        [String]$OrgId
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/auth/v1/admin/internal-networks?org_id=$OrgId"

    # Fetch images based on parameters
    try {
        $NetworkRangesInfo = Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop
        Write-Verbose "Network Ranges Infromation - $NetworkRangesInfo"
        $NetworkRanges = $NetworkRangesInfo.internalNetworks
        Write-Verbose "Only Internal Networks - $NetworkRanges"
        return $NetworkRanges
    }
    catch {
        Write-Host -ForegroundColor Red "Get-HCSInternalNetworks: Error retrieving Network range details for Internal Networks, Please check the OrgId"
        Write-Host $_.Exception.Message
    }
}

function Get-HCSUserDesktopMapping {
    <#
    .SYNOPSIS
        Retrieves User to desktop mapping details of a specific org or specific with poolId or poolGroupId
    .DESCRIPTION
        The Get-HCSUserDesktopMapping cmdlet is utilized to retrieve information about the User to desktop mapping details of a specific org or specific with poolId or poolGroupId in a nextgen Org . 
        When the Get-HCSIdentityProvider cmdlet is used with OrgID or "OrgID and poolid" or  "OrgID and poolGroupid"
    .PARAMETER OrgId
        Every organization in the next-gen has a long OrgId and a short OrgId. Kindly copy the long OrgId and input it into this parameter.
    .PARAMETER PoolId
        Enter the PoolId
    .PARAMETER PoolGroupId
        Enter the PoolGroupId
    .EXAMPLE
        Get-HCSUserDesktopMapping -OrgId f9b98412-658b-45db-a06b-000000000000
    #>
    [CmdletBinding(DefaultParameterSetName = 'OrgId')]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [String]$OrgId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolId,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [String]$PoolGroupId
    )

    $headers = @{
        'Authorization' = "Bearer $env:HCSAccessToken"
        'Accept' = "*/*"
    }

    # Check token validity
    $tokenExpiry = (Get-HCSAccessTokenValidity -Token $env:HCSAccessToken).expiryDateTime
    if ((Get-Date).AddMinutes(5) -gt $tokenExpiry) {
        Write-Host -ForegroundColor Yellow "Token expired - renew the token using Get-HCSAccessToken and run the command again"
        return
    }
    
    Write-Verbose "Token is valid"

    # Construct base URL
    $baseUrl = "https://cloud.omnissahorizon.com/portal/v1/userdesktopmapping?org_id=$OrgId"

    if($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolId') -and !$PSBoundParameters.ContainsKey('PoolGroupId')){
        $PoolIDMapURL = $baseUrl + "&" + "templateId=$PoolId"
        Write-Verbose "URL - $PoolIDMapURL"
        return (Invoke-RestMethod -Uri $PoolIDMapURL -Method Get -Headers $headers -ErrorAction Stop)
    }
    elseif ($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId') -and !$PSBoundParameters.ContainsKey('PoolId')) {
        $PoolGroupIDMapURL = $baseUrl + "&" + "poolId=$PoolGroupId"
        Write-Verbose "URL - $PoolGroupIDMapURL"
        return (Invoke-RestMethod -Uri $PoolGroupIDMapURL -Method Get -Headers $headers -ErrorAction Stop)
    }
    elseif($PSBoundParameters.ContainsKey('OrgId') -and !$PSBoundParameters.ContainsKey('PoolGroupId') -and !$PSBoundParameters.ContainsKey('PoolId')){
        Write-Verbose "URL - $baseUrl"
        return (Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers -ErrorAction Stop)
    }
    elseif($PSBoundParameters.ContainsKey('OrgId') -and $PSBoundParameters.ContainsKey('PoolGroupId') -and $PSBoundParameters.ContainsKey('PoolId')){
        Write-Host -ForegroundColor Yellow  "Get-HCSUserDesktopMapping: Please verify the parameters; only one of PoolId or PoolGroupId is allowed"
    }

}

# Export the function
Export-ModuleMember -Function Get-HCSUsers, Get-HCSGroups, Get-HCSUserGroups, Get-HCSGroupUsers
# Pool related
Export-ModuleMember -Function Get-HCSPoolGroup, Get-HCSPool, Get-HCSPoolVM, Remove-HCSVM, Remove-HCSPoolGroup, Remove-HCSPool, Get-HCSPublishedApps, New-HCSPoolGroup, New-HCSPool, Set-HCSPool, Set-HCSPoolGroup
# Edge related
Export-ModuleMember -Function Get-HCSEdge, Get-HCSUag, New-HCSEdge, New-HCSUAG
# ActiveDirectory related
Export-ModuleMember -Function Get-HCSAD
# Provider related
Export-ModuleMember -Function Get-HCSProvider, Get-HCSUserAssignedIdentities
# IDP Related
Export-ModuleMember -Function Get-HCSIdentityProvider
# User details
Export-ModuleMember -Function Get-HCSUsers, Get-HCSGroups, Get-HCSUserGroups, Get-HCSGroupUsers
# Token related
Export-ModuleMember -Function Get-HCSAccessToken, Get-HCSAccessTokenValidity
# Multiple pages data retrieval
Export-ModuleMember -Function Get-RetrieveByPage
# Entitlement related
Export-ModuleMember -Function Get-HCSEntitlements, New-HCSEntitlement, Remove-HCSEntitlement, Get-HCSUserDesktopMapping
# Inventory related -  Only available for Super Users
Export-ModuleMember -Function Get-HCSInv
# Individual VM related
Export-ModuleMember -Function Start-HCSVM, Stop-HCSVM, Restart-HCSVM, Remove-HCSVM
# Image related
Export-ModuleMember -Function Get-HCSImage, Get-HCSImageId, Get-HCSImageVersion, Get-HCSImageCopies, Get-HCSImageMarkers, New-HCSImageCopy, New-HCSImagePublish
# Azure Infra related
Export-ModuleMember -Function Get-HCSNetworks, Get-HCSSubnets, Get-HCSAzureVmSkus, Get-HCSAzureDiskSkus
# App Volmes
Export-ModuleMember -Function Get-HCSAvApps, Get-HCSAvAppVersions, Get-HCSAvAppShortcuts, Get-HCSAVEntitlement, Remove-HCSAVEntitlement, Get-HCSAVFileShares
# Activities related
Export-ModuleMember -Function Get-HCSUserActivity, Get-HCSAdminActivity
# Sessions related
Export-ModuleMember -Function Get-HCSSessionCount, Get-HCSSession
# License related 
Export-ModuleMember -Function Get-HCSLicenseConsumption
# Client Settings Related
Export-ModuleMember -Function Get-HCSCustomClientSubDomain, Get-HCSCustomClientURL, Get-HCSInternalNetworks
# Site related
Export-ModuleMember -Function Get-HCSSite, New-HCSSite, Set-HCSSite