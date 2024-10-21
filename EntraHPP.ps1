Write-Host -ForegroundColor Blue @"
          ______        __                  __  __ ____   ____
        / ____/____   / /_ _____ ____ _   / / / // __ \ / __ \
      / __/  / __ \ / __// ___// __ `/  / /_/ // /_/ // /_/ /
     / /___ / / / // /_ / /   / /_/ /  / __  // ____// ____/
    /_____//_/ /_/ \__//_/    \__,_/  /_/ /_//_/    /_/

  Detect and Report High-Priority Permissions in Entra ID Apps

  To start, run Import-Module .\EntraHPP.ps1
  To list EntraHPP functions, run List-EntraHPPFunctions
"@


#Define level of risks
$CriticalValues = @(
    "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "Policy.ReadWrite.PermissionGrant",
    "RoleManagement.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
    "RoleManagementPolicy.ReadWrite.Directory",
    "RoleManagementPolicy.ReadWrite.AzureADGroup",
    "Group.ReadWrite.All"
)


$HighValues = @(
    "User.Read.All",
    "User.ReadWrite.All",
    "Files.ReadWrite.All",
    "Calendars.ReadWrite",
    "Mail.Send",
    "User.Export.All",
    "Directory.Read.All",
    "Exchange.ManageAsApp",
    "Sites.ReadWrite.All",
    "full_access_as_app",
    ".ReadWrite.All",
    "Tenant."
)


$MediumValues = @(
    ".All",
    ".ReadWrite.",
    "Mail",
    ".Read.",
    "Calendars"
)


function ConnectToAzureAD {
    [Parameter(Position = 0, Mandatory = $False)]
    [String]$AzureEnv

    [boolean]$isConnectedToAzureAD = $false

    echo "Connecting to Microsoft services:"

    # Check for AzureAD module
    Write-Host -NoNewline "`t`t`tChecking for AzureAD Module "
    if (Get-Module -ListAvailable -Name AzureAD) {
        Write-Host "`t`t`tDONE"
    } else {
        Write-Host "`t`tFAILED"
        Write-Host "`tInstalling the AzureAD Module..."
        Install-Module AzureAD -Force -ErrorAction Stop
        Write-Host "`tAzureAD Module installed successfully"
    }

    # Connect to AzureAD based on environment
    if ($AzureEnv -eq "China") {
        try {
            Write-Host -NoNewline "`t`t`tConnecting to Entra with Connect-AzureAD"
            Connect-AzureAD -AzureEnvironmentName AzureChinaCloud > $null
            $isConnectedToAzureAD = $true
            Write-Host "`tDONE"
        } catch {
            Write-Host "Could not connect to Entra."
            throw $_
        }
    } else {
        try {
            Write-Host -NoNewline "`t`t`tConnecting to Entra with Connect-AzureAD"
            Connect-AzureAD > $null
            $isConnectedToAzureAD = $true
            Write-Host "`tDONE"
        } catch {
            Write-Host "Could not connect to Entra."
            throw $_
        }
    }
    
    # Return connection status
    return $isConnectedToAzureAD
}




function Get-EntraApp {
    Write-Host -NoNewline "`t`t`tRetrieving dangerous Entra Applications "
    
    try {
        # Récupération des applications intégrées avec Azure AD
        $entra_apps = Get-AzureADServicePrincipal -All:$true | Where-Object { $_.Tags -eq "WindowsAzureActiveDirectoryIntegratedApp" } | Select-Object ObjectId, AppDisplayName, AppId
        Write-Host "`tDONE"
    } catch {
        Write-Host "`tFAILED`n`tError recovering Entra applications."
        throw $_
    }
    
    return $entra_apps
}



function Get-EntraAppOwners {
    param (
        [string]$EntraAppName,
        [string]$User
    )

    try {
        # Récupération de l'application Entra par son nom
        $entraApp = Get-AzureADApplication -Filter "DisplayName eq '$($EntraAppName)'"
        
        if ($entraApp.ObjectId) {
            # Récupération des propriétaires de l'application
            $entraAppOwners = Get-AzureADApplicationOwner -ObjectId $entraApp.ObjectId
            
            if ($entraAppOwners.UserPrincipalName) {
                if ($entraAppOwners.UserPrincipalName -like $User) {
                    $entraAppOwnersName = $entraAppOwners.UserPrincipalName + " (Pwn!)"
                } else {
                    $entraAppOwnersName = $entraAppOwners.UserPrincipalName
                }
                return $entraAppOwnersName
            } else {
                return "NA"
            }
        } else {
            return "NA"
        }
    } catch {
        Write-Host "Error occurred: $_"
        return "NA"
    }
}


function Get-HPP {
    <#
    .SYNOPSIS
      Get-HPP detects and reports High-Priority Permissions in Entra ID Apps.
      
    .DESCRIPTION
      Get-HPP is used to obtain all applications with "Application" authorization. A risk level is assigned to each authorization.
      
    .PARAMETER Risk
      Allows applications to be filtered according to the risk assigned to authorizations (Critical, High, Medium). By default, all applications are listed.
      
    .PARAMETER FileName
      If specified, saves results in CSV format.
    
    .EXAMPLE
      C:\PS> Get-HPP
        This command will list all applications considered to be potentially dangerous.
    
      C:\PS> Get-HPP -Risk Critical -FileName results.csv
        This command will list all applications considered with critical risk and will export results to results.csv file.
    #>

    param(
        [Parameter(Position = 0, Mandatory=$False)]
        [ValidateSet("Critical", "High", "Medium", "To Check", "All")]
        [String[]]$Risk="All",

        [Parameter(Position = 1, Mandatory=$False)]
        [String]$FileName,

        [Parameter(Position = 2, Mandatory=$False)]
        [String]$AzureEnv
    )

    # Connect to Azure
    if ($AzureEnv -eq "China") {
        ConnectToAzureAD -AzureEnv $AzureEnv
    } else {
        ConnectToAzureAD
    }

    # Get email of current user
    $CurrentUser = (Get-AzureADCurrentSessionInfo).Account.Id

    # Get all Application Permissions granted to an application
    echo "Checking Applications in Entra:"
    $entra_apps = Get-EntraApp

    # Consolidation of results
    Write-Host -NoNewline "`t`t`tPreparing results "

    # Init CSV File if needed
    if ($FileName) {
        echo "Risk;Id;Display Name;Owner;Permission;Role;Description" | Out-File -FilePath .\$FileName
    }

    foreach ($app in $entra_apps) {
        # Variables
        $EntraAppPrincipalId = $app.ObjectId
        $EntraAppName = $app.AppDisplayName
        $AppPermissions = @()
        $AppInfos = @()
        $ResourceAppHash = @{}
        $ServicePrincipalId = $EntraAppPrincipalId

        # Get Role Assignments for the Service Principal
        $AppRoleAssignments = Get-AzureADServiceAppRoleAssignedTo -ObjectId $ServicePrincipalId
        
        if ($AppRoleAssignments) {
            $owner = Get-EntraAppOwners -EntraAppName $EntraAppName -User "$($CurrentUser)"
            $AppPermissions += [PSCustomObject]@{
                Application = $EntraAppName
                Owner = $owner
            }

            foreach ($RoleAssignment in $AppRoleAssignments) {
                # Cache roles to minimize queries
                $AppRoles = if ($ResourceAppHash.ContainsKey($RoleAssignment.ResourceId)) {
                    $ResourceAppHash[$RoleAssignment.ResourceId]
                } else {
                    $AppRoles = (Get-AzureADServicePrincipal -ObjectId $RoleAssignment.ResourceId).AppRoles
                    $ResourceAppHash[$RoleAssignment.ResourceId] = $AppRoles
                    $AppRoles
                }

                # Identify applied role and its risk level
                $AppliedRole = $AppRoles | Where-Object { $_.Id -eq $RoleAssignment.Id }
                if ($AppliedRole.IsEnabled) {
                    $RiskLevel = if ($AppliedRole.Value -match [string]::Join('|', $CriticalValues)) {
                        "Critical"
                    } elseif ($AppliedRole.Value -match [string]::Join('|', $HighValues)) {
                        "High"
                    } elseif ($AppliedRole.Value -match [string]::Join('|', $MediumValues)) {
                        "Medium"
                    } else {
                        "To Check"
                    }

                    $AppPermissions += [PSCustomObject]@{
                        DisplayName = $AppliedRole.DisplayName
                        Description = $AppliedRole.Description
                        Roles = $AppliedRole.Value
                        ResourceName = $RoleAssignment.ResourceDisplayName
                        Risk = $RiskLevel
                    }

                    if ($FileName) {
                        echo "$($RiskLevel);$($EntraAppPrincipalId);$($EntraAppName);$($owner);$($AppliedRole.DisplayName);$($AppliedRole.Value);$($AppliedRole.Description)" | Out-File -FilePath .\$FileName -Append
                    }
                }
            }
        }

        if ($Risk -eq "All") {
            $AppPermissions | Format-List
        } else {
            if ($AppPermissions | Where-Object { $_.Risk -eq $Risk }) {
                $AppPermissions | Format-List
            }
        }
    }

    if ($FileName) {
        echo "File created"
        Get-ChildItem -Path .\$FileName
    }

    Disconnect-AzureAD > $null
}


function Get-Pwn {
    <#
    .SYNOPSIS
      Get-Pwn is used to obtain applications owned by supplied users in Entra with "Application" authorization. A risk level is assigned to each authorization.

    .DESCRIPTION
      Get-Pwn is used to obtain applications owned by supplied users in Entra with "Application" authorization. A risk level is assigned to each authorization.

    .PARAMETER Users
      Email address of one or more Tenant users. Email addresses are separated by commas.

    .PARAMETER Risk
      Allows applications to be filtered according to the risk assigned to authorizations (Critical, High, Medium). By default, all applications are listed.

    .PARAMETER FileName
      If specified, saves results in CSV format.

    .EXAMPLE
      C:\PS> Get-Pwn -Users david@company.com
        This command will list all applications owned by user david@company.com and considered to be potentially dangerous.

      C:\PS> Get-Pwn -Users david@company.com,pascal@company.com -Risk Critical -FileName results.csv
        This command will list all applications owned by david@company.com or pascal@company.com and considered with critical risk then will export results to results.csv file.
    #>

    param(
        [Parameter(Position = 0, Mandatory=$True)]
        [String[]]$Users,

        [Parameter(Position = 1, Mandatory=$False)]
        [ValidateSet("Critical", "High", "Medium", "To Check", "All")]
        [String[]]$Risk="All",

        [Parameter(Position = 2, Mandatory=$False)]
        [String]$FileName
    )

    # Connect to Azure
    ConnectToAzureAD

    # Get all Application Permissions granted to an application
    echo "Checking Applications in Entra:"
    $entra_apps = Get-EntraApp

    # Consolidation of results
    Write-Host -NoNewline "`t`t`tPreparing results "

    # Init CSV File if needed
    if ($FileName) {
        echo "Risk;Id;Display Name;Owner;Permission;Role;Description" | Out-File -FilePath .\$FileName
    }

    foreach ($app in $entra_apps) {
        # Variables
        $EntraAppPrincipalId = $app.ObjectId
        $EntraAppName = $app.AppDisplayName
        $Pwn = $False
        $AppPermissions = @()
        $ResourceAppHash = @{}
        $ServicePrincipalId = $EntraAppPrincipalId

        # Check each user for ownership
        foreach ($User in $Users) {
            $owner = Get-EntraAppOwners -EntraAppName $EntraAppName -User "$($User)"
            if ($owner -like "*(Pwn!)") {
                $Pwn = $True
                break
            }
        }

        # If owned by any of the supplied users
        if ($Pwn) {
            $AppRoleAssignments = Get-AzureADServiceAppRoleAssignedTo -ObjectId $ServicePrincipalId

            if ($AppRoleAssignments) {
                $AppPermissions += [PSCustomObject]@{
                    Application = $EntraAppName
                    Owner = $owner
                }
            }

            foreach ($RoleAssignment in $AppRoleAssignments) {
                # Cache roles to minimize queries
                $AppRoles = if ($ResourceAppHash.ContainsKey($RoleAssignment.ResourceId)) {
                    $ResourceAppHash[$RoleAssignment.ResourceId]
                } else {
                    $AppRoles = (Get-AzureADServicePrincipal -ObjectId $RoleAssignment.ResourceId).AppRoles
                    $ResourceAppHash[$RoleAssignment.ResourceId] = $AppRoles
                    $AppRoles
                }

                # Identify applied role and its risk level
                $AppliedRole = $AppRoles | Where-Object { $_.Id -eq $RoleAssignment.Id }
                if ($AppliedRole.IsEnabled) {
                    $RiskLevel = if ($AppliedRole.Value -match [string]::Join('|', $CriticalValues)) {
                        "Critical"
                    } elseif ($AppliedRole.Value -match [string]::Join('|', $HighValues)) {
                        "High"
                    } elseif ($AppliedRole.Value -match [string]::Join('|', $MediumValues)) {
                        "Medium"
                    } else {
                        "To Check"
                    }

                    $AppPermissions += [PSCustomObject]@{
                        DisplayName = $AppliedRole.DisplayName
                        Description = $AppliedRole.Description
                        Roles = $AppliedRole.Value
                        ResourceName = $RoleAssignment.ResourceDisplayName
                        Risk = $RiskLevel
                    }

                    if ($FileName) {
                        echo "$($RiskLevel);$($EntraAppPrincipalId);$($EntraAppName);$($owner);$($AppliedRole.DisplayName);$($AppliedRole.Value);$($AppliedRole.Description)" | Out-File -FilePath .\$FileName -Append
                    }
                }
            }

            if ($Risk -eq "All") {
                $AppPermissions | Format-List
            } else {
                if ($AppPermissions | Where-Object { $_.Risk -eq $Risk }) {
                    $AppPermissions | Format-List
                }
            }
        }
    }

    if ($FileName) {
        echo "File created"
        Get-ChildItem -Path .\$FileName
    }

    Disconnect-AzureAD > $null
}



function List-EntraHPPFunctions {
    <#
    .SYNOPSIS
      A module to list all of the EntraHPP functions.
    #>

    Write-Host -ForegroundColor Blue "[*] Listing EntraHPP functions..."
    
    Write-Host -ForegroundColor Blue "-------------------- Get-HPP --------------------"
    Write-Host -ForegroundColor Blue "`t- DESCRIPTION"
    Write-Host -ForegroundColor Blue "  Get-HPP is used to obtain all applications with 'Application' authorization. A risk level is assigned to each authorization."

    Write-Host -ForegroundColor Blue "-------------------- Get-Pwn --------------------"
    Write-Host -ForegroundColor Blue "`t- DESCRIPTION"
    Write-Host -ForegroundColor Blue "  Get-Pwn is used to obtain applications owned by supplied users in Entra with 'Application' authorization. A risk level is assigned to each authorization."
}
