Write-Host -ForegroundColor blue "
  
        ______        __                  __  __ ____   ____ 
       / ____/____   / /_ _____ ____ _   / / / // __ \ / __ \
      / __/  / __ \ / __// ___// __ `/  / /_/ // /_/ // /_/ /
     / /___ / / / // /_ / /   / /_/ /  / __  // ____// ____/ 
    /_____//_/ /_/ \__//_/    \__,_/  /_/ /_//_/    /_/                                                               

    Detect and Report High-Priority Permissions in Entra ID Apps


To start, run Import-Module .\EntraHPP.ps1
                       
To list EntraHPP functions run List-EntraHPPFunctions
"

#Define level of risks
$CriticalValues = @("Directory.ReadWrite.All", "Group.ReadWrite.All", "Tenant.")
$HighValues = @("User.Read.All", "User.ReadWrite.All", "Files.ReadWrite.All", "Calendars.ReadWrite", "Mail.Send", "User.Export.All", "Directory.Read.All", "Exchange.ManageAsApp", "Sites.ReadWrite.All", "full_access_as_app", ".ReadWrite.All")
$MediumValues = @(".All",".ReadWrite.", "Mail",".Read.","Calendars")


function ConnectToAzureAD{
    [boolean]$connectedToAzureAD = $false
    
    echo "Connecting to Microsoft services:"   

    Write-Host -NoNewline "`t`t`tChecking for AzureAD Module "

    if (Get-Module -ListAvailable -Name AzureAD) {
        Write-Host "`t`t`tDONE"
    }else{
        Write-Host "`t`tFAILED"
        Write-Host "`tPlease install the AzureAD Module:`n`t`tInstall-Module AzureAD"
        exit
    }

    try {
        Write-Host -NoNewline "`t`t`tConnecting to Entra with Connect-AzureAD"
        Connect-AzureAD > $null
        $connectedToAzureAD = $true
        Write-Host "`tDONE"
    }catch{
        Write-Host "Could not connect to Entra."
        throw $_
        exit
    }
}



function Get-EntraApp{
    Write-Host -NoNewline "`t`t`tRetrieving dangerous Entra Applications "
    $entra_apps = Get-AzureADServicePrincipal -All:$true |?{$_.Tags -eq "WindowsAzureActiveDirectoryIntegratedApp"} | Select-Object ObjectId,AppDisplayName,AppId
    Write-Host "`tDONE"
    return $entra_apps
}


function Get-EntraAppOwners{
    param ($EntraAppName, $User)
    try {
        $entra_app = Get-AzureADApplication -Filter "DisplayName eq '$($EntraAppName)'"
        if($entra_app.ObjectId){
            $entra_app_owners = Get-AzureADApplicationOwner -ObjectId $entra_app.ObjectId
       
            if($entra_app_owners.UserPrincipalName){
                if($entra_app_owners.UserPrincipalName -like $User){
                    $entra_app_owners_name = $entra_app_owners.UserPrincipalName + " (Pwn!)"
                } else {
                    $entra_app_owners_name = $entra_app_owners.UserPrincipalName
                }
                return $entra_app_owners_name
            } else {
                return "NA"
            }
            
        } else{
            return "NA"
        }
    } catch {
        return "NA"
    }
}

Function Get-HPP{

    <#
    .SYNOPSIS
      Get-HPP detects and reports High-Priority Permissions in Entra ID Apps.
      Author: Valentin GUICHON (@NitValen)
      Required Dependencies: AzureAD
      Optional Dependencies: None

    .DESCRIPTION
        
       Get-HPP is used to obtain all applications with "Application" authorisation. A risk level is assigned to each authorisation.
    
    .PARAMETER Risk
        
        Allows applications to be filtered according to the risk assigned to authorisations (Critical, High, Medium). By default, all applications are listed.
    
    .PARAMETER FileName
        
        If specified, saves results in CSV format.

    .EXAMPLE
        
        C:\PS> Get-HPP
        Description
        -----------
        This command will list all applications considered to be potentially dangerous.

        C:\PS> Get-HPP -Risk Critical -FileName results.csv
        Description
        -----------
        This command will list all applications considered with critical risk and will export results to results csv file.
     #>

    param(
    [Parameter(Position = 0,Mandatory=$False)]
    [ValidateSet("Critical", "High", "Medium", "To Check", "All")]
    [String[]]$Risk="All",
    [Parameter(Position = 1,Mandatory=$False)]
    [String]$FileName    
    )


    #Connect to Azure
    ConnectToAzureAD

    #Get email of current user
    $CurrentUser = Get-AzureADCurrentSessionInfo
    $CurrentUser = $CurrentUser.Account.Id

    #Get all Application Permissions granted to an application 
    echo "Checking Applications in Entra:"  
    $entra_apps = Get-EntraApp

    #Consolidation of results
    Write-Host -NoNewline "`t`t`tPreparing results "

    #Init CSV File if needed
    if($FileName){
        echo "Risk;Id;Display Name;Owner;Permission;Description" | Out-File -FilePath .\$FileName
    }

    ForEach($app in $entra_apps){

        #Variables
        $EntraAppPrincipalId = $app.ObjectId
        $EntraAppName = $app.AppDisplayName

        $AppPermissions =@()
        $AppInfos =@()

        $ResourceAppHash = @{}
        $ServicePrincipalId = $EntraAppPrincipalId
        $AppRoleAssignments = Get-AzureADServiceAppRoleAssignedTo -ObjectId $ServicePrincipalId


        if($AppRoleAssignments){

            $owner = Get-EntraAppOwners -EntraAppName $EntraAppName -User "$($CurrentUser)"

            $AppPermissions += New-Object PSObject -property @{
                Application = $EntraAppName
                Owner = $owner
            }    
        }

        $AppRoleAssignments | ForEach-Object {
            $RoleAssignment = $_
            $AppRoles = {}
            If ($ResourceAppHash.ContainsKey($RoleAssignment.ResourceId)) {
                $AppRoles = $ResourceAppHash[$RoleAssignment.ResourceId]
            } Else {
                $AppRoles = (Get-AzureADServicePrincipal -ObjectId $RoleAssignment.ResourceId).AppRoles
                $ResourceAppHash[$RoleAssignment.ResourceId] = $AppRoles
            }
            $AppliedRole = $AppRoles | Where-Object {$_.Id -eq $RoleAssignment.Id}
            if($AppliedRole.IsEnabled){
                if($AppliedRole.Value -match [string]::Join('|',$CriticalValues)){
                    $RiskLevel = "Critical"
                }elseif ($AppliedRole.Value -match [string]::Join('|',$HighValues)){
                    $RiskLevel = "High"
                }elseif ($AppliedRole.Value -match [string]::Join('|',$MediumValues)){
                    $RiskLevel = "Medium"
                }else{
                    $RiskLevel = "To Check"
                }
                $AppPermissions += New-Object PSObject -property @{
                    DisplayName = $AppliedRole.DisplayName
                    Description = $AppliedRole.Description
                    Roles = $AppliedRole.Value
                    #IsEnabled = $AppliedRole.IsEnabled
                    ResourceName = $RoleAssignment.ResourceDisplayName
                    Risk = $RiskLevel
                } 
                if($FileName){
                    echo "$($RiskLevel);$($EntraAppPrincipalId);$($EntraAppName);$($owner);$($AppliedRole.DisplayName);$($AppliedRole.Description)" | Out-File -FilePath .\$FileName -Append
                }
            }
        }
        if($Risk -eq "All"){
            $AppPermissions | FL 
        } else {
            if ($AppPermissions | Where-Object {$_.Risk -eq $Risk}) {
                $AppPermissions | FL 
            }
        }
    }

    if($FileName){
        echo "File created"
        ls .\${CURRENTJOB}\$($FileName)
    }

    Disconnect-AzureAD > $null

}

Function Get-Pwn{
        <#
    .SYNOPSIS
      Get-Pwn is used to obtain applications owned by supplied users in Entra with "Application" authorisation. A risk level is assigned to each authorisation.
      Author: Valentin GUICHON (@NitValen)
      Required Dependencies: AzureAD
      Optional Dependencies: None

    .DESCRIPTION
        
       Get-Pwn is used to obtain applications owned by supplied users in Entra with "Application" authorisation. A risk level is assigned to each authorisation.

    .PARAMETER Users
        Email address of one or more Tenant users. Email addresses are separated by commas.
    
    .PARAMETER Risk
        
        Allows applications to be filtered according to the risk assigned to authorisations (Critical, High, Medium). By default, all applications are listed.
    
    .PARAMETER FileName
        
        If specified, saves results in CSV format.

    .EXAMPLE
        
        C:\PS> Get-HPP -Users david@company.com
        Description
        -----------
        This command will list all applications owned by user david@company.com and considered to be potentially dangerous.

        C:\PS> Get-HPP -Users david@company.com,pascal@company.com -Risk Critical -FileName results.csv
        Description
        -----------
        This command will list all applications owned by david@company.com or pascal@company.com and considered with critical risk then will export results to results csv file.
     #>

    param(
    [Parameter(Position = 0,Mandatory=$True)]
    [String[]]$Users,
    [Parameter(Position = 1,Mandatory=$False)]
    [ValidateSet("Critical", "High", "Medium", "To Check", "All")]
    [String[]]$Risk="All",
    [Parameter(Position = 2,Mandatory=$False)]
    [String]$FileName    
    )


    #Connect to Azure
    ConnectToAzureAD

    #Get all Application Permissions granted to an application 
    echo "Checking Applications in Entra:"  
    $entra_apps = Get-EntraApp

    #Consolidation of results
    Write-Host -NoNewline "`t`t`tPreparing results "
    
    #Init CSV File if needed
    if($FileName){
        echo "Risk;Id;Display Name;Owner;Permission;Description" | Out-File -FilePath .\$FileName
    }

    ForEach($app in $entra_apps){

        #Variables
        $EntraAppPrincipalId = $app.ObjectId
        $EntraAppName = $app.AppDisplayName
        $Pwn = $False

        $AppPermissions =@()
        $AppInfos =@()

        $ResourceAppHash = @{}
        $ServicePrincipalId = $EntraAppPrincipalId
        $AppRoleAssignments = Get-AzureADServiceAppRoleAssignedTo -ObjectId $ServicePrincipalId

        foreach($User in $Users){
            $owner = Get-EntraAppOwners -EntraAppName $EntraAppName -User "$($User)"
            if($owner -like "*(Pwn!)"){
                $Pwn = $True
                break
            }
        }

        if($Pwn){
            if($AppRoleAssignments){

                $AppPermissions += New-Object PSObject -property @{
                    Application = $EntraAppName
                    Owner = $owner
                }    
            }

            $AppRoleAssignments | ForEach-Object {
                $RoleAssignment = $_
                $AppRoles = {}
                If ($ResourceAppHash.ContainsKey($RoleAssignment.ResourceId)) {
                    $AppRoles = $ResourceAppHash[$RoleAssignment.ResourceId]
                } Else {
                    $AppRoles = (Get-AzureADServicePrincipal -ObjectId $RoleAssignment.ResourceId).AppRoles
                    $ResourceAppHash[$RoleAssignment.ResourceId] = $AppRoles
                }
                $AppliedRole = $AppRoles | Where-Object {$_.Id -eq $RoleAssignment.Id}
                if($AppliedRole.IsEnabled){
                    if($AppliedRole.Value -match [string]::Join('|',$CriticalValues)){
                        $RiskLevel = "Critical"
                    }elseif ($AppliedRole.Value -match [string]::Join('|',$HighValues)){
                        $RiskLevel = "High"
                    }elseif ($AppliedRole.Value -match [string]::Join('|',$MediumValues)){
                        $RiskLevel = "Medium"
                    }else{
                        $RiskLevel = "To Check"
                    }
                    $AppPermissions += New-Object PSObject -property @{
                        DisplayName = $AppliedRole.DisplayName
                        Description = $AppliedRole.Description
                        Roles = $AppliedRole.Value
                        #IsEnabled = $AppliedRole.IsEnabled
                        ResourceName = $RoleAssignment.ResourceDisplayName
                        Risk = $RiskLevel
                    } 
                    if($FileName){
                        echo "$($RiskLevel);$($EntraAppPrincipalId);$($EntraAppName);$($owner);$($AppliedRole.DisplayName);$($AppliedRole.Description)" | Out-File -FilePath .\$FileName -Append
                    }
                }
            }
            if($Risk -eq "All"){
                $AppPermissions | FL 
            } else {
                if ($AppPermissions | Where-Object {$_.Risk -eq $Risk}) {
                    $AppPermissions | FL 
                }
            }
        }
    }

    if($FileName){
        echo "File created"
        ls .\${CURRENTJOB}\$($FileName)
    }

    Disconnect-AzureAD > $null
}


function List-EntraHPPFunctions{
    <#
    .SYNOPSIS 
    A module to list all of the EntraHPP functions
    #>

    Write-Host -foregroundcolor blue "[*] Listing EntraHPP functions..."

    Write-Host -ForegroundColor blue "-------------------- Get-HPP -------------------"
    Write-Host -ForegroundColor blue "`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor blue "Get-HPP is used to obtain all applications with 'Application' authorisation. A risk level is assigned to each authorisation."
    Write-Host -ForegroundColor blue "----------------- Get-HPP -----------------"
    Write-Host -ForegroundColor blue "`t`t`t-`t DESCRIPTION"
    Write-Host -ForegroundColor blue "Get-Pwn is used to obtain applications owned by supplied users in Entra with 'Application' authorisation. A risk level is assigned to each authorisation."
}