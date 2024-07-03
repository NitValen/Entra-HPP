# Entra-HPP
Detect and Report High-Priority Permissions in Entra ID Apps.

## Setup
Install AzureAD module:  
```
Install-Module AzureAD
```

## Usage
First import the PowerShell script:  
```
Import-Module .\EntraHPP.ps1
```
To obtain all applications with "Application" authorisation:
```
Get-HPP
```
To obtain applications owned by supplied users in Entra with "Application" authorisation:  
```
Get-Pwn -Users david@company.com
```
It is possible to filter the results according to the criticality associated with the permission and to export the results in CSV format.
```
# List all applications considered with critical risk and export results to results.csv file
Get-HPP -Risk Critical -FileName results.csv

# List all applications owned by david@company.com or pascal@company.com and considered with critical risk then export results to results.csv file
Get-Pwn -Users david@company.com,pascal@company.com -Risk Critical -FileName results.csv
```


