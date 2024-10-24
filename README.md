# Entra-HPP

## Description

Entra-HPP is a PowerShell tool developed to detect and report High-Priority Permissions in Entra ID Apps (formerly Azure AD). This script helps detect critical application permissions that could lead to privilege escalation (PrivEsc), thereby compromising the security of the entire tenant.

## Main Features

- **Get-HPP**
  - Lists all applications with application permissions in Entra ID.
  - Analyzes each associated permission and assigns a risk level based on potential security threats.

- **Get-Pwn**
  - Retrieves all applications owned by specified users using their email addresses.
  - Particularly useful for identifying potential compromise paths in the tenant by exploiting abusive application permissions, especially during a security audit.


## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/NitValen/Entra-HPP.git
    cd Entra-HPP
    ```

2. Import the PowerShell module:
    ```powershell
    Import-Module .\EntraHPP.ps1
    ```

## Usage

### Get-HPP

To list all applications and identify critical permissions:  

```powershell
Get-HPP -Risk Critical -FileName results.csv
```

This command will identify all applications with critical risk and export the results to a CSV file.

### Get-Pwn

To retrieve applications owned by a specific user:  

```powershell
Get-Pwn -Users user@example.com -Risk High -FileName owner_results.csv
```

This command will identify all high-risk applications owned by user@example.com and export the results to a CSV file.

## Contribution

Contributions are welcome! If you have suggestions or improvements, feel free to submit a pull request.
