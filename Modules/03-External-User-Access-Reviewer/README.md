# External User Access Reviewer

## Overview
The External User Access Reviewer is a comprehensive PowerShell script that audits guest users and B2B collaboration in your Entra ID environment. It provides detailed analysis of external user access patterns, risk assessment, and automated remediation recommendations.

## Features
- **Guest User Inventory**: Complete audit of all external users in your tenant
- **Access Pattern Analysis**: Detailed review of permissions and group memberships
- **Risk Assessment**: Automated scoring based on access levels and activity
- **Compliance Checking**: Validation against B2B collaboration policies
- **Remediation Scripts**: Automated generation of cleanup scripts
- **Multi-format Reporting**: HTML, JSON, and CSV output options

## Prerequisites
- PowerShell 5.1 or PowerShell Core 7.x
- Microsoft Graph PowerShell SDK
- Entra ID Premium P1 or P2 license (for advanced features)
- Global Reader or Security Reader permissions minimum

## Required Permissions
- User.Read.All
- Group.Read.All
- Directory.Read.All
- AuditLog.Read.All
- IdentityRiskyUser.Read.All

## Configuration
Edit the `External-User-Review-Config.json` file to customize:
- Review scope and filters
- Risk scoring parameters
- Reporting preferences
- Notification settings

## Usage
```powershell
.\Review-ExternalUserAccess.ps1 -ConfigPath ".\External-User-Review-Config.json"
```

## Output
- Detailed HTML report with executive summary
- JSON data for integration with other tools
- CSV export for spreadsheet analysis
- Automated remediation scripts (when enabled)

## Security Considerations
- Review permissions carefully before granting
- Test in non-production environment first
- Validate remediation scripts before execution
- Monitor for false positives in risk scoring
