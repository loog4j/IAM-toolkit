# API Key Rotation Reminder

## Overview
The API Key Rotation Reminder is a credential lifecycle management script that monitors API keys, certificates, and service principal credentials across Azure services. It provides automated expiration notifications and tracking to prevent service disruptions.

## Features
- **Multi-Service Monitoring**: Azure Key Vault, App Registrations, Service Principals
- **Expiration Tracking**: Configurable warning periods (30, 14, 7, 1 days)
- **Automated Notifications**: Email, Teams, and webhook alerts
- **Certificate Management**: X.509 certificate monitoring and validation
- **Compliance Reporting**: Detailed reports for audit and compliance
- **Integration Ready**: API endpoints for ITSM and automation platforms

## Prerequisites
- PowerShell 5.1 or PowerShell Core 7.x
- Microsoft Graph PowerShell SDK
- Azure PowerShell module
- Application Administrator or Global Administrator permissions

## Required Permissions
- Application.Read.All
- Directory.Read.All
- KeyVault Contributor (for Key Vault monitoring)

## Configuration
Edit the `API-Key-Rotation-Config.json` file to customize:
- Monitoring scope and services
- Warning thresholds and notification schedules
- Email and Teams webhook settings
- Exclusion lists for managed certificates

## Usage
```powershell
.\Invoke-APIKeyRotationReminder.ps1 -ConfigPath ".\API-Key-Rotation-Config.json"
```

## Automation
- Schedule as daily/weekly task
- Integrate with monitoring systems
- Connect to ITSM for ticket creation

## Security Considerations
- Protect configuration files with sensitive information
- Use managed identities where possible
- Implement proper access controls for Key Vault
