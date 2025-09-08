# Risky User Remediator

## Overview
The Risky User Remediator is an automated security response script that integrates with Microsoft Identity Protection to detect and remediate compromised user accounts. It provides tiered response actions based on risk levels and includes manual approval workflows for critical incidents.

## Features
- **Identity Protection Integration**: Direct integration with Microsoft Identity Protection APIs
- **Automated Risk Detection**: Real-time monitoring of user risk events
- **Tiered Response Actions**: Escalating remediation based on risk severity
- **Manual Approval Workflows**: Human oversight for critical security incidents
- **Comprehensive Logging**: Detailed audit trail of all remediation actions
- **Notification System**: Automated alerts to security teams

## Prerequisites
- PowerShell 5.1 or PowerShell Core 7.x
- Microsoft Graph PowerShell SDK
- Entra ID Premium P2 license (required for Identity Protection)
- Security Administrator or Global Administrator permissions

## Required Permissions
- IdentityRiskyUser.ReadWrite.All
- IdentityRiskEvent.Read.All
- User.ReadWrite.All
- Directory.ReadWrite.All
- Policy.ReadWrite.ConditionalAccess

## Risk Response Tiers
1. **Low Risk**: Password reset notification, monitoring increase
2. **Medium Risk**: Force password reset, revoke refresh tokens
3. **High Risk**: Block sign-in, disable account, notify security team
4. **Critical Risk**: Immediate account lockdown, manual approval required

## Configuration
Edit the `Risky-User-Remediation-Config.json` file to customize:
- Risk thresholds and response actions
- Approval workflows and escalation paths
- Notification recipients and methods
- Exclusion lists for privileged accounts

## Usage
```powershell
.\Invoke-RiskyUserRemediation.ps1 -ConfigPath ".\Risky-User-Remediation-Config.json"
```

## Automation Options
- Schedule as a recurring task for continuous monitoring
- Integrate with SIEM/SOAR platforms via API
- Configure webhook triggers for real-time response

## Security Considerations
- Test thoroughly in non-production environment
- Implement proper approval workflows for high-risk actions
- Monitor for false positives and adjust thresholds accordingly
- Ensure proper backup and recovery procedures
