# Entra ID App Consent Auditor

## Overview

The Entra ID App Consent Auditor is a comprehensive PowerShell script that performs security analysis of all application registrations and enterprise applications in your Entra ID tenant. It identifies high-risk permissions, suspicious consent grants, unverified publishers, and potential "shadow IT" integrations to help security teams maintain visibility and control over third-party application access.

## Features

### 🔍 **Comprehensive Application Analysis**
- Scans all app registrations and enterprise applications
- Analyzes both delegated and application permissions
- Identifies high-risk and medium-risk permission grants
- Tracks application usage patterns and last sign-in data

### 🚨 **Risk Assessment Engine**
- Calculates risk scores (1-10) based on multiple factors
- Categorizes applications by risk level (Critical, High, Medium, Low, Minimal)
- Identifies suspicious patterns in application names and descriptions
- Flags unverified publishers and external tenant applications

### 📊 **Multi-Format Reporting**
- **HTML Reports**: Executive-ready dashboards with visual risk indicators
- **JSON Reports**: Detailed technical data for automation and integration
- **CSV Reports**: Spreadsheet-compatible format for analysis and filtering

### 🎯 **Security Intelligence**
- Publisher verification status analysis
- User vs. admin consent tracking
- Orphaned application detection
- Multi-tenant application identification
- Usage analytics and inactive application detection

## Prerequisites

### Required PowerShell Modules
```powershell
Install-Module Microsoft.Graph.Authentication -Force
Install-Module Microsoft.Graph.Applications -Force
Install-Module Microsoft.Graph.DirectoryObjects -Force
Install-Module Microsoft.Graph.Reports -Force
```

### Required Permissions
The script requires the following Microsoft Graph permissions:
- `Application.Read.All` - Read application registrations and service principals
- `Directory.Read.All` - Read directory objects and tenant information
- `AuditLog.Read.All` - Read sign-in logs for usage analysis (optional)

### Entra ID Requirements
- Entra ID Premium license (recommended for full feature access)
- Global Reader or Application Administrator role
- PowerShell 5.1 or later

## Quick Start

### Basic Usage
```powershell
# Run with default settings
.\Export-EntraIDAppConsent.ps1

# Generate HTML report only for high-risk applications
.\Export-EntraIDAppConsent.ps1 -RiskThreshold 8 -ExportFormat "HTML"

# Run for specific tenant with custom output path
.\Export-EntraIDAppConsent.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\Reports"
```

### Advanced Usage
```powershell
# Include Microsoft system applications in analysis
.\Export-EntraIDAppConsent.ps1 -IncludeSystemApps -Detailed

# Generate all report formats with detailed analysis
.\Export-EntraIDAppConsent.ps1 -ExportFormat "ALL" -Detailed -RiskThreshold 5
```

## Configuration

### Configuration File: `App-Consent-Audit-Config.json`

The script uses a JSON configuration file to define risk assessment criteria, thresholds, and reporting options:

```json
{
  "HighRiskPermissions": [
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "Mail.ReadWrite.All",
    "Files.ReadWrite.All",
    "User.ReadWrite.All",
    "Application.ReadWrite.All"
  ],
  "AlertThresholds": {
    "MaxHighRiskPermissions": 3,
    "DaysUnusedThreshold": 90,
    "MinRiskScoreForAlert": 7
  },
  "RiskScoring": {
    "HighRiskPermissionWeight": 10,
    "UnverifiedPublisherWeight": 3,
    "ExternalTenantWeight": 2
  }
}
```

### Key Configuration Sections

#### **High-Risk Permissions**
Permissions that significantly increase an application's risk score:
- `Directory.ReadWrite.All` - Full directory write access
- `Application.ReadWrite.All` - Manage all applications
- `RoleManagement.ReadWrite.Directory` - Manage directory roles
- `Mail.ReadWrite.All` - Access all mailboxes

#### **Risk Scoring Weights**
- **High-Risk Permissions**: 10 points each
- **Medium-Risk Permissions**: 5 points each
- **Unverified Publisher**: 3 points
- **External Tenant**: 2 points
- **User Consent Enabled**: 2 points

#### **Alert Thresholds**
- **Minimum Risk Score**: 7 (triggers security alerts)
- **Unused Application**: 90 days without sign-in
- **Maximum High-Risk Permissions**: 3 per application

## Understanding Risk Levels

### 🔴 **Critical (8-10 points)**
- Multiple high-risk permissions
- Unverified publisher with dangerous permissions
- Suspicious patterns in application metadata

### 🟠 **High (6-7 points)**
- Several high-risk permissions
- External tenant applications with significant access
- Unverified publishers with medium-risk permissions

### 🟡 **Medium (4-5 points)**
- Some high-risk or many medium-risk permissions
- Applications with user consent enabled
- Moderate security concerns

### 🟢 **Low (2-3 points)**
- Few medium-risk permissions
- Minor security considerations
- Generally acceptable risk level

### ⚪ **Minimal (0-1 points)**
- Basic permissions only
- Verified publishers
- Low security impact

## Report Formats

### HTML Dashboard Report
- **Executive Summary**: High-level metrics and key findings
- **Risk Distribution**: Visual breakdown of applications by risk level
- **Detailed Application Table**: Sortable list with risk indicators
- **Recommended Actions**: Prioritized security recommendations

### JSON Technical Report
```json
{
  "ReportMetadata": {
    "GeneratedDateTime": "2024-01-15T10:30:00Z",
    "TotalApplicationsAnalyzed": 156,
    "HighRiskApplications": 8
  },
  "ExecutiveSummary": {
    "TotalApplications": 156,
    "HighRiskApplications": 8,
    "UnverifiedPublishers": 23
  },
  "Applications": [...]
}
```

### CSV Export Format
Includes all application data in spreadsheet-compatible format:
- Application details (name, ID, publisher)
- Risk metrics (score, level, factors)
- Permission analysis (high-risk, medium-risk counts)
- Usage data (last sign-in, activity status)

## Security Recommendations

### Immediate Actions for High-Risk Applications
1. **Review Permissions**: Audit all high-risk permissions granted
2. **Verify Publisher**: Confirm application publisher legitimacy
3. **Check Usage**: Determine if application is actively used
4. **Consider Removal**: Remove unused or suspicious applications

### Ongoing Security Practices
1. **Regular Audits**: Run monthly application consent audits
2. **Publisher Verification**: Require verified publishers for new applications
3. **Permission Governance**: Implement approval workflows for high-risk permissions
4. **User Education**: Train users on consent grant risks

## Troubleshooting

### Common Issues

#### **Permission Errors**
```
Error: Insufficient privileges to complete the operation
```
**Solution**: Ensure your account has the required Graph API permissions and appropriate Entra ID role.

#### **Module Import Failures**
```
Error: Failed to import required module: Microsoft.Graph.Applications
```
**Solution**: Install missing modules using `Install-Module` with administrator privileges.

#### **Authentication Issues**
```
Error: Failed to connect to Microsoft Graph
```
**Solution**: Check network connectivity and ensure MFA requirements are met.

### Performance Considerations

#### **Large Tenants (1000+ Applications)**
- Use `-RiskThreshold` parameter to filter results
- Run during off-peak hours to minimize impact
- Consider excluding system applications with default settings

#### **Limited Permissions**
- Some features require `AuditLog.Read.All` for usage data
- Script will continue with reduced functionality if permissions are missing
- Usage data will show as "Unknown" without audit log access

## Integration Examples

### Automated Security Monitoring
```powershell
# Daily high-risk application check
$results = .\Export-EntraIDAppConsent.ps1 -RiskThreshold 8 -ExportFormat "JSON"
if ($results.HighRiskApplications -gt 0) {
    Send-SecurityAlert -Message "High-risk applications detected"
}
```

### Compliance Reporting
```powershell
# Monthly compliance report
.\Export-EntraIDAppConsent.ps1 -ExportFormat "ALL" -Detailed
Move-Item ".\reports\*" "\\compliance-share\monthly-reports\"
```

## Advanced Configuration

### Custom Risk Scoring
Modify the configuration file to adjust risk scoring for your environment:

```json
{
  "RiskScoring": {
    "HighRiskPermissionWeight": 15,
    "MediumRiskPermissionWeight": 7,
    "UnverifiedPublisherWeight": 5,
    "ExternalTenantWeight": 3,
    "UserConsentWeight": 2,
    "UnusedAppWeight": 1
  }
}
```

### Custom Permission Categories
Add organization-specific permissions to risk categories:

```json
{
  "HighRiskPermissions": [
    "Directory.ReadWrite.All",
    "CustomAPI.FullAccess",
    "Organization.SpecificPermission"
  ]
}
```

## Support and Maintenance

### Log Files
- Location: `./logs/AppConsentAudit_YYYYMMDD.log`
- Contains detailed execution information and error messages
- Useful for troubleshooting and audit trails

### Version History
- **v1.0.0**: Initial release with comprehensive application analysis
- Supports PowerShell 5.1+ and Microsoft Graph PowerShell SDK

### Contributing
This script is part of the Identity Security Automation toolkit. For issues, enhancements, or contributions, please follow the project's contribution guidelines.

---

**⚠️ Security Notice**: This script analyzes sensitive application permission data. Ensure reports are stored securely and access is restricted to authorized security personnel only.
