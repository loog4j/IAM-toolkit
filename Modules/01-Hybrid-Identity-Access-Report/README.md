# Hybrid Identity Access Reporter

## Overview
The Hybrid Identity Access Reporter provides a comprehensive 360-degree view of a user's identity, attributes, group memberships (including nested), role assignments, and effective permissions across both on-premises Active Directory and Entra ID environments.

## Features

### 🔍 **Identity Correlation**
- Searches for users across both Active Directory and Entra ID
- Supports multiple identifier types (UPN, sAMAccountName, employeeId)
- Validates identity correlation and detects conflicts
- Provides confidence scoring for identity matches

### 🏢 **Active Directory Analysis**
- Complete user attribute enumeration
- **Recursive nested group membership resolution** - shows the complete inheritance chain
- Privileged group membership detection
- Account status and security settings analysis
- Last logon and activity tracking

### ☁️ **Entra ID Analysis**
- User profile and attribute analysis
- Direct and transitive group memberships
- Administrative role assignments
- Application role assignments and permissions
- Sign-in activity analysis

### 📊 **Risk Assessment**
- Automated risk scoring based on privileged access
- Risk level classification (Critical, High, Medium, Low)
- Detailed risk factor identification
- Privilege escalation path analysis

### 📄 **Comprehensive Reporting**
- **HTML Report**: Visual, color-coded report with executive summary
- **JSON Export**: Structured data for integration with other tools
- **CSV Export**: Flattened data for spreadsheet analysis
- **All Formats**: Generate all report types simultaneously

## Usage

### Basic Usage
```powershell
# Generate HTML report for a user
.\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "john.doe@contoso.com"

# Search by sAMAccountName
.\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "jdoe" -OutputFormat "HTML"

# Generate all report formats
.\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "john.doe@contoso.com" -OutputFormat "All"
```

### Advanced Usage
```powershell
# Custom configuration file
.\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "john.doe@contoso.com" -ConfigPath ".\custom-config.json"

# Skip nested group analysis for faster execution
.\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "john.doe@contoso.com" -IncludeNestedGroups:$false

# Debug mode with detailed logging
.\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "john.doe@contoso.com" -LogLevel "DEBUG"
```

## Prerequisites

### PowerShell Modules
```powershell
# Install required modules
Install-Module ActiveDirectory
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Users
Install-Module Microsoft.Graph.Groups
Install-Module Microsoft.Graph.Identity.DirectoryManagement
```

### Permissions Required

#### Active Directory
- **Domain Users** (minimum for user/group queries)
- **Account Operators** (for comprehensive analysis)

#### Microsoft Graph API
- `User.Read.All`
- `Group.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.All`
- `Application.Read.All`

## Configuration

### Configuration File: `Hybrid-Identity-Config.json`

```json
{
  "IdentitySettings": {
    "ActiveDirectoryDomain": "contoso.com",
    "EntraIDTenantId": "your-tenant-id",
    "IdentityCorrelationMethod": "userPrincipalName",
    "FallbackCorrelationMethods": ["mail", "employeeId"],
    "IncludeDisabledAccounts": false
  },
  "AnalysisScope": {
    "IncludeNestedGroups": true,
    "MaxNestingDepth": 10,
    "IncludeApplicationRoles": true,
    "IncludeAdministrativeRoles": true
  },
  "PrivilegedGroups": {
    "ActiveDirectory": [
      "Domain Admins",
      "Enterprise Admins",
      "Schema Admins",
      "Administrators"
    ],
    "EntraID": [
      "Global Administrator",
      "Privileged Role Administrator",
      "Security Administrator"
    ]
  },
  "OutputPath": "./IdentityReports"
}
```

### Key Configuration Options

#### Identity Correlation
- **IdentityCorrelationMethod**: Primary method for matching users (userPrincipalName, mail, employeeId)
- **FallbackCorrelationMethods**: Alternative methods if primary fails
- **IncludeDisabledAccounts**: Whether to include disabled accounts in analysis

#### Analysis Scope
- **IncludeNestedGroups**: Enable recursive group membership analysis
- **MaxNestingDepth**: Maximum depth for nested group resolution (default: 10)
- **IncludeApplicationRoles**: Include application role assignments
- **IncludeAdministrativeRoles**: Include administrative role assignments

#### Privileged Groups
- **ActiveDirectory**: List of AD groups considered privileged
- **EntraID**: List of Entra ID roles considered privileged

## Output Reports

### 1. HTML Report
**File**: `IdentityReport_{UserIdentifier}_{Timestamp}.html`

Features:
- Executive summary with risk assessment
- Color-coded risk levels
- Detailed AD and Entra ID analysis
- Interactive group membership tables
- Privileged access highlighting

### 2. JSON Report
**File**: `IdentityReport_{UserIdentifier}_{Timestamp}.json`

Structure:
```json
{
  "reportMetadata": {
    "generatedDate": "2024-01-15T10:30:00Z",
    "reportVersion": "1.0",
    "userIdentifier": "john.doe@contoso.com"
  },
  "identityCorrelation": {
    "correlationStatus": "Matched",
    "correlationConfidence": 100
  },
  "activeDirectoryAnalysis": {
    "groupMemberships": [...],
    "userAttributes": {...}
  },
  "entraIDAnalysis": {
    "groupMemberships": [...],
    "applicationRoles": [...]
  },
  "riskAssessment": {
    "overallRiskScore": 15,
    "riskLevel": "Medium",
    "riskFactors": [...]
  }
}
```

### 3. CSV Report
**File**: `IdentityReport_{UserIdentifier}_{Timestamp}.csv`

Contains flattened data with columns:
- Source (ActiveDirectory/EntraID)
- Type (Group/Role)
- Name
- MembershipType (Direct/Nested)
- IsPrivileged
- Depth (for nested groups)

## Use Cases

### 🔍 **Security Investigations**
- Quickly understand a user's complete access during incidents
- Identify privilege escalation paths
- Analyze effective permissions across hybrid environments
- Support forensic analysis with detailed access mapping

### 📋 **Access Reviews**
- Provide managers with complete access picture for attestation
- Support compliance audits with comprehensive documentation
- Identify over-privileged accounts
- Track nested group inheritance

### 🛡️ **Compliance & Auditing**
- Generate evidence for regulatory compliance
- Support internal and external audits
- Document access governance processes
- Maintain audit trails

### 🔧 **Troubleshooting**
- Diagnose access issues by seeing all effective permissions
- Understand why users have specific access
- Identify conflicting permissions
- Support helpdesk with detailed access information

## Risk Assessment

### Risk Levels
- **Critical (25+)**: Multiple privileged roles, high-risk combinations
- **High (15-24)**: Privileged access, administrative roles
- **Medium (8-14)**: Some elevated permissions, group memberships
- **Low (0-7)**: Standard user access

### Risk Factors
- Privileged AD group memberships
- Administrative role assignments
- Multiple admin roles
- Cross-tenant access
- Unusual group combinations
- Inconsistent attributes between systems

## Performance Considerations

### Optimization Tips
- Use `-IncludeNestedGroups:$false` for faster execution when nested analysis isn't needed
- Configure `MaxNestingDepth` appropriately for your environment
- Run during off-peak hours for large environments
- Consider batch processing for multiple users

### Typical Performance
- **Standard User**: 10-30 seconds
- **Privileged User**: 30-60 seconds
- **Complex Nested Groups**: 1-3 minutes

## Troubleshooting

### Common Issues

#### Authentication Problems
```powershell
# Verify Graph connection
Get-MgContext

# Reconnect if needed
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All"
```

#### Active Directory Connectivity
```powershell
# Test AD connectivity
Get-ADDomain

# Verify user search
Get-ADUser -Filter "UserPrincipalName -eq 'test@domain.com'"
```

#### Permission Issues
- Verify Azure AD role assignments
- Check API permissions in Azure portal
- Ensure proper scopes during Graph authentication
- Confirm AD permissions for group queries

### Error Messages

#### "User not found in either Active Directory or Entra ID"
- Verify the user identifier is correct
- Check if the user exists in either system
- Try alternative identifiers (UPN vs sAMAccountName)

#### "Failed to connect to Microsoft Graph"
- Check internet connectivity
- Verify Azure AD permissions
- Ensure correct tenant context

#### "Maximum nesting depth reached"
- Increase `MaxNestingDepth` in configuration
- Check for circular group memberships
- Consider reducing scope for performance

## Security Considerations

### Data Protection
- Reports may contain sensitive user information
- Store reports in secure locations
- Consider encrypting reports for sensitive environments
- Implement proper access controls for report files

### Audit Trail
- All operations are logged with timestamps
- User queries are tracked for compliance
- Failed attempts are recorded
- Consider SIEM integration for monitoring

### Least Privilege
- Use read-only permissions where possible
- Limit scope of analysis to necessary attributes
- Implement approval workflows for sensitive users
- Regular review of script permissions

## Integration

### SIEM Integration
Export JSON reports to SIEM platforms for:
- Automated risk alerting
- Trend analysis
- Compliance reporting
- Incident response support

### Identity Governance
Integrate with:
- Access review systems
- Privileged access management
- Identity lifecycle workflows
- Compliance dashboards

### Automation
- Schedule regular reports for high-risk users
- Integrate with ticketing systems
- Automate report distribution
- Trigger on identity events

## Version History

### Version 1.0
- Initial release
- Basic identity correlation
- AD and Entra ID analysis
- HTML, JSON, and CSV reporting
- Risk assessment engine
- Nested group analysis

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review log files for detailed error information
3. Verify prerequisites and permissions
4. Test with a known working user account

## License

This script is part of the Identity Security Automation toolkit. See project documentation for licensing information.
