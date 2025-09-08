# Identity Security Automation

## Overview
A comprehensive collection of enterprise-grade PowerShell and Bash scripts for automating identity and security operations in Microsoft Entra ID (Azure AD) environments. This toolkit provides security engineers and identity administrators with ready-to-use automation modules for auditing, compliance, security response, and lifecycle management.

## Project Structure
```
Identity-Security-Automation/
├── Modules/                          # Production-ready automation modules
│   ├── 01-Hybrid-Identity-Access-Report/
│   ├── 02-Entra-ID-App-Consent-Auditor/
│   ├── 03-External-User-Access-Reviewer/
│   ├── 04-Risky-User-Remediator/
│   ├── 05-API-Key-Rotation-Reminder/
│   ├── 06-Dynamic-Group-Rule-Validator/
│   ├── 07-Terraform-State-Drift-Detector/
│   ├── 08-Conditional-Access-Policy-Auditor/
│   ├── 09-Bulk-User-Attribute-Manager/
│   ├── 10-Conditional-Access-Policy-Auditor-Bash/
│   └── 11-Bulk-User-Attribute-Manager-Bash/
├── _Archive/                         # Development artifacts and planning files
└── README.md                         # This file
```

## Available Modules

### Auditing & Compliance
- **Hybrid Identity Access Report**: Comprehensive analysis of hybrid identity configurations and access patterns
- **Entra ID App Consent Auditor**: Shadow IT detection and application consent analysis
- **External User Access Reviewer**: Guest user security and B2B collaboration governance

### Security Response
- **Risky User Remediator**: Automated security response for compromised accounts with Identity Protection integration

### Security Operations
- **API Key Rotation Reminder**: Credential lifecycle management across Azure services

### Entra ID/AD Automation
- **Dynamic Group Rule Validator**: Validation and optimization of dynamic group membership rules
- **Conditional Access Policy Auditor**: Comprehensive CA policy analysis and compliance checking

### Lifecycle Management
- **Bulk User Attribute Manager**: Enterprise-scale user attribute management system

### Infrastructure Security
- **Terraform State Drift Detector**: Infrastructure drift detection and security compliance monitoring

### Cross-Platform Support
- **Bash Equivalents**: Linux/macOS compatible versions for CI/CD and automation pipelines

## Key Features

### Enterprise-Grade Quality
- **Comprehensive Error Handling**: Robust error management with detailed logging
- **Configuration-Driven**: JSON-based configuration for easy customization
- **Multi-Format Reporting**: HTML, JSON, and CSV output options
- **Risk Assessment**: Automated scoring and security analysis
- **Audit Trails**: Complete logging of all operations

### Security-First Design
- **Least Privilege**: Minimal required permissions for each module
- **Secure Configuration**: Built-in security best practices
- **Compliance Ready**: Designed for enterprise compliance requirements
- **Identity Protection Integration**: Native support for Microsoft security features

### Production Ready
- **Scalable Architecture**: Handles enterprise-scale environments
- **Performance Optimized**: Efficient processing of large datasets
- **Integration Friendly**: API endpoints and webhook support
- **Cross-Platform**: PowerShell Core and Bash compatibility

## Prerequisites

### PowerShell Modules
- PowerShell 5.1 or PowerShell Core 7.x
- Microsoft Graph PowerShell SDK
- Azure PowerShell module (for some modules)

### Bash Scripts
- Bash 4.0 or higher
- curl and jq utilities
- Azure CLI (optional)

### Permissions
Each module specifies its minimum required permissions. Common requirements include:
- Directory.Read.All
- User.Read.All
- Group.Read.All
- Policy.Read.All
- AuditLog.Read.All

## Quick Start

1. **Choose a Module**: Navigate to the specific module directory
2. **Review Prerequisites**: Check the module's README for requirements
3. **Configure**: Edit the JSON configuration file
4. **Test**: Run in a non-production environment first
5. **Deploy**: Execute in your production environment

### Example Usage
```powershell
# Navigate to a module
cd "Modules/01-Hybrid-Identity-Access-Report"

# Review the configuration
notepad "Hybrid-Identity-Config.json"

# Execute the script
.\Get-HybridIdentityAccessReport.ps1 -ConfigPath ".\Hybrid-Identity-Config.json"
```

## Security Considerations

### Before Deployment
- Review all permissions carefully
- Test in non-production environments
- Validate configuration files
- Implement proper access controls

### During Operation
- Monitor for false positives
- Review automated actions
- Maintain audit logs
- Regular security assessments

### Best Practices
- Use managed identities where possible
- Implement approval workflows for critical actions
- Regular review of automation results
- Keep modules updated

## Support and Contribution

### Documentation
Each module includes comprehensive documentation:
- Feature overview and capabilities
- Prerequisites and permissions
- Configuration options
- Usage examples
- Security considerations

### Customization
All modules are designed for customization:
- JSON configuration files
- Modular architecture
- Extensible reporting
- Integration-ready APIs

## License
This project is provided as-is for educational and enterprise use. Please review and test thoroughly before production deployment.

## Version History
- **v1.0**: Initial release with 11 core modules
- Comprehensive PowerShell automation suite
- Cross-platform Bash equivalents
- Enterprise-grade security and compliance features
