# Conditional Access Policy Auditor

## Overview
The Conditional Access Policy Auditor is a comprehensive tool for analyzing and auditing Entra ID Conditional Access policies. It provides detailed policy analysis, compliance checking, and security assessment to ensure optimal policy configurations.

## Features
- **Policy Analysis**: Complete analysis of all Conditional Access policies
- **Compliance Checking**: Validation against security standards and best practices
- **Gap Analysis**: Identification of policy gaps and coverage issues
- **Risk Assessment**: Security risk evaluation of policy configurations
- **Optimization Recommendations**: Suggestions for policy improvements
- **Multi-format Reporting**: HTML, JSON, and CSV output options

## Prerequisites
- PowerShell 5.1 or PowerShell Core 7.x
- Microsoft Graph PowerShell SDK
- Security Administrator or Global Administrator permissions

## Required Permissions
- Policy.Read.All
- Directory.Read.All
- Application.Read.All
- Group.Read.All

## Analysis Categories
1. **Policy Configuration**: Structure and settings analysis
2. **Coverage Analysis**: User and application coverage assessment
3. **Security Assessment**: Risk and compliance evaluation
4. **Best Practices**: Alignment with Microsoft recommendations

## Configuration
Edit the `CA-Policy-Audit-Config.json` file to customize:
- Analysis scope and criteria
- Compliance standards and benchmarks
- Reporting preferences and formats
- Exclusion lists for specific policies

## Usage
```powershell
.\Export-ConditionalAccessPolicies.ps1 -ConfigPath ".\CA-Policy-Audit-Config.json"
```

## Output
- Comprehensive policy audit report
- Policy configuration export
- Compliance assessment findings
- Optimization recommendations

## Best Practices
- Regular policy audits and reviews
- Test policy changes in report-only mode
- Document policy business requirements
- Monitor policy effectiveness and impact
