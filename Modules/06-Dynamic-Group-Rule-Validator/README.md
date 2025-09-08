# Dynamic Group Rule Validator

## Overview
The Dynamic Group Rule Validator is a comprehensive validation tool for Entra ID dynamic group membership rules. It performs syntax validation, logic analysis, performance testing, and security assessment to ensure optimal dynamic group configurations.

## Features
- **Syntax Validation**: Complete rule syntax checking and error detection
- **Logic Analysis**: Rule logic validation and conflict detection
- **Performance Testing**: Rule efficiency and performance impact assessment
- **Security Assessment**: Security implications and risk analysis
- **Optimization Recommendations**: Suggestions for rule improvements
- **Bulk Validation**: Process multiple groups simultaneously

## Prerequisites
- PowerShell 5.1 or PowerShell Core 7.x
- Microsoft Graph PowerShell SDK
- Groups Administrator or Global Administrator permissions

## Required Permissions
- Group.Read.All
- Group.ReadWrite.All (for testing rule changes)
- Directory.Read.All

## Validation Categories
1. **Syntax Validation**: Rule structure and syntax correctness
2. **Logic Validation**: Rule logic and condition analysis
3. **Performance Validation**: Rule efficiency and processing impact
4. **Security Validation**: Security implications and access patterns

## Configuration
Edit the `Dynamic-Group-Validation-Config.json` file to customize:
- Validation scope and criteria
- Performance thresholds
- Security assessment parameters
- Reporting preferences

## Usage
```powershell
.\Test-DynamicGroupRules.ps1 -ConfigPath ".\Dynamic-Group-Validation-Config.json"
```

## Output
- Comprehensive validation report
- Rule optimization recommendations
- Security assessment findings
- Performance impact analysis

## Best Practices
- Test rule changes in non-production environment
- Monitor group membership changes after rule updates
- Regular validation of existing rules
- Document rule logic and business requirements
