# Terraform State Drift Detector

## Overview
The Terraform State Drift Detector is an infrastructure security tool that monitors Terraform state files for configuration drift and security compliance violations. It provides automated detection of unauthorized changes and security policy violations in your infrastructure.

## Features
- **Drift Detection**: Compare actual infrastructure with Terraform state
- **Security Compliance**: Validate against security policies and standards
- **Resource Analysis**: Detailed analysis of infrastructure resources
- **Automated Notifications**: Alert on critical security violations
- **Compliance Reporting**: Generate compliance reports for audits
- **Integration Ready**: API endpoints for CI/CD and monitoring systems

## Prerequisites
- PowerShell 5.1 or PowerShell Core 7.x
- Terraform CLI installed and configured
- Azure CLI or AWS CLI (depending on cloud provider)
- Appropriate cloud provider permissions

## Required Permissions
- Read access to Terraform state storage (Azure Storage, S3, etc.)
- Read access to cloud resources for comparison
- Network access to Terraform state backends

## Detection Categories
1. **Configuration Drift**: Changes outside of Terraform
2. **Security Violations**: Non-compliant security configurations
3. **Resource Compliance**: Policy and standard violations
4. **State Integrity**: Terraform state file validation

## Configuration
Edit the `Terraform-Drift-Config.json` file to customize:
- Terraform workspace and state file locations
- Security policies and compliance rules
- Notification settings and thresholds
- Exclusion lists for expected drift

## Usage
```powershell
.\Test-TerraformStateDrift.ps1 -ConfigPath ".\Terraform-Drift-Config.json"
```

## Automation
- Schedule as part of CI/CD pipeline
- Run as scheduled task for continuous monitoring
- Integrate with infrastructure monitoring tools

## Security Considerations
- Secure access to Terraform state files
- Implement proper authentication for cloud providers
- Monitor for sensitive data exposure in drift reports
- Use least privilege access principles
