# Bulk User Attribute Manager

## Overview
PowerShell script for performing bulk updates to user attributes in Active Directory and Entra ID from CSV files. This script is designed for identity and security engineers who need to automate user attribute changes at scale while maintaining comprehensive audit trails.

## Features
- ✅ **Dual Environment Support**: Works with both Active Directory and Entra ID
- ✅ **Batch Processing**: Handles large datasets efficiently with configurable batch sizes
- ✅ **Comprehensive Validation**: Validates user data before processing
- ✅ **Audit Logging**: Detailed logging with multiple log levels
- ✅ **WhatIf Mode**: Preview changes without applying them
- ✅ **Error Handling**: Robust error handling with retry capabilities
- ✅ **Throttling**: Built-in rate limiting to prevent API overload
- ✅ **Configuration-Driven**: Externalized settings for easy customization

## Prerequisites

### Software Requirements
- **PowerShell 5.1** or later
- **ActiveDirectory PowerShell module** (for AD operations)
- **Microsoft.Graph PowerShell modules** (for Entra ID operations)
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Users

### Permissions Required
- **Active Directory**: User modification permissions in target OUs
- **Entra ID**: User.ReadWrite.All and Directory.ReadWrite.All permissions

### Installation
```powershell
# Install required PowerShell modules
Install-Module ActiveDirectory
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Users

# Verify installation
Get-Module -ListAvailable ActiveDirectory, Microsoft.Graph.*
```

## Quick Start

### 1. Prepare Your Data
Use the provided `UserUpdateTemplate.csv` as a starting point:

```csv
UserPrincipalName,DisplayName,Department,Title,Manager,OfficeLocation,PhoneNumber,Action
john.doe@company.com,John Doe,IT,Senior Engineer,jane.smith@company.com,Building A,555-1234,UPDATE
```

### 2. Basic Usage
```powershell
# Update both AD and Entra ID (default)
.\Update-UserAttributesBulk.ps1 -CsvPath ".\UserUpdateTemplate.csv"

# Update only Active Directory
.\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -TargetEnvironment "AD"

# Update only Entra ID
.\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -TargetEnvironment "EntraID"

# Preview changes without applying them
.\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -WhatIf

# Enable debug logging
.\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -LogLevel "DEBUG"
```

## CSV File Format

### Required Fields
- **UserPrincipalName**: User's email address/UPN (Required)
- **Action**: Operation to perform - UPDATE, CREATE, or DISABLE (Required)

### Optional Fields
- **DisplayName**: User's display name
- **Department**: Department name
- **Title**: Job title
- **Manager**: Manager's UserPrincipalName
- **OfficeLocation**: Physical office location
- **PhoneNumber**: Business phone number

### Example CSV
```csv
UserPrincipalName,DisplayName,Department,Title,Manager,OfficeLocation,PhoneNumber,Action
john.doe@company.com,John Doe,IT,Senior Engineer,jane.smith@company.com,Building A,555-1234,UPDATE
jane.smith@company.com,Jane Smith,IT,IT Manager,,Building A,555-5678,UPDATE
bob.wilson@company.com,Bob Wilson,Finance,Financial Analyst,mary.jones@company.com,Building B,555-9012,UPDATE
```

## Configuration

### Configuration File
The script uses `Update-UserAttributesBulk-Config.json` for settings:

```json
{
  "LogPath": "./logs/",
  "BatchSize": 100,
  "ThrottleDelay": 1000,
  "SupportedActions": ["UPDATE", "CREATE", "DISABLE"],
  "RequiredFields": ["UserPrincipalName", "Action"],
  "AttributeMapping": {
    "DisplayName": "DisplayName",
    "Department": "Department", 
    "Title": "Title",
    "Manager": "Manager",
    "OfficeLocation": "Office",
    "PhoneNumber": "OfficePhone"
  },
  "ValidationRules": {
    "UserPrincipalName": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
    "PhoneNumber": "^\\+?[1-9]\\d{1,14}$"
  }
}
```

### Key Settings
- **BatchSize**: Number of users to process in each batch (default: 100)
- **ThrottleDelay**: Milliseconds to wait between batches (default: 1000)
- **LogPath**: Directory for log files (default: ./logs/)
- **ValidationRules**: Regex patterns for data validation

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| CsvPath | String | Yes | - | Path to CSV file containing user updates |
| ConfigPath | String | No | .\Update-UserAttributesBulk-Config.json | Path to configuration file |
| TargetEnvironment | String | No | Both | Target environment: AD, EntraID, or Both |
| LogLevel | String | No | INFO | Logging level: INFO, WARNING, ERROR, DEBUG |
| WhatIf | Switch | No | False | Preview changes without applying them |

## Logging

### Log Levels
- **DEBUG**: Detailed execution information
- **INFO**: General information about progress
- **SUCCESS**: Successful operations
- **WARNING**: Non-critical issues
- **ERROR**: Critical errors

### Log Files
- Logs are saved to timestamped files in the configured log directory
- Format: `BulkUserUpdate_yyyyMMdd_HHmmss.log`
- Both console and file logging are supported

### Sample Log Output
```
[2024-01-15 10:30:15] [INFO] 🚀 Starting Identity Security Automation - Bulk User Update
[2024-01-15 10:30:15] [INFO] 📁 CSV File: .\UserUpdateTemplate.csv
[2024-01-15 10:30:15] [INFO] 🎯 Target Environment: Both
[2024-01-15 10:30:16] [SUCCESS] ✅ Configuration loaded successfully
[2024-01-15 10:30:16] [SUCCESS] ✅ ActiveDirectory module loaded
[2024-01-15 10:30:17] [SUCCESS] ✅ Connected to Microsoft Graph
[2024-01-15 10:30:17] [INFO] 📊 Loaded 5 user records from CSV
[2024-01-15 10:30:18] [SUCCESS] ✅ Updated AD user: john.doe@company.com
[2024-01-15 10:30:19] [SUCCESS] ✅ Updated Entra ID user: john.doe@company.com
```

## Error Handling

### Common Issues and Solutions

#### 1. Module Import Failures
**Error**: "ActiveDirectory module not found"
**Solution**: 
```powershell
Install-Module ActiveDirectory -Force
Import-Module ActiveDirectory
```

#### 2. Authentication Failures
**Error**: "Failed to connect to Microsoft Graph"
**Solution**: 
```powershell
# Ensure you have appropriate permissions
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All"
```

#### 3. CSV Format Issues
**Error**: "Validation failed for user"
**Solution**: 
- Verify CSV headers match expected format
- Check for missing required fields
- Validate email format for UserPrincipalName

#### 4. User Not Found
**Error**: "User not found in AD/Entra ID"
**Solution**: 
- Verify UserPrincipalName is correct
- Check user exists in target environment
- Ensure proper permissions to read user objects

## Best Practices

### 1. Testing
- Always use `-WhatIf` parameter first to preview changes
- Test with a small subset of users before processing large batches
- Verify configuration settings in a lab environment

### 2. Data Preparation
- Validate CSV data before processing
- Use consistent formatting for phone numbers and other fields
- Ensure manager relationships exist before setting them

### 3. Performance
- Adjust batch size based on your environment's capacity
- Monitor API rate limits and adjust throttle delay if needed
- Process during off-peak hours for large updates

### 4. Security
- Use least privilege permissions
- Store credentials securely (avoid hardcoding)
- Review logs for any security-related issues

### 5. Backup and Recovery
- Backup user data before making bulk changes
- Keep detailed logs for audit purposes
- Have a rollback plan for critical changes

## Advanced Usage

### Custom Configuration
```powershell
# Use custom configuration file
.\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -ConfigPath ".\custom-config.json"

# Process with detailed debugging
.\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -LogLevel "DEBUG" -WhatIf
```

### Batch Processing Large Files
```powershell
# For very large files, consider splitting them
# Process in smaller chunks with custom batch size
# Modify BatchSize in config file to 50 for slower environments
```

## Troubleshooting

### Validation Errors
Check the log file for specific validation failures:
- Invalid email format
- Missing required fields
- Unsupported action types

### Connection Issues
- Verify network connectivity
- Check firewall settings
- Ensure proper authentication

### Performance Issues
- Reduce batch size
- Increase throttle delay
- Check system resources

## Support and Maintenance

### Regular Maintenance
- Review and rotate log files
- Update PowerShell modules regularly
- Test scripts after module updates

### Monitoring
- Monitor log files for errors
- Set up alerts for failed operations
- Review performance metrics

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-15 | Initial release with AD and Entra ID support |

## Related Scripts
- **Dormant Account Processor**: Automated account lifecycle management
- **RBAC Enforcer**: Role-based access control automation
- **Privileged Access Reporter**: Admin access reporting

## Contributing
This script is part of the Identity Security Automation project. For improvements or bug reports, please follow the project's contribution guidelines.
