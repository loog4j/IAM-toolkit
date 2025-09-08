# Bulk User Attribute Manager (Bash)

## Overview
The Bash version of the Bulk User Attribute Manager provides cross-platform compatibility for managing user attributes in Entra ID environments on Linux and macOS systems.

## Features
- **Cross-platform Compatibility**: Runs on Linux, macOS, and Windows (WSL)
- **Bulk Operations**: Process multiple users simultaneously
- **CSV Input**: Standard CSV file format for user data
- **REST API Integration**: Direct Microsoft Graph API calls
- **Error Handling**: Comprehensive error reporting and rollback capabilities
- **Dry Run Mode**: Test operations before execution

## Prerequisites
- Bash 4.0 or higher
- curl (for API calls)
- jq (for JSON processing)
- Azure CLI or valid access token

## Required Permissions
- User.ReadWrite.All
- Directory.ReadWrite.All

## Installation
```bash
# Install dependencies on Ubuntu/Debian
sudo apt-get install curl jq

# Install dependencies on macOS
brew install curl jq

# Install Azure CLI (optional)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

## CSV Format
The input CSV file should contain the following columns:
- UserPrincipalName (required)
- DisplayName
- Department
- JobTitle
- Manager
- OfficeLocation
- (Additional attributes as needed)

## Usage
```bash
# Using Azure CLI authentication
./update-user-attributes-bulk.sh --input users.csv

# Using access token
./update-user-attributes-bulk.sh --input users.csv --token "your-access-token"

# Dry run mode (test without making changes)
./update-user-attributes-bulk.sh --input users.csv --dry-run

# Specify log file
./update-user-attributes-bulk.sh --input users.csv --log update.log
```

## Output
- Detailed operation logs
- Success/failure summary
- Error reports for failed operations
- Rollback scripts (when applicable)

## Integration
- Perfect for CI/CD pipelines
- Compatible with automation frameworks
- Easy integration with HR systems and data feeds
