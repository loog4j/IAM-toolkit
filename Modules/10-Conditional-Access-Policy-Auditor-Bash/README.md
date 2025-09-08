# Conditional Access Policy Auditor (Bash)

## Overview
The Bash version of the Conditional Access Policy Auditor provides cross-platform compatibility for analyzing and auditing Entra ID Conditional Access policies on Linux and macOS systems.

## Features
- **Cross-platform Compatibility**: Runs on Linux, macOS, and Windows (WSL)
- **Policy Analysis**: Complete analysis of all Conditional Access policies
- **JSON Output**: Machine-readable output for integration with other tools
- **REST API Integration**: Direct Microsoft Graph API calls
- **Lightweight**: Minimal dependencies and fast execution

## Prerequisites
- Bash 4.0 or higher
- curl (for API calls)
- jq (for JSON processing)
- Azure CLI or valid access token

## Required Permissions
- Policy.Read.All
- Directory.Read.All
- Application.Read.All
- Group.Read.All

## Installation
```bash
# Install dependencies on Ubuntu/Debian
sudo apt-get install curl jq

# Install dependencies on macOS
brew install curl jq

# Install Azure CLI (optional)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

## Usage
```bash
# Using Azure CLI authentication
./export-conditional-access-policies.sh

# Using access token
./export-conditional-access-policies.sh --token "your-access-token"

# Specify output file
./export-conditional-access-policies.sh --output "ca-policies.json"
```

## Output
- JSON formatted policy export
- Policy analysis summary
- Error logs and debugging information

## Integration
- Perfect for CI/CD pipelines
- Compatible with automation frameworks
- Easy integration with monitoring systems
