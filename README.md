# SCCM & Domain Infrastructure Discovery Tool

A PowerShell 5 script for discovering Microsoft SCCM (System Center Configuration Manager) and Active Directory domain infrastructure from a domain-joined Windows machine. Designed to run with standard domain user privileges.

## Overview

This tool performs comprehensive discovery of SCCM and Active Directory infrastructure without requiring administrative privileges. It's ideal for IT administrators, security professionals, and system engineers who need to quickly audit or document their SCCM environment.

## Features

- **Zero Admin Required** — Runs entirely under standard domain user context
- **Multi-Source Discovery** — Queries WMI, Registry, Active Directory, HTTP endpoints, and DNS
- **Safe Execution** — Graceful error handling; won't crash on access denied
- **Dual Output Formats** — Human-readable console/text output plus JSON for automation
- **No External Dependencies** — Pure PowerShell 5.0, no modules required

## Requirements

| Requirement | Details |
|-------------|---------|
| PowerShell | Version 5.0 or higher |
| Operating System | Windows 10/11 or Windows Server 2016+ |
| Domain | Machine must be domain-joined |
| Permissions | Standard domain user (no local admin needed) |

## Installation

```powershell
# Clone the repository
git clone https://github.com/mr-r3b00t/sccm_hunter.git

# Or download directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mr-r3b00t/sccm_hunter/main/SCCM-Domain-Discovery.ps1" -OutFile "SCCM-Domain-Discovery.ps1"
```

## Usage

### Basic Discovery

Run the script for console output only:

```powershell
.\SCCM-Domain-Discovery.ps1
```

### Export Results

Export to both TXT and JSON files on your desktop:

```powershell
.\SCCM-Domain-Discovery.ps1 -ExportToFile
```

### Custom Output Path

Specify a custom location for exported files:

```powershell
.\SCCM-Domain-Discovery.ps1 -ExportToFile -OutputPath "C:\Reports\sccm-audit.txt"
```

### Capture Results for Scripting

```powershell
$results = .\SCCM-Domain-Discovery.ps1
$results.DomainInformation.DomainControllers | Format-Table
```

## What Gets Discovered

### Domain Information

| Data Point | Source |
|------------|--------|
| Domain & Forest Names | .NET DirectoryServices |
| Domain Controllers | AD Domain object |
| FSMO Role Holders | AD Domain object |
| AD Sites | AD Forest object |
| Trust Relationships | AD Domain trusts |
| DNS Servers & Suffixes | WMI Network Config |

### SCCM Client Information

| Data Point | Source |
|------------|--------|
| Client Version | WMI `root\ccm` |
| Client ID (GUID) | WMI CCM_ClientIdentificationInfo |
| Assigned Site Code | WMI SMS_Authority |
| Current Management Point | WMI SMS_Authority |
| Client Components | WMI CCM_InstalledComponent |
| Cache Location & Size | WMI CacheConfig |

### SCCM Infrastructure (from Active Directory)

| Data Point | Source |
|------------|--------|
| Site Servers | AD System Management container |
| Management Points | AD mSSMSManagementPoint objects |
| Server Locator Points | AD mSSMSServerLocatorPoint objects |
| Service Connection Points | AD SCP objects |

### SCCM Server Polling

| Data Point | Source |
|------------|--------|
| MP List | HTTP `/sms_mp/.sms_aut?mplist` |
| MP Certificate | HTTP `/sms_mp/.sms_aut?mpcert` |
| Site Signing Cert | HTTP `/sms_mp/.sms_aut?SITESIGNCERT` |
| SMS Provider Locations | Remote WMI (if permitted) |
| SRV Records | DNS `_mssms_mp_*._tcp` |

### Site System Roles

| Role | Discovery Method |
|------|------------------|
| Management Points | Client cache, AD, HTTP |
| Distribution Points | Client cache (SMS_ActiveDP) |
| Software Update Points | WMI CCM_UpdateSource |
| State Migration Points | WMI LocationServices |
| Cloud Management Gateway | WMI LocationServices |
| Application Catalog | Registry (legacy) |

### Collections & Policy

| Data Point | Source |
|------------|--------|
| Collection Membership | WMI Policy namespace |
| Machine Policies | WMI RequestedConfig |
| Application Deployments | WMI ActualConfig |

### Boundary Information

| Data Point | Source |
|------------|--------|
| Current AD Site | WMI CCM_ADSite |
| Network Locations | WMI CCM_NetworkLocation |
| Boundary Groups | WMI/Registry LocationServices |

## Output Examples

### Console Output

```
======================================================================
  LOCAL MACHINE & DOMAIN INFORMATION
======================================================================

  --- Computer Information ---
    Computer Name : WORKSTATION01
    Domain : corp.contoso.com
    Domain Role : Member Workstation
    Current User : CORP\jsmith

  --- Active Directory Information ---
    AD Domain Name : corp.contoso.com
    AD Forest Name : contoso.com
    PDC Emulator : DC01.corp.contoso.com
```

### JSON Output Structure

```json
{
  "DomainInformation": {
    "ComputerName": "WORKSTATION01",
    "Domain": "corp.contoso.com",
    "DomainControllers": [
      {
        "Name": "DC01.corp.contoso.com",
        "IPAddress": "10.0.0.10",
        "SiteName": "Default-First-Site-Name"
      }
    ]
  },
  "SCCMClientInfo": {
    "ClientInstalled": true,
    "ClientVersion": "5.00.9096.1000",
    "AssignedSite": "PS1",
    "CurrentManagementPoint": "SCCM01.corp.contoso.com"
  }
}
```

## Permissions Deep Dive

The script is designed to work with minimal permissions. Here's what each discovery method requires:

| Method | Required Permission | Fallback |
|--------|---------------------|----------|
| Local WMI | Local user | N/A |
| AD LDAP Queries | Domain user (read) | Graceful skip |
| HTTP MP Endpoints | Network access | Reports inaccessible |
| Remote WMI | Usually admin | Graceful skip |
| DNS SRV Queries | Network access | Graceful skip |

## Troubleshooting

### "Access Denied" Messages

These are expected when querying resources requiring elevated privileges. The script continues and reports what it can access.

### No SCCM Client Information

If the SCCM sections are empty, verify:
1. The SCCM client is installed (`C:\Windows\CCM` exists)
2. The client service is running (`CcmExec`)
3. Run `Get-WmiObject -Namespace root\ccm -Class SMS_Client`

### Active Directory Queries Fail

Ensure:
1. Machine is properly domain-joined
2. Network connectivity to domain controllers
3. DNS is resolving domain names correctly

### Management Point HTTP Queries Fail

The MP may require HTTPS or client certificate authentication. Check:
1. SCCM site configuration for client communication settings
2. Whether Enhanced HTTP or PKI is enabled

## Use Cases

- **Environment Documentation** — Quickly inventory SCCM infrastructure
- **Troubleshooting** — Verify client-to-server connectivity and configuration
- **Security Audits** — Identify SCCM attack surface and published AD objects
- **Migration Planning** — Document current state before upgrades
- **Onboarding** — Help new team members understand the environment

## Security Considerations

This script performs read-only discovery operations. However, be aware that:

- Discovery results may contain sensitive infrastructure details
- JSON exports should be stored securely
- Running discovery may generate logs on target systems
- Some organizations may have policies against infrastructure enumeration

Always obtain appropriate authorization before running discovery tools in production environments.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Bug fixes
- Additional discovery methods
- Support for newer SCCM/MECM versions
- Documentation improvements

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Microsoft documentation for WMI namespaces and AD schema
- The SCCM/MECM community for infrastructure insights

## Changelog

### v1.0.0
- Initial release
- Domain and forest discovery
- SCCM client information gathering
- AD-based SCCM infrastructure discovery
- Management Point HTTP polling
- Site system role enumeration
- Boundary and collection information
- TXT and JSON export functionality
