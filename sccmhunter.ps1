<#
.SYNOPSIS
    Domain and SCCM Infrastructure Discovery Script
.DESCRIPTION
    This script discovers domain information and SCCM infrastructure from a 
    domain-joined Windows machine running as a standard domain user.
.NOTES
    Requires: PowerShell 5.0+, Domain-joined machine
    Permissions: Domain User (no admin required for most queries)
    Author: IT Administration Script
    Version: 1.0
#>

#Requires -Version 5.0

[CmdletBinding()]
param(
    [switch]$ExportToFile,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\SCCM_Discovery_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Initialize results collection
$Script:DiscoveryResults = [ordered]@{}

#region Helper Functions
function Write-Section {
    param([string]$Title)
    $separator = "=" * 70
    Write-Host "`n$separator" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "$separator" -ForegroundColor Cyan
}

function Write-SubSection {
    param([string]$Title)
    Write-Host "`n  --- $Title ---" -ForegroundColor Green
}

function Write-Info {
    param([string]$Label, [string]$Value)
    if ($Value) {
        Write-Host "    $Label : " -NoNewline -ForegroundColor White
        Write-Host "$Value" -ForegroundColor Gray
    }
}

function Safe-WMIQuery {
    param(
        [string]$Query,
        [string]$Namespace = "root\cimv2",
        [string]$ComputerName = "."
    )
    try {
        Get-WmiObject -Query $Query -Namespace $Namespace -ComputerName $ComputerName -ErrorAction Stop
    }
    catch {
        $null
    }
}

function Safe-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $value.$Name
    }
    catch {
        return $null
    }
}
#endregion

#region Domain Discovery
function Get-LocalDomainInformation {
    Write-Section "LOCAL MACHINE & DOMAIN INFORMATION"
    
    $domainInfo = [ordered]@{}
    
    # Basic Computer Information
    Write-SubSection "Computer Information"
    $computerSystem = Safe-WMIQuery "SELECT * FROM Win32_ComputerSystem"
    $operatingSystem = Safe-WMIQuery "SELECT * FROM Win32_OperatingSystem"
    
    $domainInfo["ComputerName"] = $env:COMPUTERNAME
    $domainInfo["Domain"] = $computerSystem.Domain
    $domainInfo["DomainRole"] = switch ($computerSystem.DomainRole) {
        0 { "Standalone Workstation" }
        1 { "Member Workstation" }
        2 { "Standalone Server" }
        3 { "Member Server" }
        4 { "Backup Domain Controller" }
        5 { "Primary Domain Controller" }
        default { "Unknown" }
    }
    $domainInfo["PartOfDomain"] = $computerSystem.PartOfDomain
    $domainInfo["Workgroup"] = $computerSystem.Workgroup
    $domainInfo["CurrentUser"] = "$env:USERDOMAIN\$env:USERNAME"
    $domainInfo["OSVersion"] = $operatingSystem.Caption
    $domainInfo["OSBuild"] = $operatingSystem.BuildNumber
    
    Write-Info "Computer Name" $domainInfo["ComputerName"]
    Write-Info "Domain" $domainInfo["Domain"]
    Write-Info "Domain Role" $domainInfo["DomainRole"]
    Write-Info "Part of Domain" $domainInfo["PartOfDomain"]
    Write-Info "Current User" $domainInfo["CurrentUser"]
    Write-Info "OS Version" $domainInfo["OSVersion"]
    Write-Info "OS Build" $domainInfo["OSBuild"]
    
    # Active Directory Information via .NET
    Write-SubSection "Active Directory Information"
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainInfo["ADDomainName"] = $domain.Name
        $domainInfo["ADForestName"] = $domain.Forest.Name
        $domainInfo["DomainMode"] = $domain.DomainMode.ToString()
        $domainInfo["ForestMode"] = $domain.Forest.ForestMode.ToString()
        $domainInfo["PDCEmulator"] = $domain.PdcRoleOwner.Name
        $domainInfo["RIDMaster"] = $domain.RidRoleOwner.Name
        $domainInfo["InfrastructureMaster"] = $domain.InfrastructureRoleOwner.Name
        
        Write-Info "AD Domain Name" $domainInfo["ADDomainName"]
        Write-Info "AD Forest Name" $domainInfo["ADForestName"]
        Write-Info "Domain Mode" $domainInfo["DomainMode"]
        Write-Info "Forest Mode" $domainInfo["ForestMode"]
        Write-Info "PDC Emulator" $domainInfo["PDCEmulator"]
        Write-Info "RID Master" $domainInfo["RIDMaster"]
        Write-Info "Infrastructure Master" $domainInfo["InfrastructureMaster"]
        
        # Domain Controllers
        Write-SubSection "Domain Controllers"
        $domainInfo["DomainControllers"] = @()
        foreach ($dc in $domain.DomainControllers) {
            $dcInfo = @{
                Name = $dc.Name
                IPAddress = $dc.IPAddress
                OSVersion = $dc.OSVersion
                Roles = ($dc.Roles -join ", ")
                SiteName = $dc.SiteName
            }
            $domainInfo["DomainControllers"] += $dcInfo
            Write-Info "DC" "$($dc.Name) [$($dc.IPAddress)] - Site: $($dc.SiteName)"
        }
        
        # Sites Information
        Write-SubSection "AD Sites"
        $domainInfo["Sites"] = @()
        foreach ($site in $domain.Forest.Sites) {
            $domainInfo["Sites"] += $site.Name
            Write-Info "Site" $site.Name
        }
        
        # Trust Relationships
        Write-SubSection "Domain Trusts"
        $domainInfo["Trusts"] = @()
        try {
            $trusts = $domain.GetAllTrustRelationships()
            foreach ($trust in $trusts) {
                $trustInfo = @{
                    TargetName = $trust.TargetName
                    TrustType = $trust.TrustType.ToString()
                    TrustDirection = $trust.TrustDirection.ToString()
                }
                $domainInfo["Trusts"] += $trustInfo
                Write-Info "Trust" "$($trust.TargetName) - Type: $($trust.TrustType) - Direction: $($trust.TrustDirection)"
            }
        }
        catch {
            Write-Info "Trusts" "Unable to enumerate (insufficient permissions)"
        }
    }
    catch {
        Write-Host "    [!] Unable to query Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # DNS Information
    Write-SubSection "DNS Configuration"
    try {
        $networkConfig = Safe-WMIQuery "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"
        $domainInfo["DNSServers"] = @()
        foreach ($adapter in $networkConfig) {
            if ($adapter.DNSServerSearchOrder) {
                foreach ($dns in $adapter.DNSServerSearchOrder) {
                    if ($dns -notin $domainInfo["DNSServers"]) {
                        $domainInfo["DNSServers"] += $dns
                        Write-Info "DNS Server" $dns
                    }
                }
            }
        }
        $domainInfo["DNSSuffix"] = (Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue).SuffixSearchList -join ", "
        Write-Info "DNS Suffix Search List" $domainInfo["DNSSuffix"]
    }
    catch {
        Write-Host "    [!] Unable to query DNS configuration" -ForegroundColor Red
    }
    
    $Script:DiscoveryResults["DomainInformation"] = $domainInfo
}
#endregion

#region Local SCCM Client Discovery
function Get-LocalSCCMClientInformation {
    Write-Section "LOCAL SCCM CLIENT INFORMATION"
    
    $sccmInfo = [ordered]@{}
    $sccmInfo["ClientInstalled"] = $false
    
    # Check if SCCM Client is installed
    Write-SubSection "SCCM Client Status"
    
    # Method 1: Check WMI Namespace
    try {
        $smsClient = Safe-WMIQuery "SELECT * FROM SMS_Client" -Namespace "root\ccm"
        if ($smsClient) {
            $sccmInfo["ClientInstalled"] = $true
            $sccmInfo["ClientVersion"] = $smsClient.ClientVersion
            Write-Info "Client Installed" "Yes"
            Write-Info "Client Version" $sccmInfo["ClientVersion"]
        }
    }
    catch {
        Write-Info "Client Installed" "No (WMI namespace not found)"
    }
    
    if ($sccmInfo["ClientInstalled"]) {
        # Get detailed client information
        Write-SubSection "Client Configuration"
        
        # Client ID and Site
        $ccmClient = Safe-WMIQuery "SELECT * FROM CCM_Client" -Namespace "root\ccm"
        if ($ccmClient) {
            $sccmInfo["ClientId"] = (Safe-WMIQuery "SELECT * FROM CCM_ClientIdentificationInfo" -Namespace "root\ccm").ClientId
            Write-Info "Client ID" $sccmInfo["ClientId"]
        }
        
        # Site Assignment
        $authority = Safe-WMIQuery "SELECT * FROM SMS_Authority" -Namespace "root\ccm"
        if ($authority) {
            $sccmInfo["AssignedSite"] = $authority.Name -replace "SMS:", ""
            $sccmInfo["CurrentManagementPoint"] = $authority.CurrentManagementPoint
            Write-Info "Assigned Site Code" $sccmInfo["AssignedSite"]
            Write-Info "Current Management Point" $sccmInfo["CurrentManagementPoint"]
        }
        
        # Management Points from Client
        Write-SubSection "Management Points (from client)"
        $mpInfo = Safe-WMIQuery "SELECT * FROM SMS_MPInformation" -Namespace "root\ccm"
        $sccmInfo["ManagementPoints"] = @()
        if ($mpInfo) {
            foreach ($mp in $mpInfo) {
                $mpData = @{
                    Name = $mp.MP
                    SiteCode = $mp.SiteCode
                    Version = $mp.Version
                }
                $sccmInfo["ManagementPoints"] += $mpData
                Write-Info "MP" "$($mp.MP) [Site: $($mp.SiteCode)]"
            }
        }
        
        # Distribution Points
        Write-SubSection "Distribution Points (cached)"
        $dpInfo = Safe-WMIQuery "SELECT * FROM SMS_ActiveDP" -Namespace "root\ccm\SoftwareDistribution"
        $sccmInfo["DistributionPoints"] = @()
        if ($dpInfo) {
            foreach ($dp in $dpInfo) {
                $sccmInfo["DistributionPoints"] += $dp.ServerName
                Write-Info "DP" $dp.ServerName
            }
        }
        
        # Boundary Information
        Write-SubSection "Boundary Information"
        $boundary = Safe-WMIQuery "SELECT * FROM SMS_ActiveMPCandidate" -Namespace "root\ccm\LocationServices"
        if ($boundary) {
            foreach ($b in $boundary) {
                Write-Info "Active MP Candidate" "$($b.MP) - Type: $($b.Type)"
            }
        }
        
        # Client Components
        Write-SubSection "Client Components"
        $components = Safe-WMIQuery "SELECT * FROM CCM_InstalledComponent" -Namespace "root\ccm"
        $sccmInfo["Components"] = @()
        if ($components) {
            foreach ($comp in $components) {
                $sccmInfo["Components"] += @{
                    Name = $comp.Name
                    Version = $comp.Version
                }
                Write-Info "Component" "$($comp.Name) v$($comp.Version)"
            }
        }
        
        # Registry Information
        Write-SubSection "Registry Configuration"
        $regPath = "HKLM:\SOFTWARE\Microsoft\CCM"
        $sccmInfo["RegistryConfig"] = @{}
        
        $regValues = @(
            @{Path = "$regPath"; Name = "GUID"},
            @{Path = "$regPath"; Name = "LogLevel"},
            @{Path = "$regPath"; Name = "LogMaxSize"},
            @{Path = "$regPath\CcmEval"; Name = "LastEvalTime"}
        )
        
        foreach ($rv in $regValues) {
            $value = Safe-RegistryValue -Path $rv.Path -Name $rv.Name
            if ($value) {
                $sccmInfo["RegistryConfig"][$rv.Name] = $value
                Write-Info $rv.Name $value
            }
        }
        
        # Cache Information
        Write-SubSection "Client Cache Information"
        $cache = Safe-WMIQuery "SELECT * FROM CacheConfig" -Namespace "root\ccm\SoftMgmtAgent"
        if ($cache) {
            $sccmInfo["CacheLocation"] = $cache.Location
            $sccmInfo["CacheSize"] = "$($cache.Size) MB"
            Write-Info "Cache Location" $sccmInfo["CacheLocation"]
            Write-Info "Cache Size" $sccmInfo["CacheSize"]
        }
    }
    
    $Script:DiscoveryResults["SCCMClientInfo"] = $sccmInfo
}
#endregion

#region SCCM Infrastructure Discovery from Active Directory
function Get-SCCMInfrastructureFromAD {
    Write-Section "SCCM INFRASTRUCTURE DISCOVERY (Active Directory)"
    
    $sccmADInfo = [ordered]@{}
    
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configNC = $rootDSE.configurationNamingContext
        $defaultNC = $rootDSE.defaultNamingContext
        
        # Search for SCCM System Container
        Write-SubSection "SCCM System Management Container"
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://CN=System Management,CN=System,$defaultNC"
        $searcher.PageSize = 1000
        
        # Find Site Servers
        Write-SubSection "Site Servers (from AD)"
        $searcher.Filter = "(objectClass=mSSMSSite)"
        $sccmADInfo["Sites"] = @()
        
        try {
            $sites = $searcher.FindAll()
            foreach ($site in $sites) {
                $siteProps = $site.Properties
                $siteData = @{
                    SiteCode = [string]$siteProps["mssmsroamingboundaries"]
                    Name = [string]$siteProps["name"]
                    DN = [string]$siteProps["distinguishedname"]
                }
                $sccmADInfo["Sites"] += $siteData
                Write-Info "Site" "$($siteData.Name)"
            }
        }
        catch {
            Write-Host "    [!] Unable to enumerate sites from AD" -ForegroundColor Yellow
        }
        
        # Find Management Points
        Write-SubSection "Management Points (from AD)"
        $searcher.Filter = "(objectClass=mSSMSManagementPoint)"
        $sccmADInfo["ManagementPoints"] = @()
        
        try {
            $mps = $searcher.FindAll()
            foreach ($mp in $mps) {
                $mpProps = $mp.Properties
                $mpData = @{
                    Name = [string]$mpProps["mssmsmpname"]
                    SiteCode = [string]$mpProps["mssmssitecode"]
                    DefaultMP = [string]$mpProps["mssmsdefaultmp"]
                    DeviceMP = [string]$mpProps["mssmsdevicemanagementpoint"]
                    MPAddress = [string]$mpProps["mssmsmpaddress"]
                }
                $sccmADInfo["ManagementPoints"] += $mpData
                Write-Info "Management Point" "$($mpData.Name) [Site: $($mpData.SiteCode)]"
                if ($mpData.MPAddress) {
                    Write-Info "  MP Address" $mpData.MPAddress
                }
            }
        }
        catch {
            Write-Host "    [!] Unable to enumerate Management Points from AD" -ForegroundColor Yellow
        }
        
        # Find Server Locator Points (legacy)
        Write-SubSection "Server Locator Points (from AD - Legacy)"
        $searcher.Filter = "(objectClass=mSSMSServerLocatorPoint)"
        $sccmADInfo["ServerLocatorPoints"] = @()
        
        try {
            $slps = $searcher.FindAll()
            foreach ($slp in $slps) {
                $slpProps = $slp.Properties
                $slpName = [string]$slpProps["mssmslslpname"]
                if ($slpName) {
                    $sccmADInfo["ServerLocatorPoints"] += $slpName
                    Write-Info "SLP" $slpName
                }
            }
            if ($sccmADInfo["ServerLocatorPoints"].Count -eq 0) {
                Write-Info "SLP" "None found (expected in modern SCCM)"
            }
        }
        catch {
            Write-Host "    [!] Unable to enumerate SLPs from AD" -ForegroundColor Yellow
        }
        
        # Look for SCCM-related Service Connection Points
        Write-SubSection "Service Connection Points"
        $searcher.SearchRoot = [ADSI]"LDAP://$configNC"
        $searcher.Filter = "(&(objectClass=serviceConnectionPoint)(keywords=*SMS*))"
        $sccmADInfo["ServiceConnectionPoints"] = @()
        
        try {
            $scps = $searcher.FindAll()
            foreach ($scp in $scps) {
                $scpProps = $scp.Properties
                $scpData = @{
                    Name = [string]$scpProps["cn"]
                    Keywords = ($scpProps["keywords"] | ForEach-Object { $_.ToString() }) -join ", "
                    ServiceBindingInfo = ($scpProps["servicebindinginformation"] | ForEach-Object { $_.ToString() }) -join "; "
                }
                $sccmADInfo["ServiceConnectionPoints"] += $scpData
                Write-Info "SCP" "$($scpData.Name)"
                Write-Info "  Keywords" $scpData.Keywords
            }
        }
        catch {
            Write-Host "    [!] Unable to enumerate SCPs" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Host "    [!] Unable to query Active Directory for SCCM objects: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    $Script:DiscoveryResults["SCCMFromAD"] = $sccmADInfo
}
#endregion

#region SCCM Server Polling
function Get-SCCMServerInformation {
    Write-Section "SCCM SERVER INFRASTRUCTURE POLLING"
    
    $serverInfo = [ordered]@{}
    
    # Get Management Point from local client or AD discovery
    $mpToQuery = $null
    
    if ($Script:DiscoveryResults["SCCMClientInfo"]["CurrentManagementPoint"]) {
        $mpToQuery = $Script:DiscoveryResults["SCCMClientInfo"]["CurrentManagementPoint"]
    }
    elseif ($Script:DiscoveryResults["SCCMFromAD"]["ManagementPoints"].Count -gt 0) {
        $mpToQuery = $Script:DiscoveryResults["SCCMFromAD"]["ManagementPoints"][0].Name
    }
    
    if ($mpToQuery) {
        Write-SubSection "Querying Management Point: $mpToQuery"
        
        # Try to get MP information via HTTP
        Write-SubSection "Management Point HTTP Endpoints"
        $mpEndpoints = @(
            "/sms_mp/.sms_aut?mplist",
            "/sms_mp/.sms_aut?mpcert",
            "/sms_mp/.sms_aut?SITESIGNCERT"
        )
        
        $serverInfo["MPEndpointResponses"] = @{}
        foreach ($endpoint in $mpEndpoints) {
            $url = "http://$mpToQuery$endpoint"
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                $serverInfo["MPEndpointResponses"][$endpoint] = "Accessible (Status: $($response.StatusCode))"
                Write-Info "Endpoint" "$endpoint - Accessible"
                
                # Parse MP List if available
                if ($endpoint -like "*mplist*" -and $response.Content) {
                    Write-SubSection "Management Point List (from HTTP)"
                    try {
                        [xml]$mpListXml = $response.Content
                        foreach ($mpEntry in $mpListXml.MPList.MP) {
                            Write-Info "MP Entry" "$($mpEntry.Name) [Site: $($mpEntry.SiteCode)]"
                        }
                    }
                    catch {
                        Write-Host "    [!] Unable to parse MP list XML" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                $serverInfo["MPEndpointResponses"][$endpoint] = "Not accessible or requires authentication"
                Write-Info "Endpoint" "$endpoint - Not accessible"
            }
        }
        
        # Try WMI query against MP (requires permissions)
        Write-SubSection "Remote WMI Query (if permitted)"
        try {
            $remoteSiteInfo = Safe-WMIQuery "SELECT * FROM SMS_ProviderLocation" -Namespace "root\sms" -ComputerName $mpToQuery
            if ($remoteSiteInfo) {
                $serverInfo["ProviderLocations"] = @()
                foreach ($provider in $remoteSiteInfo) {
                    $providerData = @{
                        SiteCode = $provider.SiteCode
                        Machine = $provider.Machine
                        ProviderForLocalSite = $provider.ProviderForLocalSite
                    }
                    $serverInfo["ProviderLocations"] += $providerData
                    Write-Info "SMS Provider" "$($provider.Machine) [Site: $($provider.SiteCode)]"
                }
            }
        }
        catch {
            Write-Host "    [!] Remote WMI not accessible (expected without admin rights)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "    [!] No Management Point identified for polling" -ForegroundColor Yellow
    }
    
    # DNS-based discovery
    Write-SubSection "DNS-based SCCM Discovery"
    $serverInfo["DNSRecords"] = @{}
    
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        $dnsQueries = @(
            "_mssms_mp_*._tcp.$domain",
            "_mssms_slp._tcp.$domain"
        )
        
        foreach ($query in $dnsQueries) {
            try {
                # Try to resolve SRV records
                $srvRecords = Resolve-DnsName -Name $query -Type SRV -ErrorAction SilentlyContinue
                if ($srvRecords) {
                    $serverInfo["DNSRecords"][$query] = @()
                    foreach ($record in $srvRecords) {
                        if ($record.Type -eq "SRV") {
                            $serverInfo["DNSRecords"][$query] += "$($record.NameTarget):$($record.Port)"
                            Write-Info "SRV Record" "$($record.NameTarget):$($record.Port)"
                        }
                    }
                }
            }
            catch {
                # SRV records may not exist
            }
        }
    }
    
    $Script:DiscoveryResults["SCCMServerInfo"] = $serverInfo
}
#endregion

#region Site System Roles Discovery
function Get-SCCMSiteSystemRoles {
    Write-Section "SCCM SITE SYSTEM ROLES DISCOVERY"
    
    $roleInfo = [ordered]@{}
    
    # Query local client for cached site system information
    Write-SubSection "Site Systems (from local client cache)"
    
    $roleInfo["SiteSystemsFromCache"] = @()
    
    # Try to get information from client LocationServices namespace
    $locationServices = Safe-WMIQuery "SELECT * FROM SMS_MPInformation" -Namespace "root\ccm"
    if ($locationServices) {
        foreach ($ls in $locationServices) {
            $roleInfo["SiteSystemsFromCache"] += @{
                Name = $ls.MP
                Role = "Management Point"
                SiteCode = $ls.SiteCode
            }
        }
    }
    
    # Software Update Points
    Write-SubSection "Software Update Points"
    $supInfo = Safe-WMIQuery "SELECT * FROM CCM_UpdateSource" -Namespace "root\ccm\SoftwareUpdates\WUAHandler"
    $roleInfo["SoftwareUpdatePoints"] = @()
    if ($supInfo) {
        foreach ($sup in $supInfo) {
            $roleInfo["SoftwareUpdatePoints"] += $sup.UpdateSource
            Write-Info "SUP" $sup.UpdateSource
        }
    }
    else {
        Write-Host "    No SUP information in client cache" -ForegroundColor Gray
    }
    
    # State Migration Points
    Write-SubSection "State Migration Points"
    $smpInfo = Safe-WMIQuery "SELECT * FROM SMS_StateMigrationPoint" -Namespace "root\ccm\LocationServices"
    $roleInfo["StateMigrationPoints"] = @()
    if ($smpInfo) {
        foreach ($smp in $smpInfo) {
            $roleInfo["StateMigrationPoints"] += $smp.ServerName
            Write-Info "SMP" $smp.ServerName
        }
    }
    else {
        Write-Host "    No SMP information in client cache" -ForegroundColor Gray
    }
    
    # Application Catalog (legacy)
    Write-SubSection "Application Catalog (Legacy)"
    $appCatalogReg = Safe-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\CCM\ApplicationCatalog" -Name "WebServiceUrl"
    if ($appCatalogReg) {
        $roleInfo["ApplicationCatalog"] = $appCatalogReg
        Write-Info "App Catalog URL" $appCatalogReg
    }
    else {
        Write-Host "    No Application Catalog configured (expected in modern SCCM)" -ForegroundColor Gray
    }
    
    # Cloud Management Gateway check
    Write-SubSection "Cloud Management Gateway"
    $cmgInfo = Safe-WMIQuery "SELECT * FROM SMS_ActiveMPCandidate WHERE Type = 'CMG'" -Namespace "root\ccm\LocationServices"
    $roleInfo["CloudManagementGateway"] = @()
    if ($cmgInfo) {
        foreach ($cmg in $cmgInfo) {
            $roleInfo["CloudManagementGateway"] += $cmg.MP
            Write-Info "CMG" $cmg.MP
        }
    }
    else {
        Write-Host "    No CMG information in client cache" -ForegroundColor Gray
    }
    
    $Script:DiscoveryResults["SiteSystemRoles"] = $roleInfo
}
#endregion

#region Collection and Policy Information
function Get-SCCMCollectionInfo {
    Write-Section "SCCM COLLECTIONS & POLICY INFORMATION"
    
    $collectionInfo = [ordered]@{}
    
    # Collection membership
    Write-SubSection "Collection Membership"
    $collections = Safe-WMIQuery "SELECT * FROM CCM_CollectionVariable" -Namespace "root\ccm\Policy\Machine"
    $collectionInfo["Collections"] = @()
    
    if ($collections) {
        foreach ($col in $collections) {
            $collectionInfo["Collections"] += $col.CollectionID
            Write-Info "Collection" $col.CollectionID
        }
    }
    
    # Alternatively check RequestedConfig
    $collMembership = Safe-WMIQuery "SELECT * FROM CCM_ClientSiteMode" -Namespace "root\ccm"
    if ($collMembership) {
        Write-Info "Client Site Mode" $collMembership.SiteMode
    }
    
    # Policies received
    Write-SubSection "Recent Policy Information"
    $machinePolicy = Safe-WMIQuery "SELECT * FROM CCM_Policy" -Namespace "root\ccm\Policy\Machine\RequestedConfig"
    if ($machinePolicy) {
        $policyCount = ($machinePolicy | Measure-Object).Count
        Write-Info "Machine Policies" "$policyCount policies cached"
    }
    
    # Deployments
    Write-SubSection "Active Deployments (Assignments)"
    $assignments = Safe-WMIQuery "SELECT * FROM CCM_ApplicationCIAssignment" -Namespace "root\ccm\Policy\Machine\ActualConfig"
    $collectionInfo["ApplicationDeployments"] = @()
    if ($assignments) {
        foreach ($assignment in $assignments | Select-Object -First 10) {
            $collectionInfo["ApplicationDeployments"] += $assignment.AssignmentName
            Write-Info "Deployment" $assignment.AssignmentName
        }
        $totalAssignments = ($assignments | Measure-Object).Count
        if ($totalAssignments -gt 10) {
            Write-Host "    ... and $($totalAssignments - 10) more deployments" -ForegroundColor Gray
        }
    }
    
    $Script:DiscoveryResults["CollectionInfo"] = $collectionInfo
}
#endregion

#region Boundary and Network Information
function Get-SCCMBoundaryInfo {
    Write-Section "SCCM BOUNDARY & NETWORK LOCATION INFORMATION"
    
    $boundaryInfo = [ordered]@{}
    
    # Current boundary
    Write-SubSection "Current Boundary Information"
    $adSite = Safe-WMIQuery "SELECT * FROM CCM_ADSite" -Namespace "root\ccm\LocationServices"
    if ($adSite) {
        $boundaryInfo["ADSite"] = $adSite.SiteName
        Write-Info "AD Site" $adSite.SiteName
    }
    
    # IP Subnets
    $ipInfo = Safe-WMIQuery "SELECT * FROM CCM_NetworkLocation" -Namespace "root\ccm\LocationServices"
    $boundaryInfo["NetworkLocations"] = @()
    if ($ipInfo) {
        foreach ($net in $ipInfo) {
            $boundaryInfo["NetworkLocations"] += @{
                Subnet = $net.IPSubnet
                ADSite = $net.ADSiteName
            }
            Write-Info "Network" "$($net.IPSubnet) - AD Site: $($net.ADSiteName)"
        }
    }
    
    # Boundary Groups
    Write-SubSection "Boundary Group Membership"
    $boundaryGroups = Safe-WMIQuery "SELECT * FROM SMS_BoundaryGroupRelationship" -Namespace "root\ccm\LocationServices"
    $boundaryInfo["BoundaryGroups"] = @()
    if ($boundaryGroups) {
        foreach ($bg in $boundaryGroups) {
            $boundaryInfo["BoundaryGroups"] += $bg.BoundaryGroupID
            Write-Info "Boundary Group ID" $bg.BoundaryGroupID
        }
    }
    else {
        # Alternative method
        $bgCache = Safe-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\CCM\LocationServices" -Name "BoundaryGroupIDs"
        if ($bgCache) {
            Write-Info "Boundary Group IDs" $bgCache
        }
    }
    
    $Script:DiscoveryResults["BoundaryInfo"] = $boundaryInfo
}
#endregion

#region Output and Export
function Export-DiscoveryResults {
    param([string]$Path)
    
    Write-Section "EXPORT RESULTS"
    
    $output = @"
================================================================================
SCCM AND DOMAIN DISCOVERY REPORT
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME
User: $env:USERDOMAIN\$env:USERNAME
================================================================================

"@
    
    function ConvertTo-ReportText($obj, $indent = 0) {
        $result = ""
        $prefix = "  " * $indent
        
        if ($obj -is [hashtable] -or $obj -is [System.Collections.Specialized.OrderedDictionary]) {
            foreach ($key in $obj.Keys) {
                $value = $obj[$key]
                if ($value -is [array]) {
                    $result += "$prefix$key:`n"
                    foreach ($item in $value) {
                        if ($item -is [hashtable]) {
                            $result += ConvertTo-ReportText $item ($indent + 1)
                            $result += "$prefix  ---`n"
                        }
                        else {
                            $result += "$prefix  - $item`n"
                        }
                    }
                }
                elseif ($value -is [hashtable]) {
                    $result += "$prefix$key:`n"
                    $result += ConvertTo-ReportText $value ($indent + 1)
                }
                else {
                    $result += "$prefix$key : $value`n"
                }
            }
        }
        return $result
    }
    
    foreach ($section in $Script:DiscoveryResults.Keys) {
        $output += "`n--- $section ---`n"
        $output += ConvertTo-ReportText $Script:DiscoveryResults[$section]
    }
    
    $output | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "  Results exported to: $Path" -ForegroundColor Green
    
    # Also export as JSON for programmatic use
    $jsonPath = $Path -replace "\.txt$", ".json"
    $Script:DiscoveryResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "  JSON export: $jsonPath" -ForegroundColor Green
}
#endregion

#region Main Execution
function Invoke-SCCMDiscovery {
    Write-Host @"

    ╔═══════════════════════════════════════════════════════════════════╗
    ║       SCCM & DOMAIN INFRASTRUCTURE DISCOVERY SCRIPT               ║
    ║                    Domain User Context                            ║
    ╚═══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    Write-Host "  Starting discovery at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "  Running as: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
    Write-Host "  Target: $env:COMPUTERNAME" -ForegroundColor White
    
    # Execute discovery functions
    Get-LocalDomainInformation
    Get-LocalSCCMClientInformation
    Get-SCCMInfrastructureFromAD
    Get-SCCMServerInformation
    Get-SCCMSiteSystemRoles
    Get-SCCMCollectionInfo
    Get-SCCMBoundaryInfo
    
    # Summary
    Write-Section "DISCOVERY SUMMARY"
    
    Write-SubSection "Domain"
    Write-Info "Domain" $Script:DiscoveryResults["DomainInformation"]["Domain"]
    Write-Info "Forest" $Script:DiscoveryResults["DomainInformation"]["ADForestName"]
    
    Write-SubSection "SCCM"
    Write-Info "Client Installed" $Script:DiscoveryResults["SCCMClientInfo"]["ClientInstalled"]
    if ($Script:DiscoveryResults["SCCMClientInfo"]["ClientInstalled"]) {
        Write-Info "Client Version" $Script:DiscoveryResults["SCCMClientInfo"]["ClientVersion"]
        Write-Info "Site Code" $Script:DiscoveryResults["SCCMClientInfo"]["AssignedSite"]
        Write-Info "Management Point" $Script:DiscoveryResults["SCCMClientInfo"]["CurrentManagementPoint"]
    }
    
    $mpCount = $Script:DiscoveryResults["SCCMFromAD"]["ManagementPoints"].Count
    Write-Info "MPs Discovered (AD)" $mpCount
    
    # Export if requested
    if ($ExportToFile) {
        Export-DiscoveryResults -Path $OutputPath
    }
    
    Write-Host "`n  Discovery completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host "`n  To export results, run with -ExportToFile switch" -ForegroundColor Yellow
    
    # Return results object for programmatic use
    return $Script:DiscoveryResults
}

# Run the discovery
$results = Invoke-SCCMDiscovery

# Return results for pipeline use
return $results
#endregion
