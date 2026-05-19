# ASPM Host Iterator - Enhanced ServiceNow Integration

🚀 **Automated ASPM Host Discovery and Correlation Tool**

A powerful Python script that automatically discovers all hosts from CrowdStrike ASPM deployments, correlates them with Falcon host management data, and enriches services with comprehensive ASPM metadata for seamless ServiceNow integration.

## 🎯 Key Features

### Enhanced ASPM Correlation

- ✅ **Risk Assessment**: Automatic risk scoring (0-100) and severity classification (Low/Medium/High/Critical)
- ✅ **Technology Detection**: Intelligent detection of technology stacks (Java, Node.js, Python, .NET, etc.)
- ✅ **Service Classification**: Automatic categorization (API Service, Web Application, Database Service, etc.)
- ✅ **Deployment Correlation**: Complete host-service mapping with deployment context
- ✅ **Interface Discovery**: Enhanced endpoint data with schema detection (HTTP/HTTPS)
- ✅ **ASPM Signatures**: Persistent signature tracking for service identification

### Flexible Host Targeting

- 🎯 **All Hosts**: Discover and process all hosts from ASPM deployments
- 🎯 **Single Host**: Target a specific hostname for focused analysis
- 🎯 **Multiple Hosts**: Process a list of specific hostnames
- 🎯 **File-Based**: Load hostnames from a text file for batch processing

### ServiceNow Integration Ready

- 📋 **CMDB CI Integration**: All required fields for Configuration Item records
- 🚨 **Incident Integration**: Risk assessment data for security incident prioritization
- 🔗 **Host Correlation**: Complete deployment context for asset management
- 📊 **Technology Inventory**: Stack analysis for compliance and governance

## 📦 Installation

### Prerequisites

- Python 3.7+
- CrowdStrike API credentials with ASPM access
- `requests` library

### Setup

```bash
# Clone the repository
git clone https://github.com/mikedzikowski/aspm-inventory-script.git
cd aspm-inventory-script

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (recommended)
export CROWDSTRIKE_CLIENT_ID="your_client_id"
export CROWDSTRIKE_CLIENT_SECRET="your_client_secret"
```

## 🚀 Usage

### Basic Usage Examples

#### 1. Process All Hosts (Auto Discovery)

```bash
python3 aspm_host_iterator.py --auto
```

#### 2. Target a Single Host

```bash
python3 aspm_host_iterator.py --auto --hostname web-app-server-01
```

#### 3. Target Multiple Specific Hosts

```bash
python3 aspm_host_iterator.py --auto --hostnames web-app-server-01 api-gateway-prod database-server-main
```

#### 4. Target Hosts from File

```bash
python3 aspm_host_iterator.py --auto --hostnames-file example_hosts.txt
```

#### 5. Interactive Mode (Review Each Host)

```bash
python3 aspm_host_iterator.py --interactive --hostname web-app-server-01
```

#### 6. Testing with Limits

```bash
python3 aspm_host_iterator.py --auto --max-hosts 5
```

### Advanced Usage

#### Using API Credentials Directly

```bash
python3 aspm_host_iterator.py --auto \
  --client-id "your_client_id" \
  --client-secret "your_client_secret" \
  --hostname web-app-server-01
```

#### Custom API Base URL

```bash
python3 aspm_host_iterator.py --auto \
  --base-url "https://api.eu-1.crowdstrike.com" \
  --hostnames-file production_hosts.txt
```

## 📋 Host List File Format

Create a text file with one hostname per line (see `example_hosts.txt`):

```text
web-app-server-01
api-gateway-prod
database-server-main
frontend-load-balancer
backend-services-cluster
monitoring-dashboard-vm
```

## 🔧 Command Line Options

| Option | Description | Example |
| --- | --- | --- |
| `--auto` | Fully automated processing (no interaction) | `--auto` |
| `--interactive` | Interactive mode (review each host) | `--interactive` |
| `--hostname` | Target a specific hostname | `--hostname web-app-server-01` |
| `--hostnames` | Target multiple hostnames | `--hostnames vm1 vm2 vm3` |
| `--hostnames-file` | Load hostnames from file | `--hostnames-file hosts.txt` |
| `--max-hosts` | Limit number of hosts (testing) | `--max-hosts 5` |
| `--client-id` | CrowdStrike API Client ID | `--client-id "abc123"` |
| `--client-secret` | CrowdStrike API Client Secret | `--client-secret "xyz789"` |
| `--base-url` | Custom API base URL | `--base-url "https://api.eu-1.crowdstrike.com"` |

## 📊 Output Files

The script generates comprehensive JSON files with different naming conventions:

- **All Hosts**: `aspm_all_hosts_YYYYMMDD_HHMMSS.json`
- **Single Host**: `aspm_single_host_{hostname}_YYYYMMDD_HHMMSS.json`
- **Multiple Hosts**: `aspm_targeted_hosts_{count}_hosts_YYYYMMDD_HHMMSS.json`

## 📋 Output Structure

### Metadata

```json
{
  "metadata": {
    "generated_at": "2026-05-18T19:42:12.613069",
    "export_type": "aspm_host_iteration_enhanced_servicenow_correlation",
    "version": "2.0",
    "statistics": {
      "total_hosts_discovered": 3,
      "total_services_found": 3,
      "total_interfaces_found": 24,
      "high_risk_services": 1,
      "critical_risk_services": 1,
      "technology_distribution": {
        "NodeJS": 1,
        "Python": 1,
        "Java": 1
      }
    }
  }
}
```

### Host Data Structure

Each processed host includes:

- **Falcon Host Details**: Essential system information (OS, IPs, hardware, etc.)
- **ASPM Services**: Deployed services with full correlation data
- **Risk Assessment**: Risk scores and severity levels
- **Technology Stack**: Detected technologies and service types
- **Interface Discovery**: API endpoints with schema detection
- **Deployment Context**: Host-service correlation data

See `example_output_sanitized.json` for a complete example.

## 🎯 ServiceNow Integration Fields

The script provides all necessary fields for ServiceNow integration:

### CMDB Configuration Items (CI)

- `device_id`, `hostname`, `os_version`, `platform_name`
- `local_ip`, `external_ip`, `mac_address`
- `service_provider`, `instance_id` (for cloud assets)
- `first_seen`, `last_seen`, `criticality`

### Service Correlation

- `riskScore`, `riskSeverity` (for incident prioritization)
- `technology`, `type` (for service classification)
- `deployment_hosts` (host correlation)
- `persistentSignature` (service tracking)
- `interfaces` (endpoint discovery)

## 🔍 Example Scenarios

### Scenario 1: Security Assessment

```bash
# Get risk assessment for critical production hosts
python3 aspm_host_iterator.py --auto --hostnames-file production_hosts.txt
```

**Use Case**: Identify high-risk services across production infrastructure for security prioritization.

### Scenario 2: Compliance Audit

```bash
# Inventory all hosts with technology stack analysis
python3 aspm_host_iterator.py --auto
```

**Use Case**: Generate complete technology inventory for compliance reporting and governance.

### Scenario 3: Incident Response

```bash
# Quick analysis of specific compromised host
python3 aspm_host_iterator.py --auto --hostname suspicious-server-01
```

**Use Case**: Rapidly gather host details and service inventory during security incidents.

### Scenario 4: ServiceNow CMDB Sync

```bash
# Bulk export for CMDB integration
python3 aspm_host_iterator.py --auto --hostnames-file cmdb_targets.txt
```

**Use Case**: Automated data export for ServiceNow CMDB configuration item updates.

## 🛠️ Technical Details

### API Endpoints Used

- **ASPM Query API**: `/aspm-api-gateway/api/v1/query`
- **Falcon Hosts API**: `/devices/queries/devices/v1`, `/devices/entities/devices/v2`

### Authentication

- OAuth2 client credentials flow
- Requires `aspm:read` and `hosts:read` scopes

### Query Strategy

The script uses an optimized query approach:

1. **Service Discovery**: Query `in:services` to get all services with ASPM metadata
2. **Deployment Correlation**: Use `in:deployments and services:(name:"service_name")` to find host deployments
3. **Host Matching**: Cross-reference deployment names with target hostnames
4. **Falcon Enrichment**: Correlate with Falcon host management data

## 📈 Performance

- **Throughput**: ~2-3 hosts per second (varies with service count)
- **Scalability**: Handles 100+ hosts efficiently
- **Rate Limiting**: Built-in API rate limiting and retry logic
- **Memory Usage**: Optimized for large host inventories

## 🔧 Troubleshooting

### Common Issues

#### Authentication Failures

```bash
❌ Error: CrowdStrike credentials required!
```

**Solution**: Set environment variables or use `--client-id`/`--client-secret` flags

#### No Services Found

```bash
⚠️ No deployed services found for hostname
```

**Solution**: Verify hostname exists in ASPM deployments and has associated services

#### API Rate Limiting

```bash
❌ Error: Rate limited by API
```

**Solution**: Script automatically retries with exponential backoff

### Debug Mode

Add verbose logging by modifying the script to include debug output for troubleshooting API queries.

## 📁 Repository Structure

```text
aspm-inventory-script/
├── aspm_host_iterator.py          # Main script
├── requirements.txt               # Python dependencies
├── example_hosts.txt             # Sample host list file
├── example_output_sanitized.json # Example output (sanitized)
├── README.md                     # This file
└── LICENSE                       # MIT License
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏷️ Version History

- **v2.0** - Enhanced ServiceNow integration with ASPM correlation
- **v1.5** - Added flexible host targeting (single, multiple, file-based)
- **v1.0** - Initial release with basic host discovery

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/mikedzikowski/aspm-inventory-script/issues)
- **Documentation**: See example outputs and usage scenarios above
- **CrowdStrike API**: [Official API Documentation](https://falcon.crowdstrike.com/documentation)

---

🎯 **Ready for Enterprise ServiceNow Integration** | 🛡️ **Enhanced Security Correlation** | 🚀 **Automated Host Discovery**