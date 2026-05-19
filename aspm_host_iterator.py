#!/usr/bin/env python3
"""
ASPM Host Iterator - Enhanced with ServiceNow Correlation Data
=============================================================

This script automatically discovers ALL hosts currently inventoried in ASPM and
loops through each one to gather comprehensive host details, deployed services,
and API interfaces with full ASMP correlation data for ServiceNow integration.

Key Improvements over manual web interface:
- Automatic host discovery from ASPM deployments
- Batch processing of all hosts with enhanced ASPM metadata
- Rich progress reporting with real-time status
- Interactive mode with host-by-host review option
- Comprehensive export capabilities with ServiceNow correlation
- Error handling and retry logic

Enhanced ASPM Features:
- Risk scoring and severity assessment for all services
- Technology stack detection and classification
- Service type identification (API, Web App, Database, etc.)
- Deployment host correlation with full context
- Enhanced interface data with schema detection (HTTP/HTTPS)
- ASPM signature tracking for persistent service identification
- ServiceNow CMDB CI and Incident integration ready

Features:
- Auto-discovers hosts from ASPM deployments API
- Enriches each host with Falcon host management data
- Finds deployed services and interfaces per host with ASPM correlation
- Schema detection (HTTP/HTTPS) and API architecture analysis
- Risk assessment and technology classification per service
- Multiple output formats (JSON, CSV, interactive console)
- Progress bars and detailed logging

Usage:
    python3 aspm_host_iterator.py --auto                    # Fully automated
    python3 aspm_host_iterator.py --interactive             # Review each host
    python3 aspm_host_iterator.py --auto --export-format json csv   # Auto with exports
"""

import json
import requests
import argparse
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import os
from urllib.parse import urlparse

class ASPMHostIterator:
    """Automated iterator through all ASPM inventoried hosts"""

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        """Initialize the host iterator"""
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip('/')
        self.token = None
        self.token_expires_at = None
        self.session = requests.Session()

        # Data storage
        self.discovered_hosts = []
        self.processed_hosts = []
        self.failed_hosts = []

        # Statistics
        self.stats = {
            'total_hosts_discovered': 0,
            'total_hosts_processed': 0,
            'total_services_found': 0,
            'total_interfaces_found': 0,
            'hosts_with_services': 0,
            'hosts_with_falcon_data': 0,
            'processing_errors': 0,
            # Enhanced ASPM correlation statistics
            'high_risk_services': 0,
            'critical_risk_services': 0,
            'services_with_multiple_interfaces': 0,
            'total_deployment_correlations': 0,
            'technology_distribution': {},
            'service_type_distribution': {}
        }

    def authenticate(self) -> bool:
        """Authenticate with CrowdStrike API"""
        print("🔐 Authenticating with CrowdStrike API...")

        try:
            token_url = f"{self.base_url}/oauth2/token"
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials'
            }

            response = self.session.post(token_url, headers=headers, data=data, timeout=30)
            response.raise_for_status()

            result = response.json()
            self.token = result.get('access_token')
            expires_in = result.get('expires_in', 1800)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)

            if not self.token:
                print("❌ Failed to obtain access token")
                return False

            print("✅ Authentication successful")
            return True

        except requests.exceptions.RequestException as e:
            print(f"❌ Authentication failed: {e}")
            return False

    def refresh_token_if_needed(self) -> bool:
        """Refresh token if needed"""
        if not self.token_expires_at or datetime.now() >= self.token_expires_at:
            print("🔄 Token expired, refreshing...")
            return self.authenticate()
        return True

    def make_authenticated_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make authenticated request with auto-refresh"""
        if not self.refresh_token_if_needed():
            return None

        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self.token}'
        kwargs['headers'] = headers

        try:
            response = self.session.request(method, url, timeout=60, **kwargs)
            if response.status_code == 401:
                print("🔄 Token expired during request, refreshing...")
                if self.authenticate():
                    headers['Authorization'] = f'Bearer {self.token}'
                    response = self.session.request(method, url, timeout=60, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            return None

    def discover_all_hosts_from_aspm(self) -> List[str]:
        """Discover all hosts from ASPM deployments API"""
        print("🔍 Discovering all hosts from ASPM deployments...")

        try:
            url = f"{self.base_url}/aspm-api-gateway/api/v1/query"
            headers = {'Content-Type': 'application/json'}

            # Query all deployments to find host names
            payload = {
                "query": "in:deployments",
                "params": {
                    "selectFields": {
                        "fields": ["*"],
                        "withoutServices": False
                    },
                    "paginate": {
                        "limit": 100,
                        "offset": 0
                    }
                }
            }

            all_deployments = []
            offset = 0

            while True:
                payload["params"]["paginate"]["offset"] = offset
                response = self.make_authenticated_request('POST', url, json=payload)

                if not response or response.status_code != 200:
                    print(f"❌ Failed to query deployments at offset {offset}")
                    break

                result = response.json()
                deployments = result.get("resources", result.get("resultJson", []))

                if not deployments:
                    break

                all_deployments.extend(deployments)
                print(f"   📊 Retrieved {len(all_deployments)} deployments so far...")

                if len(deployments) < 100:
                    break

                offset += 100
                time.sleep(0.2)

            # Extract unique hostnames from deployments
            host_names = set()
            for deployment in all_deployments:
                name = deployment.get('name', '')
                if name and self._looks_like_hostname(name):
                    host_names.add(name)

            discovered_hosts = sorted(list(host_names))
            self.stats['total_hosts_discovered'] = len(discovered_hosts)

            print(f"✅ Discovered {len(discovered_hosts)} unique hosts from ASPM deployments")

            # Show sample of discovered hosts
            sample_size = min(10, len(discovered_hosts))
            if discovered_hosts:
                print(f"   📋 Sample hosts: {discovered_hosts[:sample_size]}")
                if len(discovered_hosts) > sample_size:
                    print(f"   📋 ... and {len(discovered_hosts) - sample_size} more")

            return discovered_hosts

        except Exception as e:
            print(f"❌ Failed to discover hosts: {e}")
            return []

    def _looks_like_hostname(self, name: str) -> bool:
        """Determine if a deployment name looks like a hostname"""
        if not name or len(name) < 3:
            return False

        # Skip obvious external services
        external_indicators = [
            'api.', '.com', '.org', '.net', '.io', 'http://', 'https://',
            'www.', 'localhost'
        ]

        name_lower = name.lower()
        for indicator in external_indicators:
            if indicator in name_lower:
                return False

        # Look for hostname patterns
        hostname_indicators = [
            '-vm', '-host', '-server', 'vm-', 'host-', 'server-',
            'aspm', 'backend', 'frontend', 'database', 'db-',
            'web-', 'app-', 'api-', 'svc-', 'prod-', 'dev-', 'test-'
        ]

        for indicator in hostname_indicators:
            if indicator in name_lower:
                return True

        # If it contains dashes or underscores and no dots, likely internal
        if ('-' in name or '_' in name) and '.' not in name:
            return True

        return False

    def get_host_details_from_falcon(self, hostname: str) -> Dict[str, Any]:
        """Get detailed host information from Falcon Hosts API (filtered fields only)"""
        try:
            # Find device by hostname
            query_url = f"{self.base_url}/devices/queries/devices/v1"
            params = {'filter': f"hostname:'{hostname}'", 'limit': 1}

            response = self.make_authenticated_request('GET', query_url, params=params)
            if not response or response.status_code != 200:
                return {}

            result = response.json()
            device_ids = result.get('resources', [])

            if not device_ids:
                return {}

            # Get detailed host information
            details_url = f"{self.base_url}/devices/entities/devices/v2"
            params = {'ids': device_ids[0]}

            response = self.make_authenticated_request('GET', details_url, params=params)
            if not response or response.status_code != 200:
                return {}

            result = response.json()
            devices = result.get('resources', [])

            if not devices:
                return {}

            # Extract only the desired fields for cleaner output
            raw_data = devices[0]

            # Define the fields to include in the output
            desired_fields = [
                "device_id", "cid", "agent_load_flags", "agent_local_time", "agent_version",
                "bios_manufacturer", "bios_version", "config_id_base", "config_id_build",
                "config_id_platform", "cpu_signature", "cpu_vendor", "external_ip",
                "mac_address", "instance_id", "service_provider", "service_provider_account_id",
                "hostname", "filesystem_containment_status", "first_seen", "last_seen",
                "safe_mode", "criticality", "local_ip", "machine_domain", "major_version",
                "minor_version", "os_version", "platform_id", "platform_name"
            ]

            # Create filtered falcon data with only desired fields
            filtered_falcon_data = {}
            for field in desired_fields:
                if field in raw_data:
                    filtered_falcon_data[field] = raw_data[field]

            print(f"   📋 Filtered Falcon data - included {len(filtered_falcon_data)} essential fields")
            return filtered_falcon_data

        except Exception as e:
            print(f"   ❌ Error getting Falcon data for {hostname}: {e}")
            return {}

    def get_deployed_services_for_host(self, hostname: str) -> List[Dict[str, Any]]:
        """Get services deployed on a specific host from ASPM with enhanced correlation data"""
        try:
            url = f"{self.base_url}/aspm-api-gateway/api/v1/query"

            print(f"   🔍 Using working ASPM service discovery approach for {hostname}...")

            # FIXED APPROACH 1: Get all services from ASPM first (this has the correlation data)
            services_payload = {
                "query": "in:services",
                "params": {
                    "selectFields": {"fields": ["*"]},
                    "paginate": {"limit": 100, "offset": 0}  # Get more services
                }
            }

            response = self.make_authenticated_request('POST', url, json=services_payload)
            if not response or response.status_code != 200:
                print(f"      ❌ Failed to get services from ASPM")
                return []

            result = response.json()
            all_services = result.get("resources", result.get("resultJson", []))
            print(f"      📋 Found {len(all_services)} total services in ASPM")

            # FIXED APPROACH 2: For each service, check if it's deployed on our target host
            enriched_services = []
            for service in all_services:
                service_name = service.get('name', '')
                if not service_name:
                    continue

                # Use the working deployment query approach
                deployment_payload = {
                    "query": f"in:deployments and services:(name:\"{service_name}\")",
                    "params": {
                        "selectFields": {"fields": ["*"]},
                        "paginate": {"limit": 20, "offset": 0}
                    }
                }

                deployment_response = self.make_authenticated_request('POST', url, json=deployment_payload)
                if deployment_response and deployment_response.status_code == 200:
                    deployment_result = deployment_response.json()
                    service_deployments = deployment_result.get("resources", deployment_result.get("resultJson", []))

                    # Check if any deployment matches our target hostname
                    for deployment in service_deployments:
                        deployment_name = deployment.get("name", "").lower()
                        if deployment_name == hostname.lower():
                            print(f"      ✅ Service '{service_name}' is deployed on {hostname}")
                            # Enrich service with ASPM correlation data and deployment info
                            enriched_service = self._enrich_service_with_aspm_data(service, hostname, deployment)
                            enriched_services.append(enriched_service)
                            break

            print(f"      📊 Found {len(enriched_services)} services deployed on {hostname}")
            return enriched_services

        except Exception as e:
            print(f"   ❌ Error getting services for {hostname}: {e}")
            return []

    def _enrich_service_with_aspm_data(self, service: Dict[str, Any], hostname: str, deployment: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich service data with ASPM correlation metadata for ServiceNow integration"""
        # Start with the original service data (which already has ASPM fields!)
        enriched_service = service.copy()

        print(f"         🔍 Service '{service.get('name')}' has ASPM fields: {list(service.keys())}")

        # The service already has most ASPM correlation data, just add deployment context
        enriched_service.update({
            # Deployment Correlation (add host context)
            'deployment_hosts': [hostname],  # Host where this service is deployed
            'deployments': [{
                'hostname': hostname,
                'deployment_id': deployment.get('id', ''),
                'deployment_name': deployment.get('name', hostname),
                'deployment_status': deployment.get('status', 'active')
            }]
        })

        # Use existing ASPM values or provide intelligent defaults if missing
        if 'riskScore' not in enriched_service:
            enriched_service['riskScore'] = self._calculate_risk_score(service)
        if 'riskSeverity' not in enriched_service:
            enriched_service['riskSeverity'] = self._determine_risk_severity(service)
        if 'technology' not in enriched_service:
            enriched_service['technology'] = self._detect_technology(service)
        if 'type' not in enriched_service:
            enriched_service['type'] = self._classify_service_type(service)

        # Ensure ID is present
        if 'id' not in enriched_service:
            enriched_service['id'] = f"aspm-service-{service.get('name', 'unknown')}-{hostname}"

        # Add persistentSignature if missing
        if 'persistentSignature' not in enriched_service:
            enriched_service['persistentSignature'] = service.get('signature', f"{service.get('name', 'unknown')}-{hostname}")

        return enriched_service

    def _calculate_risk_score(self, service: Dict[str, Any]) -> int:
        """Calculate a risk score based on service characteristics"""
        base_score = 50  # Default medium risk

        # Increase risk for certain characteristics
        name = service.get('name', '').lower()
        if any(keyword in name for keyword in ['admin', 'api', 'database', 'auth', 'login']):
            base_score += 20

        if any(keyword in name for keyword in ['test', 'dev', 'debug']):
            base_score += 15

        # Check interface count (more interfaces = higher exposure)
        interfaces = service.get('interfaces', [])
        if len(interfaces) > 5:
            base_score += 10
        elif len(interfaces) > 10:
            base_score += 20

        return min(base_score, 100)  # Cap at 100

    def _determine_risk_severity(self, service: Dict[str, Any]) -> str:
        """Determine risk severity based on calculated risk score"""
        risk_score = self._calculate_risk_score(service)

        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

    def _detect_technology(self, service: Dict[str, Any]) -> str:
        """Detect the technology stack based on service characteristics"""
        name = service.get('name', '').lower()

        # Technology detection patterns
        if any(tech in name for tech in ['java', 'spring', 'tomcat']):
            return "Java"
        elif any(tech in name for tech in ['node', 'express', 'npm']):
            return "Node.js"
        elif any(tech in name for tech in ['python', 'django', 'flask']):
            return "Python"
        elif any(tech in name for tech in ['dotnet', '.net', 'aspnet']):
            return ".NET"
        elif any(tech in name for tech in ['php', 'laravel', 'symfony']):
            return "PHP"
        elif any(tech in name for tech in ['go', 'golang']):
            return "Go"
        elif any(tech in name for tech in ['ruby', 'rails']):
            return "Ruby"
        else:
            return "Unknown"

    def _classify_service_type(self, service: Dict[str, Any]) -> str:
        """Classify the service type based on its characteristics"""
        name = service.get('name', '').lower()

        if any(keyword in name for keyword in ['api', 'rest', 'graphql', 'endpoint']):
            return "API Service"
        elif any(keyword in name for keyword in ['web', 'frontend', 'ui', 'portal']):
            return "Web Application"
        elif any(keyword in name for keyword in ['database', 'db', 'sql', 'mongo', 'redis']):
            return "Database Service"
        elif any(keyword in name for keyword in ['auth', 'login', 'oauth', 'saml']):
            return "Authentication Service"
        elif any(keyword in name for keyword in ['queue', 'message', 'kafka', 'rabbit']):
            return "Message Queue"
        elif any(keyword in name for keyword in ['cache', 'redis', 'memcached']):
            return "Cache Service"
        else:
            return "Application Service"

    def _enhance_interfaces_with_schema_detection(self, interfaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance interface data with schema detection and standardization"""
        enhanced_interfaces = []

        for interface in interfaces:
            if not isinstance(interface, dict):
                continue

            enhanced_interface = interface.copy()

            # Ensure schema detection
            if 'schema' not in enhanced_interface:
                # Try to detect from URL or path
                path = interface.get('path', '')
                url = interface.get('url', '')

                if path.startswith('https://') or url.startswith('https://'):
                    enhanced_interface['schema'] = 'https'
                elif path.startswith('http://') or url.startswith('http://'):
                    enhanced_interface['schema'] = 'http'
                else:
                    # Default to HTTP for internal services
                    enhanced_interface['schema'] = 'http'

            # Ensure method is present
            if 'method' not in enhanced_interface:
                enhanced_interface['method'] = 'GET'  # Default to GET

            # Ensure type classification
            if 'type' not in enhanced_interface:
                enhanced_interface['type'] = 'HTTP'  # Default type

            # Add endpoint metadata
            enhanced_interface.update({
                'endpoint_id': f"ep-{interface.get('id', 'unknown')}-{len(enhanced_interfaces)}",
                'discovery_source': 'CrowdStrike ASPM'
            })

            enhanced_interfaces.append(enhanced_interface)

        return enhanced_interfaces

    def get_interfaces_for_service(self, service_name: str) -> List[Dict[str, Any]]:
        """Get interfaces for a specific service from ASPM"""
        try:
            url = f"{self.base_url}/aspm-api-gateway/api/v1/query"

            # Query all interfaces and filter for this service
            payload = {
                "query": "in:interfaces",
                "params": {
                    "selectFields": {"fields": ["*"]},
                    "paginate": {"limit": 1000, "offset": 0}
                }
            }

            response = self.make_authenticated_request('POST', url, json=payload)
            if not response or response.status_code != 200:
                return []

            result = response.json()
            all_interfaces = result.get("resources", result.get("resultJson", []))

            # Filter interfaces for this service
            service_interfaces = []
            for interface in all_interfaces:
                interface_service = interface.get('service')
                if isinstance(interface_service, dict):
                    interface_service_name = interface_service.get('name', '')
                else:
                    interface_service_name = str(interface_service) if interface_service else ''

                if interface_service_name.lower() == service_name.lower():
                    service_interfaces.append(interface)

            return service_interfaces

        except Exception as e:
            print(f"   ❌ Error getting interfaces for service {service_name}: {e}")
            return []

    def process_single_host(self, hostname: str, interactive: bool = False) -> Dict[str, Any]:
        """Process a single host and gather all its data"""
        print(f"\n🖥️ Processing host: {hostname}")

        host_data = {
            'hostname': hostname,
            'falcon_details': {},
            'deployed_services': [],
            'total_interfaces': 0,
            'processing_status': 'success',
            'error_message': None
        }

        try:
            # Step 1: Get Falcon host details
            print(f"   🔍 Querying Falcon for host details...")
            falcon_details = self.get_host_details_from_falcon(hostname)

            if falcon_details:
                host_data['falcon_details'] = falcon_details
                self.stats['hosts_with_falcon_data'] += 1
                print(f"   ✅ Found Falcon data: {falcon_details.get('os_version', 'Unknown OS')} on {falcon_details.get('platform_name', 'Unknown Platform')}")
            else:
                print(f"   ⚠️ No Falcon data found for {hostname}")

            # Step 2: Get deployed services
            print(f"   🔍 Querying ASPM for deployed services...")
            deployed_services = self.get_deployed_services_for_host(hostname)

            if deployed_services:
                host_data['deployed_services'] = deployed_services
                self.stats['hosts_with_services'] += 1
                self.stats['total_services_found'] += len(deployed_services)
                print(f"   ✅ Found {len(deployed_services)} deployed services")

                # Step 3: Get interfaces for each service and collect enhanced ASPM statistics
                total_interfaces = 0
                for service in deployed_services:
                    service_name = service.get('name', '')
                    if service_name:
                        print(f"   🔍 Getting interfaces for service: {service_name}")
                        interfaces = self.get_interfaces_for_service(service_name)
                        service['interfaces'] = self._enhance_interfaces_with_schema_detection(interfaces)
                        total_interfaces += len(service['interfaces'])
                        if service['interfaces']:
                            print(f"      ✅ Found {len(service['interfaces'])} interfaces")

                    # Collect enhanced ASPM statistics
                    risk_severity = service.get('riskSeverity', 'Unknown')
                    if risk_severity == 'High':
                        self.stats['high_risk_services'] += 1
                    elif risk_severity == 'Critical':
                        self.stats['critical_risk_services'] += 1

                    if len(service.get('interfaces', [])) > 5:
                        self.stats['services_with_multiple_interfaces'] += 1

                    # Track technology distribution
                    technology = service.get('technology', 'Unknown')
                    self.stats['technology_distribution'][technology] = self.stats['technology_distribution'].get(technology, 0) + 1

                    # Track service type distribution
                    service_type = service.get('type', 'Unknown')
                    self.stats['service_type_distribution'][service_type] = self.stats['service_type_distribution'].get(service_type, 0) + 1

                    # Track deployment correlations
                    deployment_hosts = service.get('deployment_hosts', [])
                    if deployment_hosts:
                        self.stats['total_deployment_correlations'] += len(deployment_hosts)

                host_data['total_interfaces'] = total_interfaces
                self.stats['total_interfaces_found'] += total_interfaces
                print(f"   📊 Total interfaces found: {total_interfaces}")
            else:
                print(f"   ⚠️ No deployed services found for {hostname}")

            # Interactive review
            if interactive:
                self._interactive_host_review(host_data)

            self.stats['total_hosts_processed'] += 1

        except Exception as e:
            host_data['processing_status'] = 'error'
            host_data['error_message'] = str(e)
            self.stats['processing_errors'] += 1
            print(f"   ❌ Error processing {hostname}: {e}")

        return host_data

    def _interactive_host_review(self, host_data: Dict[str, Any]):
        """Interactive review of host data with enhanced ASPM correlation information"""
        hostname = host_data['hostname']
        print(f"\n📋 INTERACTIVE REVIEW: {hostname}")
        print("=" * 50)

        # Show Falcon details
        falcon = host_data.get('falcon_details', {})
        if falcon:
            print(f"🖥️ Falcon Details:")
            print(f"   OS: {falcon.get('os_version', 'Unknown')}")
            print(f"   Platform: {falcon.get('platform_name', 'Unknown')}")
            print(f"   Local IP: {falcon.get('local_ip', 'Unknown')}")
            print(f"   External IP: {falcon.get('external_ip', 'Unknown')}")
            print(f"   Last Seen: {falcon.get('last_seen', 'Unknown')}")
            print(f"   Zone Group: {falcon.get('zone_group', 'Unknown')}")
        else:
            print("🖥️ Falcon Details: None found")

        # Show deployed services with enhanced ASPM data
        services = host_data.get('deployed_services', [])
        if services:
            print(f"\n🔧 Deployed Services ({len(services)}):")
            for i, service in enumerate(services, 1):
                service_name = service.get('name', 'Unknown')
                risk_score = service.get('riskScore', 'N/A')
                risk_severity = service.get('riskSeverity', 'Unknown')
                technology = service.get('technology', 'Unknown')
                service_type = service.get('type', 'Unknown')
                interface_count = len(service.get('interfaces', []))

                print(f"   {i}. {service_name}")
                print(f"      🎯 Type: {service_type} | Tech: {technology}")
                print(f"      ⚠️ Risk: {risk_severity} (Score: {risk_score})")
                print(f"      🔌 Interfaces: {interface_count}")

                # Show some interface details if available
                interfaces = service.get('interfaces', [])
                if interfaces:
                    for j, interface in enumerate(interfaces[:3], 1):  # Show first 3
                        schema = interface.get('schema', 'http')
                        method = interface.get('method', 'GET')
                        path = interface.get('path', interface.get('url', 'Unknown'))
                        print(f"         {j}. {method} {schema}://{path}")
                    if len(interfaces) > 3:
                        print(f"         ... and {len(interfaces) - 3} more interfaces")
        else:
            print("\n🔧 Deployed Services: None found")

        print(f"\n📊 Total Interfaces: {host_data.get('total_interfaces', 0)}")

        # Show ASPM correlation summary
        total_services = len(services)
        high_risk_services = len([s for s in services if s.get('riskSeverity') in ['High', 'Critical']])
        if total_services > 0:
            print(f"\n🎯 ASPM Risk Assessment:")
            print(f"   High/Critical Risk Services: {high_risk_services}/{total_services}")

            # Show technology breakdown
            technologies = {}
            for service in services:
                tech = service.get('technology', 'Unknown')
                technologies[tech] = technologies.get(tech, 0) + 1

            if technologies:
                print(f"   Technology Stack: {', '.join(f'{tech}({count})' for tech, count in technologies.items())}")

        # Ask user if they want to continue
        while True:
            choice = input("\nContinue to next host? (y/n/q to quit): ").lower().strip()
            if choice in ['y', 'yes', '']:
                break
            elif choice in ['n', 'no']:
                print("⏸️ Pausing... Press Enter to continue")
                input()
                break
            elif choice in ['q', 'quit']:
                print("🛑 User requested quit")
                sys.exit(0)
            else:
                print("Please enter 'y', 'n', or 'q'")

    def run_automated_iteration(self, interactive: bool = False, max_hosts: Optional[int] = None, target_hostnames: Optional[List[str]] = None):
        """Run automated iteration through all ASPM hosts or target specific hostnames"""
        print("🚀 Starting Automated ASPM Host Iteration")
        print("=" * 55)

        # Authenticate
        if not self.authenticate():
            return False

        # Handle target hostnames mode (single or multiple)
        if target_hostnames:
            print(f"🎯 Targeting {len(target_hostnames)} specific hostname(s): {', '.join(target_hostnames)}")

            # Process the target hosts
            start_time = datetime.now()
            for i, hostname in enumerate(target_hostnames, 1):
                print(f"\n📍 Progress: {i}/{len(target_hostnames)} ({(i/len(target_hostnames)*100):.1f}%)")

                host_data = self.process_single_host(hostname, interactive)

                if host_data['processing_status'] == 'success':
                    self.processed_hosts.append(host_data)
                else:
                    self.failed_hosts.append(host_data)

                # Show running statistics for multiple hosts
                if len(target_hostnames) > 1:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    avg_time = elapsed / i
                    remaining = (len(target_hostnames) - i) * avg_time
                    print(f"   ⏱️ Elapsed: {elapsed:.1f}s | Avg: {avg_time:.1f}s/host | ETA: {remaining:.1f}s")

            # Set discovered hosts and stats
            self.discovered_hosts = target_hostnames
            self.stats['total_hosts_discovered'] = len(target_hostnames)

            # Print final summary
            self._print_final_summary()

            # Generate exports
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if len(target_hostnames) == 1:
                json_file = f"aspm_single_host_{target_hostnames[0]}_{timestamp}.json"
            else:
                json_file = f"aspm_targeted_hosts_{len(target_hostnames)}_hosts_{timestamp}.json"
            self._export_to_json(json_file)

            return True

        # Discover all hosts (original logic)
        discovered_hosts = self.discover_all_hosts_from_aspm()
        if not discovered_hosts:
            print("❌ No hosts discovered from ASPM deployments")
            return False

        self.discovered_hosts = discovered_hosts

        # Limit hosts if specified
        if max_hosts and max_hosts < len(discovered_hosts):
            discovered_hosts = discovered_hosts[:max_hosts]
            print(f"⚠️ Limited to first {max_hosts} hosts for testing")

        print(f"\n🎯 Processing {len(discovered_hosts)} hosts...")
        if interactive:
            print("📋 Interactive mode: You'll review each host individually")

        # Process each host
        start_time = datetime.now()
        for i, hostname in enumerate(discovered_hosts, 1):
            print(f"\n📍 Progress: {i}/{len(discovered_hosts)} ({(i/len(discovered_hosts)*100):.1f}%)")

            host_data = self.process_single_host(hostname, interactive)

            if host_data['processing_status'] == 'success':
                self.processed_hosts.append(host_data)
            else:
                self.failed_hosts.append(host_data)

            # Show running statistics
            elapsed = (datetime.now() - start_time).total_seconds()
            avg_time = elapsed / i
            remaining = (len(discovered_hosts) - i) * avg_time

            print(f"   ⏱️ Elapsed: {elapsed:.1f}s | Avg: {avg_time:.1f}s/host | ETA: {remaining:.1f}s")

        # Print final summary
        self._print_final_summary()

        # Generate exports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"aspm_all_hosts_{timestamp}.json"
        self._export_to_json(json_file)

        return True

    def _print_final_summary(self):
        """Print comprehensive final summary with enhanced ASPM correlation data"""
        print("\n" + "="*70)
        print("📊 ASPM HOST ITERATION COMPLETE - Enhanced with ServiceNow Correlation")
        print("="*70)

        print(f"🔍 Discovery Results:")
        print(f"   Hosts Discovered: {self.stats['total_hosts_discovered']}")
        print(f"   Hosts Processed Successfully: {self.stats['total_hosts_processed']}")
        print(f"   Processing Errors: {self.stats['processing_errors']}")

        print(f"\n🖥️ Host Details:")
        print(f"   Hosts with Falcon Data: {self.stats['hosts_with_falcon_data']}")
        print(f"   Hosts with Services: {self.stats['hosts_with_services']}")

        print(f"\n🔧 Services & APIs:")
        print(f"   Total Services Found: {self.stats['total_services_found']}")
        print(f"   Total Interfaces Found: {self.stats['total_interfaces_found']}")
        print(f"   Services with 5+ Interfaces: {self.stats['services_with_multiple_interfaces']}")
        print(f"   Total Deployment Correlations: {self.stats['total_deployment_correlations']}")

        print(f"\n⚠️ ASPM Risk Assessment:")
        print(f"   High Risk Services: {self.stats['high_risk_services']}")
        print(f"   Critical Risk Services: {self.stats['critical_risk_services']}")
        total_risk_services = self.stats['high_risk_services'] + self.stats['critical_risk_services']
        if self.stats['total_services_found'] > 0:
            risk_percentage = (total_risk_services / self.stats['total_services_found']) * 100
            print(f"   High/Critical Risk Percentage: {risk_percentage:.1f}%")

        # Technology Distribution
        if self.stats['technology_distribution']:
            print(f"\n🔧 Technology Stack Distribution:")
            for tech, count in sorted(self.stats['technology_distribution'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.stats['total_services_found']) * 100 if self.stats['total_services_found'] > 0 else 0
                print(f"   {tech}: {count} services ({percentage:.1f}%)")

        # Service Type Distribution
        if self.stats['service_type_distribution']:
            print(f"\n📋 Service Type Distribution:")
            for service_type, count in sorted(self.stats['service_type_distribution'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.stats['total_services_found']) * 100 if self.stats['total_services_found'] > 0 else 0
                print(f"   {service_type}: {count} services ({percentage:.1f}%)")

        if self.stats['total_hosts_processed'] > 0:
            avg_services = self.stats['total_services_found'] / self.stats['total_hosts_processed']
            avg_interfaces = self.stats['total_interfaces_found'] / self.stats['total_hosts_processed']
            print(f"\n📈 Averages per Host:")
            print(f"   Services per Host: {avg_services:.1f}")
            print(f"   Interfaces per Host: {avg_interfaces:.1f}")

        # Show failed hosts if any
        if self.failed_hosts:
            print(f"\n❌ Failed Hosts ({len(self.failed_hosts)}):")
            for failed in self.failed_hosts:
                print(f"   • {failed['hostname']}: {failed['error_message']}")

        print(f"\n🎯 ServiceNow Integration Status:")
        print(f"   All services enriched with ASPM correlation data")
        print(f"   Risk scoring and severity assessment completed")
        print(f"   Technology detection and service classification completed")
        print(f"   Schema detection (HTTP/HTTPS) completed for all interfaces")
        print(f"   Ready for ServiceNow CMDB CI and Incident export")

        print("="*70)

    def _export_to_json(self, filename: str):
        """Export all data to comprehensive JSON file with enhanced ASPM correlation"""
        export_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "export_type": "aspm_host_iteration_enhanced_servicenow_correlation",
                "version": "2.0",
                "enhancement": "ServiceNow integration ready with ASPM correlation",
                "statistics": self.stats,
                "features": [
                    "ASPM risk scoring and severity assessment",
                    "Technology stack detection and classification",
                    "Service type identification and categorization",
                    "Deployment host correlation with full context",
                    "Enhanced interface data with schema detection",
                    "ASPM signature tracking for persistent identification",
                    "ServiceNow CMDB CI integration ready",
                    "ServiceNow Incident integration ready"
                ]
            },
            "discovered_hosts": self.discovered_hosts,
            "processed_hosts": self.processed_hosts,
            "failed_hosts": self.failed_hosts
        }

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            print(f"\n✅ Enhanced ASPM correlation data exported to: {filename}")
            print(f"   📋 Ready for ServiceNow CMDB CI and Incident integration")
            print(f"   🎯 Includes risk assessment, technology detection, and schema validation")
        except IOError as e:
            print(f"❌ Failed to export data: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Automated iteration through all ASPM inventoried hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fully automated processing (all hosts)
  python3 aspm_host_iterator.py --auto

  # Interactive mode (review each host)
  python3 aspm_host_iterator.py --interactive

  # Target a specific hostname
  python3 aspm_host_iterator.py --auto --hostname aspm-backend-vm

  # Target multiple specific hostnames
  python3 aspm_host_iterator.py --auto --hostnames aspm-backend-vm aspm-frontend-vm customer-pii-vm

  # Target hostnames from a file
  python3 aspm_host_iterator.py --auto --hostnames-file my_hosts.txt

  # Auto mode with limits (for testing)
  python3 aspm_host_iterator.py --auto --max-hosts 5

  # Using environment variables for credentials
  python3 aspm_host_iterator.py --auto
        """
    )

    parser.add_argument('--client-id', help='CrowdStrike API Client ID')
    parser.add_argument('--client-secret', help='CrowdStrike API Client Secret')
    parser.add_argument('--base-url', default='https://api.crowdstrike.com',
                       help='CrowdStrike API Base URL')
    parser.add_argument('--auto', action='store_true',
                       help='Fully automated processing (no interaction)')
    parser.add_argument('--interactive', action='store_true',
                       help='Interactive mode (review each host)')
    parser.add_argument('--hostname', type=str,
                       help='Target a specific hostname (e.g., aspm-backend-vm)')
    parser.add_argument('--hostnames', type=str, nargs='+',
                       help='Target multiple specific hostnames (e.g., aspm-backend-vm aspm-frontend-vm)')
    parser.add_argument('--hostnames-file', type=str,
                       help='File containing list of hostnames (one per line)')
    parser.add_argument('--max-hosts', type=int,
                       help='Maximum number of hosts to process (for testing)')

    args = parser.parse_args()

    # Determine mode
    if not args.auto and not args.interactive:
        # Default to interactive if no mode specified
        args.interactive = True

    # Get credentials
    client_id = args.client_id or os.getenv('CROWDSTRIKE_CLIENT_ID')
    client_secret = args.client_secret or os.getenv('CROWDSTRIKE_CLIENT_SECRET')

    if not client_id or not client_secret:
        print("❌ Error: CrowdStrike credentials required!")
        print("Provide via:")
        print("  --client-id and --client-secret arguments")
        print("  CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET environment variables")
        sys.exit(1)

    # Prepare target hostnames list
    target_hostnames = None
    if args.hostname:
        target_hostnames = [args.hostname]
    elif args.hostnames:
        target_hostnames = args.hostnames
    elif args.hostnames_file:
        try:
            with open(args.hostnames_file, 'r') as f:
                target_hostnames = [line.strip() for line in f.readlines() if line.strip()]
            print(f"📋 Loaded {len(target_hostnames)} hostnames from file: {args.hostnames_file}")
        except FileNotFoundError:
            print(f"❌ Error: Hostnames file not found: {args.hostnames_file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading hostnames file: {e}")
            sys.exit(1)

    # Create iterator and run
    iterator = ASPMHostIterator(
        client_id=client_id,
        client_secret=client_secret,
        base_url=args.base_url
    )

    success = iterator.run_automated_iteration(
        interactive=args.interactive,
        max_hosts=args.max_hosts,
        target_hostnames=target_hostnames
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()