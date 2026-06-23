#!/usr/bin/env python3
"""
ASPM Host Iterator - Enterprise Production Version
==================================================

Enterprise-grade features:
1. Token refresh for long operations
2. Batch processing for large host lists
3. Better error handling and reporting
4. Fallback strategies for API limits
5. Performance optimization for enterprise scale
"""

import json
import urllib.request
import urllib.parse
import os
import sys
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

class ASPMHostIteratorEnterprise:
    """Enterprise-hardened version with batch processing and token refresh"""

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        """Initialize with enterprise-grade settings"""
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip('/')
        self.token = None
        self.token_expires = None

        # Enterprise configuration
        self.batch_size = int(os.getenv('ASPM_BATCH_SIZE', '8'))  # Limit OR query complexity
        self.max_retries = int(os.getenv('ASPM_MAX_RETRIES', '3'))
        self.retry_delay = float(os.getenv('ASPM_RETRY_DELAY', '5.0'))
        self.token_refresh_buffer = int(os.getenv('ASPM_TOKEN_BUFFER', '300'))  # 5 min buffer

        # Statistics and caching
        self.discovered_hosts = []
        self.processed_hosts = []
        self.failed_hosts = []
        self._all_services_cache = None
        self._service_deployment_cache = {}

        self.stats = {
            'total_hosts_discovered': 0,
            'total_hosts_processed': 0,
            'total_services_found': 0,
            'api_calls_made': 0,
            'token_refreshes': 0,
            'batch_operations': 0,
            'failed_operations': 0
        }

        print(f"🏢 Enterprise mode: batch_size={self.batch_size}, max_retries={self.max_retries}")

    def _needs_token_refresh(self) -> bool:
        """Check if token needs refresh (with buffer time)"""
        if not self.token or not self.token_expires:
            return True

        # Refresh if within buffer time of expiration
        buffer_time = datetime.now() + timedelta(seconds=self.token_refresh_buffer)
        return buffer_time >= self.token_expires

    def _refresh_token_if_needed(self) -> bool:
        """Refresh token if needed for long operations"""
        if self._needs_token_refresh():
            print("🔄 Refreshing authentication token...")
            if self.authenticate():
                self.stats['token_refreshes'] += 1
                return True
            return False
        return True

    def authenticate(self) -> bool:
        """Authenticate with CrowdStrike API and track token expiration"""
        print("🔐 Authenticating with CrowdStrike API...")

        try:
            url = f"{self.base_url}/oauth2/token"
            data = urllib.parse.urlencode({
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials'
            }).encode()

            req = urllib.request.Request(url, data=data)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            req.add_header('Accept', 'application/json')

            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                self.token = result.get('access_token')
                expires_in = result.get('expires_in', 3600)  # Default 1 hour

                # Track token expiration
                self.token_expires = datetime.now() + timedelta(seconds=expires_in)

                self.stats['api_calls_made'] += 1

            if self.token:
                print(f"✅ Authentication successful (expires in {expires_in}s)")
                return True
            else:
                print("❌ Authentication failed: No token received")
                return False

        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False

    def _make_api_call_with_retry(self, url: str, payload: Dict, description: str = "API call") -> Optional[Dict]:
        """Make API call with retry logic and token refresh"""

        for attempt in range(self.max_retries + 1):
            try:
                # Refresh token if needed before each attempt
                if not self._refresh_token_if_needed():
                    print(f"❌ Token refresh failed for {description}")
                    return None

                data = json.dumps(payload).encode()
                req = urllib.request.Request(url, data=data, method='POST')
                req.add_header('Authorization', f'Bearer {self.token}')
                req.add_header('Content-Type', 'application/json')

                with urllib.request.urlopen(req) as response:
                    result = json.loads(response.read().decode())
                    self.stats['api_calls_made'] += 1
                    return result

            except urllib.error.HTTPError as e:
                if e.code == 401:  # Unauthorized
                    print(f"🚨 Unauthorized error on attempt {attempt + 1} for {description}")
                    if attempt < self.max_retries:
                        print("🔄 Forcing token refresh...")
                        self.token = None  # Force refresh
                        time.sleep(self.retry_delay)
                        continue
                    else:
                        print(f"❌ Max retries exceeded for {description}")
                        self.stats['failed_operations'] += 1
                        return None
                else:
                    print(f"❌ HTTP Error {e.code} for {description}: {e}")
                    self.stats['failed_operations'] += 1
                    return None
            except Exception as e:
                print(f"❌ Error on attempt {attempt + 1} for {description}: {e}")
                if attempt < self.max_retries:
                    print(f"⏳ Retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    print(f"❌ Max retries exceeded for {description}")
                    self.stats['failed_operations'] += 1
                    return None

        return None

    def discover_hosts_batch_optimized(self, target_hosts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Discover hosts using batch processing for large host lists"""

        if not target_hosts:
            print("🔍 [ENTERPRISE] Discovering all hosts...")
            return self._discover_all_hosts()

        if len(target_hosts) <= self.batch_size:
            print(f"🎯 [ENTERPRISE] Small batch: {len(target_hosts)} hosts (single query)")
            return self._discover_hosts_single_batch(target_hosts)
        else:
            print(f"🏭 [ENTERPRISE] Large batch: {len(target_hosts)} hosts ({len(target_hosts) // self.batch_size + 1} batches)")
            return self._discover_hosts_multi_batch(target_hosts)

    def _discover_all_hosts(self) -> List[Dict[str, Any]]:
        """Discover all hosts (original approach)"""
        url = f"{self.base_url}/aspm-api-gateway/api/v1/query"
        payload = {
            "query": "in:deployments AND type:\"Machine\"",
            "params": {
                "selectFields": {"fields": ["*"], "withoutServices": False},
                "paginate": {"limit": 100, "offset": 0}
            }
        }

        result = self._make_api_call_with_retry(url, payload, "discover all hosts")
        if result:
            hosts = result.get("resources", result.get("resultJson", []))
            print(f"📊 Retrieved {len(hosts)} total hosts")
            return hosts
        return []

    def _discover_hosts_single_batch(self, target_hosts: List[str]) -> List[Dict[str, Any]]:
        """Discover hosts using single server-side filtered query"""
        url = f"{self.base_url}/aspm-api-gateway/api/v1/query"

        hostname_filters = ' OR '.join([f'name:"{host}"' for host in target_hosts])
        query = f"in:deployments AND type:\"Machine\" AND ({hostname_filters})"

        payload = {
            "query": query,
            "params": {
                "selectFields": {"fields": ["*"], "withoutServices": False},
                "paginate": {"limit": 100, "offset": 0}
            }
        }

        print(f"   🚀 Server-side filtering: {len(target_hosts)} hosts in single query")
        result = self._make_api_call_with_retry(url, payload, f"discover {len(target_hosts)} hosts")

        if result:
            hosts = result.get("resources", result.get("resultJson", []))
            print(f"   📊 Retrieved {len(hosts)} matching hosts")
            return hosts
        return []

    def _discover_hosts_multi_batch(self, target_hosts: List[str]) -> List[Dict[str, Any]]:
        """Discover hosts using multiple batch queries to avoid API limits"""
        all_hosts = []
        batch_count = 0

        # Split into batches to avoid overly complex queries
        for i in range(0, len(target_hosts), self.batch_size):
            batch_hosts = target_hosts[i:i + self.batch_size]
            batch_count += 1

            print(f"   📦 Batch {batch_count}: {len(batch_hosts)} hosts")

            batch_result = self._discover_hosts_single_batch(batch_hosts)
            if batch_result:
                all_hosts.extend(batch_result)
                print(f"   ✅ Batch {batch_count}: Found {len(batch_result)} hosts")
            else:
                print(f"   ❌ Batch {batch_count}: Failed")

            self.stats['batch_operations'] += 1

            # Small delay between batches to avoid rate limiting
            if i + self.batch_size < len(target_hosts):
                time.sleep(0.5)

        print(f"🏭 Batch processing complete: {len(all_hosts)} total hosts found")
        return all_hosts

    def get_services_for_host_enterprise(self, host_id: str, hostname: str) -> List[Dict[str, Any]]:
        """Get services with enterprise retry logic and better error handling"""
        try:
            print(f"      🔍 Finding services for {hostname} (ID: {host_id})")

            # Use cached services with retry logic
            all_services = self._get_all_services_cached_enterprise()
            if not all_services:
                print(f"      ❌ No services available for correlation")
                return []

            print(f"      📊 Checking {len(all_services)} cached services...")

            found_services = []
            failed_correlations = 0

            for service in all_services:
                service_id = service.get('id')
                service_name = service.get('name', 'Unknown')

                # Check cache first
                cache_key = f"{service_id}_{host_id}"
                if cache_key in self._service_deployment_cache:
                    if self._service_deployment_cache[cache_key]:
                        found_services.append(self._service_deployment_cache[cache_key])
                    continue

                # Query deployments for this service with retry logic
                url = f"{self.base_url}/aspm-api-gateway/api/v1/query"
                dep_payload = {
                    "query": f"in:deployments AND services:(id:{service_id})",
                    "params": {
                        "selectFields": {"fields": ["*"]},
                        "paginate": {"limit": 100, "offset": 0}
                    }
                }

                dep_result = self._make_api_call_with_retry(url, dep_payload, f"service {service_name} deployment")

                if not dep_result:
                    failed_correlations += 1
                    self._service_deployment_cache[cache_key] = None
                    continue

                deployments = dep_result.get("resources", dep_result.get("resultJson", []))

                # Check if deployment matches our host
                service_found = False
                for deployment in deployments:
                    dep_name = deployment.get('name', '')
                    dep_id = str(deployment.get('id', ''))

                    if dep_name == hostname or dep_id == host_id:
                        print(f"      ✅ Found service '{service_name}' on {hostname}")

                        # Create enriched service object
                        enriched_service = {
                            'id': service_id,
                            'name': service_name,
                            'riskScore': service.get('riskScore', 0),
                            'riskSeverity': service.get('riskSeverity', 'Unknown'),
                            'technology': service.get('technology', 'Unknown'),
                            'interfaces': []  # Would be populated by interface query
                        }

                        self._service_deployment_cache[cache_key] = enriched_service
                        found_services.append(enriched_service)
                        service_found = True
                        break

                if not service_found:
                    self._service_deployment_cache[cache_key] = None

            if failed_correlations > 0:
                print(f"      ⚠️ {failed_correlations} service correlations failed")

            print(f"      ✅ Found {len(found_services)} services on {hostname}")
            return found_services

        except Exception as e:
            print(f"   ❌ Error getting services for {hostname}: {e}")
            return []

    def _get_all_services_cached_enterprise(self) -> List[Dict[str, Any]]:
        """Get all services with enterprise retry logic"""
        if self._all_services_cache is not None:
            return self._all_services_cache

        print("🔄 [ENTERPRISE] Caching all services...")

        url = f"{self.base_url}/aspm-api-gateway/api/v1/query"
        payload = {
            "query": "in:services",
            "params": {
                "selectFields": {"fields": ["*"], "withoutServices": False},
                "paginate": {"limit": 1000, "offset": 0}
            }
        }

        result = self._make_api_call_with_retry(url, payload, "cache all services")

        if result:
            self._all_services_cache = result.get("resources", result.get("resultJson", []))
            print(f"   ✅ Cached {len(self._all_services_cache)} services")
            return self._all_services_cache
        else:
            print(f"   ❌ Failed to cache services")
            return []

    def run_enterprise_iteration(self, max_hosts: Optional[int] = None, target_hosts: Optional[List[str]] = None):
        """Run enterprise iteration with batch processing and error handling"""
        print("🏢 [ENTERPRISE] ASPM Host Iterator - Production Scale")
        print("=" * 70)

        start_time = time.time()

        if not self.authenticate():
            return False

        # Discover hosts using batch-optimized approach
        hosts = self.discover_hosts_batch_optimized(target_hosts)
        if not hosts:
            print("❌ No hosts discovered")
            return False

        self.discovered_hosts = hosts

        # Validate and report targeting results
        if target_hosts:
            found_hostnames = [host.get('name') for host in hosts]
            missing_hosts = [h for h in target_hosts if h not in found_hostnames]

            print(f"🎯 Host targeting results:")
            print(f"   ✅ Found {len(hosts)} of {len(target_hosts)} target hosts")
            print(f"   📋 Found: {', '.join(found_hostnames)}")
            if missing_hosts:
                print(f"   ⚠️ Missing: {', '.join(missing_hosts)}")

        # Apply numeric limit if specified
        if max_hosts and max_hosts < len(hosts):
            hosts = hosts[:max_hosts]
            print(f"⚠️ Limited to first {max_hosts} hosts")

        print(f"\n🏭 Processing {len(hosts)} hosts with enterprise features...")

        # Process hosts with enterprise error handling
        for i, host_info in enumerate(hosts, 1):
            print(f"\n📍 Progress: {i}/{len(hosts)} ({(i/len(hosts)*100):.1f}%)")

            try:
                host_data = self._process_host_enterprise(host_info)

                if host_data.get('processing_status') == 'success':
                    self.processed_hosts.append(host_data)
                    self.stats['total_hosts_processed'] += 1
                else:
                    self.failed_hosts.append(host_data)

            except Exception as e:
                print(f"❌ Critical error processing host {host_info.get('name', 'Unknown')}: {e}")

                # Create error record
                error_host = {
                    'hostname': host_info.get('name', 'Unknown'),
                    'id': host_info.get('id'),
                    'processing_status': 'critical_error',
                    'error_message': str(e),
                    'falcon_details': {},
                    'deployed_services': [],
                    'total_interfaces': 0
                }
                self.failed_hosts.append(error_host)

        # Print enterprise summary
        self._print_enterprise_summary(start_time)
        self._export_results()
        return True

    def _process_host_enterprise(self, host_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process single host with enterprise error handling"""
        hostname = host_info.get('name', 'Unknown')
        host_id = str(host_info.get('id', ''))

        print(f"🖥️ [ENTERPRISE] Processing: {hostname} (ID: {host_id})")

        # Initialize result structure
        result = {
            'hostname': hostname,
            'id': host_id,
            'falcon_details': {},
            'deployed_services': [],
            'total_interfaces': 0,
            'processing_status': 'processing',
            'error_message': None
        }

        try:
            # Step 1: Get Falcon details (with retry)
            print(f"   🔍 Querying Falcon for: {hostname}")
            falcon_details = self._get_falcon_details_with_retry(hostname)

            if falcon_details:
                result['falcon_details'] = falcon_details
                print(f"   ✅ Falcon data: {falcon_details.get('os_version', 'Unknown OS')}")
            else:
                print(f"   ⚠️ No Falcon data found for {hostname}")

            # Step 2: Get deployed services (with retry)
            services = self.get_services_for_host_enterprise(host_id, hostname)
            result['deployed_services'] = services

            # Count total interfaces
            total_interfaces = sum(len(service.get('interfaces', [])) for service in services)
            result['total_interfaces'] = total_interfaces

            print(f"   📊 Summary: {len(services)} services, {total_interfaces} interfaces")

            # Mark as successful
            result['processing_status'] = 'success'
            return result

        except Exception as e:
            print(f"   ❌ Error processing {hostname}: {e}")
            result['processing_status'] = 'error'
            result['error_message'] = str(e)
            return result

    def _get_falcon_details_with_retry(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Get Falcon details with retry logic"""
        try:
            # Query for device by hostname
            query_url = f"{self.base_url}/devices/queries/devices/v1"
            params = urllib.parse.urlencode({'filter': f"hostname:'{hostname}'", 'limit': '1'})

            # Use manual retry for Falcon API calls
            for attempt in range(self.max_retries + 1):
                try:
                    if not self._refresh_token_if_needed():
                        return None

                    req = urllib.request.Request(f"{query_url}?{params}")
                    req.add_header('Authorization', f'Bearer {self.token}')

                    with urllib.request.urlopen(req) as response:
                        result = json.loads(response.read().decode())
                        self.stats['api_calls_made'] += 1

                    device_ids = result.get('resources', [])
                    if not device_ids:
                        return None

                    # Get detailed device info
                    details_url = f"{self.base_url}/devices/entities/devices/v2"
                    params = urllib.parse.urlencode({'ids': device_ids[0]})

                    req = urllib.request.Request(f"{details_url}?{params}")
                    req.add_header('Authorization', f'Bearer {self.token}')

                    with urllib.request.urlopen(req) as response:
                        result = json.loads(response.read().decode())
                        self.stats['api_calls_made'] += 1

                    devices = result.get('resources', [])
                    if devices:
                        device = devices[0]
                        return {
                            'device_id': device.get('device_id'),
                            'cid': device.get('cid'),
                            'hostname': device.get('hostname'),
                            'os_version': device.get('os_version'),
                            'platform_name': device.get('platform_name'),
                            'external_ip': device.get('external_ip'),
                            'local_ip': device.get('local_ip'),
                            'service_provider': device.get('service_provider')
                        }
                    return None

                except urllib.error.HTTPError as e:
                    if e.code == 401 and attempt < self.max_retries:
                        print(f"   🔄 Falcon unauthorized, retrying... ({attempt + 1})")
                        self.token = None  # Force refresh
                        time.sleep(self.retry_delay)
                        continue
                    else:
                        print(f"   ❌ Falcon HTTP error {e.code}")
                        return None
                except Exception as e:
                    if attempt < self.max_retries:
                        print(f"   ⏳ Falcon error, retrying: {e}")
                        time.sleep(self.retry_delay)
                        continue
                    else:
                        print(f"   ❌ Falcon error after retries: {e}")
                        return None

        except Exception as e:
            print(f"   ❌ Falcon lookup failed for {hostname}: {e}")
            return None

    def _print_enterprise_summary(self, start_time: float):
        """Print comprehensive enterprise summary"""
        duration = time.time() - start_time

        print("\n" + "="*70)
        print("📊 [ENTERPRISE] ASPM ITERATION COMPLETE")
        print("="*70)

        print(f"⏱️ PERFORMANCE:")
        print(f"   Total time: {duration:.1f}s ({duration/60:.1f} min)")
        print(f"   API calls made: {self.stats['api_calls_made']}")
        print(f"   Token refreshes: {self.stats['token_refreshes']}")
        print(f"   Batch operations: {self.stats['batch_operations']}")

        print(f"\n📊 PROCESSING RESULTS:")
        print(f"   Hosts discovered: {len(self.discovered_hosts)}")
        print(f"   Hosts processed successfully: {len(self.processed_hosts)}")
        print(f"   Hosts with errors: {len(self.failed_hosts)}")

        if self.failed_hosts:
            print(f"\n⚠️ FAILED HOSTS:")
            for failed in self.failed_hosts[:5]:  # Show first 5
                status = failed.get('processing_status', 'unknown')
                error = failed.get('error_message', 'No error message')
                print(f"   ❌ {failed.get('hostname', 'Unknown')}: {status} - {error}")

            if len(self.failed_hosts) > 5:
                print(f"   ... and {len(self.failed_hosts) - 5} more (see JSON output)")

    def _export_results(self):
        """Export results with enterprise metadata"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"aspm_enterprise_results_{timestamp}.json"

        export_data = {
            'metadata': {
                'timestamp': timestamp,
                'version': 'enterprise-1.0',
                'batch_size': self.batch_size,
                'statistics': self.stats
            },
            'successful_hosts': self.processed_hosts,
            'failed_hosts': self.failed_hosts,
            'summary': {
                'total_discovered': len(self.discovered_hosts),
                'total_processed': len(self.processed_hosts),
                'total_failed': len(self.failed_hosts),
                'success_rate': len(self.processed_hosts) / max(len(self.discovered_hosts), 1) * 100
            }
        }

        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"\n✅ Enterprise results exported to: {filename}")


if __name__ == "__main__":
    # Get credentials
    client_id = os.getenv('FALCON_CLIENT_ID')
    client_secret = os.getenv('FALCON_CLIENT_SECRET')
    base_url = os.getenv('FALCON_BASE_URL', 'https://api.crowdstrike.com')

    if not client_id or not client_secret:
        print("❌ Missing credentials. Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")
        sys.exit(1)

    print("🏢 ASPM Enterprise Host Iterator")
    print("=" * 50)
    print(f"🌐 Endpoint: {base_url}")
    print("🔧 Enterprise features: Token refresh, batch processing, retry logic")
    print()

    # Parse command line arguments (simplified)
    target_hosts = None
    if len(sys.argv) > 1:
        if sys.argv[1] == '--hosts' and len(sys.argv) > 2:
            target_hosts = sys.argv[2:]
        elif not sys.argv[1].startswith('--'):
            try:
                max_hosts = int(sys.argv[1])
                print(f"🎯 Limited to {max_hosts} hosts")
            except ValueError:
                target_hosts = sys.argv[1:]

    if target_hosts:
        print(f"🎯 Targeting {len(target_hosts)} specific hosts")

    # Run enterprise iteration
    iterator = ASPMHostIteratorEnterprise(client_id, client_secret, base_url)
    success = iterator.run_enterprise_iteration(target_hosts=target_hosts)

    sys.exit(0 if success else 1)