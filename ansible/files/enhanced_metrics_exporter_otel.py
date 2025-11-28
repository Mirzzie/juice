# #!/usr/bin/env python3
# import time, json, os, re, threading, requests, docker
# from prometheus_client import start_http_server, Gauge, Counter

# METRICS_DIR = '/opt/security-metrics/data'
# SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
# TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
# JUICE_CONTAINER_NAME = 'juice-shop'
# DD_API_KEY = os.environ.get('DD_API_KEY')
# DD_APP_KEY = os.environ.get('DD_APP_KEY')
# DD_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')

# SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current Thesis Scenario')
# IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'DataDog IAST', ['vuln_type', 'source'])
# IAST_API_VULNS = Gauge('thesis_iast_api_vulns', 'Official DataDog IAST Findings', ['vuln_type', 'severity'])
# RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'RASP Detections')
# RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'RASP Blocks')
# TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container Vulns', ['severity'])
# REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Avg Latency')

# def fetch_datadog_vulns():
#     if not DD_API_KEY or not DD_APP_KEY: return
#     headers = {"DD-API-KEY": DD_API_KEY, "DD-APPLICATION-KEY": DD_APP_KEY, "Content-Type": "application/json"}
#     url = f"https://api.{DD_SITE}/api/v2/security_monitoring/signals/search"
#     payload = {"filter": {"query": "service:juice-shop status:high", "from": "now-1h", "to": "now"}, "page": {"limit": 50}}
#     try:
#         response = requests.post(url, headers=headers, json=payload, timeout=10)
#         if response.status_code == 200:
#             data = response.json()
#             counts = {}
#             for signal in data.get('data', []):
#                 vuln = "Generic"
#                 for tag in signal.get('attributes', {}).get('tags', []):
#                     if tag.startswith('vulnerability_type:'): vuln = tag.split(':')[1].replace('_', ' ').title()
#                 key = (vuln, signal.get('attributes', {}).get('severity', 'medium'))
#                 counts[key] = counts.get(key, 0) + 1
#             for (v, s), c in counts.items(): IAST_API_VULNS.labels(vuln_type=v, severity=s).set(c)
#     except: pass

# def update_files():
#     try:
#         if os.path.exists(SCENARIO_FILE):
#             with open(SCENARIO_FILE) as f: SCENARIO_GAUGE.set(json.load(f).get('scenario_id', 0))
#         if os.path.exists(TRIVY_FILE):
#             with open(TRIVY_FILE) as f:
#                 data = json.load(f)
#                 counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
#                 if 'Results' in data:
#                     for r in data['Results']:
#                         for v in r.get('Vulnerabilities', []):
#                             s = v.get('Severity', 'UNKNOWN')
#                             if s in counts: counts[s] += 1
#                 for s, c in counts.items(): TRIVY_VULNS.labels(severity=s).set(c)
#     except: pass

# def watch_docker_logs():
#     client = docker.from_env()
#     print(f"🔌 Watching {JUICE_CONTAINER_NAME}")
#     while True:
#         try:
#             container = client.containers.get(JUICE_CONTAINER_NAME)
#             for line in container.logs(stream=True, tail=0, follow=True):
#                 log = line.decode('utf-8', errors='ignore').strip()
#                 if not log: continue
                
#                 if "Vulnerability detected" in log or "dd-trace" in log:
#                     vuln = "Generic"
#                     if "SQL" in log: vuln = "SQL Injection"
#                     elif "XSS" in log: vuln = "XSS"
#                     IAST_DETECTIONS.labels(vuln_type=vuln, source='log').inc()
#                     print(f"🚨 IAST: {vuln}")

#                 if "Zen" in log or "Aikido" in log:
#                     if "blocked" in log.lower(): RASP_BLOCKS.inc(); print("🛡️ BLOCK")
#                     elif "detected" in log.lower(): RASP_DETECTIONS.inc(); print("👁️ DETECT")
                
#                 match = re.search(r'(?:response_time=|)(\d+\.?\d*)\s*ms', log)
#                 if match:
#                     try: REQUEST_LATENCY.set(float(match.group(1)))
#                     except: pass
#         except: time.sleep(5)

# if __name__ == '__main__':
#     print("🚀 Exporter Running")
#     start_http_server(9999)
#     threading.Thread(target=lambda: [update_files() or fetch_datadog_vulns() or time.sleep(60) for _ in iter(int, 1)], daemon=True).start()
#     watch_docker_logs()

#!/usr/bin/env python3
"""
Thesis Metrics Exporter - FIXED VERSION
Issues Fixed:
1. DataDog API query syntax (status:high -> @severity:*)
2. Added active latency measurement (doesn't rely on log parsing)
3. Added metric initialization (prevents "No Data" in Grafana)
4. Better error logging for debugging
5. Multiple API endpoint fallbacks for IAST findings
"""

import time
import json
import os
import re
import threading
import requests
import docker
from prometheus_client import start_http_server, Gauge, Counter, Info

# ================= CONFIGURATION =================
METRICS_DIR = '/opt/security-metrics/data'
SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
JUICE_CONTAINER_NAME = 'juice-shop'
JUICE_SHOP_URL = os.environ.get('JUICE_SHOP_URL', 'http://juice-shop:3000')

# DataDog API Config
DD_API_KEY = os.environ.get('DD_API_KEY')
DD_APP_KEY = os.environ.get('DD_APP_KEY')
DD_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')

# ================= METRICS =================
# Scenario
SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current Thesis Scenario (1=Baseline, 2=Detection, 3=Blocking)')

# IAST Metrics
IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'Real-time IAST detections from logs', ['vuln_type', 'source'])
IAST_API_VULNS = Gauge('thesis_iast_api_vulns', 'DataDog API verified IAST findings', ['vuln_type', 'severity'])
IAST_API_TOTAL = Gauge('thesis_iast_api_total', 'Total IAST vulnerabilities from API')

# RASP Metrics
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Aikido RASP detections')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Aikido RASP blocks')

# Container Security
TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container vulnerabilities by severity', ['severity'])

# Performance - FIXED: Active measurement instead of log parsing
REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Average request latency in milliseconds')
REQUEST_LATENCY_P95 = Gauge('thesis_request_latency_p95_ms', 'P95 request latency')
REQUEST_LATENCY_P99 = Gauge('thesis_request_latency_p99_ms', 'P99 request latency')

# Debug/Status
EXPORTER_STATUS = Info('thesis_exporter', 'Exporter status information')
API_LAST_SUCCESS = Gauge('thesis_api_last_success_timestamp', 'Last successful DataDog API call')
API_ERRORS = Counter('thesis_api_errors_total', 'DataDog API errors', ['endpoint'])

# ================= INITIALIZATION =================
def initialize_metrics():
    """Initialize all metrics with default values to prevent 'No Data' in Grafana"""
    print("📊 Initializing metrics with defaults...")
    
    # Initialize gauges to 0
    SCENARIO_GAUGE.set(0)
    IAST_API_TOTAL.set(0)
    REQUEST_LATENCY.set(0)
    REQUEST_LATENCY_P95.set(0)
    REQUEST_LATENCY_P99.set(0)
    
    # Initialize labeled gauges
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        IAST_API_VULNS.labels(vuln_type='Initialized', severity=severity).set(0)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        TRIVY_VULNS.labels(severity=severity).set(0)
    
    EXPORTER_STATUS.info({
        'version': '2.0',
        'dd_site': DD_SITE,
        'api_configured': str(bool(DD_API_KEY and DD_APP_KEY))
    })
    
    print("✅ Metrics initialized")

# ================= DATADOG API - FIXED =================
def fetch_datadog_vulns():
    """
    Fetch IAST vulnerabilities from DataDog API
    FIXED: Corrected query syntax and added multiple endpoint fallbacks
    """
    if not DD_API_KEY or not DD_APP_KEY:
        print("⚠️ DD_API_KEY or DD_APP_KEY not set - skipping API fetch")
        return
    
    headers = {
        "DD-API-KEY": DD_API_KEY,
        "DD-APPLICATION-KEY": DD_APP_KEY,
        "Content-Type": "application/json"
    }
    
    # Try multiple query strategies
    queries_to_try = [
        # Strategy 1: AppSec signals with IAST source
        {
            "name": "appsec_iast",
            "query": "@workflow.rule.type:application_security service:juice-shop"
        },
        # Strategy 2: Security signals for juice-shop service
        {
            "name": "security_signals", 
            "query": "service:juice-shop @severity:(high OR critical OR medium)"
        },
        # Strategy 3: All signals for the service
        {
            "name": "all_signals",
            "query": "service:juice-shop"
        }
    ]
    
    url = f"https://api.{DD_SITE}/api/v2/security_monitoring/signals/search"
    
    for strategy in queries_to_try:
        payload = {
            "filter": {
                "query": strategy["query"],
                "from": "now-24h",  # Extended window
                "to": "now"
            },
            "sort": "-timestamp",
            "page": {"limit": 100}
        }
        
        try:
            print(f"🔍 Trying DataDog API strategy: {strategy['name']}")
            print(f"   Query: {strategy['query']}")
            
            response = requests.post(url, headers=headers, json=payload, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                signals = data.get('data', [])
                
                print(f"   📦 Received {len(signals)} signals")
                
                if signals:
                    process_datadog_signals(signals)
                    API_LAST_SUCCESS.set(time.time())
                    return  # Success, stop trying
                    
            elif response.status_code == 403:
                print(f"   ❌ 403 Forbidden - Check API/APP key permissions")
                API_ERRORS.labels(endpoint='security_signals').inc()
            else:
                print(f"   ⚠️ API returned {response.status_code}: {response.text[:200]}")
                API_ERRORS.labels(endpoint='security_signals').inc()
                
        except requests.exceptions.Timeout:
            print(f"   ⏱️ Request timed out for strategy: {strategy['name']}")
            API_ERRORS.labels(endpoint='timeout').inc()
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            API_ERRORS.labels(endpoint='exception').inc()
    
    print("⚠️ All DataDog API strategies exhausted - no data retrieved")

def process_datadog_signals(signals):
    """Process DataDog security signals and update Prometheus metrics"""
    
    # Reset gauges before updating (clear stale data)
    # We'll collect all unique label combinations first
    vuln_counts = {}
    total_count = 0
    
    for signal in signals:
        attrs = signal.get('attributes', {})
        tags = attrs.get('tags', [])
        
        # Extract vulnerability type from various tag formats
        vuln_type = extract_vuln_type(attrs, tags)
        severity = attrs.get('severity', 'medium')
        
        # Normalize severity
        if severity:
            severity = severity.lower()
        else:
            severity = 'medium'
        
        key = (vuln_type, severity)
        vuln_counts[key] = vuln_counts.get(key, 0) + 1
        total_count += 1
    
    # Update Prometheus metrics
    for (v_type, sev), count in vuln_counts.items():
        IAST_API_VULNS.labels(vuln_type=v_type, severity=sev).set(count)
        print(f"   📈 {v_type} ({sev}): {count}")
    
    IAST_API_TOTAL.set(total_count)
    print(f"✅ DataDog API: Updated {len(vuln_counts)} vulnerability categories, {total_count} total findings")

def extract_vuln_type(attrs, tags):
    """Extract vulnerability type from DataDog signal attributes and tags"""
    
    # Try multiple extraction methods
    
    # Method 1: Direct attribute
    if 'rule' in attrs and 'name' in attrs['rule']:
        return normalize_vuln_name(attrs['rule']['name'])
    
    # Method 2: From tags
    for tag in tags:
        tag_lower = tag.lower()
        
        # vulnerability_type tag
        if tag.startswith('vulnerability_type:'):
            return normalize_vuln_name(tag.split(':', 1)[1])
        
        # attack_type tag
        if tag.startswith('attack_type:'):
            return normalize_vuln_name(tag.split(':', 1)[1])
        
        # CWE tag
        if tag.startswith('cwe:') or tag.startswith('cwe-'):
            return tag.upper()
        
        # OWASP tag
        if 'owasp' in tag_lower:
            return tag
    
    # Method 3: From title/message
    title = attrs.get('title', '') or attrs.get('message', '')
    if title:
        return classify_from_text(title)
    
    return 'Unknown'

def normalize_vuln_name(name):
    """Normalize vulnerability names for consistent labeling"""
    name = name.replace('_', ' ').replace('-', ' ').title()
    
    # Map common variations
    mappings = {
        'Sql Injection': 'SQL Injection',
        'Sqli': 'SQL Injection',
        'Xss': 'XSS',
        'Cross Site Scripting': 'XSS',
        'Path Traversal': 'Path Traversal',
        'Directory Traversal': 'Path Traversal',
        'Command Injection': 'Command Injection',
        'Ssrf': 'SSRF',
        'Server Side Request Forgery': 'SSRF',
        'Nosql Injection': 'NoSQL Injection',
    }
    
    return mappings.get(name, name)

def classify_from_text(text):
    """Classify vulnerability type from descriptive text"""
    text_lower = text.lower()
    
    if 'sql' in text_lower and ('inject' in text_lower or 'query' in text_lower):
        return 'SQL Injection'
    if 'xss' in text_lower or 'cross-site scripting' in text_lower or 'script' in text_lower:
        return 'XSS'
    if 'path' in text_lower and 'traversal' in text_lower:
        return 'Path Traversal'
    if 'command' in text_lower and 'inject' in text_lower:
        return 'Command Injection'
    if 'ssrf' in text_lower or 'server-side request' in text_lower:
        return 'SSRF'
    if 'nosql' in text_lower:
        return 'NoSQL Injection'
    if 'ldap' in text_lower:
        return 'LDAP Injection'
    if 'xxe' in text_lower or 'xml' in text_lower:
        return 'XXE'
    
    return 'Other'

# ================= LATENCY MEASUREMENT - FIXED =================
def measure_latency():
    """
    Actively measure request latency instead of relying on log parsing
    FIXED: This provides reliable latency data for Grafana
    """
    test_endpoints = [
        '/rest/products/search?q=test',
        '/api/Challenges/',
        '/'
    ]
    
    while True:
        latencies = []
        
        for endpoint in test_endpoints:
            try:
                url = f"{JUICE_SHOP_URL}{endpoint}"
                start = time.time()
                response = requests.get(url, timeout=5)
                latency_ms = (time.time() - start) * 1000
                latencies.append(latency_ms)
            except Exception as e:
                # App might be restarting, skip this measurement
                pass
        
        if latencies:
            # Update metrics
            avg_latency = sum(latencies) / len(latencies)
            REQUEST_LATENCY.set(round(avg_latency, 2))
            
            # Calculate percentiles if we have enough samples
            sorted_latencies = sorted(latencies)
            if len(sorted_latencies) >= 3:
                p95_idx = int(len(sorted_latencies) * 0.95)
                p99_idx = int(len(sorted_latencies) * 0.99)
                REQUEST_LATENCY_P95.set(round(sorted_latencies[min(p95_idx, len(sorted_latencies)-1)], 2))
                REQUEST_LATENCY_P99.set(round(sorted_latencies[min(p99_idx, len(sorted_latencies)-1)], 2))
        
        time.sleep(5)  # Measure every 5 seconds

# ================= LOCAL FILE METRICS =================
def update_scenario_metrics():
    """Read scenario from local file"""
    try:
        if os.path.exists(SCENARIO_FILE):
            with open(SCENARIO_FILE, 'r') as f:
                data = json.load(f)
                scenario_id = data.get('scenario_id', 0)
                SCENARIO_GAUGE.set(scenario_id)
                return scenario_id
    except Exception as e:
        print(f"⚠️ Error reading scenario file: {e}")
    return 0

def update_trivy_metrics():
    """Read Trivy scan results from local file"""
    try:
        if os.path.exists(TRIVY_FILE):
            with open(TRIVY_FILE, 'r') as f:
                data = json.load(f)
            
            counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
            
            if 'Results' in data:
                for result in data['Results']:
                    for vuln in result.get('Vulnerabilities', []):
                        severity = vuln.get('Severity', 'UNKNOWN').upper()
                        if severity in counts:
                            counts[severity] += 1
            
            for severity, count in counts.items():
                TRIVY_VULNS.labels(severity=severity).set(count)
            
            total = sum(counts.values())
            if total > 0:
                print(f"📦 Trivy: {total} vulnerabilities (C:{counts['CRITICAL']} H:{counts['HIGH']} M:{counts['MEDIUM']})")
                
    except Exception as e:
        print(f"⚠️ Error reading Trivy file: {e}")

# ================= DOCKER LOG WATCHER =================
def classify_attack_type(log_line):
    """Classify attack type from log content"""
    log = log_line.lower()
    
    if any(x in log for x in ['sql', 'injection', 'union', 'select', '1=1', "'"]):
        return 'SQL Injection'
    if any(x in log for x in ['xss', 'script', '<script', 'alert(']):
        return 'XSS'
    if any(x in log for x in ['path', 'traversal', '../', '..\\', 'directory']):
        return 'Path Traversal'
    if any(x in log for x in ['command', 'exec', 'shell', 'cmd']):
        return 'Command Injection'
    if any(x in log for x in ['ssrf', 'localhost', '127.0.0.1', '169.254']):
        return 'SSRF'
    
    return 'Generic'

def watch_docker_logs():
    """Watch Docker container logs for real-time security events"""
    client = docker.from_env()
    print(f"🔌 Watching '{JUICE_CONTAINER_NAME}' container logs...")
    
    while True:
        try:
            container = client.containers.get(JUICE_CONTAINER_NAME)
            
            for line in container.logs(stream=True, tail=0, follow=True):
                log = line.decode('utf-8', errors='ignore').strip()
                if not log:
                    continue
                
                # --- IAST DETECTIONS (DataDog dd-trace) ---
                if any(x in log for x in ['Vulnerability detected', 'dd-trace', 'appsec', 'IAST']):
                    if 'attack' in log.lower() or 'vulnerability' in log.lower():
                        vuln_type = classify_attack_type(log)
                        IAST_DETECTIONS.labels(vuln_type=vuln_type, source='log').inc()
                        print(f"🚨 IAST Detection: {vuln_type}")
                
                # --- RASP Events (Aikido Zen) ---
                if 'Zen' in log or 'Aikido' in log or 'aikidosec' in log.lower():
                    if 'blocked' in log.lower() or 'block' in log.lower():
                        RASP_BLOCKS.inc()
                        print(f"🛡️ RASP BLOCKED attack")
                    elif 'detected' in log.lower() or 'attack' in log.lower():
                        RASP_DETECTIONS.inc()
                        print(f"👁️ RASP DETECTED attack")
                
        except docker.errors.NotFound:
            print(f"⚠️ Container '{JUICE_CONTAINER_NAME}' not found. Retrying in 10s...")
            time.sleep(10)
        except Exception as e:
            print(f"❌ Docker log watch error: {e}. Retrying in 5s...")
            time.sleep(5)

# ================= BACKGROUND WORKERS =================
def file_and_api_worker():
    """Background thread for file reading and API polling"""
    while True:
        try:
            # Update from local files
            update_scenario_metrics()
            update_trivy_metrics()
            
            # Fetch from DataDog API (every iteration = 60s)
            fetch_datadog_vulns()
            
        except Exception as e:
            print(f"❌ Worker error: {e}")
        
        time.sleep(60)  # Run every 60 seconds

# ================= MAIN =================
if __name__ == '__main__':
    print("=" * 50)
    print("🚀 Thesis Metrics Exporter v2.0 (FIXED)")
    print("=" * 50)
    print(f"   DataDog Site: {DD_SITE}")
    print(f"   API Key Set: {bool(DD_API_KEY)}")
    print(f"   APP Key Set: {bool(DD_APP_KEY)}")
    print(f"   Juice Shop URL: {JUICE_SHOP_URL}")
    print("=" * 50)
    
    # Initialize metrics with defaults
    initialize_metrics()
    
    # Start Prometheus HTTP server
    start_http_server(9999)
    print("📊 Prometheus metrics server started on :9999")
    
    # Thread 1: File & API Worker (60s interval)
    api_thread = threading.Thread(target=file_and_api_worker, daemon=True)
    api_thread.start()
    print("🔄 Started file/API worker thread")
    
    # Thread 2: Latency Measurement (5s interval)
    latency_thread = threading.Thread(target=measure_latency, daemon=True)
    latency_thread.start()
    print("⏱️ Started latency measurement thread")
    
    # Main Thread: Docker Log Watcher
    print("👀 Starting Docker log watcher (main thread)...")
    watch_docker_logs()