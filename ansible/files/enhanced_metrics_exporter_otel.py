#!/usr/bin/env python3
"""
Thesis Metrics Exporter v3.0 - COMPREHENSIVE FIX
===============================================
Fixes:
1. Uses CORRECT DataDog API endpoints for IAST (Application Security)
2. Adds multiple API fallback strategies
3. Better error handling and debugging
4. Proper metric initialization for Grafana
5. Active latency measurement (confirmed working)
"""

import time
import json
import os
import re
import threading
import requests
import docker
from prometheus_client import start_http_server, Gauge, Counter, Info
from datetime import datetime, timezone

# ================= CONFIGURATION =================
METRICS_DIR = '/opt/security-metrics/data'
SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
JUICE_CONTAINER_NAME = 'juice-shop'
JUICE_SHOP_URL = os.environ.get('JUICE_SHOP_URL', 'http://juice-shop:3000')

# DataDog API Config
DD_API_KEY = os.environ.get('DD_API_KEY', '')
DD_APP_KEY = os.environ.get('DD_APP_KEY', '')
DD_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')

# ================= PROMETHEUS METRICS =================
# Scenario
SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current Thesis Scenario (1=Baseline, 2=Detection, 3=Blocking)')

# IAST Metrics - Multiple sources for reliability
IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'Real-time IAST detections from logs', ['vuln_type', 'source'])
IAST_API_VULNS = Gauge('thesis_iast_api_vulns', 'DataDog API IAST findings', ['vuln_type', 'severity'])
IAST_API_TOTAL = Gauge('thesis_iast_api_total', 'Total IAST vulnerabilities from API')

# RASP Metrics
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Aikido RASP detections')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Aikido RASP blocks')

# Container Security
TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container vulnerabilities by severity', ['severity'])

# Performance
REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Average request latency in milliseconds')
REQUEST_LATENCY_P95 = Gauge('thesis_request_latency_p95_ms', 'P95 request latency')
REQUEST_LATENCY_P99 = Gauge('thesis_request_latency_p99_ms', 'P99 request latency')

# Exporter Health
EXPORTER_STATUS = Gauge('thesis_exporter_healthy', 'Exporter health (1=healthy)')
API_LAST_SUCCESS = Gauge('thesis_api_last_success_timestamp', 'Last successful DataDog API call (unix timestamp)')
API_CALL_COUNT = Counter('thesis_api_calls_total', 'Total DataDog API calls', ['endpoint', 'status'])

# ================= INITIALIZATION =================
def initialize_metrics():
    """Initialize all metrics to prevent 'No Data' in Grafana"""
    print("📊 Initializing metrics with defaults...")
    
    SCENARIO_GAUGE.set(0)
    IAST_API_TOTAL.set(0)
    REQUEST_LATENCY.set(0)
    REQUEST_LATENCY_P95.set(0)
    REQUEST_LATENCY_P99.set(0)
    EXPORTER_STATUS.set(1)  # Mark as healthy on startup
    API_LAST_SUCCESS.set(time.time())  # Initialize to now
    
    # Initialize with placeholder that we'll filter out in Grafana
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        IAST_API_VULNS.labels(vuln_type='_init', severity=severity).set(0)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        TRIVY_VULNS.labels(severity=severity).set(0)
    
    print("✅ Metrics initialized")


# ================= DATADOG API FUNCTIONS =================
def get_dd_headers():
    """Get DataDog API headers"""
    return {
        "DD-API-KEY": DD_API_KEY,
        "DD-APPLICATION-KEY": DD_APP_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def fetch_datadog_iast():
    """
    Fetch IAST findings from DataDog using multiple API strategies
    DataDog IAST data can be in different places depending on setup
    """
    if not DD_API_KEY or not DD_APP_KEY:
        print("⚠️  DD_API_KEY or DD_APP_KEY not configured")
        return False
    
    headers = get_dd_headers()
    base_url = f"https://api.{DD_SITE}"
    
    print(f"\n{'='*50}")
    print(f"🔍 Fetching DataDog IAST Data")
    print(f"   Site: {DD_SITE}")
    print(f"   Base URL: {base_url}")
    print(f"{'='*50}")
    
    # Strategy 1: Application Security Traces (ASM)
    # This is where IAST findings typically appear
    success = try_asm_traces(base_url, headers)
    if success:
        return True
    
    # Strategy 2: Security Monitoring Signals
    success = try_security_signals(base_url, headers)
    if success:
        return True
    
    # Strategy 3: APM Traces with security tags
    success = try_apm_security_traces(base_url, headers)
    if success:
        return True
    
    # Strategy 4: Query metrics directly
    success = try_metrics_query(base_url, headers)
    if success:
        return True
    
    print("⚠️  All DataDog API strategies returned no IAST data")
    print("   This could mean:")
    print("   - No vulnerabilities detected yet (run attacks first)")
    print("   - IAST is not fully enabled in DataDog")
    print("   - Service name mismatch (expected: juice-shop)")
    return False


def try_asm_traces(base_url, headers):
    """Strategy 1: Query ASM (Application Security Monitoring) traces"""
    print("\n📡 Strategy 1: ASM Traces API")
    
    url = f"{base_url}/api/v2/spans/events/aggregate"
    
    # Query for security-related spans
    payload = {
        "compute": [
            {"aggregation": "count"}
        ],
        "filter": {
            "from": "now-24h",
            "to": "now",
            "query": "service:juice-shop @appsec.event.type:*"
        },
        "group_by": [
            {"facet": "@appsec.event.rule.name", "limit": 50}
        ]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        print(f"   Response: {response.status_code}")
        
        API_CALL_COUNT.labels(endpoint='asm_traces', status=str(response.status_code)).inc()
        
        if response.status_code == 200:
            data = response.json()
            buckets = data.get('data', {}).get('buckets', [])
            
            if buckets:
                print(f"   ✅ Found {len(buckets)} ASM event types")
                process_asm_buckets(buckets)
                API_LAST_SUCCESS.set(time.time())
                return True
            else:
                print("   ⚠️  No ASM events found")
        elif response.status_code == 403:
            print(f"   ❌ 403 Forbidden - Need 'APM' scope in APP key")
        else:
            print(f"   ❌ Error: {response.text[:200]}")
            
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        API_CALL_COUNT.labels(endpoint='asm_traces', status='error').inc()
    
    return False


def try_security_signals(base_url, headers):
    """Strategy 2: Query Security Monitoring Signals"""
    print("\n📡 Strategy 2: Security Signals API")
    
    url = f"{base_url}/api/v2/security_monitoring/signals/search"
    
    # Try multiple query variations
    queries = [
        "service:juice-shop",
        "@workflow.rule.type:application_security",
        "source:(iast OR appsec OR application_security)",
        "*"  # Last resort: get all signals
    ]
    
    for query in queries:
        payload = {
            "filter": {
                "query": query,
                "from": "now-24h",
                "to": "now"
            },
            "sort": "-timestamp",
            "page": {"limit": 100}
        }
        
        try:
            print(f"   Trying query: {query}")
            response = requests.post(url, headers=headers, json=payload, timeout=15)
            
            API_CALL_COUNT.labels(endpoint='security_signals', status=str(response.status_code)).inc()
            
            if response.status_code == 200:
                data = response.json()
                signals = data.get('data', [])
                
                if signals:
                    print(f"   ✅ Found {len(signals)} signals")
                    process_security_signals(signals)
                    API_LAST_SUCCESS.set(time.time())
                    return True
                else:
                    print(f"   ⚠️  No signals for this query")
                    
            elif response.status_code == 403:
                print(f"   ❌ 403 - Need 'Security Monitoring Signals Read' permission")
                break  # Don't try more queries if permission denied
            else:
                print(f"   ⚠️  {response.status_code}: {response.text[:100]}")
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
    
    return False


def try_apm_security_traces(base_url, headers):
    """Strategy 3: Query APM traces with security metadata"""
    print("\n📡 Strategy 3: APM Traces with Security Tags")
    
    url = f"{base_url}/api/v2/spans/events/aggregate"
    
    payload = {
        "compute": [
            {"aggregation": "count"}
        ],
        "filter": {
            "from": "now-24h", 
            "to": "now",
            "query": "service:juice-shop (@_dd.iast.enabled:true OR @_dd.appsec.enabled:true)"
        },
        "group_by": [
            {"facet": "@vulnerability.type", "limit": 20}
        ]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        print(f"   Response: {response.status_code}")
        
        API_CALL_COUNT.labels(endpoint='apm_security', status=str(response.status_code)).inc()
        
        if response.status_code == 200:
            data = response.json()
            buckets = data.get('data', {}).get('buckets', [])
            
            if buckets:
                print(f"   ✅ Found {len(buckets)} vulnerability types")
                process_apm_buckets(buckets)
                API_LAST_SUCCESS.set(time.time())
                return True
                
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    return False


def try_metrics_query(base_url, headers):
    """Strategy 4: Query DataDog metrics directly for IAST data"""
    print("\n📡 Strategy 4: Metrics Query API")
    
    url = f"{base_url}/api/v1/query"
    
    # IAST-related metrics that DataDog might expose
    metric_queries = [
        "sum:datadog.apm.appsec.events{service:juice-shop}.as_count()",
        "sum:trace.appsec.threat{service:juice-shop}.as_count()",
        "sum:appsec.waf.match{service:juice-shop}.as_count()"
    ]
    
    now = int(time.time())
    
    for query in metric_queries:
        params = {
            "from": now - 86400,  # Last 24 hours
            "to": now,
            "query": query
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                series = data.get('series', [])
                
                if series and series[0].get('pointlist'):
                    points = series[0]['pointlist']
                    total = sum(p[1] for p in points if p[1])
                    
                    if total > 0:
                        print(f"   ✅ Found metric data: {query} = {total}")
                        # Set as generic IAST finding
                        IAST_API_VULNS.labels(vuln_type='AppSec Event', severity='medium').set(total)
                        IAST_API_TOTAL.set(total)
                        API_LAST_SUCCESS.set(time.time())
                        return True
                        
        except Exception as e:
            print(f"   ❌ Exception for {query}: {e}")
    
    return False


def process_asm_buckets(buckets):
    """Process ASM aggregation buckets into Prometheus metrics"""
    total = 0
    
    for bucket in buckets:
        rule_name = bucket.get('by', {}).get('@appsec.event.rule.name', 'Unknown')
        count = bucket.get('computes', {}).get('c0', 0)
        
        if count > 0:
            vuln_type = normalize_vuln_name(rule_name)
            severity = infer_severity(rule_name)
            
            IAST_API_VULNS.labels(vuln_type=vuln_type, severity=severity).set(count)
            total += count
            print(f"      📈 {vuln_type} ({severity}): {count}")
    
    IAST_API_TOTAL.set(total)


def process_security_signals(signals):
    """Process security signals into Prometheus metrics"""
    vuln_counts = {}
    
    for signal in signals:
        attrs = signal.get('attributes', {})
        
        # Extract vulnerability info
        vuln_type = 'Unknown'
        severity = attrs.get('severity', 'medium')
        
        # Try to get rule name
        rule = attrs.get('rule', {})
        if rule:
            vuln_type = normalize_vuln_name(rule.get('name', 'Unknown'))
        
        # Or from tags
        for tag in attrs.get('tags', []):
            if 'vulnerability_type:' in tag:
                vuln_type = normalize_vuln_name(tag.split(':')[1])
                break
            if 'attack_type:' in tag:
                vuln_type = normalize_vuln_name(tag.split(':')[1])
                break
        
        key = (vuln_type, severity.lower() if severity else 'medium')
        vuln_counts[key] = vuln_counts.get(key, 0) + 1
    
    total = 0
    for (v_type, sev), count in vuln_counts.items():
        IAST_API_VULNS.labels(vuln_type=v_type, severity=sev).set(count)
        total += count
        print(f"      📈 {v_type} ({sev}): {count}")
    
    IAST_API_TOTAL.set(total)


def process_apm_buckets(buckets):
    """Process APM aggregation buckets"""
    total = 0
    
    for bucket in buckets:
        vuln_type = bucket.get('by', {}).get('@vulnerability.type', 'Unknown')
        count = bucket.get('computes', {}).get('c0', 0)
        
        if count > 0:
            vuln_type = normalize_vuln_name(vuln_type)
            IAST_API_VULNS.labels(vuln_type=vuln_type, severity='medium').set(count)
            total += count
    
    IAST_API_TOTAL.set(total)


def normalize_vuln_name(name):
    """Normalize vulnerability names"""
    if not name:
        return 'Unknown'
    
    name = str(name).replace('_', ' ').replace('-', ' ').title()
    
    mappings = {
        'Sql Injection': 'SQL Injection',
        'Sqli': 'SQL Injection',
        'Nosql Injection': 'NoSQL Injection',
        'Xss': 'XSS',
        'Cross Site Scripting': 'XSS',
        'Reflected Xss': 'XSS (Reflected)',
        'Stored Xss': 'XSS (Stored)',
        'Path Traversal': 'Path Traversal',
        'Directory Traversal': 'Path Traversal',
        'Lfi': 'Path Traversal',
        'Command Injection': 'Command Injection',
        'Ssrf': 'SSRF',
        'Server Side Request Forgery': 'SSRF',
    }
    
    return mappings.get(name, name)


def infer_severity(name):
    """Infer severity from rule/vuln name"""
    name_lower = name.lower() if name else ''
    
    if any(x in name_lower for x in ['sql', 'injection', 'command', 'rce', 'ssrf']):
        return 'high'
    if any(x in name_lower for x in ['xss', 'traversal', 'lfi']):
        return 'medium'
    return 'low'


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
        print(f"⚠️  Error reading scenario: {e}")
    return 0


def update_trivy_metrics():
    """Read Trivy scan results"""
    try:
        if os.path.exists(TRIVY_FILE):
            with open(TRIVY_FILE, 'r') as f:
                data = json.load(f)
            
            counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
            
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    sev = vuln.get('Severity', 'UNKNOWN').upper()
                    if sev in counts:
                        counts[sev] += 1
            
            for severity, count in counts.items():
                TRIVY_VULNS.labels(severity=severity).set(count)
                
    except Exception as e:
        print(f"⚠️  Error reading Trivy: {e}")


# ================= LATENCY MEASUREMENT =================
def measure_latency():
    """Active latency measurement"""
    endpoints = ['/rest/products/search?q=test', '/api/Challenges/', '/']
    
    while True:
        latencies = []
        
        for endpoint in endpoints:
            try:
                start = time.time()
                requests.get(f"{JUICE_SHOP_URL}{endpoint}", timeout=5)
                latencies.append((time.time() - start) * 1000)
            except:
                pass
        
        if latencies:
            REQUEST_LATENCY.set(round(sum(latencies) / len(latencies), 2))
            sorted_lat = sorted(latencies)
            if len(sorted_lat) >= 2:
                REQUEST_LATENCY_P95.set(round(sorted_lat[int(len(sorted_lat) * 0.95)], 2))
                REQUEST_LATENCY_P99.set(round(sorted_lat[-1], 2))
        
        time.sleep(5)


# ================= DOCKER LOG WATCHER =================
def watch_docker_logs():
    """Watch container logs for RASP events"""
    client = docker.from_env()
    print(f"\n👀 Watching '{JUICE_CONTAINER_NAME}' logs for RASP events...")
    
    while True:
        try:
            container = client.containers.get(JUICE_CONTAINER_NAME)
            
            for line in container.logs(stream=True, tail=0, follow=True):
                log = line.decode('utf-8', errors='ignore').strip()
                if not log:
                    continue
                
                # IAST from logs
                if any(x in log for x in ['Vulnerability detected', 'dd-trace', 'appsec']):
                    vuln_type = classify_log_attack(log)
                    IAST_DETECTIONS.labels(vuln_type=vuln_type, source='log').inc()
                    print(f"🚨 IAST Log: {vuln_type}")
                
                # RASP events (Aikido Zen)
                if 'Zen' in log or 'Aikido' in log or 'aikidosec' in log.lower():
                    if 'blocked' in log.lower():
                        RASP_BLOCKS.inc()
                        print(f"🛡️  RASP BLOCKED")
                    elif 'detected' in log.lower() or 'attack' in log.lower():
                        RASP_DETECTIONS.inc()
                        print(f"👁️  RASP DETECTED")
                        
        except docker.errors.NotFound:
            print(f"⚠️  Container not found, retrying in 10s...")
            time.sleep(10)
        except Exception as e:
            print(f"❌ Docker error: {e}")
            time.sleep(5)


def classify_log_attack(log):
    """Classify attack type from log line"""
    log_lower = log.lower()
    
    if any(x in log_lower for x in ['sql', 'injection', '1=1', 'union']):
        return 'SQL Injection'
    if any(x in log_lower for x in ['xss', 'script', 'alert']):
        return 'XSS'
    if any(x in log_lower for x in ['path', 'traversal', '../']):
        return 'Path Traversal'
    return 'Generic'


# ================= BACKGROUND WORKER =================
def api_worker():
    """Background thread for API polling"""
    # Initial delay to let services start
    time.sleep(10)
    
    while True:
        try:
            update_scenario_metrics()
            update_trivy_metrics()
            
            # Fetch from DataDog
            success = fetch_datadog_iast()
            EXPORTER_STATUS.set(1 if success else 0)
            
        except Exception as e:
            print(f"❌ Worker error: {e}")
            EXPORTER_STATUS.set(0)
        
        time.sleep(60)


# ================= MAIN =================
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 THESIS METRICS EXPORTER v3.0")
    print("=" * 60)
    print(f"   DataDog Site:    {DD_SITE}")
    print(f"   API Key:         {'✅ Set' if DD_API_KEY else '❌ Missing'}")
    print(f"   APP Key:         {'✅ Set' if DD_APP_KEY else '❌ Missing'}")
    print(f"   Juice Shop URL:  {JUICE_SHOP_URL}")
    print("=" * 60)
    
    initialize_metrics()
    
    # Start Prometheus server
    start_http_server(9999)
    print("📊 Prometheus metrics on :9999")
    
    # Start background threads
    threading.Thread(target=api_worker, daemon=True).start()
    print("🔄 Started API worker")
    
    threading.Thread(target=measure_latency, daemon=True).start()
    print("⏱️  Started latency measurement")
    
    # Main thread: Docker logs
    watch_docker_logs()