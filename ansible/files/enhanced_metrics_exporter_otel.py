#!/usr/bin/env python3
"""
Thesis Metrics Exporter v4.1 - JARVIS Edition
==============================================
Improved IAST detection:
- Captures dd-trace security logs
- Detects attack patterns in HTTP requests
- Better latency percentile calculation
"""

import time
import json
import os
import re
import threading
import requests
import docker
from prometheus_client import start_http_server, Gauge, Counter
from collections import deque

# ================= CONFIGURATION =================
METRICS_DIR = '/opt/security-metrics/data'
SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
JUICE_CONTAINER_NAME = 'juice-shop'
JUICE_SHOP_URL = os.environ.get('JUICE_SHOP_URL', 'http://juice-shop:3000')

# ================= PROMETHEUS METRICS =================
SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current scenario (1=Baseline, 2=Detection, 3=Blocking)')

# IAST Metrics
IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'IAST detections', ['vuln_type', 'source'])

# RASP Metrics
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Aikido RASP detections')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Aikido RASP blocks')

# Container Security
TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container vulnerabilities', ['severity'])

# Performance
REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Average request latency (ms)')
REQUEST_LATENCY_P95 = Gauge('thesis_request_latency_p95_ms', 'P95 request latency (ms)')

# Track seen log lines to avoid duplicates
seen_logs = deque(maxlen=1000)


# ================= INITIALIZATION =================
def initialize_metrics():
    print("📊 Initializing metrics...")
    SCENARIO_GAUGE.set(0)
    REQUEST_LATENCY.set(0)
    REQUEST_LATENCY_P95.set(0)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        TRIVY_VULNS.labels(severity=severity).set(0)
    print("✅ Metrics initialized")


# ================= ATTACK CLASSIFICATION =================
def classify_attack(log_line):
    """Classify attack type from log content"""
    log = log_line.lower()
    
    # SQL Injection
    sql_patterns = [
        'sql', 'injection', '1=1', 'union', 'select', 'drop table',
        "' or", "' and", '--', 'or 1=1', '%27', 'sqlmap'
    ]
    if any(p in log for p in sql_patterns):
        return 'SQL Injection'
    
    # XSS
    xss_patterns = [
        'xss', '<script', 'script>', 'alert(', 'onerror', 'onload',
        'javascript:', '%3cscript', 'document.cookie'
    ]
    if any(p in log for p in xss_patterns):
        return 'XSS'
    
    # Path Traversal
    path_patterns = ['../', '..\\', 'path traversal', '%2e%2e', 'etc/passwd']
    if any(p in log for p in path_patterns):
        return 'Path Traversal'
    
    # Command Injection
    cmd_patterns = ['command', '; ls', '| cat', '`', '$(', 'exec(', 'shell']
    if any(p in log for p in cmd_patterns):
        return 'Command Injection'
    
    # NoSQL
    nosql_patterns = ['$where', '$gt', '$ne', '$regex', 'mongodb']
    if any(p in log for p in nosql_patterns):
        return 'NoSQL Injection'
    
    return 'Generic'


def is_attack_request(log_line):
    """Detect if log line contains an attack pattern in HTTP request"""
    attack_signatures = [
        # SQL Injection
        "' OR 1=1", "' OR '1'='1", "1=1--", "UNION SELECT",
        "%27%20OR", "%27%20AND", "1%3D1",
        # XSS
        "<script>", "</script>", "alert(", "onerror=",
        "%3Cscript", "javascript:",
        # Path Traversal
        "../../../", "..\\..\\", "%2e%2e%2f",
        # Command Injection
        "; ls", "| cat", "`id`",
    ]
    return any(sig in log_line for sig in attack_signatures)


# ================= SCENARIO & TRIVY =================
def update_scenario():
    try:
        if os.path.exists(SCENARIO_FILE):
            with open(SCENARIO_FILE, 'r') as f:
                data = json.load(f)
                SCENARIO_GAUGE.set(data.get('scenario_id', 0))
                return data.get('scenario_id', 0)
    except Exception as e:
        print(f"⚠️ Scenario error: {e}")
    return 0


def update_trivy():
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
        print(f"⚠️ Trivy error: {e}")


# ================= LATENCY MEASUREMENT =================
def measure_latency():
    """Measure HTTP latency with proper percentile calculation"""
    endpoints = ['/rest/products/search?q=test', '/api/Challenges/', '/']
    latency_window = deque(maxlen=50)  # Rolling window of 50 samples
    
    while True:
        batch_latencies = []
        
        for endpoint in endpoints:
            try:
                start = time.time()
                requests.get(f"{JUICE_SHOP_URL}{endpoint}", timeout=5)
                latency_ms = (time.time() - start) * 1000
                batch_latencies.append(latency_ms)
            except:
                pass
        
        if batch_latencies:
            # Add to rolling window
            latency_window.extend(batch_latencies)
            
            # Calculate metrics from window
            samples = list(latency_window)
            avg = sum(samples) / len(samples)
            REQUEST_LATENCY.set(round(avg, 2))
            
            # P95 calculation
            if len(samples) >= 5:
                sorted_samples = sorted(samples)
                p95_idx = int(len(sorted_samples) * 0.95)
                REQUEST_LATENCY_P95.set(round(sorted_samples[p95_idx], 2))
        
        time.sleep(5)


# ================= DOCKER LOG WATCHER =================
def watch_docker_logs():
    """Watch container logs for security events"""
    client = docker.from_env()
    print(f"\n👀 Watching '{JUICE_CONTAINER_NAME}' logs...")
    
    while True:
        try:
            container = client.containers.get(JUICE_CONTAINER_NAME)
            
            for line in container.logs(stream=True, tail=0, follow=True):
                log = line.decode('utf-8', errors='ignore').strip()
                if not log:
                    continue
                
                # Skip if we've seen this exact log recently
                log_hash = hash(log)
                if log_hash in seen_logs:
                    continue
                seen_logs.append(log_hash)
                
                # ===== RASP DETECTION (Aikido Zen) - PRIORITY =====
                if any(x in log for x in ['Zen', 'Aikido', 'aikidosec', 'firewall']):
                    if any(x in log.lower() for x in ['blocked', 'block', 'prevented']):
                        RASP_BLOCKS.inc()
                        print(f"🛡️ RASP BLOCK: {log[:100]}")
                    elif any(x in log.lower() for x in ['detected', 'attack', 'threat']):
                        RASP_DETECTIONS.inc()
                        print(f"👁️ RASP DETECT: {log[:100]}")
                
                # ===== IAST DETECTION (dd-trace) =====
                # Pattern 1: Explicit dd-trace/appsec logs
                if any(x in log for x in [
                    'dd-trace', 'datadog', 'appsec',
                    'Vulnerability detected', 'security event',
                    'IAST', 'attack detected'
                ]):
                    vuln_type = classify_attack(log)
                    IAST_DETECTIONS.labels(vuln_type=vuln_type, source='ddtrace').inc()
                    print(f"🔬 IAST [dd-trace]: {vuln_type}")
                
                # Pattern 2: HTTP request logs containing attack patterns
                elif is_attack_request(log):
                    vuln_type = classify_attack(log)
                    IAST_DETECTIONS.labels(vuln_type=vuln_type, source='http').inc()
                    print(f"🔬 IAST [http]: {vuln_type} - {log[:80]}")
                
                # Pattern 3: Error responses that might indicate attack detection
                elif any(x in log for x in ['400', '403', '500']) and any(x in log.lower() for x in ['error', 'invalid', 'blocked', 'forbidden']):
                    if is_attack_request(log):
                        vuln_type = classify_attack(log)
                        IAST_DETECTIONS.labels(vuln_type=vuln_type, source='error').inc()
                        print(f"🔬 IAST [error]: {vuln_type}")
                        
        except docker.errors.NotFound:
            print(f"⚠️ Container not found, retrying in 10s...")
            time.sleep(10)
        except Exception as e:
            print(f"❌ Docker error: {e}")
            time.sleep(5)


# ================= BACKGROUND WORKER =================
def file_worker():
    while True:
        try:
            scenario = update_scenario()
            update_trivy()
            scenario_names = {0: 'STANDBY', 1: 'BASELINE', 2: 'DETECTION', 3: 'BLOCKING'}
            print(f"📋 Scenario: {scenario_names.get(scenario, '?')}")
        except Exception as e:
            print(f"❌ Worker error: {e}")
        time.sleep(30)


# ================= MAIN =================
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 THESIS METRICS EXPORTER v4.1 (JARVIS Edition)")
    print("=" * 60)
    print(f"   Target: {JUICE_SHOP_URL}")
    print(f"   Container: {JUICE_CONTAINER_NAME}")
    print("=" * 60)
    
    initialize_metrics()
    
    start_http_server(9999)
    print("📊 Metrics: http://localhost:9999/metrics")
    
    threading.Thread(target=file_worker, daemon=True).start()
    print("📁 File worker started")
    
    threading.Thread(target=measure_latency, daemon=True).start()
    print("⏱️ Latency measurement started")
    
    print("\n👀 Starting log monitor...\n")
    watch_docker_logs()