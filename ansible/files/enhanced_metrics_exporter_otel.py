#!/usr/bin/env python3
"""
Thesis Metrics Exporter v4.0 - SIMPLIFIED
==========================================
Focused on reliable, local metrics:
- Log-based IAST/RASP detection
- Active latency measurement
- Trivy container scan results
- Scenario tracking

Removed: DataDog API integration (unreliable)
"""

import time
import json
import os
import re
import threading
import requests
import docker
from prometheus_client import start_http_server, Gauge, Counter

# ================= CONFIGURATION =================
METRICS_DIR = '/opt/security-metrics/data'
SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
JUICE_CONTAINER_NAME = 'juice-shop'
JUICE_SHOP_URL = os.environ.get('JUICE_SHOP_URL', 'http://juice-shop:3000')

# ================= PROMETHEUS METRICS =================
# Scenario Tracking
SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current scenario (1=Baseline, 2=Detection, 3=Blocking)')

# IAST Metrics (Log-based)
IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'IAST detections from logs', ['vuln_type', 'source'])

# RASP Metrics (Aikido Zen)
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Aikido RASP detections')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Aikido RASP blocks')

# Container Security (Trivy)
TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container vulnerabilities', ['severity'])

# Performance Metrics
REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Average request latency (ms)')
REQUEST_LATENCY_P95 = Gauge('thesis_request_latency_p95_ms', 'P95 request latency (ms)')
REQUEST_LATENCY_P99 = Gauge('thesis_request_latency_p99_ms', 'P99 request latency (ms)')


# ================= INITIALIZATION =================
def initialize_metrics():
    """Set initial values to prevent 'No Data' in Grafana"""
    print("📊 Initializing metrics...")
    
    SCENARIO_GAUGE.set(0)
    REQUEST_LATENCY.set(0)
    REQUEST_LATENCY_P95.set(0)
    REQUEST_LATENCY_P99.set(0)
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        TRIVY_VULNS.labels(severity=severity).set(0)
    
    print("✅ Metrics initialized")


# ================= SCENARIO & TRIVY =================
def update_scenario():
    """Read current scenario from file"""
    try:
        if os.path.exists(SCENARIO_FILE):
            with open(SCENARIO_FILE, 'r') as f:
                data = json.load(f)
                scenario_id = data.get('scenario_id', 0)
                SCENARIO_GAUGE.set(scenario_id)
                return scenario_id
    except Exception as e:
        print(f"⚠️ Scenario read error: {e}")
    return 0


def update_trivy():
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
            
            total = sum(counts.values())
            if total > 0:
                print(f"📦 Trivy: {total} vulns (C:{counts['CRITICAL']} H:{counts['HIGH']} M:{counts['MEDIUM']} L:{counts['LOW']})")
                
    except Exception as e:
        print(f"⚠️ Trivy read error: {e}")


# ================= LATENCY MEASUREMENT =================
def measure_latency():
    """Actively measure HTTP latency"""
    endpoints = [
        '/rest/products/search?q=test',
        '/api/Challenges/',
        '/'
    ]
    
    # Collect samples for percentile calculation
    latency_samples = []
    max_samples = 100
    
    while True:
        current_latencies = []
        
        for endpoint in endpoints:
            try:
                start = time.time()
                requests.get(f"{JUICE_SHOP_URL}{endpoint}", timeout=5)
                latency_ms = (time.time() - start) * 1000
                current_latencies.append(latency_ms)
            except:
                pass
        
        if current_latencies:
            avg = sum(current_latencies) / len(current_latencies)
            REQUEST_LATENCY.set(round(avg, 2))
            
            # Store for percentiles
            latency_samples.extend(current_latencies)
            if len(latency_samples) > max_samples:
                latency_samples = latency_samples[-max_samples:]
            
            # Calculate percentiles
            if len(latency_samples) >= 10:
                sorted_samples = sorted(latency_samples)
                p95_idx = int(len(sorted_samples) * 0.95)
                p99_idx = int(len(sorted_samples) * 0.99)
                REQUEST_LATENCY_P95.set(round(sorted_samples[p95_idx], 2))
                REQUEST_LATENCY_P99.set(round(sorted_samples[min(p99_idx, len(sorted_samples)-1)], 2))
        
        time.sleep(5)


# ================= LOG CLASSIFICATION =================
def classify_attack(log_line):
    """Classify attack type from log content"""
    log = log_line.lower()
    
    # SQL Injection patterns
    if any(x in log for x in ['sql', 'injection', '1=1', 'union select', 'or 1=1', "' or", "' and"]):
        return 'SQL Injection'
    
    # XSS patterns
    if any(x in log for x in ['xss', '<script', 'script>', 'alert(', 'onerror=', 'onload=']):
        return 'XSS'
    
    # Path Traversal patterns
    if any(x in log for x in ['../', '..\\', 'path traversal', 'directory traversal', '%2e%2e']):
        return 'Path Traversal'
    
    # Command Injection
    if any(x in log for x in ['command injection', '; ls', '| cat', '`id`', '$(whoami)']):
        return 'Command Injection'
    
    # NoSQL Injection
    if any(x in log for x in ['nosql', '$where', '$gt', '$ne', 'mongodb']):
        return 'NoSQL Injection'
    
    return 'Generic'


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
                
                # ===== IAST DETECTION (DataDog dd-trace) =====
                # Look for dd-trace security events
                if any(x in log for x in [
                    'Vulnerability detected',
                    'dd-trace',
                    'appsec',
                    'attack detected',
                    'security event',
                    'IAST'
                ]):
                    vuln_type = classify_attack(log)
                    IAST_DETECTIONS.labels(vuln_type=vuln_type, source='log').inc()
                    print(f"🔬 IAST [{vuln_type}]: {log[:80]}...")
                
                # ===== RASP DETECTION (Aikido Zen) =====
                if any(x in log for x in ['Zen', 'Aikido', 'aikidosec', 'firewall']):
                    
                    # BLOCKED events
                    if any(x in log.lower() for x in ['blocked', 'block', 'prevented', 'stopped']):
                        RASP_BLOCKS.inc()
                        print(f"🛡️ RASP BLOCK: {log[:80]}...")
                    
                    # DETECTED events (not blocked)
                    elif any(x in log.lower() for x in ['detected', 'attack', 'threat', 'suspicious']):
                        RASP_DETECTIONS.inc()
                        print(f"👁️ RASP DETECT: {log[:80]}...")
                
                # ===== Additional Attack Patterns =====
                # Catch obvious attacks even without explicit security tool mention
                if any(x in log for x in ["' OR 1=1", "<script>", "../../../"]):
                    vuln_type = classify_attack(log)
                    IAST_DETECTIONS.labels(vuln_type=vuln_type, source='pattern').inc()
                    print(f"⚠️ PATTERN [{vuln_type}]: {log[:60]}...")
                        
        except docker.errors.NotFound:
            print(f"⚠️ Container '{JUICE_CONTAINER_NAME}' not found. Retrying in 10s...")
            time.sleep(10)
        except docker.errors.APIError as e:
            print(f"❌ Docker API error: {e}. Retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"❌ Unexpected error: {e}. Retrying in 5s...")
            time.sleep(5)


# ================= BACKGROUND WORKER =================
def file_worker():
    """Background thread for file-based metrics"""
    while True:
        try:
            scenario = update_scenario()
            update_trivy()
            
            scenario_names = {0: 'STANDBY', 1: 'BASELINE', 2: 'DETECTION', 3: 'BLOCKING'}
            print(f"📋 Scenario: {scenario_names.get(scenario, 'UNKNOWN')} | Trivy updated")
            
        except Exception as e:
            print(f"❌ File worker error: {e}")
        
        time.sleep(30)


# ================= MAIN =================
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 THESIS METRICS EXPORTER v4.0 (JARVIS Edition)")
    print("=" * 60)
    print(f"   Target: {JUICE_SHOP_URL}")
    print(f"   Container: {JUICE_CONTAINER_NAME}")
    print(f"   Metrics Port: 9999")
    print("=" * 60)
    print("   Mode: Log-based detection (DataDog API removed)")
    print("=" * 60)
    
    # Initialize metrics
    initialize_metrics()
    
    # Start Prometheus HTTP server
    start_http_server(9999)
    print("📊 Prometheus metrics server: http://localhost:9999/metrics")
    
    # Start background threads
    threading.Thread(target=file_worker, daemon=True, name="FileWorker").start()
    print("📁 File worker started (scenario + trivy)")
    
    threading.Thread(target=measure_latency, daemon=True, name="LatencyWorker").start()
    print("⏱️ Latency measurement started")
    
    # Main thread: Docker log watcher
    print("\n" + "=" * 60)
    print("👀 Starting real-time log monitoring...")
    print("=" * 60 + "\n")
    
    watch_docker_logs()