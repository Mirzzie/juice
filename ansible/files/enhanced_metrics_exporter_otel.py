#!/usr/bin/env python3
"""
Thesis Metrics Exporter v5.0 - JARVIS Edition (Clean)
======================================================
Focused metrics:
- RASP blocks & detections (Aikido Zen)
- Response latency (active measurement)
- Container vulnerabilities (Trivy)
- Scenario tracking

Removed: IAST detection logic (unreliable)
"""

import time
import json
import os
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
# Scenario
SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current scenario (1=Baseline, 2=Detection, 3=Blocking)')

# RASP (Aikido Zen)
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Aikido RASP attack detections')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Aikido RASP attack blocks')

# Container Security (Trivy)
TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container vulnerabilities', ['severity'])

# Performance
REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Average request latency (ms)')
REQUEST_LATENCY_P95 = Gauge('thesis_request_latency_p95_ms', 'P95 request latency (ms)')


# ================= INITIALIZATION =================
def initialize_metrics():
    print("📊 Initializing metrics...")
    SCENARIO_GAUGE.set(0)
    REQUEST_LATENCY.set(0)
    REQUEST_LATENCY_P95.set(0)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        TRIVY_VULNS.labels(severity=severity).set(0)
    print("✅ Done")


# ================= FILE-BASED METRICS =================
def update_scenario():
    """Read scenario from file"""
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
    """Read Trivy results from file"""
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
    """Active HTTP latency measurement"""
    endpoints = ['/rest/products/search?q=test', '/api/Challenges/', '/']
    latency_window = deque(maxlen=50)
    
    while True:
        batch = []
        for endpoint in endpoints:
            try:
                start = time.time()
                requests.get(f"{JUICE_SHOP_URL}{endpoint}", timeout=5)
                batch.append((time.time() - start) * 1000)
            except:
                pass
        
        if batch:
            latency_window.extend(batch)
            samples = list(latency_window)
            
            # Average
            REQUEST_LATENCY.set(round(sum(samples) / len(samples), 2))
            
            # P95
            if len(samples) >= 5:
                sorted_s = sorted(samples)
                p95_idx = int(len(sorted_s) * 0.95)
                REQUEST_LATENCY_P95.set(round(sorted_s[p95_idx], 2))
        
        time.sleep(5)


# ================= DOCKER LOG WATCHER =================
def watch_logs():
    """Watch container logs for RASP events"""
    client = docker.from_env()
    print(f"👀 Watching '{JUICE_CONTAINER_NAME}' logs...")
    
    while True:
        try:
            container = client.containers.get(JUICE_CONTAINER_NAME)
            
            for line in container.logs(stream=True, tail=0, follow=True):
                log = line.decode('utf-8', errors='ignore').strip()
                if not log:
                    continue
                
                # RASP Detection (Aikido Zen)
                if any(x in log for x in ['Zen', 'Aikido', 'aikidosec']):
                    log_lower = log.lower()
                    
                    if any(x in log_lower for x in ['blocked', 'block', 'prevented', 'stopped']):
                        RASP_BLOCKS.inc()
                        print(f"🛡️ BLOCK: {log[:80]}")
                    
                    elif any(x in log_lower for x in ['detected', 'attack', 'threat', 'suspicious']):
                        RASP_DETECTIONS.inc()
                        print(f"👁️ DETECT: {log[:80]}")
                        
        except docker.errors.NotFound:
            print(f"⚠️ Container not found, waiting...")
            time.sleep(10)
        except Exception as e:
            print(f"❌ Error: {e}")
            time.sleep(5)


# ================= BACKGROUND WORKER =================
def file_worker():
    """Update file-based metrics periodically"""
    while True:
        try:
            scenario = update_scenario()
            update_trivy()
            names = {0: 'STANDBY', 1: 'BASELINE', 2: 'DETECTION', 3: 'BLOCKING'}
            print(f"📋 Scenario: {names.get(scenario, '?')}")
        except Exception as e:
            print(f"❌ Worker error: {e}")
        time.sleep(30)


# ================= MAIN =================
if __name__ == '__main__':
    print("=" * 50)
    print("🚀 THESIS EXPORTER v5.0 (JARVIS)")
    print("=" * 50)
    print(f"   Target: {JUICE_SHOP_URL}")
    print(f"   Container: {JUICE_CONTAINER_NAME}")
    print("=" * 50)
    
    initialize_metrics()
    
    start_http_server(9999)
    print("📊 Metrics: http://localhost:9999")
    
    threading.Thread(target=file_worker, daemon=True).start()
    threading.Thread(target=measure_latency, daemon=True).start()
    
    print("\n👀 Monitoring RASP events...\n")
    watch_logs()