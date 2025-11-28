
# #!/usr/bin/env python3
# """
# Thesis Metrics Exporter: Hybrid (Log + API)
# Features:
# 1. Real-Time Log Telemetry (For Attack Timelines)
# 2. DataDog API Polling (For Verified IAST Vulnerability Data)
# 3. Trivy Scanning (For Container Security)
# 4. OpenTelemetry Metrics (For Performance/Latency)
# """

# import time
# import json
# import os
# import re
# import threading
# import requests
# import docker
# from prometheus_client import start_http_server, Gauge, Counter

# # ================= CONFIGURATION =================
# METRICS_DIR = '/opt/security-metrics/data'
# SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
# TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
# JUICE_CONTAINER_NAME = 'juice-shop'

# # DATADOG API CONFIG (Passed from Docker Env)
# DD_API_KEY = os.environ.get('DD_API_KEY')
# DD_APP_KEY = os.environ.get('DD_APP_KEY')
# DD_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')

# # ================= METRICS =================
# SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current Thesis Scenario')

# # Security Metrics
# # We separate "Log" detections (Fast) from "API" findings (Accurate)
# IAST_LOG_DETECTIONS = Counter('thesis_iast_log_detections', 'Real-time log detections', ['vuln_type'])
# IAST_API_VULNS = Gauge('thesis_iast_api_vulns', 'Official DataDog IAST Findings', ['vuln_type', 'severity'])

# RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Aikido RASP detections')
# RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Aikido RASP blocks')
# TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container Vulnerabilities', ['severity'])

# # Performance
# REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Average request latency')

# # ================= DATADOG API WORKER =================
# def fetch_datadog_vulns():
#     """
#     Queries DataDog API to get the official list of IAST vulnerabilities.
#     This ensures the 'Vulnerability Breakdown' chart is 100% accurate.
#     """
#     if not DD_API_KEY or not DD_APP_KEY:
#         print("⚠️ DD_API_KEY or DD_APP_KEY missing. Skipping API fetch.")
#         return

#     headers = {
#         "DD-API-KEY": DD_API_KEY,
#         "DD-APPLICATION-KEY": DD_APP_KEY,
#         "Content-Type": "application/json"
#     }
    
#     # Endpoint for Security Signals (IAST/AppSec)
#     url = f"https://api.{DD_SITE}/api/v2/security_monitoring/signals/search"
    
#     payload = {
#         "filter": {
#             "query": "service:juice-shop status:high",
#             "from": "now-1h",
#             "to": "now"
#         },
#         "page": {"limit": 50}
#     }

#     try:
#         response = requests.post(url, headers=headers, json=payload, timeout=10)
#         if response.status_code == 200:
#             data = response.json()
            
#             # Reset Gauges to avoid stale data
#             counts = {} 
            
#             for signal in data.get('data', []):
#                 attrs = signal.get('attributes', {})
#                 tags = attrs.get('tags', [])
                
#                 # Extract Vulnerability Type from Tags
#                 vuln_type = "Generic"
#                 severity = "medium"
                
#                 for tag in tags:
#                     if tag.startswith('vulnerability_type:'):
#                         vuln_type = tag.split(':')[1].replace('_', ' ').title()
                
#                 key = (vuln_type, attrs.get('severity', 'medium'))
#                 counts[key] = counts.get(key, 0) + 1

#             # Update Prometheus Metrics
#             for (v_type, sev), count in counts.items():
#                 IAST_API_VULNS.labels(vuln_type=v_type, severity=sev).set(count)
            
#             print(f"✅ DataDog API: Synced {len(data.get('data', []))} vulnerabilities.")
#         else:
#             print(f"⚠️ DataDog API Error: {response.status_code} - {response.text}")
            
#     except Exception as e:
#         print(f"⚠️ DataDog API Exception: {e}")

# # ================= LOCAL LOGIC =================
# def update_scenario_metrics():
#     try:
#         if os.path.exists(SCENARIO_FILE):
#             with open(SCENARIO_FILE, 'r') as f:
#                 data = json.load(f)
#                 SCENARIO_GAUGE.set(data.get('scenario_id', 0))
#     except: pass

# def update_trivy_metrics():
#     try:
#         if os.path.exists(TRIVY_FILE):
#             with open(TRIVY_FILE, 'r') as f:
#                 data = json.load(f)
#             counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
#             if 'Results' in data:
#                 for result in data['Results']:
#                     if 'Vulnerabilities' in result:
#                         for vuln in result['Vulnerabilities']:
#                             sev = vuln.get('Severity', 'UNKNOWN')
#                             if sev in counts: counts[sev] += 1
#             for sev, count in counts.items():
#                 TRIVY_VULNS.labels(severity=sev).set(count)
#     except: pass

# def classify_attack_type(log_line):
#     log = log_line.lower()
#     if 'sql' in log or 'injection' in log: return 'SQL Injection'
#     if 'xss' in log or 'script' in log: return 'XSS'
#     if 'path' in log or 'traversal' in log: return 'Path Traversal'
#     return 'Generic Vulnerability'

# def watch_docker_logs():
#     client = docker.from_env()
#     print(f"🔌 Watching '{JUICE_CONTAINER_NAME}' logs...")
    
#     while True:
#         try:
#             container = client.containers.get(JUICE_CONTAINER_NAME)
#             for line in container.logs(stream=True, tail=0, follow=True):
#                 log = line.decode('utf-8', errors='ignore').strip()
#                 if not log: continue
                
#                 # --- REAL-TIME LOGS (Fast) ---
#                 if "Vulnerability detected" in log or "dd-trace" in log and "attack" in log.lower():
#                     vuln_type = classify_attack_type(log)
#                     IAST_LOG_DETECTIONS.labels(vuln_type=vuln_type).inc()
#                     print(f"🚨 LOG DETECT: {vuln_type}")

#                 if "Zen" in log or "Aikido" in log:
#                     if "blocked" in log.lower():
#                         RASP_BLOCKS.inc()
#                         print(f"🛡️ RASP BLOCKED")
#                     elif "detected" in log.lower():
#                         RASP_DETECTIONS.inc()
#                         print(f"👁️ RASP DETECTED")
                        
#                 # --- LATENCY (Performance) ---
#                 match = re.search(r'(\d+\.?\d*)\s*ms', log)
#                 if match:
#                     try:
#                         REQUEST_LATENCY.set(float(match.group(1)))
#                     except: pass

#         except Exception as e:
#             print(f"❌ Docker error: {e}. Retrying in 5s...")
#             time.sleep(5)

# if __name__ == '__main__':
#     print("🚀 Hybrid Metrics Exporter Running on :9999")
#     start_http_server(9999)
    
#     # Thread 1: Scenarios & Trivy (Local Files)
#     threading.Thread(target=lambda: [update_scenario_metrics() or update_trivy_metrics() or time.sleep(5) for _ in iter(int, 1)], daemon=True).start()
    
#     # Thread 2: DataDog API (Remote Fetch - Every 60s)
#     threading.Thread(target=lambda: [fetch_datadog_vulns() or time.sleep(60) for _ in iter(int, 1)], daemon=True).start()
    
#     # Main Thread: Logs
#     watch_docker_logs()

#!/usr/bin/env python3
import time, json, os, re, threading, requests, docker
from prometheus_client import start_http_server, Gauge, Counter

METRICS_DIR = '/opt/security-metrics/data'
SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
TRIVY_FILE = os.path.join(METRICS_DIR, 'trivy-results.json')
JUICE_CONTAINER_NAME = 'juice-shop'
DD_API_KEY = os.environ.get('DD_API_KEY')
DD_APP_KEY = os.environ.get('DD_APP_KEY')
DD_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')

SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current Thesis Scenario')
IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'DataDog IAST', ['vuln_type', 'source'])
IAST_API_VULNS = Gauge('thesis_iast_api_vulns', 'Official DataDog IAST Findings', ['vuln_type', 'severity'])
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'RASP Detections')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'RASP Blocks')
TRIVY_VULNS = Gauge('thesis_trivy_vulns_total', 'Container Vulns', ['severity'])
REQUEST_LATENCY = Gauge('thesis_request_latency_ms', 'Avg Latency')

def fetch_datadog_vulns():
    if not DD_API_KEY or not DD_APP_KEY: return
    headers = {"DD-API-KEY": DD_API_KEY, "DD-APPLICATION-KEY": DD_APP_KEY, "Content-Type": "application/json"}
    url = f"https://api.{DD_SITE}/api/v2/security_monitoring/signals/search"
    payload = {"filter": {"query": "service:juice-shop status:high", "from": "now-1h", "to": "now"}, "page": {"limit": 50}}
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            counts = {}
            for signal in data.get('data', []):
                vuln = "Generic"
                for tag in signal.get('attributes', {}).get('tags', []):
                    if tag.startswith('vulnerability_type:'): vuln = tag.split(':')[1].replace('_', ' ').title()
                key = (vuln, signal.get('attributes', {}).get('severity', 'medium'))
                counts[key] = counts.get(key, 0) + 1
            for (v, s), c in counts.items(): IAST_API_VULNS.labels(vuln_type=v, severity=s).set(c)
    except: pass

def update_files():
    try:
        if os.path.exists(SCENARIO_FILE):
            with open(SCENARIO_FILE) as f: SCENARIO_GAUGE.set(json.load(f).get('scenario_id', 0))
        if os.path.exists(TRIVY_FILE):
            with open(TRIVY_FILE) as f:
                data = json.load(f)
                counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                if 'Results' in data:
                    for r in data['Results']:
                        for v in r.get('Vulnerabilities', []):
                            s = v.get('Severity', 'UNKNOWN')
                            if s in counts: counts[s] += 1
                for s, c in counts.items(): TRIVY_VULNS.labels(severity=s).set(c)
    except: pass

def watch_docker_logs():
    client = docker.from_env()
    print(f"🔌 Watching {JUICE_CONTAINER_NAME}")
    while True:
        try:
            container = client.containers.get(JUICE_CONTAINER_NAME)
            for line in container.logs(stream=True, tail=0, follow=True):
                log = line.decode('utf-8', errors='ignore').strip()
                if not log: continue
                
                if "Vulnerability detected" in log or "dd-trace" in log:
                    vuln = "Generic"
                    if "SQL" in log: vuln = "SQL Injection"
                    elif "XSS" in log: vuln = "XSS"
                    IAST_DETECTIONS.labels(vuln_type=vuln, source='log').inc()
                    print(f"🚨 IAST: {vuln}")

                if "Zen" in log or "Aikido" in log:
                    if "blocked" in log.lower(): RASP_BLOCKS.inc(); print("🛡️ BLOCK")
                    elif "detected" in log.lower(): RASP_DETECTIONS.inc(); print("👁️ DETECT")
                
                match = re.search(r'(?:response_time=|)(\d+\.?\d*)\s*ms', log)
                if match:
                    try: REQUEST_LATENCY.set(float(match.group(1)))
                    except: pass
        except: time.sleep(5)

if __name__ == '__main__':
    print("🚀 Exporter Running")
    start_http_server(9999)
    threading.Thread(target=lambda: [update_files() or fetch_datadog_vulns() or time.sleep(60) for _ in iter(int, 1)], daemon=True).start()
    watch_docker_logs()