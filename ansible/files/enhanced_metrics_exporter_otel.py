#!/usr/bin/env python3
"""
Thesis Log Telemetry Exporter
- Connects to Docker Socket.
- Tails Juice Shop logs in Real-Time.
- Regex matches Datadog IAST and Aikido RASP events.
- Zero Latency Dashboard updates.
"""
import time
import json
import os
import docker
import re
from prometheus_client import start_http_server, Gauge, Counter

# ============= CONFIGURATION =============
METRICS_DIR = '/opt/security-metrics/data'
SCENARIO_FILE = os.path.join(METRICS_DIR, 'scenario_info.json')
JUICE_CONTAINER_NAME = 'juice-shop'

# ============= METRICS DEFINITIONS =============

# 1. SCENARIO STATUS
SCENARIO_GAUGE = Gauge('thesis_scenario_id', 'Current Thesis Scenario (1=Baseline, 2=Detect, 3=Block)')

# 2. TOOL SPECIFIC COUNTERS (This answers your "Attribution" need)
# Counts whenever Datadog prints a detection log
IAST_DETECTIONS = Counter('thesis_iast_detections_total', 'Real-time detections by Datadog IAST')

# Counts whenever Aikido prints a block/detect log
RASP_DETECTIONS = Counter('thesis_rasp_detections_total', 'Real-time detections by Aikido RASP')
RASP_BLOCKS = Counter('thesis_rasp_blocks_total', 'Real-time BLOCKS by Aikido RASP')

# ============= LOGIC =============

def watch_docker_logs():
    """
    Infinite loop that reads every line of log from Juice Shop.
    """
    client = docker.from_env()
    print(f"🔌 Connected to Docker. Waiting for container '{JUICE_CONTAINER_NAME}'...")

    while True:
        try:
            container = client.containers.get(JUICE_CONTAINER_NAME)
            print(f"✅ Attached to {JUICE_CONTAINER_NAME} logs.")
            
            # stream=True makes this a blocking loop that runs forever
            for line in container.logs(stream=True, tail=0, follow=True):
                log_line = line.decode('utf-8', errors='ignore')
                process_log_line(log_line)
                
        except docker.errors.NotFound:
            print(f"⚠️ Container {JUICE_CONTAINER_NAME} not found. Retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"❌ Docker error: {e}. Retrying...")
            time.sleep(5)

def process_log_line(line):
    """
    The Brains: Decides if a log line is an IAST detection or RASP block.
    NOTE: You may need to adjust these substrings based on exact output during testing.
    """
    
    # --- DATADOG IAST DETECTION LOGIC ---
    # Datadog usually logs: "[dd-trace] Vulnerability detected: ..."
    if "dd-trace" in line and "Vulnerability detected" in line:
        IAST_DETECTIONS.inc()
        print(f"🚨 IAST HIT: {line[:50]}...")

    # --- AIKIDO RASP DETECTION LOGIC ---
    # Aikido logs vary, but usually contain "@aikidosec" or specific error codes
    # We look for "Aikido" and distinct behaviors
    if "Aikido" in line or "@aikidosec" in line:
        
        # If it's a blocking event (Exception thrown)
        if "SecurityException" in line or "Blocked" in line or "Attack detected" in line:
            RASP_DETECTIONS.inc() # It was detected
            
            # Check if we are in blocking mode (Scenario 3)
            # We can infer this from the log or just check if it actually stopped execution
            # For simplicity, if it says "Blocked", we increment blocks.
            if "Blocked" in line:
                RASP_BLOCKS.inc()
                print(f"🛡️ RASP BLOCK: {line[:50]}...")
            else:
                print(f"👁️ RASP DETECT: {line[:50]}...")

def update_scenario_file():
    """Reads the JSON file to update the dashboard context"""
    try:
        if os.path.exists(SCENARIO_FILE):
            with open(SCENARIO_FILE, 'r') as f:
                data = json.load(f)
                SCENARIO_GAUGE.set(data.get('scenario_id', 0))
    except:
        pass

def main():
    print("🚀 Thesis Log Telemetry Exporter Running on :9999")
    start_http_server(9999)
    
    # We run the log watcher in the main thread because it blocks
    # We need a separate thread for the scenario file updater
    import threading
    
    def file_watcher():
        while True:
            update_scenario_file()
            time.sleep(2)
            
    t = threading.Thread(target=file_watcher)
    t.daemon = True
    t.start()
    
    # Start the log watcher
    watch_docker_logs()

if __name__ == '__main__':
    main()