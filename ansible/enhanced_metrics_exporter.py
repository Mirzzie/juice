#!/usr/bin/env python3
"""
Enhanced Security Metrics Exporter for Prometheus - Scenario-Based Comparison
Collects metrics from Semgrep SAST, OWASP ZAP DAST, DataDog IAST, and Aikido RASP
Supports two scenarios:
- Scenario 1: IAST Only (DataDog IAST ON, Aikido RASP OFF)
- Scenario 2: IAST + RASP (DataDog IAST ON, Aikido RASP ON)
"""
import json
import os
import time
import traceback
from collections import defaultdict
from prometheus_client import start_http_server, Gauge, Counter
import requests

# ============= PROMETHEUS METRICS DEFINITIONS =============

# SAST Metrics (Semgrep) - No scenario tagging (runs once)
sast_vulnerabilities = Gauge(
    'sast_vulnerabilities_found', 
    'SAST vulnerabilities from Semgrep', 
    ['severity', 'rule_id', 'language']
)

# DAST Metrics (OWASP ZAP) - WITH scenario tagging
dast_vulnerabilities = Gauge(
    'dast_vulnerabilities_found', 
    'DAST vulnerabilities from ZAP', 
    ['severity', 'scan_type', 'vuln_name', 'confidence', 'scenario']
)

# IAST/RASP Metrics - WITH scenario tagging
security_detections = Counter(
    'security_detections_total', 
    'Total security detections', 
    ['tool', 'vuln_type', 'severity', 'scenario']
)

security_blocks = Counter(
    'security_blocks_total', 
    'Total attack blocks (RASP only)', 
    ['tool', 'attack_type', 'scenario']
)

response_time = Gauge(
    'security_response_time_ms', 
    'Security tool response time impact', 
    ['tool', 'scenario']
)

scan_phase = Gauge(
    'current_scan_phase', 
    'Current DAST scan phase (0=idle, 1=baseline, 2=full, 3=attacks, 4=analysis)'
)

scenario_id = Gauge(
    'current_scenario_id',
    'Current test scenario (1=iast-only, 2=iast-rasp)'
)

# Scenario comparison metrics
scenario_comparison = Gauge(
    'scenario_metrics',
    'Comparative metrics by scenario',
    ['metric_type', 'scenario']
)

# ============= CONFIGURATION =============

DATADOG_API_KEY = os.environ.get('DD_API_KEY', '')
DATADOG_APP_KEY = os.environ.get('DD_APP_KEY', '')
DATADOG_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')
AIKIDO_TOKEN = os.environ.get('AIKIDO_TOKEN', '')
METRICS_DIR = '/opt/security-metrics/data'
ZAP_RESULTS_DIR = '/opt/security-metrics/zap-results'

os.makedirs(METRICS_DIR, exist_ok=True)
os.makedirs(ZAP_RESULTS_DIR, exist_ok=True)

# Global state
current_scenario = "unknown"
current_phase = 0

# ============= SEMGREP SAST PARSER =============

def parse_semgrep_results():
    """Parse Semgrep SAST results (runs once, no scenario)"""
    try:
        semgrep_file = os.path.join(METRICS_DIR, 'semgrep-results.json')
        if not os.path.exists(semgrep_file):
            return
        
        print(f"📄 Parsing Semgrep SAST results...")
        with open(semgrep_file, 'r') as f:
            data = json.load(f)
        
        # Clear old metrics
        sast_vulnerabilities._metrics.clear()
        
        results = data.get('results', [])
        severity_counts = defaultdict(int)
        
        for finding in results:
            extra = finding.get('extra', {})
            severity = extra.get('severity', 'INFO').upper()
            rule_id = finding.get('check_id', 'unknown').split('.')[-1]
            
            path = finding.get('path', '')
            if path.endswith(('.js', '.ts')):
                language = 'javascript'
            elif path.endswith('.py'):
                language = 'python'
            elif path.endswith('.java'):
                language = 'java'
            else:
                language = 'other'
            
            severity_counts[severity] += 1
            
            sast_vulnerabilities.labels(
                severity=severity,
                rule_id=rule_id,
                language=language
            ).set(1)
        
        # Set aggregate counts
        for severity, count in severity_counts.items():
            sast_vulnerabilities.labels(
                severity=severity,
                rule_id='total',
                language='all'
            ).set(count)
        
        total = len(results)
        print(f"✅ SAST (Semgrep): {total} findings")
        for severity, count in severity_counts.items():
            print(f"   - {severity}: {count}")
        
        return total
        
    except Exception as e:
        print(f"❌ Error parsing Semgrep results: {e}")
        return 0

# ============= OWASP ZAP DAST PARSER (Scenario-Aware) =============

def parse_zap_results():
    """Parse OWASP ZAP DAST scan results for both scenarios"""
    global current_scenario
    
    try:
        # Look for scenario-specific results
        for scenario in ['scenario1', 'scenario2']:
            scenario_name = 'iast-only' if scenario == 'scenario1' else 'iast-rasp'
            
            for scan_type in ['baseline', 'full']:
                json_file = os.path.join(ZAP_RESULTS_DIR, f'{scenario}_{scan_type}.json')
                
                if not os.path.exists(json_file):
                    continue
                
                print(f"📄 Parsing ZAP {scan_type} scan for {scenario_name}...")
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                site = data.get('site', [{}])
                if isinstance(site, list):
                    site = site[0] if len(site) > 0 else {}
                
                alerts = site.get('alerts', [])
                
                if not alerts:
                    continue
                
                severity_counts = defaultdict(int)
                
                for alert in alerts:
                    risk_desc = alert.get('riskdesc', 'Unknown')
                    risk = risk_desc.split()[0] if ' ' in risk_desc else risk_desc
                    vuln_name = alert.get('name', 'Unknown')
                    confidence = alert.get('confidence', 'Unknown')
                    instances = alert.get('instances', [])
                    instance_count = len(instances)
                    
                    severity_counts[risk] += instance_count
                    
                    # Set detailed metric WITH scenario tag
                    dast_vulnerabilities.labels(
                        severity=risk,
                        scan_type=scan_type,
                        vuln_name=vuln_name,
                        confidence=confidence,
                        scenario=scenario_name
                    ).set(instance_count)
                
                # Set aggregate totals
                for severity, count in severity_counts.items():
                    dast_vulnerabilities.labels(
                        severity=severity,
                        scan_type=scan_type,
                        vuln_name='total',
                        confidence='all',
                        scenario=scenario_name
                    ).set(count)
                
                total = sum(severity_counts.values())
                print(f"✅ DAST {scan_type.upper()} ({scenario_name}): {total} vulnerabilities")
        
    except Exception as e:
        print(f"❌ Error parsing ZAP results: {e}")
        traceback.print_exc()

# ============= DATADOG IAST INTEGRATION (Scenario-Aware) =============

def fetch_datadog_iast_metrics():
    """Fetch IAST vulnerabilities from DataDog API"""
    global current_scenario
    
    if not DATADOG_API_KEY or not DATADOG_APP_KEY:
        return

    try:
        headers = {
            'DD-API-KEY': DATADOG_API_KEY,
            'DD-APPLICATION-KEY': DATADOG_APP_KEY,
            'Content-Type': 'application/json'
        }
        
        # Query for both scenarios
        for scenario_name in ['juice-shop-iast-only', 'juice-shop-iast-rasp']:
            scenario_label = 'iast-only' if 'only' in scenario_name else 'iast-rasp'
            
            url = f'https://api.{DATADOG_SITE}/api/v2/security_monitoring/signals'
            params = {
                'filter[query]': f'service:{scenario_name}',
                'filter[from]': int((time.time() - 3600) * 1000),
                'page[limit]': 100
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                signals = data.get('data', [])
                detections = defaultdict(int)
                
                for signal in signals:
                    attributes = signal.get('attributes', {})
                    rule = attributes.get('rule', {})
                    vuln_type = rule.get('name', 'unknown').lower().replace(' ', '_')
                    severity = attributes.get('severity', 'unknown')
                    
                    detections[(vuln_type, severity)] += 1
                
                # Update metrics WITH scenario tag
                for (vuln_type, severity), count in detections.items():
                    security_detections.labels(
                        tool='datadog_iast',
                        vuln_type=vuln_type,
                        severity=severity,
                        scenario=scenario_label
                    )._value._value = count
                
                if detections:
                    print(f"✅ DataDog IAST ({scenario_label}): {len(detections)} types, {sum(detections.values())} detections")
            
    except requests.exceptions.Timeout:
        print(f"⚠️  DataDog API timeout")
    except Exception as e:
        print(f"❌ Error fetching DataDog metrics: {e}")

# ============= AIKIDO RASP INTEGRATION (Scenario-Aware) =============

def fetch_aikido_rasp_metrics():
    """Fetch RASP detections and blocks from Aikido API"""
    global current_scenario
    
    if not AIKIDO_TOKEN:
        return

    try:
        headers = {
            'Authorization': f'Bearer {AIKIDO_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        url = 'https://app.aikido.dev/api/v1/runtime/events'
        params = {
            'limit': 100,
            'from': int((time.time() - 3600) * 1000)
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            events = data.get('events', data.get('data', []))
            
            detections = defaultdict(int)
            blocks = defaultdict(int)
            
            for event in events:
                attack_type = event.get('type', event.get('attack_type', 'unknown'))
                severity = event.get('severity', 'unknown')
                blocked = event.get('blocked', event.get('was_blocked', False))
                
                detections[(attack_type, severity)] += 1
                if blocked:
                    blocks[attack_type] += 1
            
            # RASP only active in scenario 2 (iast-rasp)
            scenario_label = 'iast-rasp'
            
            # Update detection metrics
            for (attack_type, severity), count in detections.items():
                security_detections.labels(
                    tool='aikido_rasp',
                    vuln_type=attack_type,
                    severity=severity,
                    scenario=scenario_label
                )._value._value = count
            
            # Update block metrics
            for attack_type, count in blocks.items():
                security_blocks.labels(
                    tool='aikido_rasp',
                    attack_type=attack_type,
                    scenario=scenario_label
                )._value._value = count
            
            total_detections = sum(detections.values())
            total_blocks = sum(blocks.values())
            block_rate = (total_blocks / total_detections * 100) if total_detections > 0 else 0
            
            print(f"✅ Aikido RASP: {total_detections} detections, {total_blocks} blocks ({block_rate:.1f}% block rate)")
            
            # Update comparison metric
            scenario_comparison.labels(
                metric_type='rasp_block_rate',
                scenario=scenario_label
            ).set(block_rate)
            
    except requests.exceptions.Timeout:
        print(f"⚠️  Aikido API timeout")
    except Exception as e:
        print(f"❌ Error fetching Aikido metrics: {e}")

# ============= MANUAL METRICS LOADER =============

def load_manual_metrics():
    """Load manually recorded metrics from JSON files"""
    global current_scenario, current_phase
    
    try:
        metrics_file = os.path.join(METRICS_DIR, 'manual_metrics.json')
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                data = json.load(f)
            
            if 'scan_phase' in data:
                current_phase = data['scan_phase']
                scan_phase.set(current_phase)
            
            if 'scenario' in data:
                current_scenario = data['scenario']
            
            if 'scenario_id' in data:
                scenario_id.set(data['scenario_id'])
            
            if 'response_times' in data:
                for tool, time_ms in data['response_times'].items():
                    response_time.labels(tool=tool, scenario=current_scenario).set(time_ms)
            
            print(f"✅ Loaded manual metrics - Scenario: {current_scenario}, Phase: {current_phase}")
    except Exception as e:
        print(f"⚠️  Error loading manual metrics: {e}")

# ============= SCENARIO COMPARISON CALCULATOR =============

def calculate_scenario_comparison():
    """Calculate comparative metrics between scenarios"""
    try:
        # This would query existing metrics and compute comparisons
        # For now, just placeholder logic
        
        print("📊 Calculating scenario comparison metrics...")
        
        # You can add more sophisticated comparison logic here
        # For example, compare detection rates, response times, etc.
        
    except Exception as e:
        print(f"⚠️  Error calculating comparisons: {e}")

# ============= MAIN COLLECTION LOOP =============

def collect_all_metrics():
    """Collect metrics from all sources"""
    print(f"\n{'='*70}")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Collecting Security Metrics")
    print(f"Current Scenario: {current_scenario.upper()}")
    print(f"{'='*70}")
    
    parse_semgrep_results()         # SAST (no scenario)
    parse_zap_results()             # DAST (scenario-aware)
    fetch_datadog_iast_metrics()    # IAST (scenario-aware)
    fetch_aikido_rasp_metrics()     # RASP (scenario 2 only)
    load_manual_metrics()           # Manual metrics
    calculate_scenario_comparison() # Comparative analysis
    
    print(f"{'='*70}")
    print("✅ Metrics collection cycle complete\n")

# ============= STARTUP =============

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 Security Metrics Exporter Starting (Scenario Comparison Mode)")
    print("="*70)
    print(f"📊 Metrics endpoint: http://localhost:9999/metrics")
    print(f"📁 Metrics directory: {METRICS_DIR}")
    print(f"🕷️  ZAP results directory: {ZAP_RESULTS_DIR}")
    print(f"🔄 Collection interval: 30 seconds")
    print(f"🎯 Scenarios supported:")
    print(f"   - Scenario 1: IAST Only (iast-only)")
    print(f"   - Scenario 2: IAST + RASP (iast-rasp)")
    print("="*70 + "\n")
    
    # Start Prometheus HTTP server
    start_http_server(9999)
    print("✅ Prometheus exporter running on port 9999\n")
    
    # Initial collection
    try:
        collect_all_metrics()
    except Exception as e:
        print(f"❌ Error in initial collection: {e}")
    
    # Continuous collection loop
    while True:
        try:
            time.sleep(30)
            collect_all_metrics()
        except KeyboardInterrupt:
            print("\n👋 Shutting down metrics exporter...")
            break
        except Exception as e:
            print(f"❌ Error in metrics collection: {e}")
            traceback.print_exc()
            time.sleep(30)
