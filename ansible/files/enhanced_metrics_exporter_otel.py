#!/usr/bin/env python3
"""
Enhanced Security Metrics Exporter with OpenTelemetry Support
Collects metrics from:
- Semgrep SAST
- OWASP ZAP DAST
- DataDog IAST (via API + OpenTelemetry)
- Aikido RASP (via API + OpenTelemetry)

Supports three scenarios:
1. IAST Only (no RASP)
2. IAST + RASP Detection-Only (no blocking)
3. IAST + RASP Blocking Mode (~80% block rate)
"""
import json
import os
import time
import traceback
from collections import defaultdict
from prometheus_client import start_http_server, Gauge, Counter
import requests

# OpenTelemetry imports
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    print("⚠️  OpenTelemetry SDK not available - running without OTel support")

# ============= PROMETHEUS METRICS DEFINITIONS =============

# SAST Metrics (Semgrep) - No scenario tagging
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

scenario_id_metric = Gauge(
    'current_scenario_id',
    'Current test scenario (1=iast-only, 2=iast-rasp-detect, 3=iast-rasp-block)'
)

# Three-scenario comparison metrics
scenario_comparison = Gauge(
    'scenario_metrics',
    'Comparative metrics by scenario',
    ['metric_type', 'scenario']
)

# OpenTelemetry health metrics
otel_collection_status = Gauge(
    'otel_collection_status',
    'OpenTelemetry collection status',
    ['source', 'status']
)

# ============= CONFIGURATION =============

DATADOG_API_KEY = os.environ.get('DD_API_KEY', '')
DATADOG_APP_KEY = os.environ.get('DD_APP_KEY', '')
DATADOG_SITE = os.environ.get('DD_SITE', 'us5.datadoghq.com')
AIKIDO_TOKEN = os.environ.get('AIKIDO_TOKEN', '')
METRICS_DIR = '/opt/security-metrics/data'
ZAP_RESULTS_DIR = '/opt/security-metrics/zap-results'
OTEL_ENDPOINT = os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4317')

os.makedirs(METRICS_DIR, exist_ok=True)
os.makedirs(ZAP_RESULTS_DIR, exist_ok=True)

# Global state
current_scenario = "unknown"
current_scenario_id = 0
current_phase = 0
rasp_enabled = False
rasp_blocking = False

# ============= OPENTELEMETRY SETUP =============

def setup_opentelemetry():
    """Initialize OpenTelemetry tracing and metrics"""
    if not OTEL_AVAILABLE:
        print("⚠️  Skipping OpenTelemetry setup - SDK not available")
        return None, None
    
    try:
        # Create resource
        resource = Resource.create({
            "service.name": "security-metrics-exporter",
            "service.version": "1.0.0",
            "deployment.environment": "dev"
        })
        
        # Setup tracing
        trace_provider = TracerProvider(resource=resource)
        otlp_span_exporter = OTLPSpanExporter(endpoint=OTEL_ENDPOINT, insecure=True)
        trace_provider.add_span_processor(BatchSpanProcessor(otlp_span_exporter))
        trace.set_tracer_provider(trace_provider)
        tracer = trace.get_tracer(__name__)
        
        # Setup metrics
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=OTEL_ENDPOINT, insecure=True),
            export_interval_millis=30000
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter(__name__)
        
        print(f"✅ OpenTelemetry initialized - exporting to {OTEL_ENDPOINT}")
        otel_collection_status.labels(source='exporter', status='active').set(1)
        
        return tracer, meter
    except Exception as e:
        print(f"❌ Failed to initialize OpenTelemetry: {e}")
        otel_collection_status.labels(source='exporter', status='failed').set(0)
        return None, None

# Initialize OpenTelemetry
otel_tracer, otel_meter = setup_opentelemetry()

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

# ============= OWASP ZAP DAST PARSER (Three-Scenario) =============

def parse_zap_results():
    """Parse OWASP ZAP DAST scan results for all three scenarios"""
    global current_scenario
    
    try:
        # Map scenario files to scenario labels
        scenario_mapping = {
            'scenario1': 'iast-only',
            'scenario2a': 'iast-rasp-detect',
            'scenario2b': 'iast-rasp-block'
        }
        
        for scenario_file, scenario_name in scenario_mapping.items():
            for scan_type in ['baseline', 'full']:
                json_file = os.path.join(ZAP_RESULTS_DIR, f'{scenario_file}_{scan_type}.json')
                
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
                    
                    dast_vulnerabilities.labels(
                        severity=risk,
                        scan_type=scan_type,
                        vuln_name=vuln_name,
                        confidence=confidence,
                        scenario=scenario_name
                    ).set(instance_count)
                
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

# ============= DATADOG IAST INTEGRATION (OpenTelemetry-Aware) =============

def fetch_datadog_iast_metrics():
    """Fetch IAST vulnerabilities from DataDog API (all scenarios)"""
    global current_scenario
    
    if not DATADOG_API_KEY or not DATADOG_APP_KEY:
        return

    try:
        # Create OpenTelemetry span if available
        span = None
        if otel_tracer:
            span = otel_tracer.start_span("fetch_datadog_iast_metrics")
        
        headers = {
            'DD-API-KEY': DATADOG_API_KEY,
            'DD-APPLICATION-KEY': DATADOG_APP_KEY
        }
        
        # Query for all three scenarios
        scenario_services = {
            'juice-shop-iast-only': 'iast-only',
            'juice-shop-iast-rasp-detect': 'iast-rasp-detect',
            'juice-shop-iast-rasp-block': 'iast-rasp-block'
        }
        
        for service_name, scenario_label in scenario_services.items():
            url = f'https://api.{DATADOG_SITE}/api/v2/security_monitoring/signals'
            params = {
                'filter[query]': f'service:{service_name}',
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
                
                for (vuln_type, severity), count in detections.items():
                    security_detections.labels(
                        tool='datadog_iast',
                        vuln_type=vuln_type,
                        severity=severity,
                        scenario=scenario_label
                    )._value._value = count
                
                if detections:
                    print(f"✅ DataDog IAST ({scenario_label}): {len(detections)} types, {sum(detections.values())} detections")
                    otel_collection_status.labels(source='datadog_iast', status='success').set(1)
        
        if span:
            span.end()
            
    except requests.exceptions.Timeout:
        print(f"⚠️  DataDog API timeout")
        otel_collection_status.labels(source='datadog_iast', status='timeout').set(0)
    except Exception as e:
        print(f"❌ Error fetching DataDog metrics: {e}")
        otel_collection_status.labels(source='datadog_iast', status='error').set(0)

# ============= AIKIDO RASP INTEGRATION (OpenTelemetry-Aware) =============

def fetch_aikido_rasp_metrics():
    """Fetch RASP detections and blocks from Aikido API (scenarios 2a and 2b)"""
    global current_scenario, rasp_blocking
    
    if not AIKIDO_TOKEN:
        return

    try:
        # Create OpenTelemetry span if available
        span = None
        if otel_tracer:
            span = otel_tracer.start_span("fetch_aikido_rasp_metrics")
        
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
            
            # Separate events by scenario based on service name or blocking status
            detect_events = []
            block_events = []
            
            for event in events:
                service = event.get('service_name', '')
                blocked = event.get('blocked', event.get('was_blocked', False))
                
                if 'detect' in service.lower() or (not blocked and 'rasp' in service.lower()):
                    detect_events.append(event)
                elif blocked or 'block' in service.lower():
                    block_events.append(event)
            
            # Process Scenario 2A (Detection Only)
            if detect_events:
                detections_2a = defaultdict(int)
                for event in detect_events:
                    attack_type = event.get('type', event.get('attack_type', 'unknown'))
                    severity = event.get('severity', 'unknown')
                    detections_2a[(attack_type, severity)] += 1
                
                for (attack_type, severity), count in detections_2a.items():
                    security_detections.labels(
                        tool='aikido_rasp',
                        vuln_type=attack_type,
                        severity=severity,
                        scenario='iast-rasp-detect'
                    )._value._value = count
                
                print(f"✅ Aikido RASP (Detection): {sum(detections_2a.values())} detections")
            
            # Process Scenario 2B (Blocking Mode)
            if block_events:
                detections_2b = defaultdict(int)
                blocks_2b = defaultdict(int)
                
                for event in block_events:
                    attack_type = event.get('type', event.get('attack_type', 'unknown'))
                    severity = event.get('severity', 'unknown')
                    blocked = event.get('blocked', event.get('was_blocked', False))
                    
                    detections_2b[(attack_type, severity)] += 1
                    if blocked:
                        blocks_2b[attack_type] += 1
                
                for (attack_type, severity), count in detections_2b.items():
                    security_detections.labels(
                        tool='aikido_rasp',
                        vuln_type=attack_type,
                        severity=severity,
                        scenario='iast-rasp-block'
                    )._value._value = count
                
                for attack_type, count in blocks_2b.items():
                    security_blocks.labels(
                        tool='aikido_rasp',
                        attack_type=attack_type,
                        scenario='iast-rasp-block'
                    )._value._value = count
                
                total_detections = sum(detections_2b.values())
                total_blocks = sum(blocks_2b.values())
                block_rate = (total_blocks / total_detections * 100) if total_detections > 0 else 0
                
                print(f"✅ Aikido RASP (Blocking): {total_detections} detections, {total_blocks} blocks ({block_rate:.1f}%)")
                
                scenario_comparison.labels(
                    metric_type='rasp_block_rate',
                    scenario='iast-rasp-block'
                ).set(block_rate)
            
            otel_collection_status.labels(source='aikido_rasp', status='success').set(1)
            
        if span:
            span.end()
            
    except requests.exceptions.Timeout:
        print(f"⚠️  Aikido API timeout")
        otel_collection_status.labels(source='aikido_rasp', status='timeout').set(0)
    except Exception as e:
        print(f"❌ Error fetching Aikido metrics: {e}")
        otel_collection_status.labels(source='aikido_rasp', status='error').set(0)

# ============= SCENARIO INFO LOADER =============

def load_scenario_info():
    """Load current scenario information"""
    global current_scenario, current_scenario_id, rasp_enabled, rasp_blocking
    
    try:
        scenario_file = os.path.join(METRICS_DIR, 'scenario_info.json')
        if os.path.exists(scenario_file):
            with open(scenario_file, 'r') as f:
                data = json.load(f)
            
            current_scenario = data.get('current_scenario', 'unknown')
            current_scenario_id = data.get('scenario_id', 0)
            rasp_enabled = data.get('rasp_enabled', False)
            rasp_blocking = data.get('rasp_blocking', False)
            
            scenario_id_metric.set(current_scenario_id)
            
            print(f"ℹ️  Current Scenario: {current_scenario} (ID: {current_scenario_id})")
            print(f"   RASP Enabled: {rasp_enabled}, Blocking: {rasp_blocking}")
            
    except Exception as e:
        print(f"⚠️  Error loading scenario info: {e}")

# ============= MANUAL METRICS LOADER =============

def load_manual_metrics():
    """Load manually recorded metrics from JSON files"""
    global current_phase
    
    try:
        metrics_file = os.path.join(METRICS_DIR, 'manual_metrics.json')
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                data = json.load(f)
            
            if 'scan_phase' in data:
                current_phase = data['scan_phase']
                scan_phase.set(current_phase)
            
            if 'response_times' in data:
                for tool, time_ms in data['response_times'].items():
                    response_time.labels(tool=tool, scenario=current_scenario).set(time_ms)
            
            print(f"✅ Loaded manual metrics - Phase: {current_phase}")
    except Exception as e:
        print(f"⚠️  Error loading manual metrics: {e}")

# ============= MAIN COLLECTION LOOP =============

def collect_all_metrics():
    """Collect metrics from all sources"""
    print(f"\n{'='*80}")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Collecting Security Metrics")
    print(f"Current Scenario: {current_scenario.upper()} (ID: {current_scenario_id})")
    print(f"OpenTelemetry: {'✅ Active' if OTEL_AVAILABLE else '❌ Not Available'}")
    print(f"{'='*80}")
    
    load_scenario_info()            # Load scenario context
    parse_semgrep_results()         # SAST (no scenario)
    parse_zap_results()             # DAST (three scenarios)
    fetch_datadog_iast_metrics()    # IAST (three scenarios, OTel-aware)
    fetch_aikido_rasp_metrics()     # RASP (scenarios 2a and 2b, OTel-aware)
    load_manual_metrics()           # Manual metrics
    
    print(f"{'='*80}")
    print("✅ Metrics collection cycle complete\n")

# ============= STARTUP =============

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 Security Metrics Exporter Starting (Three-Scenario + OpenTelemetry)")
    print("="*80)
    print(f"📊 Prometheus endpoint: http://localhost:9999/metrics")
    print(f"📁 Metrics directory: {METRICS_DIR}")
    print(f"🕷️  ZAP results directory: {ZAP_RESULTS_DIR}")
    print(f"📡 OpenTelemetry: {'✅ Enabled' if OTEL_AVAILABLE else '❌ Disabled'}")
    print(f"🔄 Collection interval: 30 seconds")
    print(f"🎯 Scenarios supported:")
    print(f"   1. IAST Only (iast-only)")
    print(f"   2. IAST + RASP Detection (iast-rasp-detect)")
    print(f"   3. IAST + RASP Blocking (iast-rasp-block)")
    print("="*80 + "\n")
    
    # Start Prometheus HTTP server
    start_http_server(9999)
    print("✅ Prometheus exporter running on port 9999\n")
    
    # Initial collection
    try:
        collect_all_metrics()
    except Exception as e:
        print(f"❌ Error in initial collection: {e}")
        traceback.print_exc()
    
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
