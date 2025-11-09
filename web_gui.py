#!/usr/bin/env python3
"""
Deep Eye - Web GUI for Configuration Management
Provides a web interface to manage API keys and AI provider settings
"""

import os
import json
import threading
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv, set_key, find_dotenv
from utils.secret_manager import encrypt_value, decrypt_value, get_decrypted_env

app = Flask(__name__)
CORS(app)

ENV_FILE = Path('.env')
CONFIG_DIR = Path('config')
CONFIG_DIR.mkdir(exist_ok=True)

load_dotenv()

scan_status = {}

@app.route('/')
def index():
    """Render the main settings page"""
    return render_template('settings.html')

@app.route('/favicon.ico')
def favicon():
    """Return empty response for favicon to avoid 404 errors"""
    return '', 204

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current AI provider settings (without exposing API keys)"""
    settings = {
        'providers': {
            'openai': {
                'enabled': os.getenv('OPENAI_ENABLED', 'false').lower() == 'true',
                'has_key': bool(get_decrypted_env('OPENAI_API_KEY'))
            },
            'claude': {
                'enabled': os.getenv('CLAUDE_ENABLED', 'false').lower() == 'true',
                'has_key': bool(get_decrypted_env('ANTHROPIC_API_KEY'))
            },
            'grok': {
                'enabled': os.getenv('GROK_ENABLED', 'false').lower() == 'true',
                'has_key': bool(get_decrypted_env('GROK_API_KEY'))
            },
            'ollama': {
                'enabled': os.getenv('OLLAMA_ENABLED', 'false').lower() == 'true',
                'has_key': bool(os.getenv('OLLAMA_HOST'))
            }
        },
        'ai_enabled': os.getenv('AI_FEATURES_ENABLED', 'false').lower() == 'true'
    }
    return jsonify(settings)

@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update AI provider settings and API keys"""
    data = request.json
    
    if not ENV_FILE.exists():
        ENV_FILE.touch()
        os.chmod(ENV_FILE, 0o600)
    
    try:
        if 'ai_enabled' in data:
            set_key(ENV_FILE, 'AI_FEATURES_ENABLED', str(data['ai_enabled']).lower())
        
        providers = data.get('providers', {})
        
        if 'openai' in providers:
            prov = providers['openai']
            if prov.get('api_key'):
                encrypted_key = encrypt_value(prov['api_key'])
                set_key(ENV_FILE, 'OPENAI_API_KEY', encrypted_key)
            set_key(ENV_FILE, 'OPENAI_ENABLED', str(prov.get('enabled', False)).lower())
        
        if 'claude' in providers:
            prov = providers['claude']
            if prov.get('api_key'):
                encrypted_key = encrypt_value(prov['api_key'])
                set_key(ENV_FILE, 'ANTHROPIC_API_KEY', encrypted_key)
            set_key(ENV_FILE, 'CLAUDE_ENABLED', str(prov.get('enabled', False)).lower())
        
        if 'grok' in providers:
            prov = providers['grok']
            if prov.get('api_key'):
                encrypted_key = encrypt_value(prov['api_key'])
                set_key(ENV_FILE, 'GROK_API_KEY', encrypted_key)
            set_key(ENV_FILE, 'GROK_ENABLED', str(prov.get('enabled', False)).lower())
        
        if 'ollama' in providers:
            prov = providers['ollama']
            if prov.get('host'):
                set_key(ENV_FILE, 'OLLAMA_HOST', prov['host'])
            set_key(ENV_FILE, 'OLLAMA_ENABLED', str(prov.get('enabled', False)).lower())
        
        load_dotenv(override=True)
        
        return jsonify({'success': True, 'message': 'Settings updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/test-connection/<provider>', methods=['POST'])
def test_connection(provider):
    """Test API connection for a specific provider"""
    try:
        if provider == 'openai':
            api_key = get_decrypted_env('OPENAI_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'message': 'API key not configured'})
            
            import openai
            client = openai.OpenAI(api_key=api_key)
            client.models.list()
            return jsonify({'success': True, 'message': 'OpenAI connection successful'})
        
        elif provider == 'claude':
            api_key = get_decrypted_env('ANTHROPIC_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'message': 'API key not configured'})
            
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            return jsonify({'success': True, 'message': 'Claude connection successful'})
        
        elif provider == 'grok':
            api_key = get_decrypted_env('GROK_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'message': 'API key not configured'})
            
            import openai
            client = openai.OpenAI(
                api_key=api_key,
                base_url='https://api.x.ai/v1'
            )
            client.models.list()
            return jsonify({'success': True, 'message': 'Grok connection successful'})
        
        elif provider == 'ollama':
            import ollama
            ollama.list()
            return jsonify({'success': True, 'message': 'Ollama connection successful'})
        
        else:
            return jsonify({'success': False, 'message': 'Unknown provider'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Connection failed: {str(e)}'}), 500

@app.route('/scanner')
def scanner():
    """Render the scanner page"""
    return render_template('scanner.html')

@app.route('/report')
def report():
    """Render the detailed report page"""
    return render_template('report.html')

@app.route('/view-report/<scan_id>')
def view_detailed_report(scan_id):
    """View detailed vulnerability report using the digest template"""
    from datetime import datetime
    try:
        scan_file = Path('reports') / f'scan_{scan_id}.json'
        
        if not scan_file.exists():
            return f"Scan report not found: {scan_id}", 404
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        target_url = scan_data.get('target_url', 'Unknown')
        timestamp = scan_data.get('timestamp', datetime.now().isoformat())
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        vulnerability_types = set()
        
        for vuln in vulnerabilities:
            severity = (vuln.get('severity', 'info')).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            vuln_type = vuln.get('name', vuln.get('type', 'Unknown'))
            vulnerability_types.add(vuln_type)
            
            if 'type' not in vuln and 'name' in vuln:
                vuln['type'] = vuln['name']
        
        return render_template(
            'vulnerability_digest.html',
            target=target_url,
            generated_date=timestamp,
            vulnerabilities=vulnerabilities,
            severity_counts=severity_counts,
            vulnerability_types=sorted(vulnerability_types),
            cerist_logo=''
        )
    except Exception as e:
        return f"Error loading report: {str(e)}", 500

def validate_url(url):
    """
    Validate and sanitize URL to prevent SSRF and other attacks
    Uses DNS resolution to detect private/local IPs
    """
    import urllib.parse
    import socket
    import ipaddress
    
    if not url:
        return False, "URL is required"
    
    try:
        parsed = urllib.parse.urlparse(url)
        
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS protocols are allowed"
        
        if not parsed.netloc:
            return False, "Invalid URL format"
        
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid hostname"
        
        if len(url) > 2048:
            return False, "URL is too long"
        
        try:
            resolved_ips = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {hostname}"
        
        for addr_info in resolved_ips:
            ip_str = addr_info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                
                if ip_obj.is_loopback:
                    return False, "Scanning loopback addresses (127.0.0.1, ::1) is not allowed"
                
                if ip_obj.is_private:
                    return False, "Scanning private IP ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, fc00::/7) is not allowed"
                
                if ip_obj.is_link_local:
                    return False, "Scanning link-local addresses (169.254.0.0/16, fe80::/10) is not allowed"
                
                if ip_obj.is_reserved:
                    return False, "Scanning reserved IP addresses is not allowed"
                
                if ip_obj.is_multicast:
                    return False, "Scanning multicast addresses is not allowed"
                    
            except ValueError:
                return False, f"Invalid IP address: {ip_str}"
        
        return True, url
        
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"

def run_scan_background(scan_id, target_url):
    """Run scan in background thread"""
    import uuid
    from datetime import datetime
    from core.scanner_engine import ScannerEngine
    from utils.config_loader import ConfigLoader
    from ai_providers.provider_manager import AIProviderManager
    
    def update_progress(progress, vulnerability_count, message):
        """Callback to update scan progress in real-time"""
        scan_status[scan_id]['progress'] = progress
        scan_status[scan_id]['vulnerability_count'] = vulnerability_count
        scan_status[scan_id]['message'] = message
    
    try:
        scan_status[scan_id]['status'] = 'running'
        scan_status[scan_id]['message'] = 'Initializing scanner...'
        scan_status[scan_id]['progress'] = 10
        
        config = ConfigLoader.load('config/config.yaml')
        scanner_config = config.get('scanner', {})
        ai_provider = scanner_config.get('ai_provider', 'openai')
        depth = scanner_config.get('default_depth', 2)
        threads = scanner_config.get('default_threads', 5)
        
        ai_manager = AIProviderManager(config)
        ai_manager.set_provider(ai_provider)
        
        scanner = ScannerEngine(
            target_url=target_url,
            config=config,
            ai_manager=ai_manager,
            depth=depth,
            threads=threads,
            progress_callback=update_progress
        )
        
        results = scanner.scan()
        
        scan_status[scan_id]['message'] = 'Processing and analyzing results...'
        scan_status[scan_id]['progress'] = 90
        
        vulnerabilities = []
        for vuln in results.get('vulnerabilities', []):
            scan_status[scan_id]['vulnerability_count'] = len(vulnerabilities) + 1
            vulnerabilities.append({
                'name': vuln.get('type', vuln.get('name', 'Unknown Vulnerability')),
                'severity': vuln.get('severity', 'info').lower(),
                'description': vuln.get('description', ''),
                'url': vuln.get('url', target_url),
                'parameter': vuln.get('parameter', ''),
                'payload': vuln.get('payload', ''),
                'evidence': vuln.get('evidence', ''),
                'remediation': vuln.get('remediation', ''),
                'remediation_steps': vuln.get('remediation_steps', []),
                'vulnerable_code': vuln.get('vulnerable_code', ''),
                'solution_code': vuln.get('solution_code', ''),
                'references': vuln.get('references', []),
                'cwe': vuln.get('cwe', ''),
                'priority': vuln.get('priority', vuln.get('severity', 'info').upper()),
                'fix_time': vuln.get('fix_time', ''),
                'timestamp': vuln.get('timestamp', datetime.now().isoformat()),
                'payload_info': vuln.get('payload_info', {}),
                'interaction': vuln.get('interaction', {}),
                'detector': vuln.get('detector', {})
            })
        
        scan_data = {
            'scan_id': scan_id,
            'target_url': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities,
            'results': results
        }
        
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        scan_file = reports_dir / f'scan_{scan_id}.json'
        with open(scan_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['message'] = f'Scan completed! Found {len(vulnerabilities)} vulnerabilities'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['vulnerability_count'] = len(vulnerabilities)
        scan_status[scan_id]['results'] = {
            'target_url': target_url,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        scan_status[scan_id]['status'] = 'failed'
        scan_status[scan_id]['message'] = f'Scan failed: {str(e)}'

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a vulnerability scan in background"""
    import uuid
    
    data = request.json
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({'success': False, 'message': 'URL is required'}), 400
    
    is_valid, message = validate_url(target_url)
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400
    
    target_url = message
    scan_id = str(uuid.uuid4())[:8]
    
    scan_status[scan_id] = {
        'status': 'starting',
        'message': 'Scan queued...',
        'progress': 0,
        'vulnerability_count': 0,
        'results': None
    }
    
    thread = threading.Thread(target=run_scan_background, args=(scan_id, target_url))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started in background. Use /api/scan-progress/<scan_id> to check progress.'
    })

@app.route('/api/scan-progress/<scan_id>', methods=['GET'])
def get_scan_progress(scan_id):
    """Get current scan progress"""
    if scan_id not in scan_status:
        return jsonify({'success': False, 'message': 'Scan not found'}), 404
    
    status = scan_status[scan_id]
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'status': status['status'],
        'message': status['message'],
        'progress': status.get('progress', 0),
        'vulnerability_count': status.get('vulnerability_count', 0),
        'results': status.get('results')
    })

@app.route('/api/scans/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """Retrieve stored scan results by scan_id"""
    try:
        scan_file = Path('reports') / f'scan_{scan_id}.json'
        
        if not scan_file.exists():
            return jsonify({'success': False, 'message': 'Scan not found'}), 404
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': {
                'target_url': scan_data.get('target_url'),
                'timestamp': scan_data.get('timestamp'),
                'vulnerabilities': scan_data.get('vulnerabilities', []),
                'total_vulnerabilities': len(scan_data.get('vulnerabilities', []))
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to retrieve scan: {str(e)}'}), 500

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all available scan reports"""
    try:
        reports_dir = Path('reports')
        if not reports_dir.exists():
            return jsonify({'success': True, 'scans': []})
        
        scans = []
        for scan_file in reports_dir.glob('scan_*.json'):
            try:
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                scan_id = scan_file.stem.replace('scan_', '')
                scans.append({
                    'scan_id': scan_id,
                    'target_url': scan_data.get('target_url'),
                    'timestamp': scan_data.get('timestamp'),
                    'total_vulnerabilities': len(scan_data.get('vulnerabilities', []))
                })
            except Exception as e:
                logger.error(f"Error reading scan file {scan_file}: {e}")
                continue
        
        scans.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify({'success': True, 'scans': scans})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to list scans: {str(e)}'}), 500

@app.route('/api/download-report/<scan_id>')
def download_report(scan_id):
    """Download scan report as HTML"""
    from flask import send_file
    
    try:
        report_file = Path('reports') / f'scan_{scan_id}_report.html'
        
        if not report_file.exists():
            scan_file = Path('reports') / f'scan_{scan_id}.json'
            if scan_file.exists():
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                from core.report_generator import ReportGenerator
                from utils.config_loader import ConfigLoader
                
                config = ConfigLoader.load('config/config.yaml')
                report_gen = ReportGenerator(config)
                
                report_gen.generate_report(
                    scan_data.get('results', {}),
                    output_file=str(report_file)
                )
        
        if report_file.exists():
            return send_file(report_file, as_attachment=True)
        else:
            return jsonify({'success': False, 'message': 'Report not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to generate report: {str(e)}'}), 500

@app.route('/api/export/<scan_id>/<format>')
def export_report(scan_id, format):
    """Export scan report in various formats (json, csv)"""
    from flask import send_file, make_response
    import csv
    from io import StringIO
    
    try:
        scan_file = Path('reports') / f'scan_{scan_id}.json'
        
        if not scan_file.exists():
            return jsonify({'success': False, 'message': 'Scan not found'}), 404
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        if format == 'json':
            response = make_response(json.dumps(scan_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.json'
            return response
        
        elif format == 'csv':
            output = StringIO()
            writer = csv.writer(output)
            
            writer.writerow(['Vulnerability Name', 'Severity', 'URL', 'Description', 'CWE', 'Remediation'])
            
            for vuln in scan_data.get('vulnerabilities', []):
                writer.writerow([
                    vuln.get('name', 'Unknown'),
                    vuln.get('severity', 'info'),
                    vuln.get('url', ''),
                    vuln.get('description', ''),
                    vuln.get('cwe', ''),
                    vuln.get('remediation', '')
                ])
            
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.csv'
            return response
        
        else:
            return jsonify({'success': False, 'message': 'Invalid format. Supported: json, csv'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to export report: {str(e)}'}), 500

if __name__ == '__main__':
    print("\n🌐 Starting Deep Eye Web GUI...")
    print("📡 Access the interface at: http://0.0.0.0:5000")
    print("🔐 Manage your AI provider settings securely\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
