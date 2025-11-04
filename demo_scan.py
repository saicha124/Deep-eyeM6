#!/usr/bin/env python3
"""
Demo script to show Deep Eye detecting vulnerabilities with multilingual reports
"""
import sys
import subprocess
import time
from pathlib import Path

def main():
    print("=" * 80)
    print("🔍 DEEP EYE MULTILINGUAL VULNERABILITY DETECTION DEMO")
    print("=" * 80)
    print()
    
    # Start vulnerable test app in background
    print("📡 Starting vulnerable test application...")
    proc = subprocess.Popen(
        [sys.executable, "test_vulnerable_app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(3)  # Wait for app to start
    
    print("✓ Test app running on http://localhost:8888")
    print()
    
    # Test the scanner manually
    print("🧪 Testing vulnerability detection...")
    print()
    
    # Import and run scanner components
    try:
        from core.http_client import HTTPClient
        from core.vulnerability_scanner import VulnerabilityScanner
        import yaml
        
        # Load config
        with open('config/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        # Create HTTP client
        http_client = HTTPClient(config)
        
        # Create scanner
        scanner = VulnerabilityScanner(config, http_client)
        
        # Scan for security headers
        print("Checking security headers on http://localhost:8888/...")
        vulns = scanner._check_security_headers("http://localhost:8888/")
        
        print(f"\n✓ Found {len(vulns)} security misconfiguration issues:")
        for v in vulns:
            print(f"  • {v['evidence']} - {v['description']}")
        
        print()
        print("=" * 80)
        print("🌍 NOW RUNNING FULL SCAN WITH MULTILINGUAL REPORTS")
        print("=" * 80)
        print()
        
    except Exception as e:
        print(f"Note: {e}")
        print()
    
    # Run full scan with multilingual reports
    try:
        result = subprocess.run(
            [sys.executable, "deep_eye.py", "-u", "http://localhost:8888", "--multilingual", "--no-banner"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(result.stdout)
        
        # Check if reports were generated
        reports_dir = Path("reports")
        en_reports = list(reports_dir.glob("*_en.html"))
        fr_reports = list(reports_dir.glob("*_fr.html"))  
        ar_reports = list(reports_dir.glob("*_ar.html"))
        
        print()
        print("=" * 80)
        print("📊 REPORT GENERATION RESULTS")
        print("=" * 80)
        print()
        print(f"🇬🇧 English reports: {len(en_reports)} found")
        if en_reports:
            print(f"   Latest: {en_reports[-1].name}")
        
        print(f"🇫🇷 French reports: {len(fr_reports)} found")
        if fr_reports:
            print(f"   Latest: {fr_reports[-1].name}")
        
        print(f"🇸🇦 Arabic reports: {len(ar_reports)} found")
        if ar_reports:
            print(f"   Latest: {ar_reports[-1].name}")
        
        print()
        
    except Exception as e:
        print(f"Error running scan: {e}")
    
    finally:
        # Stop test app
        print("Stopping test application...")
        proc.terminate()
        proc.wait()
        print("✓ Done")

if __name__ == "__main__":
    main()
