"""
Enhanced Reporting Demo
Demonstrates the new timestamp and detailed remediation features
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import core modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.remediation_guide import RemediationGuide
from core.vulnerability_helper import create_vulnerability
from datetime import datetime


def demo_enhanced_vulnerability():
    """Demonstrate creating a vulnerability with enhanced features."""
    
    # Create a vulnerability with timestamp (automatically added)
    vuln = create_vulnerability(
        vuln_type='SQL Injection',
        severity='critical',
        url='https://example.com/api/users?id=1',
        description='SQL injection vulnerability allows attackers to manipulate database queries',
        evidence='Error message: "You have an error in your SQL syntax"',
        remediation='Use parameterized queries or prepared statements',
        parameter='id',
        payload="' OR '1'='1",
        cwe='CWE-89: SQL Injection'
    )
    
    print("=" * 80)
    print("BASIC VULNERABILITY RECORD (with timestamp)")
    print("=" * 80)
    for key, value in vuln.items():
        print(f"{key}: {value}")
    
    print("\n" + "=" * 80)
    print("ENHANCED VULNERABILITY RECORD (with detailed remediation)")
    print("=" * 80)
    
    # Enhance with detailed remediation guidance
    enhanced_vuln = RemediationGuide.enhance_vulnerability(vuln.copy())
    
    print(f"\nType: {enhanced_vuln['type']}")
    print(f"Severity: {enhanced_vuln['severity']}")
    print(f"Timestamp: {enhanced_vuln['timestamp']}")
    print(f"URL: {enhanced_vuln['url']}")
    print(f"Parameter: {enhanced_vuln['parameter']}")
    
    # Display remediation details
    remediation_details = enhanced_vuln['remediation_details']
    print(f"\nREMEDIATION GUIDANCE:")
    print(f"  Priority: {remediation_details['priority']}")
    print(f"  Estimated Fix Time: {remediation_details['fix_time']}")
    
    print(f"\n  Steps to Fix:")
    for i, step in enumerate(remediation_details['steps'], 1):
        print(f"    {i}. {step}")
    
    print(f"\n  Code Example:")
    print(remediation_details['code_example'])
    
    print(f"\n  References:")
    for ref in remediation_details['references']:
        print(f"    - {ref}")


def demo_multiple_vulnerabilities():
    """Demonstrate multiple vulnerability types with remediation."""
    
    vulnerabilities = [
        create_vulnerability(
            vuln_type='Cross-Site Scripting (XSS)',
            severity='high',
            url='https://example.com/search?q=test',
            description='Reflected XSS vulnerability allows script injection',
            evidence='Script tag reflected in response: <script>alert(1)</script>',
            remediation='Implement proper output encoding',
            parameter='q',
            payload='<script>alert(1)</script>',
            cwe='CWE-79: XSS'
        ),
        create_vulnerability(
            vuln_type='CSRF (Cross-Site Request Forgery)',
            severity='medium',
            url='https://example.com/profile/update',
            description='Missing CSRF token allows unauthorized actions',
            evidence='No CSRF token found in form',
            remediation='Implement CSRF tokens for all state-changing operations',
            cwe='CWE-352: CSRF'
        ),
    ]
    
    print("\n" + "=" * 80)
    print("SUMMARY OF VULNERABILITIES WITH TIMESTAMPS")
    print("=" * 80)
    
    for vuln in vulnerabilities:
        enhanced = RemediationGuide.enhance_vulnerability(vuln)
        remediation = enhanced['remediation_details']
        
        print(f"\n[{enhanced['severity'].upper()}] {enhanced['type']}")
        print(f"  Discovered: {enhanced['timestamp']}")
        print(f"  Fix Priority: {remediation['priority']}")
        print(f"  Est. Fix Time: {remediation['fix_time']}")
        print(f"  URL: {enhanced['url']}")


if __name__ == "__main__":
    print("\n🔍 DEEP EYE - ENHANCED VULNERABILITY REPORTING DEMO\n")
    
    demo_enhanced_vulnerability()
    demo_multiple_vulnerabilities()
    
    print("\n" + "=" * 80)
    print("Demo complete! These features are now available in all report formats.")
    print("=" * 80)
