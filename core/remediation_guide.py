"""
Remediation Guide
Provides detailed remediation instructions for common vulnerabilities
"""

from typing import Dict, List


class RemediationGuide:
    """Enhanced remediation guidance for vulnerabilities."""
    
    REMEDIATION_DATABASE = {
        'SQL Injection': {
            'priority': 'CRITICAL',
            'fix_time': '1-2 days',
            'steps': [
                'Use parameterized queries (prepared statements) for all database interactions',
                'Implement input validation and sanitization',
                'Apply principle of least privilege for database accounts',
                'Use ORM frameworks that handle parameterization automatically',
                'Enable SQL error logging but hide errors from users',
                'Conduct code review of all database queries'
            ],
            'code_example': '''
# Bad (Vulnerable):
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good (Secure):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# Or with ORM:
User.objects.get(id=user_id)
''',
            'references': [
                'OWASP SQL Injection Prevention Cheat Sheet',
                'CWE-89: Improper Neutralization of Special Elements',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            ]
        },
        
        'Cross-Site Scripting (XSS)': {
            'priority': 'HIGH',
            'fix_time': '1-3 days',
            'steps': [
                'Implement output encoding for all user-supplied data',
                'Use Content Security Policy (CSP) headers',
                'Validate and sanitize all input data',
                'Use HTTPOnly and Secure flags for cookies',
                'Implement context-aware output encoding (HTML, JavaScript, URL)',
                'Use modern frameworks with built-in XSS protection'
            ],
            'code_example': '''
# Bad (Vulnerable):
<div>{{ user_input }}</div>

# Good (Secure):
<div>{{ user_input | escape }}</div>

# CSP Header:
Content-Security-Policy: default-src 'self'; script-src 'self'
''',
            'references': [
                'OWASP XSS Prevention Cheat Sheet',
                'CWE-79: Improper Neutralization of Input',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            ]
        },
        
        'Command Injection': {
            'priority': 'CRITICAL',
            'fix_time': '1 day',
            'steps': [
                'Avoid calling system commands with user input',
                'Use language-specific libraries instead of shell commands',
                'Implement strict input validation with whitelisting',
                'Use parameterized/prepared commands if shell execution is necessary',
                'Run application with minimal privileges',
                'Implement command execution logging and monitoring'
            ],
            'code_example': '''
# Bad (Vulnerable):
os.system(f"ping {user_ip}")

# Good (Secure):
import subprocess
subprocess.run(["ping", "-c", "4", user_ip], timeout=5)
''',
            'references': [
                'OWASP Command Injection',
                'CWE-78: OS Command Injection',
                'https://owasp.org/www-community/attacks/Command_Injection'
            ]
        },
        
        'CSRF (Cross-Site Request Forgery)': {
            'priority': 'MEDIUM',
            'fix_time': '1-2 days',
            'steps': [
                'Implement CSRF tokens for all state-changing operations',
                'Use SameSite cookie attribute',
                'Verify Origin and Referer headers',
                'Implement double-submit cookie pattern',
                'Require re-authentication for sensitive actions',
                'Use frameworks with built-in CSRF protection'
            ],
            'code_example': '''
# Generate CSRF token:
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">

# Validate on server:
if request.form['csrf_token'] != session['csrf_token']:
    abort(403)

# Cookie settings:
Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly
''',
            'references': [
                'OWASP CSRF Prevention Cheat Sheet',
                'CWE-352: Cross-Site Request Forgery',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
            ]
        },
        
        'SSRF (Server-Side Request Forgery)': {
            'priority': 'HIGH',
            'fix_time': '2-3 days',
            'steps': [
                'Implement URL whitelist for allowed destinations',
                'Disable or restrict URL redirects',
                'Validate and sanitize all URLs',
                'Use network segmentation to isolate internal services',
                'Block access to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)',
                'Implement request signing for internal API calls'
            ],
            'code_example': '''
# Validate URL before making request:
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)
    # Check against whitelist
    allowed_hosts = ['api.example.com', 'data.example.com']
    if parsed.hostname not in allowed_hosts:
        return False
    # Block private IPs
    if parsed.hostname in ['localhost', '127.0.0.1'] or \
       parsed.hostname.startswith('192.168.') or \
       parsed.hostname.startswith('10.'):
        return False
    return True
''',
            'references': [
                'OWASP Server-Side Request Forgery Prevention',
                'CWE-918: Server-Side Request Forgery',
                'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
            ]
        },
        
        'Path Traversal': {
            'priority': 'HIGH',
            'fix_time': '1-2 days',
            'steps': [
                'Use whitelist for allowed file paths',
                'Validate and canonicalize file paths',
                'Use built-in path functions (os.path.join, Path)',
                'Implement chroot jails or sandboxing',
                'Reject paths containing ".." or absolute paths',
                'Use indirect object references (map IDs to files)'
            ],
            'code_example': '''
# Bad (Vulnerable):
file_path = f"/var/data/{user_input}"

# Good (Secure):
from pathlib import Path
base_dir = Path("/var/data")
file_path = (base_dir / user_input).resolve()
if not file_path.is_relative_to(base_dir):
    raise ValueError("Invalid file path")
''',
            'references': [
                'OWASP Path Traversal',
                'CWE-22: Path Traversal',
                'https://owasp.org/www-community/attacks/Path_Traversal'
            ]
        },
        
        'Authentication Bypass': {
            'priority': 'CRITICAL',
            'fix_time': '1-2 days',
            'steps': [
                'Implement proper session management',
                'Use secure password hashing (bcrypt, Argon2)',
                'Enforce multi-factor authentication',
                'Implement account lockout after failed attempts',
                'Use secure session tokens (cryptographically random)',
                'Implement proper logout functionality',
                'Set secure session timeout values'
            ],
            'code_example': '''
# Secure password hashing:
import bcrypt

# Hash password:
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify password:
if bcrypt.checkpw(password.encode(), stored_hash):
    # Password correct
    pass
''',
            'references': [
                'OWASP Authentication Cheat Sheet',
                'CWE-287: Improper Authentication',
                'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
            ]
        },
        
        'JWT Vulnerabilities': {
            'priority': 'HIGH',
            'fix_time': '1-2 days',
            'steps': [
                'Always verify JWT signatures',
                'Use strong signing algorithms (RS256, not "none")',
                'Implement token expiration (exp claim)',
                'Validate all JWT claims (aud, iss, exp)',
                'Store secrets securely (never in code)',
                'Implement token refresh mechanism',
                'Use HTTPS to prevent token interception'
            ],
            'code_example': '''
# Secure JWT validation:
import jwt

try:
    payload = jwt.decode(
        token,
        secret_key,
        algorithms=["RS256"],  # Specify algorithm
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True
        }
    )
except jwt.InvalidTokenError:
    # Handle invalid token
    pass
''',
            'references': [
                'JWT Security Best Practices',
                'CWE-347: Improper Verification of Cryptographic Signature',
                'https://tools.ietf.org/html/rfc7519'
            ]
        },
        
        'Insecure Deserialization': {
            'priority': 'CRITICAL',
            'fix_time': '2-3 days',
            'steps': [
                'Avoid deserializing untrusted data',
                'Use safe serialization formats (JSON instead of pickle)',
                'Implement integrity checks (HMAC signatures)',
                'Restrict deserialization to allowed classes',
                'Run deserialization in isolated/sandboxed environment',
                'Monitor for suspicious deserialization patterns'
            ],
            'code_example': '''
# Bad (Vulnerable):
import pickle
data = pickle.loads(user_input)

# Good (Secure):
import json
data = json.loads(user_input)
# Or with signature verification:
# signed_data = serializer.loads(user_input)
''',
            'references': [
                'OWASP Deserialization Cheat Sheet',
                'CWE-502: Deserialization of Untrusted Data',
                'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
            ]
        }
    }
    
    @classmethod
    def get_remediation(cls, vulnerability_type: str) -> Dict:
        """
        Get detailed remediation guidance for a vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            Dictionary with remediation details
        """
        # Try to find exact match first
        for key, value in cls.REMEDIATION_DATABASE.items():
            if key.lower() in vulnerability_type.lower() or \
               vulnerability_type.lower() in key.lower():
                return value
        
        # Return generic guidance if specific not found
        return {
            'priority': 'MEDIUM',
            'fix_time': '1-3 days',
            'steps': [
                'Review the vulnerability description and evidence',
                'Consult OWASP guidelines for this vulnerability type',
                'Implement proper input validation and output encoding',
                'Apply security patches and updates',
                'Conduct thorough testing after remediation'
            ],
            'code_example': 'Refer to security best practices for this vulnerability type',
            'references': [
                'OWASP Top 10',
                'https://owasp.org/www-project-top-ten/'
            ]
        }
    
    @classmethod
    def enhance_vulnerability(cls, vulnerability: Dict) -> Dict:
        """
        Enhance vulnerability dict with detailed remediation.
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            Enhanced vulnerability dictionary
        """
        vuln_type = vulnerability.get('type', '')
        remediation_details = cls.get_remediation(vuln_type)
        
        vulnerability['remediation_details'] = remediation_details
        
        # Keep original remediation as summary
        if 'remediation' not in vulnerability or not vulnerability['remediation']:
            vulnerability['remediation'] = remediation_details['steps'][0]
        
        return vulnerability
