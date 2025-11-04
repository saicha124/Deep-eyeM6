#!/usr/bin/env python3
"""
Simple vulnerable Flask app for testing Deep Eye scanner
This app has intentional security misconfigurations
"""
from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)

# Vulnerable HTML template with XSS
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test App</title>
</head>
<body>
    <h1>Security Testing Application</h1>
    <p>This app has intentional vulnerabilities for testing Deep Eye scanner.</p>
    
    <h2>Search</h2>
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search...">
        <input type="submit" value="Search">
    </form>
    
    <h2>User Profile</h2>
    <form action="/user" method="GET">
        <input type="text" name="id" placeholder="User ID">
        <input type="submit" value="Get User">
    </form>
    
    <h2>File Viewer</h2>
    <form action="/file" method="GET">
        <input type="text" name="path" placeholder="File path">
        <input type="submit" value="View File">
    </form>
    
    <hr>
    <p><small>Deep Eye Test Application v1.0</small></p>
</body>
</html>
'''

@app.route('/')
def index():
    """Main page - Missing security headers"""
    response = make_response(render_template_string(TEMPLATE))
    # Intentionally NOT setting security headers:
    # - X-Content-Type-Options: nosniff
    # - X-Frame-Options: DENY
    # - Content-Security-Policy
    # - Strict-Transport-Security
    return response

@app.route('/search')
def search():
    """Reflected XSS vulnerability"""
    query = request.args.get('q', '')
    # Vulnerable: No escaping of user input
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    response = make_response(html)
    return response

@app.route('/user')
def user():
    """SQL Injection vulnerability (simulated)"""
    user_id = request.args.get('id', '1')
    # Simulated SQL query (vulnerable to SQL injection)
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>User Profile</title></head>
    <body>
        <h1>User Profile</h1>
        <p>Query: SELECT * FROM users WHERE id={user_id}</p>
        <p>User ID: {user_id}</p>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    response = make_response(html)
    return response

@app.route('/file')
def file_viewer():
    """Path Traversal vulnerability (simulated)"""
    file_path = request.args.get('path', 'index.txt')
    # Vulnerable: No validation of file path
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>File Viewer</title></head>
    <body>
        <h1>File Viewer</h1>
        <p>Attempting to read file: {file_path}</p>
        <p>File path provided: {file_path}</p>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    response = make_response(html)
    return response

@app.route('/api/data')
def api_data():
    """CORS misconfiguration"""
    data = {'message': 'This is API data', 'status': 'success'}
    response = make_response(data)
    # Vulnerable: Allow all origins
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/admin')
def admin():
    """Missing authentication"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel</title></head>
    <body>
        <h1>Admin Panel</h1>
        <p>Welcome to the admin panel!</p>
        <p>This should require authentication!</p>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    # Vulnerable: No authentication check
    return html

if __name__ == '__main__':
    print("=" * 60)
    print("🔓 VULNERABLE TEST APPLICATION")
    print("=" * 60)
    print("\nThis app has intentional security vulnerabilities:")
    print("  ✗ Missing X-Content-Type-Options header")
    print("  ✗ Missing X-Frame-Options header")
    print("  ✗ Missing Content-Security-Policy")
    print("  ✗ Missing Strict-Transport-Security")
    print("  ✗ Reflected XSS on /search")
    print("  ✗ SQL Injection on /user")
    print("  ✗ Path Traversal on /file")
    print("  ✗ CORS Misconfiguration on /api/data")
    print("  ✗ Missing Authentication on /admin")
    print("\nStarting server on http://0.0.0.0:8888")
    print("=" * 60)
    print("\nTest with Deep Eye:")
    print("  python deep_eye.py -u http://localhost:8888 --multilingual")
    print("\n")
    
    app.run(host='0.0.0.0', port=8888, debug=False)
