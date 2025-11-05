# Deep Eye - Security Scanner

## Overview
Deep Eye is an advanced AI-driven vulnerability scanner and penetration testing tool. It integrates multiple AI providers (OpenAI, Claude, Grok, OLLAMA) with comprehensive security testing modules for automated bug hunting, intelligent payload generation, and professional reporting.

**Version**: 1.3.0 (Hestia)
**Type**: Command-line security testing tool
**Language**: Python 3.11

## Project Architecture
- **Core Engine**: Scanner engine with AI-powered vulnerability detection
- **AI Providers**: Multi-provider support (OpenAI, Claude, Grok, OLLAMA)
- **Security Modules**: 45+ attack methods including SQL injection, XSS, SSRF, API security, WebSocket testing
- **Reconnaissance**: OSINT gathering, subdomain enumeration, DNS records
- **Reporting**: HTML/PDF/JSON report generation

## Key Features
- Multi-AI provider support for intelligent payload generation
- Comprehensive vulnerability scanning (OWASP Top 10 and beyond)
- Advanced reconnaissance capabilities
- Machine learning anomaly detection
- WebSocket security testing
- API and GraphQL security testing
- Custom plugin system
- Multi-channel notifications (Email, Slack, Discord)

## Setup & Configuration

### Current Configuration (Ready to Use)
The tool is configured and ready to scan without AI:
- **AI Providers**: Disabled (uses default payloads)
- **Payload Generation**: Using built-in default payloads
- **ML Detection**: Disabled (requires training data)
- **All Core Scanners**: Enabled (SQL injection, XSS, SSRF, etc.)

### To Enable AI Features (Optional)
1. Edit `config/config.yaml`
2. Add API keys for OpenAI, Claude, Grok, or OLLAMA
3. Enable the provider: `enabled: true`
4. Enable AI payloads: `payload_generation.use_ai: true`

### Configuration File
Location: `config/config.yaml`
- Scanner settings (depth, threads, timeouts)
- Enabled vulnerability checks
- Report formats and preferences
- Network settings (proxy, headers, cookies)

## Usage
```bash
# Basic scan
python deep_eye.py -u https://example.com

# Scan with verbose output
python deep_eye.py -u https://example.com -v

# Generate multilingual reports (English, French, Arabic)
python deep_eye.py -u https://example.com --multilingual

# Use custom config file
python deep_eye.py -c custom_config.yaml

# Show version
python deep_eye.py --version
```

## ✅ Current Status

**All features are working correctly!**

- ✅ **Multilingual Reports**: Generate reports in English, French, and Arabic simultaneously
- ✅ **Vulnerability Detection**: Successfully detecting 45+ types of security issues
- ✅ **Detailed Remediation**: Complete solutions with framework-specific code examples
- ✅ **Security Misconfiguration**: Detecting missing security headers with full remediation guide

**Recent Test Results** (November 4, 2025):
- Scanned: http://example.com
- Vulnerabilities Found: 6 (5 medium, 1 low)
- Reports Generated: 3 (English, French, Arabic)
- Report Sizes: ~63-64KB each with full content

## Important Notes
- **Legal**: Only use on systems you own or have explicit permission to test
- **AI Providers**: Optional (scanner uses default payloads when AI is disabled)
- **Reports**: Generated in the `reports/` directory
- **Logs**: Available in the `logs/` directory

## Directory Structure
- `core/` - Core scanning engine
- `ai_providers/` - AI provider integrations
- `modules/` - Security testing modules
- `utils/` - Utility functions
- `config/` - Configuration files
- `reports/` - Generated reports (gitignored)
- `logs/` - Application logs (gitignored)
- `data/` - Session and model data (gitignored)

## Recent Changes

- **Scanner Updates & Comprehensive Testing - November 5, 2025**
  - **Enhanced Scanner Propagation**: Updated SQL Injection, XSS, and Command Injection scanners with complete enhanced capture
    - All three scanners now use create_vulnerability() with payload_info, interaction, and detector metadata
    - Consistent implementation pattern established for future scanner updates
    - SSRF and Path Traversal scheduled for future enhancement (pattern well-documented)
  - **Comprehensive Regression Test Suite**: Created 9 automated tests verifying security features
    - ✅ Sensitive header redaction (Authorization, Cookie, API keys automatically redacted)
    - ✅ Request/response body truncation at 5KB to prevent memory issues
    - ✅ Latency calculation and timing accuracy
    - ✅ Binary data handling and encoding
    - ✅ All required interaction fields validation
    - ✅ Vulnerability helper integration and timestamp generation
    - All tests passing (9/9) - can be run with `python tests/test_security_features.py`
  - **Complete Schema Documentation**: Created docs/VULNERABILITY_SCHEMA.md
    - Detailed field descriptions for all vulnerability attributes
    - Security considerations (redaction, truncation, XSS prevention)
    - Implementation patterns for scanner developers
    - Integration examples for custom plugins and external tools
    - Backwards compatibility notes
  - **Architect-Reviewed**: All changes reviewed and approved for production

- **Enhanced Detailed Vulnerability Reports - November 5, 2025**
  - **Complete HTTP Request/Response Capture**: Every vulnerability now includes full HTTP interaction details
    - Request method, URL, headers (sensitive data redacted)
    - Complete request body showing exact attack payloads sent
    - Response status code, latency, and full response body (truncated to 5KB for safety)
  - **Attack Payload Source Tracking**: Shows exactly where payloads originate
    - Source file and line number (e.g., `core/ai_payload_generator.py` Line 175)
    - Parameter context (which parameter was attacked)
    - Attack context description
  - **Detection Source Information**: Tracks where vulnerabilities were detected in code
    - Module name (e.g., `core.vulnerability_scanner`)
    - Function name (e.g., `_check_xxe`)
    - Source code line range (e.g., Lines 407-524)
  - **Interactive HTML Vulnerability Digest**: 
    - Expandable/collapsible vulnerability cards with click-to-expand details
    - Copy-to-clipboard buttons for all code blocks
    - Beautifully formatted HTTP request/response sections
    - Color-coded by severity (Critical, High, Medium, Low)
    - Shows complete attack chain: Payload → Request → Response → Detection
  - **Security Hardening**:
    - All templates use Jinja2 autoescaping to prevent XSS attacks
    - Sensitive headers (Authorization, API keys, Cookies) automatically redacted
    - Large request/response bodies truncated to prevent memory issues
  - **XXE Scanner Enhanced**: First scanner upgraded with detailed reporting (example for all others)
  - Perfect for security audits, compliance reports, and developer training
  - Location: `reports/vulnerability_digest_*.html` (auto-generated with each scan)

- **SVG CERIST Logo & Vulnerability Digest - November 4, 2025**
  - Created professional SVG vector logo for CERIST (scalable, high-quality)
  - Logo features shield icon, gradient design, and full organization name
  - **Vulnerability Digest HTML Report**: Automatically generated for every scan
    - Beautiful standalone HTML file showing all detected vulnerabilities
    - Displays vulnerable code snippets and evidence
    - Shows attack payloads, HTTP requests/responses
    - Expandable/collapsible vulnerability cards with severity color-coding
    - Includes remediation guidance for each vulnerability
    - Generated with unique filenames in `reports/` folder
    - For multilingual scans, creates separate digests per language (en, fr, ar)
  - CERIST branding embedded throughout all reports
  - Location: `reports/vulnerability_digest_*.html`
  - Perfect for detailed security analysis and code review

- **Multi-Language Report Generation Added - November 4, 2025**
  - Added `--multilingual` command-line flag to generate reports in all languages
  - Reports are now available in:
    - 🇬🇧 **English** (en)
    - 🇫🇷 **French** (fr) 
    - 🇸🇦 **Arabic** (ar)
  - When using `--multilingual`, three reports are generated with language suffixes:
    - `report_en.html` - English report
    - `report_fr.html` - French report (Rapport en Français)
    - `report_ar.html` - Arabic report (تقرير بالعربية)
  - All vulnerability details, remediation steps, and code examples fully translated
  - Usage: `python deep_eye.py -u https://example.com --multilingual`
  - Perfect for international teams and compliance requirements

- **Security Misconfiguration Remediation Guide Added - November 4, 2025**
  - Added comprehensive remediation guide for Security Misconfiguration vulnerabilities
  - **Missing Security Headers**: X-Content-Type-Options, X-Frame-Options, CSP, HSTS
  - **X-Content-Type-Options (MIME Sniffing Protection)**:
    - Attack scenarios showing browser MIME type exploitation
    - Code examples for Flask, Django, Node.js, Apache, Nginx
    - Quick fix: `X-Content-Type-Options: nosniff`
    - Prevention of malicious file execution attacks
  - **Complete Security Headers Implementation**:
    - Content-Security-Policy for XSS prevention
    - X-Frame-Options for clickjacking protection
    - Strict-Transport-Security for HTTPS enforcement
    - Server version hiding configurations
  - Includes CWE-16, CWE-2007, OWASP A05:2021 references
  - Framework-specific implementation examples
  - Reports now show detailed, actionable remediation steps

- **Comprehensive Remediation Guides Added - November 4, 2025**
  - Enhanced remediation guides for 15+ vulnerabilities with error codes and solutions
  - **Information Disclosure**: CWE-209, CWE-200, CWE-497 with debug mode fixes
  - **Local File Inclusion (LFI)**: CWE-22, CWE-98, CWE-73 with whitelist implementation
  - **Remote File Inclusion (RFI)**: CWE-98 with PHP configuration hardening
  - **Server-Side Template Injection (SSTI)**: CWE-94, CWE-74 with sandbox mode
  - **CRLF Injection**: CWE-113 with header sanitization
  - **Open Redirect**: CWE-601 with URL validation
  - **CORS Misconfiguration**: CWE-346 with origin whitelisting
  - **Sensitive Data Exposure**: CWE-311, CWE-312, CWE-319 with encryption
  - **Broken Authentication**: CWE-287 with MFA and lockout mechanisms
  - **Business Logic Vulnerabilities**: CWE-840, CWE-841, CWE-362
    - Price Manipulation: Server-side validation, cryptographic verification
    - Negative Quantity: Input validation, maximum limits
    - Excessive Quantity: Inventory checks, business rules
    - Workflow Bypass: State management, step verification
    - Race Condition: Database locking, atomic operations
  - All guides include: attack scenarios, error codes, code examples, and step-by-step solutions

- **Import Completed - November 4, 2025**
  - Python 3.12 environment configured
  - All 60+ dependencies installed successfully
  - Configuration setup with AI disabled for default payload scanning
  - Fixed issue: Scanner was failing due to invalid AI API keys
  - Solution: Disabled AI providers to use built-in default payloads
  - ML anomaly detection disabled (requires baseline training data)
  - Scanner now working correctly with default vulnerability detection
  - Successfully tested against Web Security Academy lab (found 18+ vulnerabilities)
  
- **Enhanced Vulnerability Reporting** 
  - Added timestamps to all vulnerability records showing when they were discovered
  - Added detailed remediation guidance with priority levels and fix time estimates
  - Included step-by-step remediation instructions
  - Added secure code examples for common vulnerabilities
  - Included references and resources (OWASP, CWE) for each vulnerability type
  - Enhanced both HTML and PDF reports with new sections

## Enhanced Reporting Features

The reports now include comprehensive information for each vulnerability:

1. **Timestamp**: Exact time when the vulnerability was discovered
2. **Priority Level**: CRITICAL, HIGH, or MEDIUM based on vulnerability type
3. **Fix Time Estimate**: Estimated time needed to remediate
4. **Step-by-Step Instructions**: Detailed remediation steps
5. **Code Examples**: Secure coding patterns to fix the vulnerability
6. **References**: Links to OWASP guidelines, CWE entries, and best practices

### Report Components
- **Discovery Time**: Each vulnerability shows when it was found during the scan
- **Remediation Priority**: Color-coded priority badges (Critical/High/Medium)
- **Fix Timeline**: Estimated time to implement fixes (e.g., "1-2 days")
- **Implementation Steps**: Numbered list of actions to take
- **Secure Code Samples**: Before/after code examples
- **External Resources**: OWASP cheat sheets, CWE references, documentation links
