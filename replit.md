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

# Use custom config file
python deep_eye.py -c custom_config.yaml

# Show version
python deep_eye.py --version
```

## Important Notes
- **Legal**: Only use on systems you own or have explicit permission to test
- **API Keys Required**: At least one AI provider API key must be configured
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

- **Information Disclosure Reporting Enhanced - November 4, 2025**
  - Added comprehensive remediation guide for Information Disclosure vulnerabilities
  - Now includes common error codes and attack scenarios
  - Added detailed solutions for disabling debug mode and error messages
  - Includes code examples for Python/Flask, Django, Node.js, Apache, and Nginx
  - Added CWE references: CWE-209, CWE-200, CWE-497
  - Shows specific error patterns: stack traces, database errors, version exposure
  - Provides step-by-step fix instructions with configuration examples

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
