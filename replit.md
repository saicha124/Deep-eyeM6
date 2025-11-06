# Deep Eye - Security Scanner

## Overview
Deep Eye is an advanced AI-driven vulnerability scanner and penetration testing tool. It integrates multiple AI providers with comprehensive security testing modules for automated bug hunting, intelligent payload generation, and professional reporting. Its purpose is to provide a robust solution for identifying and remediating security weaknesses, covering a wide range of attack vectors. The project aims to become a leading tool in automated security analysis, offering detailed insights and actionable remediation strategies for developers and security professionals.

## User Preferences
I prefer iterative development with clear, concise communication. Please ask before making major architectural changes or introducing new dependencies. When suggesting code, provide clear explanations and examples. I value detailed explanations for complex issues but prefer simple language where possible. Do not make changes to the `reports/` and `logs/` folders.

## System Architecture
Deep Eye is a command-line security testing tool written in Python 3.11. Its core engine is designed for AI-powered vulnerability detection.

**UI/UX Decisions:**
- **Web GUI (New):** Modern web interface for managing AI provider API keys and settings, featuring a beautiful gradient design, master AI toggle, individual provider controls, and secure encrypted key storage.
- **Report Design:** Professional, clean design with gradient backgrounds, white content cards, and a focus on readability.
- **Vulnerability Digest:** Features interactive expandable/collapsible cards, color-coded severity badges (Critical, High, Medium, Low), and copy-to-clipboard functionality for code blocks.
- **Code Comparison:** Side-by-side comparison of vulnerable code (red border) and solution code (green border) with black text for maximum contrast.
- **Multi-language Support:** Reports can be generated in English, French, and Arabic.
- **Branding:** Incorporates a professional SVG vector logo for CERIST, including a shield icon and gradient design.

**Technical Implementations & Feature Specifications:**
- **Multi-AI Provider Support:** Integrates with OpenAI, Claude, Grok, and OLLAMA for intelligent payload generation and analysis.
- **Comprehensive Scanning:** Detects 45+ types of security issues, including OWASP Top 10 vulnerabilities (SQL injection, XSS, SSRF, API security, WebSocket testing, etc.).
- **Reconnaissance:** Capabilities include OSINT gathering, subdomain enumeration, and DNS record analysis.
- **Machine Learning Anomaly Detection:** (Requires training data to enable).
- **Custom Plugin System:** Allows for extensible functionality.
- **Multi-channel Notifications:** Supports email, Slack, and Discord.
- **Detailed Remediation:** Provides complete solutions with framework-specific code examples for all detected vulnerabilities, including vulnerable and fixed code comparisons.
- **Attack Chain Visualization:** Reports include description, evidence, payload used, payload source, HTTP request/response, detection source, and remediation.
- **Security Hardening:** Automatic redaction of sensitive data (e.g., Authorization headers, API keys, Cookies) in reports and truncation of large request/response bodies (to 5KB) to prevent memory issues and XSS prevention via Jinja2 autoescaping.

**System Design Choices:**
- **Modular Structure:** Organized into `core/`, `ai_providers/`, `modules/`, `utils/`, `config/`, `templates/`, `reports/`, `logs/`, and `data/` directories for maintainability.
- **Configuration Management:** Centralized `config/config.yaml` for scanner settings, vulnerability checks, report formats, and network settings.
- **Secret Management (New):** Centralized encryption/decryption module (`utils/secret_manager.py`) using Fernet encryption. All API keys are stored encrypted in `.env` file and automatically decrypted when needed by the application or config loader.
- **Web GUI:** Flask-based web interface (`web_gui.py`) for managing AI provider settings, accessible at port 5000 with secure API key management and connection testing.
- **Automated Code Snippet Extraction:** Automatically extracts and displays relevant scanner code snippets in reports, showing exactly how vulnerabilities were detected.
- **Standardized Vulnerability Schema:** A well-defined schema for vulnerability attributes, including timestamps, priority levels, fix time estimates, and references.

## External Dependencies
- **AI Providers:** OpenAI, Claude, Grok, OLLAMA
- **HTTP/Web Testing:** `requests`, `beautifulsoup4`, `lxml`, `urllib3`, `selenium`, `webdriver-manager`, `httpx`, `aiohttp`
- **Security Libraries:** `cryptography`, `python-jwt`
- **Web Framework:** `flask`, `flask-cors`
- **Reporting & Templating:** `reportlab`, `jinja2`, `markdown`
- **Data Science (for ML anomaly detection):** `scikit-learn`, `numpy`, `pandas`
- **CLI Tools:** `click`, `rich`, `tqdm`, `colorama`

## Recent Changes (November 2025)
- **Web GUI Added**: Created a modern web interface for managing AI provider API keys and settings
- **Secure API Key Storage**: Implemented Fernet encryption for all API keys stored in environment variables
- **Centralized Secret Management**: Created `utils/secret_manager.py` for encryption/decryption across the application
- **Config Loader Enhancement**: Updated to automatically decrypt environment variables when loading configuration
- **Grok Provider Testing**: Added real API connection testing for Grok provider using xAI endpoints
- **Package Updates**: Updated to specific versions: beautifulsoup4==4.12.3, dnspython==2.6.1, requests==2.31.0, urllib3==2.2.2