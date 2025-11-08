# Deep Eye - Security Scanner

## Overview
Deep Eye is an advanced AI-driven vulnerability scanner and penetration testing tool. It integrates multiple AI providers with comprehensive security testing modules for automated bug hunting, intelligent payload generation, and professional reporting. Its purpose is to provide a robust solution for identifying and remediating security weaknesses, covering a wide range of attack vectors. The project aims to become a leading tool in automated security analysis, offering detailed insights and actionable remediation strategies for developers and security professionals.

## User Preferences
I prefer iterative development with clear, concise communication. Please ask before making major architectural changes or introducing new dependencies. When suggesting code, provide clear explanations and examples. I value detailed explanations for complex issues but prefer simple language where possible. Do not make changes to the `reports/` and `logs/` folders.

## System Architecture
Deep Eye is a command-line security testing tool written in Python 3.11. Its core engine is designed for AI-powered vulnerability detection.

**UI/UX Decisions:**
- **Web GUI:** Modern web interface with three main pages:
  - **Settings Page:** Manage AI provider API keys and settings, featuring a beautiful gradient design, master AI toggle, individual provider controls, and secure encrypted key storage.
  - **Scanner Page:** User-friendly interface for entering target URLs, initiating scans, viewing real-time progress with percentage and vulnerability count, and exporting reports in multiple formats (HTML, JSON, CSV).
  - **Report Viewer Page:** Browse all historical scan reports with metadata, view detailed vulnerability information in modal dialogs, and export past scans in any format.
- **Navigation:** Seamless navigation between Settings, Scanner, and Report pages via header links.
- **Scan Results Display:** Interactive vulnerability cards with color-coded severity badges (Critical, High, Medium, Low), summary statistics dashboard, and expandable details.
- **Report Design:** Professional, clean design with gradient backgrounds, white content cards, and a focus on readability.
- **Vulnerability Digest:** Features interactive expandable/collapsible cards, color-coded severity badges, and copy-to-clipboard functionality for code blocks.
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
- **Web GUI:** Flask-based web interface (`web_gui.py`) with comprehensive functionality:
  - Settings management for AI provider API keys with connection testing
  - Scanner interface for entering URLs and initiating vulnerability scans
  - Real-time progress tracking with live percentage and vulnerability count updates
  - Real-time scan results display with interactive vulnerability cards
  - JSON storage of scan results in `reports/` directory
  - Multi-format report export (HTML, JSON, CSV)
  - Historical scan report viewer with modal detail dialogs
  - SSRF protection with DNS resolution and private IP blocking
  - RESTful API endpoints: POST /api/scan, GET /api/scans, GET /api/scans/<scan_id>, GET /api/download-report/<scan_id>, GET /api/export/<scan_id>/<format>
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

### Session 1: AI Settings Interface
- **Web GUI Added**: Created a modern web interface for managing AI provider API keys and settings
- **Secure API Key Storage**: Implemented Fernet encryption for all API keys stored in environment variables
- **Centralized Secret Management**: Created `utils/secret_manager.py` for encryption/decryption across the application
- **Config Loader Enhancement**: Updated to automatically decrypt environment variables when loading configuration
- **Grok Provider Testing**: Added real API connection testing for Grok provider using xAI endpoints
- **Package Updates**: Updated to specific versions: beautifulsoup4==4.12.3, dnspython==2.6.1, requests==2.31.0, urllib3==2.2.2

### Session 2: Vulnerability Scanner Interface
- **Scanner Page Added**: Created `templates/scanner.html` with URL input form and real-time results display
- **Scan API Endpoints**: Implemented POST /api/scan, GET /api/scans/<scan_id>, and GET /api/download-report/<scan_id>
- **SSRF Protection**: Comprehensive URL validation with DNS resolution to block localhost, private IPs, link-local, reserved, and multicast addresses
- **Scan Results Storage**: JSON storage in `reports/` directory for persistent scan history
- **Interactive Results Display**: Vulnerability cards with severity badges, summary statistics, and expandable details
- **Navigation**: Added header navigation between Settings and Scanner pages
- **Report Downloads**: HTML report generation and download functionality

### Session 3: Real-time Progress & Report Viewer
- **Real-time Progress Tracking**: Enhanced scanner engine with progress callbacks that update UI in real-time during scans
  - Live percentage completion (0-100%)
  - Live vulnerability count updates
  - Status messages showing current scanning phase (crawling, scanning modules)
  - Progress bar visual feedback synchronized with backend scanning process
- **Interactive Report Viewer**: New `/report` page listing all historical scan reports
  - Displays scan metadata: target URL, timestamp, scan ID, vulnerability count
  - Click-to-view detailed vulnerability information in modal dialogs
  - Empty state handling when no scans exist
  - Deterministic ordering by timestamp (newest first)
- **Multi-format Export**: Added export functionality in HTML, JSON, and CSV formats
  - Export buttons on scanner page (appear after scan completion)
  - Export buttons on report viewer for all historical scans
  - New API endpoint: GET /api/export/<scan_id>/<format>
  - CSV export includes all vulnerability details in tabular format
  - JSON export provides complete structured data for integration
- **Enhanced API**: Updated REST API with new endpoints
  - GET /api/scans - Lists all available scan reports with metadata
  - GET /api/export/<scan_id>/<format> - Exports reports in JSON or CSV
  - Proper error handling and existence checks for all endpoints

## Known Limitations
- **DNS Rebinding Protection**: While URL validation resolves DNS and blocks private IPs at validation time, there's a theoretical TOCTOU (time-of-check/time-of-use) gap where DNS could change between validation and the actual scan. Complete mitigation would require modifying the core scanner engine to use validated IPs directly.