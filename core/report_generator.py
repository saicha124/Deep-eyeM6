"""
Report Generator
Creates professional security assessment reports with multi-language support
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Environment, select_autoescape
from utils.logger import get_logger
from core.remediation_guide import RemediationGuide
from utils.translations import Translator

logger = get_logger(__name__)


class ReportGenerator:
    """Generate professional security reports."""
    
    def __init__(self, config: Dict):
        """Initialize report generator."""
        self.config = config
        self.report_config = config.get('reporting', {})
        self.template_dir = Path(__file__).parent.parent.parent / 'templates'
        
        # Initialize translator with configured language
        language = self.report_config.get('language', 'en')
        self.translator = Translator(language)
        logger.info(f"Report language set to: {language}")
    
    def generate(self, results: Dict, output_path: str, format: str = 'html'):
        """
        Generate security report.
        
        Args:
            results: Scan results
            output_path: Output file path
            format: Report format (html, pdf, json)
        """
        if format == 'json':
            self._generate_json(results, output_path)
        elif format == 'html':
            self._generate_html(results, output_path)
            # Also generate vulnerability digest
            self._generate_vulnerability_digest(results, output_path)
        elif format == 'pdf':
            self._generate_pdf(results, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_multilingual(self, results: Dict, output_path: str, format: str = 'html'):
        """
        Generate security reports in all available languages (English, French, Arabic).
        
        Args:
            results: Scan results
            output_path: Output file path (will be modified with language suffix)
            format: Report format (html, pdf, json)
        
        Returns:
            List of generated report paths
        """
        generated_reports = []
        languages = ['en', 'fr', 'ar']
        language_names = {'en': 'English', 'fr': 'French', 'ar': 'Arabic'}
        
        # Parse output path
        path_obj = Path(output_path)
        stem = path_obj.stem
        suffix = path_obj.suffix
        parent = path_obj.parent
        
        logger.info(f"Generating multi-language reports in: English, French, Arabic")
        
        for lang in languages:
            # Create language-specific filename
            lang_filename = f"{stem}_{lang}{suffix}"
            lang_output_path = parent / lang_filename
            
            # Temporarily set the language for this report
            original_language = self.translator.language
            self.translator = Translator(lang)
            
            # Generate report in this language
            if format == 'json':
                self._generate_json(results, str(lang_output_path))
            elif format == 'html':
                self._generate_html(results, str(lang_output_path))
                # Also generate vulnerability digest for HTML reports
                self._generate_vulnerability_digest(results, str(lang_output_path))
            elif format == 'pdf':
                self._generate_pdf(results, str(lang_output_path))
            
            generated_reports.append(str(lang_output_path))
            logger.info(f"✓ {language_names[lang]} report: {lang_output_path}")
            
            # Restore original language
            self.translator = Translator(original_language)
        
        logger.info(f"Successfully generated {len(generated_reports)} multi-language reports")
        return generated_reports
    
    def _generate_json(self, results: Dict, output_path: str):
        """Generate JSON report."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"JSON report generated: {output_path}")
    
    def _generate_html(self, results: Dict, output_path: str):
        """Generate HTML report with multi-language support."""
        template_content = self._get_html_template()
        
        # Create Jinja environment with autoescaping enabled for security (prevent XSS)
        env = Environment(autoescape=True)
        template = env.from_string(template_content)
        
        # Read and encode CERIST logo as base64
        import base64
        logo_path = Path(__file__).parent.parent / 'assets' / 'cerist_logo.png'
        cerist_logo_base64 = ""
        try:
            with open(logo_path, 'rb') as f:
                logo_data = base64.b64encode(f.read()).decode('utf-8')
                cerist_logo_base64 = f"data:image/png;base64,{logo_data}"
        except Exception as e:
            logger.warning(f"Could not load CERIST logo: {e}")
            cerist_logo_base64 = ""
        
        # Enhance vulnerabilities with detailed remediation
        vulnerabilities = results.get('vulnerabilities', [])
        enhanced_vulns = [RemediationGuide.enhance_vulnerability(v.copy()) for v in vulnerabilities]
        
        # Prepare data for template with translations
        t = self.translator
        report_data = {
            'title': t.get('report_title'),
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': results.get('target'),
            'scan_duration': results.get('duration'),
            'summary': self._generate_summary(results),
            'vulnerabilities': self._sort_vulnerabilities(enhanced_vulns),
            'severity_counts': results.get('severity_summary', {}),
            'urls_scanned': results.get('urls_crawled', 0),
            'reconnaissance': results.get('reconnaissance', {}),
            'cerist_logo': cerist_logo_base64,
            # Add translated labels
            'labels': {
                'executive_summary': t.get('executive_summary'),
                'vulnerabilities': t.get('vulnerabilities'),
                'target': t.get('target'),
                'generated': t.get('generated_date'),
                'scan_duration': t.get('scan_duration'),
                'urls_scanned': t.get('urls_scanned'),
                'reconnaissance': t.get('reconnaissance'),
                'severity': t.get('severity'),
                'critical': t.get('critical'),
                'high': t.get('high'),
                'medium': t.get('medium'),
                'low': t.get('low'),
                'url': t.get('url'),
                'parameter': t.get('parameter'),
                'description': t.get('description'),
                'evidence': t.get('evidence'),
                'cwe': t.get('cwe'),
                'discovered': t.get('discovered'),
                'remediation_guidance': t.get('remediation_guidance'),
                'priority': t.get('priority'),
                'estimated_fix_time': t.get('estimated_fix_time'),
                'steps_to_fix': t.get('steps_to_fix'),
                'code_example': t.get('code_example'),
                'exploit_example': t.get('exploit_example'),
                'solution': t.get('solution'),
                'references': t.get('references'),
                'no_vulnerabilities': t.get('no_vulnerabilities'),
                'payload_used': t.get('payload_used'),
                'how_to_fix': t.get('how_to_fix'),
                'remediation': t.get('remediation'),
            },
            'language': self.translator.language,
        }
        
        html_content = template.render(**report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path} (Language: {self.translator.language})")
    
    def _generate_vulnerability_digest(self, results: Dict, original_output_path: str):
        """Generate a separate HTML vulnerability digest showing all vulnerabilities with code snippets."""
        # Read the vulnerability digest template
        template_path = Path(__file__).parent.parent / 'templates' / 'vulnerability_digest.html'
        
        if not template_path.exists():
            logger.warning(f"Vulnerability digest template not found: {template_path}")
            return
        
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # Create Jinja environment with autoescaping enabled for security (prevent XSS)
        env = Environment(autoescape=True)
        template = env.from_string(template_content)
        
        # Read and encode CERIST logo (try SVG first, fallback to PNG)
        import base64
        svg_path = Path(__file__).parent.parent / 'assets' / 'cerist_logo.svg'
        png_path = Path(__file__).parent.parent / 'assets' / 'cerist_logo.png'
        cerist_logo_base64 = ""
        
        try:
            if svg_path.exists():
                with open(svg_path, 'r', encoding='utf-8') as f:
                    svg_data = f.read()
                    svg_encoded = base64.b64encode(svg_data.encode('utf-8')).decode('utf-8')
                    cerist_logo_base64 = f"data:image/svg+xml;base64,{svg_encoded}"
            elif png_path.exists():
                with open(png_path, 'rb') as f:
                    logo_data = base64.b64encode(f.read()).decode('utf-8')
                    cerist_logo_base64 = f"data:image/png;base64,{logo_data}"
        except Exception as e:
            logger.warning(f"Could not load CERIST logo for digest: {e}")
        
        # Enhance vulnerabilities with detailed remediation
        vulnerabilities = results.get('vulnerabilities', [])
        enhanced_vulns = [RemediationGuide.enhance_vulnerability(v.copy()) for v in vulnerabilities]
        
        # Prepare data for template
        digest_data = {
            'target': results.get('target', 'Unknown'),
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': self._sort_vulnerabilities(enhanced_vulns),
            'severity_counts': results.get('severity_summary', {}),
            'cerist_logo': cerist_logo_base64,
        }
        
        html_content = template.render(**digest_data)
        
        # Create output path for digest in reports folder
        path_obj = Path(original_output_path).resolve()
        
        # Find the reports directory by walking up the directory tree
        reports_dir = None
        for parent in [path_obj.parent] + list(path_obj.parents):
            if parent.name == 'reports':
                reports_dir = parent
                break
        
        # If no reports directory found in the path, create one in the parent directory
        if reports_dir is None:
            reports_dir = path_obj.parent / 'reports'
        
        reports_dir.mkdir(exist_ok=True)
        
        # Extract language from filename if present (e.g., report_en.html -> en)
        lang_suffix = ''
        stem = path_obj.stem
        if '_' in stem:
            parts = stem.split('_')
            last_part = parts[-1]
            if last_part in ['en', 'fr', 'ar']:
                lang_suffix = f'_{last_part}'
        
        # Create digest filename with timestamp and optional language suffix
        import time
        # Use microseconds to ensure unique filenames even when generated quickly
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S') + f'_{int(time.time() * 1000000) % 1000000:06d}'
        digest_filename = f'vulnerability_digest{lang_suffix}_{timestamp}.html'
        digest_output_path = reports_dir / digest_filename
        
        with open(digest_output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Vulnerability digest generated: {digest_output_path}")
        logger.info(f"  └─ {len(enhanced_vulns)} vulnerabilities documented with code snippets")
    
    def _generate_pdf(self, results: Dict, output_path: str):
        """Generate PDF report using ReportLab (Windows-friendly)."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            from xml.sax.saxutils import escape
            
            # Enhance vulnerabilities with detailed remediation
            vulnerabilities = results.get('vulnerabilities', [])
            enhanced_vulns = [RemediationGuide.enhance_vulnerability(v.copy()) for v in vulnerabilities]
            results['vulnerabilities'] = enhanced_vulns
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Title (with translation)
            t = self.translator
            story.append(Paragraph(t.get('report_title'), title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Metadata table (with translations)
            metadata = [
                [t.get('target') + ':', results.get('target', 'N/A')],
                [t.get('generated_date') + ':', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                [t.get('scan_duration') + ':', str(results.get('duration', 'N/A'))],
                [t.get('urls_scanned') + ':', str(results.get('urls_crawled', 0))]
            ]
            
            metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(metadata_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Reconnaissance & OSINT Data
            recon_data = results.get('reconnaissance', {})
            if recon_data:
                story.append(Paragraph(t.get('reconnaissance'), heading_style))
                
                # DNS Information
                dns_info = recon_data.get('dns', {})
                if dns_info:
                    story.append(Paragraph(f"<b>{t.get('dns_records')}:</b>", styles['Heading4']))
                    dns_records = []
                    for record_type, records in dns_info.items():
                        if records:
                            dns_records.append([record_type.upper(), ', '.join(str(r) for r in records[:3])])
                    if dns_records:
                        dns_table = Table([[heading, data] for heading, data in dns_records], colWidths=[1.5*inch, 4.5*inch])
                        dns_table.setStyle(TableStyle([
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ]))
                        story.append(dns_table)
                        story.append(Spacer(1, 0.15*inch))
                
                # OSINT Data
                osint_data = recon_data.get('osint', {})
                if osint_data:
                    story.append(Paragraph(f"<b>{t.get('osint_findings')}:</b>", styles['Heading4']))
                    
                    # Emails
                    emails = osint_data.get('emails', [])
                    if emails:
                        story.append(Paragraph(f"{t.get('emails_found')}: {len(emails)}", styles['BodyText']))
                        safe_emails = [escape(str(e)) for e in emails[:5]]
                        story.append(Paragraph(', '.join(safe_emails), styles['BodyText']))
                        story.append(Spacer(1, 0.1*inch))
                    
                    # Subdomains
                    subdomains = osint_data.get('subdomains', [])
                    if subdomains:
                        story.append(Paragraph(f"{t.get('subdomains_discovered')}: {len(subdomains)}", styles['BodyText']))
                        safe_subdomains = [escape(str(s)) for s in subdomains[:10]]
                        story.append(Paragraph(', '.join(safe_subdomains), styles['BodyText']))
                        story.append(Spacer(1, 0.1*inch))
                    
                    # Technologies
                    technologies = recon_data.get('technologies', [])
                    if technologies:
                        safe_techs = [escape(str(tech)) for tech in technologies]
                        story.append(Paragraph(f"{t.get('technologies_detected')}: {', '.join(safe_techs)}", styles['BodyText']))
                        story.append(Spacer(1, 0.1*inch))
                
                story.append(PageBreak())
            
            # Severity Summary (with translations)
            severity_counts = results.get('severity_summary', {})
            severity_data = [
                [t.get('severity'), t.get('count')],
                [t.get('critical'), str(severity_counts.get('critical', 0))],
                [t.get('high'), str(severity_counts.get('high', 0))],
                [t.get('medium'), str(severity_counts.get('medium', 0))],
                [t.get('low'), str(severity_counts.get('low', 0))]
            ]
            
            severity_table = Table(severity_data, colWidths=[3*inch, 3*inch])
            severity_colors = {
                1: colors.HexColor('#8B0000'),  # Critical
                2: colors.HexColor('#FF4500'),  # High
                3: colors.HexColor('#FFA500'),  # Medium
                4: colors.HexColor('#FFD700')   # Low
            }
            
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ] + [
                ('BACKGROUND', (0, i), (0, i), severity_colors[i])
                for i in severity_colors.keys()
            ]))
            story.append(severity_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Executive Summary (with translation)
            story.append(Paragraph(t.get('executive_summary'), heading_style))
            summary_text = self._generate_summary(results)
            story.append(Paragraph(summary_text.replace('\n', '<br/>'), styles['BodyText']))
            story.append(Spacer(1, 0.3*inch))
            
            # Vulnerabilities (with translation)
            story.append(Paragraph(t.get('vulnerabilities'), heading_style))
            vulnerabilities = self._sort_vulnerabilities(results.get('vulnerabilities', []))
            
            if vulnerabilities:
                for vuln in vulnerabilities:
                    # Vulnerability title (escape special characters)
                    vuln_type = escape(str(vuln.get('type', 'Unknown')))
                    vuln_severity = escape(str(vuln.get('severity', 'info').upper()))
                    vuln_title = f"<b>{vuln_type}</b> - {vuln_severity}"
                    story.append(Paragraph(vuln_title, styles['Heading3']))
                    
                    # Timestamp if available (with translation)
                    if vuln.get('timestamp'):
                        timestamp_text = f"<i>{t.get('discovered')}: {escape(str(vuln.get('timestamp')))}</i>"
                        story.append(Paragraph(timestamp_text, styles['BodyText']))
                    
                    # Vulnerability details (escape special characters)
                    vuln_url = escape(str(vuln.get('url', 'N/A')))
                    vuln_param = escape(str(vuln.get('parameter', 'N/A')))
                    vuln_desc = escape(str(vuln.get('description', 'N/A')))
                    vuln_evidence = escape(str(vuln.get('evidence', 'N/A'))[:200])  # Limit evidence length
                    vuln_cwe = escape(str(vuln.get('cwe', 'N/A')))
                    
                    vuln_details = f"""
                    <b>{t.get('url')}:</b> {vuln_url}<br/>
                    <b>{t.get('parameter')}:</b> {vuln_param}<br/>
                    <b>CWE:</b> {vuln_cwe}<br/>
                    <b>{t.get('description')}:</b> {vuln_desc}<br/>
                    <b>{t.get('evidence')}:</b> {vuln_evidence}
                    """
                    story.append(Paragraph(vuln_details, styles['BodyText']))
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Enhanced remediation details
                    remediation_details = vuln.get('remediation_details', {})
                    if remediation_details:
                        priority = remediation_details.get('priority', 'MEDIUM')
                        fix_time = remediation_details.get('fix_time', 'N/A')
                        
                        story.append(Paragraph(f"<b>{t.get('remediation_guidance')}</b>", styles['Heading4']))
                        story.append(Paragraph(f"<b>{t.get('priority')}:</b> {priority} | <b>{t.get('estimated_fix_time')}:</b> {fix_time}", styles['BodyText']))
                        story.append(Spacer(1, 0.05*inch))
                        
                        # Remediation steps (with translation)
                        steps = remediation_details.get('steps', [])
                        if steps:
                            story.append(Paragraph(f"<b>{t.get('steps_to_fix')}:</b>", styles['BodyText']))
                            for i, step in enumerate(steps[:5], 1):  # Limit to 5 steps for PDF
                                step_text = f"{i}. {escape(str(step))}"
                                story.append(Paragraph(step_text, styles['BodyText']))
                            story.append(Spacer(1, 0.05*inch))
                        
                        # Code examples (Vulnerable vs Secure) (with translation)
                        code_example = remediation_details.get('code_example', '')
                        if code_example:
                            story.append(Paragraph(f"<b>{t.get('code_example')}:</b>", styles['BodyText']))
                            # Use a monospaced style for code
                            code_style = ParagraphStyle(
                                'Code',
                                parent=styles['Code'] if 'Code' in styles else styles['BodyText'],
                                fontName='Courier',
                                fontSize=9,
                                leftIndent=20,
                                rightIndent=20,
                                backColor=colors.HexColor('#f5f5f5'),
                                spaceBefore=5,
                                spaceAfter=5
                            )
                            # Clean and format code example
                            code_lines = code_example.strip().split('\n')
                            for line in code_lines:
                                story.append(Paragraph(escape(line), code_style))
                            story.append(Spacer(1, 0.05*inch))
                        
                        # References (with translation)
                        references = remediation_details.get('references', [])
                        if references:
                            story.append(Paragraph(f"<b>{t.get('references')}:</b>", styles['BodyText']))
                            for ref in references[:3]:  # Limit to 3 references for PDF
                                ref_text = f"• {escape(str(ref))}"
                                story.append(Paragraph(ref_text, styles['BodyText']))
                    else:
                        vuln_remediation = escape(str(vuln.get('remediation', 'N/A')))
                        story.append(Paragraph(f"<b>{t.get('remediation')}:</b> {vuln_remediation}", styles['BodyText']))
                    
                    story.append(Spacer(1, 0.3*inch))
            else:
                story.append(Paragraph(t.get('no_vulnerabilities'), styles['BodyText']))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
            
        except ImportError as e:
            logger.error(f"ReportLab not available: {e}")
            logger.info("Falling back to HTML report...")
            html_path = output_path.replace('.pdf', '.html')
            self._generate_html(results, html_path)
            logger.info(f"HTML report available at: {html_path}")
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            logger.info("Falling back to HTML report...")
            html_path = output_path.replace('.pdf', '.html')
            self._generate_html(results, html_path)
            logger.info(f"HTML report available at: {html_path}")
    
    def _generate_summary(self, results: Dict) -> str:
        """Generate executive summary with multi-language support."""
        total_vulns = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        t = self.translator
        
        # Get base summary text with formatting
        base_summary = t.format('summary_text', total=total_vulns)
        
        # Build risk distribution section
        risk_dist = f"""
        
        {t.get('risk_distribution')}:
        - {t.get('critical')}: {severity_counts.get('critical', 0)} {t.get('issues')}
        - {t.get('high')}: {severity_counts.get('high', 0)} {t.get('issues')}
        - {t.get('medium')}: {severity_counts.get('medium', 0)} {t.get('issues')}
        - {t.get('low')}: {severity_counts.get('low', 0)} {t.get('issues')}
        """
        
        summary = base_summary + risk_dist
        
        return summary.strip()
    
    def _sort_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Sort vulnerabilities by severity."""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        return sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )
    
    def _get_html_template(self) -> str:
        """Get enhanced HTML report template with dark mode and modern UI."""
        return '''
<!DOCTYPE html>
<html lang="{{ language }}" dir="{% if language == 'ar' %}rtl{% else %}ltr{% endif %}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #f5f5f5;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --text-primary: #333333;
            --text-secondary: #666666;
            --border-color: #e0e0e0;
            --shadow: 0 4px 6px rgba(0,0,0,0.1);
            --shadow-hover: 0 8px 16px rgba(0,0,0,0.15);
            --accent-primary: #667eea;
            --accent-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --code-bg: #2d2d2d;
            --code-text: #f8f8f2;
        }
        
        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-card: #2d2d2d;
            --text-primary: #e0e0e0;
            --text-secondary: #b0b0b0;
            --border-color: #404040;
            --shadow: 0 4px 6px rgba(0,0,0,0.3);
            --shadow-hover: 0 8px 16px rgba(0,0,0,0.4);
            --code-bg: #1e1e1e;
            --code-text: #d4d4d4;
        }
        
        body {
            font-family: {% if language == 'ar' %}'Arial', 'Tahoma', sans-serif{% else %}'Segoe UI', Tahoma, Geneva, Verdana, sans-serif{% endif %};
            line-height: 1.6;
            color: var(--text-primary);
            background-color: var(--bg-primary);
            direction: {% if language == 'ar' %}rtl{% else %}ltr{% endif %};
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            background: var(--accent-primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
        }
        
        .theme-toggle:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-hover);
        }
        
        .export-btn {
            position: fixed;
            top: 70px;
            right: 20px;
            z-index: 1000;
            background: #4caf50;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
        }
        
        .export-btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-hover);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-card);
            color: var(--text-primary);
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            border: 2px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 5px;
            background: var(--accent-gradient);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: var(--text-primary);
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .risk-dashboard {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            border: 2px solid var(--border-color);
        }
        
        .risk-dashboard h2 {
            color: var(--accent-primary);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .risk-score {
            display: inline-block;
            font-size: 3em;
            font-weight: bold;
            padding: 20px 40px;
            border-radius: 15px;
            margin: 20px 0;
            background: var(--accent-gradient);
            color: white;
            box-shadow: var(--shadow);
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metadata-card {
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }
        
        .metadata-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-hover);
        }
        
        .metadata-card h3 {
            color: var(--accent-primary);
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .metadata-card p {
            font-size: 1.3em;
            font-weight: bold;
            color: var(--text-primary);
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .severity-card {
            padding: 25px;
            border-radius: 15px;
            color: white;
            text-align: center;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .severity-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: rgba(255,255,255,0.1);
            transform: rotate(45deg);
            transition: all 0.5s ease;
        }
        
        .severity-card:hover::before {
            left: 100%;
        }
        
        .severity-card:hover {
            transform: translateY(-5px) scale(1.02);
            box-shadow: var(--shadow-hover);
        }
        
        .severity-critical { background: linear-gradient(135deg, #8B0000 0%, #a30000 100%); }
        .severity-high { background: linear-gradient(135deg, #FF4500 0%, #ff5722 100%); }
        .severity-medium { background: linear-gradient(135deg, #FFA500 0%, #ffb733 100%); }
        .severity-low { background-color: #FFD700; color: #333; }
        .severity-info { background-color: #87CEEB; color: #333; }
        
        .severity-card h3 {
            font-size: 2.5em;
            margin-bottom: 5px;
            font-weight: bold;
            position: relative;
            z-index: 1;
        }
        
        .severity-card p {
            font-size: 1em;
            text-transform: uppercase;
            letter-spacing: 1px;
            position: relative;
            z-index: 1;
        }
        
        .charts-section {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 20px;
        }
        
        .chart-container {
            background: var(--bg-primary);
            padding: 20px;
            border-radius: 10px;
            box-shadow: var(--shadow);
        }
        
        .chart-container h3 {
            color: var(--text-primary);
            margin-bottom: 15px;
            text-align: center;
        }
        
        .section {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .section h2 {
            color: var(--accent-primary);
            margin-bottom: 20px;
            border-bottom: 2px solid var(--accent-primary);
            padding-bottom: 10px;
            font-size: 1.8em;
        }
        
        .vulnerability {
            border-left: 5px solid var(--border-color);
            padding: 25px;
            margin-bottom: 25px;
            background: var(--bg-primary);
            border-radius: 10px;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
        }
        
        .vulnerability:hover {
            transform: translateX(5px);
            box-shadow: var(--shadow-hover);
        }
        
        .vulnerability.critical { border-left-color: #8B0000; }
        .vulnerability.high { border-left-color: #FF4500; }
        .vulnerability.medium { border-left-color: #FFA500; }
        .vulnerability.low { border-left-color: #FFD700; }
        
        .vulnerability h3 {
            color: var(--text-primary);
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        
        .vulnerability-meta {
            display: flex;
            gap: 15px;
            margin: 15px 0;
            flex-wrap: wrap;
        }
        
        .vulnerability-meta span {
            background: var(--bg-card);
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        
        .code {
            background: var(--code-bg);
            color: var(--code-text);
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', 'Monaco', monospace;
            margin: 10px 0;
            white-space: pre-wrap;
        }
        
        .remediation-section {
            background: var(--bg-primary);
            border: 2px solid var(--accent-primary);
            border-radius: 10px;
            padding: 25px;
            margin: 20px 0;
        }
        
        .remediation-section h4 {
            color: var(--accent-primary);
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .remediation-steps {
            margin: 20px 0;
        }
        
        .remediation-steps ol {
            margin-left: 25px;
            line-height: 2;
        }
        
        .remediation-steps li {
            margin: 12px 0;
            color: var(--text-primary);
        }
        
        .priority-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 0.9em;
            margin: 5px 0;
        }
        
        .priority-critical {
            background: #8B0000;
            color: white;
        }
        
        .priority-high {
            background: #FF4500;
            color: white;
        }
        
        .priority-medium {
            background: #FFA500;
            color: white;
        }
        
        .references {
            margin-top: 20px;
            padding: 15px;
            background: var(--bg-primary);
            border-left: 4px solid var(--accent-primary);
            border-radius: 5px;
        }
        
        .references ul {
            margin-left: 25px;
            margin-top: 10px;
        }
        
        .references li {
            color: var(--text-primary);
        }
        
        .timestamp {
            color: var(--text-secondary);
            font-size: 0.9em;
            font-style: italic;
        }
        
        .recon-subsection {
            margin: 20px 0;
            padding: 25px;
            background: var(--bg-primary);
            border-left: 5px solid var(--accent-primary);
            border-radius: 10px;
        }
        
        .recon-subsection h3 {
            color: var(--accent-primary);
            margin-bottom: 15px;
        }
        
        .recon-data {
            margin-top: 10px;
        }
        
        .recon-data p {
            margin: 10px 0;
            color: var(--text-primary);
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            margin-top: 40px;
            background: var(--bg-card);
            border-radius: 15px;
            box-shadow: var(--shadow);
        }
        
        .logo {
            max-width: 180px;
            height: auto;
            margin: 10px 0;
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .header-text {
            flex: 1;
            min-width: 300px;
        }
        
        .header-logo {
            padding: 10px;
            background: transparent;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .theme-toggle, .export-btn {
                position: static;
                margin: 10px auto;
                display: block;
                width: 200px;
            }
            
            .severity-grid,  .metadata, .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .chart-container {
                min-height: 250px;
            }
        }
        
        @media print {
            .theme-toggle, .export-btn {
                display: none !important;
            }
            
            body {
                background: white;
                color: black;
            }
            
            .vulnerability {
                page-break-inside: avoid;
            }
            
            .section {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌙 Toggle Dark Mode</button>
    <button class="export-btn" onclick="window.print()">📄 Print / Export PDF</button>
    
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="header-text">
                    <h1>🔍 {{ title }}</h1>
                    <p>Generated: {{ generated_date }}</p>
                </div>
                <div class="header-logo">
                    <img src="{{ cerist_logo }}" alt="CERIST" class="logo">
                </div>
            </div>
        </div>
        
        {% if severity_counts %}
        <div class="risk-dashboard">
            <h2>📊 Risk Assessment Dashboard</h2>
            <div>
                <span class="risk-score" id="riskScore">Loading...</span>
                <p style="color: var(--text-secondary); margin-top: 10px;">
                    Overall Security Risk Score (0-100)
                </p>
            </div>
        </div>
        {% endif %}
        
        <div class="metadata">
            <div class="metadata-card">
                <h3>Target</h3>
                <p>{{ target }}</p>
            </div>
            <div class="metadata-card">
                <h3>Scan Duration</h3>
                <p>{{ scan_duration }}</p>
            </div>
            <div class="metadata-card">
                <h3>URLs Scanned</h3>
                <p>{{ urls_scanned }}</p>
            </div>
        </div>
        
        <div class="severity-grid">
            <div class="severity-card severity-critical">
                <h3>{{ severity_counts.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="severity-card severity-high">
                <h3>{{ severity_counts.high }}</h3>
                <p>High</p>
            </div>
            <div class="severity-card severity-medium">
                <h3>{{ severity_counts.medium }}</h3>
                <p>Medium</p>
            </div>
            <div class="severity-card severity-low">
                <h3>{{ severity_counts.low }}</h3>
                <p>Low</p>
            </div>
        </div>
        
        {% if severity_counts %}
        <div class="charts-section">
            <h2 style="color: var(--accent-primary); margin-bottom: 20px;">📈 Vulnerability Analytics</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Severity Distribution</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Risk Breakdown</h3>
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
        </div>
        {% endif %}
        
        {% if reconnaissance %}
        <div class="section">
            <h2>🔎 Reconnaissance & OSINT Intelligence</h2>
            
            {% if reconnaissance.dns %}
            <div class="recon-subsection">
                <h3>DNS Records</h3>
                <div class="recon-data">
                    {% for record_type, records in reconnaissance.dns.items() %}
                        {% if records %}
                        <p><strong>{{ record_type|upper }}:</strong> {{ records|join(', ') }}</p>
                        {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            
            {% if reconnaissance.osint %}
            <div class="recon-subsection">
                <h3>OSINT Findings</h3>
                <div class="recon-data">
                    {% if reconnaissance.osint.emails %}
                    <p><strong>Emails Found:</strong> {{ reconnaissance.osint.emails|length }}</p>
                    <div class="code">{{ reconnaissance.osint.emails|join(', ') }}</div>
                    {% endif %}
                    
                    {% if reconnaissance.osint.subdomains %}
                    <p><strong>Subdomains Discovered:</strong> {{ reconnaissance.osint.subdomains|length }}</p>
                    <div class="code">{{ reconnaissance.osint.subdomains[:10]|join(', ') }}</div>
                    {% endif %}
                    
                    {% if reconnaissance.osint.github_leaks %}
                    <p><strong>GitHub Potential Leaks:</strong> {{ reconnaissance.osint.github_leaks|length }}</p>
                    {% endif %}
                    
                    {% if reconnaissance.osint.breaches %}
                    <p><strong>Breach Database Results:</strong></p>
                    <div class="code">{{ reconnaissance.osint.breaches|join(', ') }}</div>
                    {% endif %}
                </div>
            </div>
            {% endif %}
            
            {% if reconnaissance.technologies %}
            <div class="recon-subsection">
                <h3>Technologies Detected</h3>
                <div class="recon-data">
                    <p>{{ reconnaissance.technologies|join(', ') }}</p>
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        <div class="section">
            <h2>{{ labels.executive_summary }}</h2>
            <p>{{ summary }}</p>
        </div>
        
        <div class="section">
            <h2>{{ labels.vulnerabilities }}</h2>
            {% if vulnerabilities %}
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.severity }}">
                    <h3>{{ vuln.type }}</h3>
                    {% if vuln.timestamp %}
                    <p class="timestamp">🕐 {{ labels.discovered }}: {{ vuln.timestamp }}</p>
                    {% endif %}
                    <div class="vulnerability-meta">
                        <span><strong>{{ labels.severity }}:</strong> {{ vuln.severity|upper }}</span>
                        <span><strong>{{ labels.url }}:</strong> {{ vuln.url }}</span>
                        {% if vuln.parameter %}
                        <span><strong>{{ labels.parameter }}:</strong> {{ vuln.parameter }}</span>
                        {% endif %}
                        {% if vuln.cwe %}
                        <span><strong>{{ labels.cwe }}:</strong> {{ vuln.cwe }}</span>
                        {% endif %}
                    </div>
                    
                    <p><strong>{{ labels.description }}:</strong> {{ vuln.description }}</p>
                    
                    {% if vuln.payload %}
                    <p><strong>{{ labels.payload_used }}:</strong></p>
                    <div class="code">{{ vuln.payload }}</div>
                    {% endif %}
                    
                    <p><strong>{{ labels.evidence }}:</strong> {{ vuln.evidence }}</p>
                    
                    {% if vuln.remediation_details %}
                    <div class="remediation-section">
                        <h4>🛡️ {{ labels.how_to_fix }}</h4>
                        
                        <div>
                            <span class="priority-badge priority-{{ vuln.remediation_details.priority|lower }}">
                                {{ labels.priority }}: {{ vuln.remediation_details.priority }}
                            </span>
                            <span style="margin-left: 10px;">⏱️ {{ labels.estimated_fix_time }}: {{ vuln.remediation_details.fix_time }}</span>
                        </div>
                        
                        {% if vuln.remediation_details.exploit_example %}
                        <div class="exploit-section" style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 15px 0;">
                            <p><strong>⚠️ {{ labels.exploit_example }}:</strong></p>
                            <div class="code" style="background: #2d2d2d; color: #f8f8f2;">{{ vuln.remediation_details.exploit_example }}</div>
                        </div>
                        {% endif %}
                        
                        {% if vuln.remediation_details.solution %}
                        <div class="solution-section" style="background: #d4edda; border: 1px solid #28a745; border-radius: 8px; padding: 15px; margin: 15px 0;">
                            <p><strong>✅ {{ labels.solution }}:</strong></p>
                            <div class="code" style="background: #1e1e1e; color: #d4d4d4;">{{ vuln.remediation_details.solution }}</div>
                        </div>
                        {% endif %}
                        
                        <div class="remediation-steps">
                            <p><strong>{{ labels.steps_to_fix }}:</strong></p>
                            <ol>
                            {% for step in vuln.remediation_details.steps %}
                                <li>{{ step }}</li>
                            {% endfor %}
                            </ol>
                        </div>
                        
                        {% if vuln.remediation_details.code_example %}
                        <div>
                            <p><strong>{{ labels.code_example }}:</strong></p>
                            <div class="code">{{ vuln.remediation_details.code_example }}</div>
                        </div>
                        {% endif %}
                        
                        {% if vuln.remediation_details.references %}
                        <div class="references">
                            <strong>📚 {{ labels.references }}:</strong>
                            <ul>
                            {% for ref in vuln.remediation_details.references %}
                                <li>{{ ref }}</li>
                            {% endfor %}
                            </ul>
                        </div>
                        {% endif %}
                    </div>
                    {% else %}
                    <p><strong>{{ labels.remediation }}:</strong> {{ vuln.remediation }}</p>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p>{{ labels.no_vulnerabilities }}</p>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>This report was generated by Deep Eye - Advanced AI-Driven Penetration Testing Tool</p>
            <p>Powered by <img src="{{ cerist_logo }}" alt="CERIST" style="height: 30px; vertical-align: middle; margin: 0 5px; background: transparent;"> CERIST</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
    
    <script>
        // Dark Mode Toggle with Local Storage
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? '' : 'dark';
            
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            // Update button text
            const btn = document.querySelector('.theme-toggle');
            btn.textContent = newTheme === 'dark' ? '☀️ Toggle Light Mode' : '🌙 Toggle Dark Mode';
        }
        
        // Load saved theme on page load
        document.addEventListener('DOMContentLoaded', function() {
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
                document.querySelector('.theme-toggle').textContent = '☀️ Toggle Light Mode';
            }
            
            // Calculate Risk Score
            const critical = {{ severity_counts.critical|default(0) }};
            const high = {{ severity_counts.high|default(0) }};
            const medium = {{ severity_counts.medium|default(0) }};
            const low = {{ severity_counts.low|default(0) }};
            
            // Risk score formula: weighted sum normalized to 0-100
            const riskScore = Math.min(100, Math.round(
                (critical * 10) + (high * 6) + (medium * 3) + (low * 1)
            ));
            
            const riskElement = document.getElementById('riskScore');
            if (riskElement) {
                riskElement.textContent = riskScore;
                
                // Color code the risk score
                if (riskScore >= 70) {
                    riskElement.style.background = 'linear-gradient(135deg, #8B0000 0%, #a30000 100%)';
                } else if (riskScore >= 40) {
                    riskElement.style.background = 'linear-gradient(135deg, #FF4500 0%, #ff5722 100%)';
                } else if (riskScore >= 20) {
                    riskElement.style.background = 'linear-gradient(135deg, #FFA500 0%, #ffb733 100%)';
                } else {
                    riskElement.style.background = 'linear-gradient(135deg, #4caf50 0%, #66bb6a 100%)';
                }
            }
            
            // Render Charts if Chart.js is available
            if (typeof Chart !== 'undefined') {
                // Severity Distribution Doughnut Chart
                const severityCtx = document.getElementById('severityChart');
                if (severityCtx) {
                    new Chart(severityCtx, {
                        type: 'doughnut',
                        data: {
                            labels: ['Critical', 'High', 'Medium', 'Low'],
                            datasets: [{
                                data: [critical, high, medium, low],
                                backgroundColor: [
                                    '#8B0000',
                                    '#FF4500',
                                    '#FFA500',
                                    '#FFD700'
                                ],
                                borderWidth: 2,
                                borderColor: '#ffffff'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                    labels: {
                                        color: getComputedStyle(document.documentElement)
                                            .getPropertyValue('--text-primary'),
                                        padding: 15,
                                        font: {
                                            size: 12
                                        }
                                    }
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            const label = context.label || '';
                                            const value = context.parsed || 0;
                                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                            return label + ': ' + value + ' (' + percentage + '%)';
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                
                // Risk Breakdown Bar Chart
                const riskCtx = document.getElementById('riskChart');
                if (riskCtx) {
                    new Chart(riskCtx, {
                        type: 'bar',
                        data: {
                            labels: ['Critical', 'High', 'Medium', 'Low'],
                            datasets: [{
                                label: 'Vulnerabilities Count',
                                data: [critical, high, medium, low],
                                backgroundColor: [
                                    '#8B0000',
                                    '#FF4500',
                                    '#FFA500',
                                    '#FFD700'
                                ],
                                borderWidth: 0
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: true,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: {
                                        stepSize: 1,
                                        color: getComputedStyle(document.documentElement)
                                            .getPropertyValue('--text-primary')
                                    },
                                    grid: {
                                        color: getComputedStyle(document.documentElement)
                                            .getPropertyValue('--border-color')
                                    }
                                },
                                x: {
                                    ticks: {
                                        color: getComputedStyle(document.documentElement)
                                            .getPropertyValue('--text-primary')
                                    },
                                    grid: {
                                        display: false
                                    }
                                }
                            },
                            plugins: {
                                legend: {
                                    display: false
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            return 'Count: ' + context.parsed.y;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });
    </script>
</body>
</html>
'''
