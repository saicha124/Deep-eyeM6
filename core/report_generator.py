"""
Report Generator
Creates professional security assessment reports with multi-language support
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Template
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
        template = Template(template_content)
        
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
        """Get HTML report template."""
        return '''
<!DOCTYPE html>
<html lang="{{ language }}" dir="{% if language == 'ar' %}rtl{% else %}ltr{% endif %}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: {% if language == 'ar' %}'Arial', 'Tahoma', sans-serif{% else %}'Segoe UI', Tahoma, Geneva, Verdana, sans-serif{% endif %};
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            direction: {% if language == 'ar' %}rtl{% else %}ltr{% endif %};
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metadata-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .metadata-card h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .severity-card {
            padding: 20px;
            border-radius: 8px;
            color: white;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .severity-critical { background-color: #8B0000; }
        .severity-high { background-color: #FF4500; }
        .severity-medium { background-color: #FFA500; }
        .severity-low { background-color: #FFD700; color: #333; }
        .severity-info { background-color: #87CEEB; color: #333; }
        
        .severity-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .vulnerability {
            border-left: 4px solid #ddd;
            padding: 20px;
            margin-bottom: 20px;
            background: #f9f9f9;
            border-radius: 4px;
        }
        
        .vulnerability.critical { border-left-color: #8B0000; }
        .vulnerability.high { border-left-color: #FF4500; }
        .vulnerability.medium { border-left-color: #FFA500; }
        .vulnerability.low { border-left-color: #FFD700; }
        
        .vulnerability h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .vulnerability-meta {
            display: flex;
            gap: 20px;
            margin: 10px 0;
            flex-wrap: wrap;
        }
        
        .vulnerability-meta span {
            background: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        
        .code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            white-space: pre-wrap;
        }
        
        .remediation-section {
            background: #f0f8ff;
            border: 1px solid #4a90e2;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }
        
        .remediation-section h4 {
            color: #4a90e2;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        
        .remediation-steps {
            margin: 15px 0;
        }
        
        .remediation-steps ol {
            margin-left: 20px;
            line-height: 1.8;
        }
        
        .remediation-steps li {
            margin: 8px 0;
        }
        
        .priority-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
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
            margin-top: 15px;
            padding: 10px;
            background: #f9f9f9;
            border-left: 3px solid #4a90e2;
        }
        
        .references ul {
            margin-left: 20px;
            margin-top: 5px;
        }
        
        .timestamp {
            color: #666;
            font-size: 0.85em;
            font-style: italic;
        }
        
        .recon-subsection {
            margin: 20px 0;
            padding: 20px;
            background: #f9f9f9;
            border-left: 4px solid #667eea;
            border-radius: 5px;
        }
        
        .recon-subsection h3 {
            color: #667eea;
            margin-bottom: 15px;
        }
        
        .recon-data {
            margin-top: 10px;
        }
        
        .recon-data p {
            margin: 8px 0;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 30px;
        }
        
        .logo {
            max-width: 150px;
            height: auto;
            margin: 10px 0;
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
        }
        
        .header-text {
            flex: 1;
        }
        
        .header-logo {
            padding: 10px;
        }
    </style>
</head>
<body>
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
            <p>Powered by <img src="{{ cerist_logo }}" alt="CERIST" style="height: 30px; vertical-align: middle; margin: 0 5px;"> CERIST</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
'''
