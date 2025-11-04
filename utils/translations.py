"""
Multi-language Translation Support
Provides translations for Deep Eye reports in English, French, and Arabic
"""

TRANSLATIONS = {
    'en': {
        'report_title': 'Deep Eye Security Assessment Report',
        'executive_summary': 'Executive Summary',
        'vulnerabilities': 'Vulnerabilities',
        'severity': 'Severity',
        'target': 'Target',
        'generated_date': 'Generated',
        'scan_duration': 'Scan Duration',
        'urls_scanned': 'URLs Scanned',
        'reconnaissance': 'Reconnaissance & OSINT Intelligence',
        'dns_records': 'DNS Records',
        'osint_findings': 'OSINT Findings',
        'emails_found': 'Emails found',
        'subdomains_discovered': 'Subdomains discovered',
        'technologies_detected': 'Technologies detected',
        'severity_summary': 'Severity Summary',
        'count': 'Count',
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Info',
        'url': 'URL',
        'parameter': 'Parameter',
        'description': 'Description',
        'evidence': 'Evidence',
        'cwe': 'CWE',
        'discovered': 'Discovered',
        'remediation_guidance': 'Remediation Guidance',
        'priority': 'Priority',
        'estimated_fix_time': 'Estimated Fix Time',
        'steps_to_fix': 'Steps to Fix',
        'code_example': 'Code Example (Vulnerable vs Secure)',
        'exploit_example': 'Attack Scenario & Exploit Example',
        'solution': 'Solution',
        'vulnerable': 'Vulnerable',
        'secure': 'Secure',
        'references': 'References & Resources',
        'remediation': 'Remediation',
        'no_vulnerabilities': 'No vulnerabilities detected.',
        'risk_distribution': 'Risk Distribution',
        'issues': 'issues',
        'summary_text': 'This security assessment identified {total} potential security issues on the target system.\n\nCritical vulnerabilities require immediate attention as they pose significant risk to the organization.\nHigh and medium severity issues should be addressed in order of priority.',
        'payload_used': 'Payload Used',
        'how_to_fix': 'How to Fix This Vulnerability',
    },
    'fr': {
        'report_title': 'Rapport d\'Évaluation de Sécurité Deep Eye',
        'executive_summary': 'Résumé Exécutif',
        'vulnerabilities': 'Vulnérabilités',
        'severity': 'Gravité',
        'target': 'Cible',
        'generated_date': 'Généré le',
        'scan_duration': 'Durée du Scan',
        'urls_scanned': 'URLs Scannées',
        'reconnaissance': 'Reconnaissance & Renseignement OSINT',
        'dns_records': 'Enregistrements DNS',
        'osint_findings': 'Découvertes OSINT',
        'emails_found': 'Emails trouvés',
        'subdomains_discovered': 'Sous-domaines découverts',
        'technologies_detected': 'Technologies détectées',
        'severity_summary': 'Résumé de Gravité',
        'count': 'Nombre',
        'critical': 'Critique',
        'high': 'Élevé',
        'medium': 'Moyen',
        'low': 'Faible',
        'info': 'Info',
        'url': 'URL',
        'parameter': 'Paramètre',
        'description': 'Description',
        'evidence': 'Preuve',
        'cwe': 'CWE',
        'discovered': 'Découvert',
        'remediation_guidance': 'Guide de Remédiation',
        'priority': 'Priorité',
        'estimated_fix_time': 'Temps de Correction Estimé',
        'steps_to_fix': 'Étapes de Correction',
        'code_example': 'Exemple de Code (Vulnérable vs Sécurisé)',
        'exploit_example': 'Scénario d\'Attaque & Exemple d\'Exploitation',
        'solution': 'Solution',
        'vulnerable': 'Vulnérable',
        'secure': 'Sécurisé',
        'references': 'Références & Ressources',
        'remediation': 'Remédiation',
        'no_vulnerabilities': 'Aucune vulnérabilité détectée.',
        'risk_distribution': 'Distribution des Risques',
        'issues': 'problèmes',
        'summary_text': 'Cette évaluation de sécurité a identifié {total} problèmes de sécurité potentiels sur le système cible.\n\nLes vulnérabilités critiques nécessitent une attention immédiate car elles présentent un risque important pour l\'organisation.\nLes problèmes de gravité élevée et moyenne doivent être traités par ordre de priorité.',
        'payload_used': 'Charge Utile Utilisée',
        'how_to_fix': 'Comment Corriger Cette Vulnérabilité',
    },
    'ar': {
        'report_title': 'تقرير تقييم الأمان Deep Eye',
        'executive_summary': 'ملخص تنفيذي',
        'vulnerabilities': 'الثغرات الأمنية',
        'severity': 'الخطورة',
        'target': 'الهدف',
        'generated_date': 'تاريخ الإنشاء',
        'scan_duration': 'مدة الفحص',
        'urls_scanned': 'عدد الروابط الممسوحة',
        'reconnaissance': 'الاستطلاع ومعلومات OSINT',
        'dns_records': 'سجلات DNS',
        'osint_findings': 'اكتشافات OSINT',
        'emails_found': 'البريد الإلكتروني الموجود',
        'subdomains_discovered': 'النطاقات الفرعية المكتشفة',
        'technologies_detected': 'التقنيات المكتشفة',
        'severity_summary': 'ملخص الخطورة',
        'count': 'العدد',
        'critical': 'حرج',
        'high': 'عالي',
        'medium': 'متوسط',
        'low': 'منخفض',
        'info': 'معلومات',
        'url': 'الرابط',
        'parameter': 'المعامل',
        'description': 'الوصف',
        'evidence': 'الدليل',
        'cwe': 'CWE',
        'discovered': 'تم الاكتشاف',
        'remediation_guidance': 'دليل المعالجة',
        'priority': 'الأولوية',
        'estimated_fix_time': 'الوقت المقدر للإصلاح',
        'steps_to_fix': 'خطوات الإصلاح',
        'code_example': 'مثال على الكود (الضعيف مقابل الآمن)',
        'exploit_example': 'سيناريو الهجوم ومثال الاستغلال',
        'solution': 'الحل',
        'vulnerable': 'ضعيف',
        'secure': 'آمن',
        'references': 'المراجع والموارد',
        'remediation': 'المعالجة',
        'no_vulnerabilities': 'لم يتم اكتشاف أي ثغرات أمنية.',
        'risk_distribution': 'توزيع المخاطر',
        'issues': 'مشاكل',
        'summary_text': 'حدد هذا التقييم الأمني {total} مشكلة أمنية محتملة في النظام المستهدف.\n\nتتطلب الثغرات الحرجة اهتماماً فورياً حيث تشكل خطراً كبيراً على المنظمة.\nيجب معالجة المشاكل ذات الخطورة العالية والمتوسطة حسب الأولوية.',
        'payload_used': 'الحمولة المستخدمة',
        'how_to_fix': 'كيفية إصلاح هذه الثغرة',
    }
}


class Translator:
    """Translation handler for multi-language support."""
    
    def __init__(self, language: str = 'en'):
        """
        Initialize translator.
        
        Args:
            language: Language code (en, fr, ar)
        """
        self.language = language if language in TRANSLATIONS else 'en'
    
    def get(self, key: str, default: str = '') -> str:
        """
        Get translation for a key.
        
        Args:
            key: Translation key
            default: Default value if key not found
            
        Returns:
            Translated string
        """
        return TRANSLATIONS[self.language].get(key, default if default else key)
    
    def format(self, key: str, **kwargs) -> str:
        """
        Get formatted translation.
        
        Args:
            key: Translation key
            **kwargs: Format arguments
            
        Returns:
            Formatted translated string
        """
        template = self.get(key)
        return template.format(**kwargs)
    
    @staticmethod
    def get_available_languages() -> dict:
        """
        Get list of available languages.
        
        Returns:
            Dictionary of language codes and names
        """
        return {
            'en': 'English',
            'fr': 'Français',
            'ar': 'العربية'
        }
