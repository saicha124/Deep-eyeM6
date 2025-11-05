#!/usr/bin/env python3
"""
Regression Tests for Security Features
Tests for sensitive header redaction and body truncation in enhanced vulnerability reporting
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import unittest
from unittest.mock import Mock, MagicMock
from utils.http_client import HTTPClient
import time


class TestHTTPInteractionCapture(unittest.TestCase):
    """Test HTTP interaction capture security features."""
    
    def test_sensitive_header_redaction(self):
        """Test that sensitive headers are redacted in captured interactions."""
        # Create mock response
        mock_response = Mock()
        mock_response.request = Mock()
        mock_response.request.method = 'GET'
        mock_response.request.url = 'https://example.com/api'
        mock_response.request.headers = {
            'User-Agent': 'Deep-Eye/1.3.0',
            'Accept': '*/*',
            'Authorization': 'Bearer secret-token-123',
            'Cookie': 'session=abc123; user=admin',
            'X-API-Key': 'super-secret-key',
            'API-Key': 'another-secret',
            'Content-Type': 'application/json'
        }
        mock_response.request.body = None
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok"}'
        
        # Capture interaction
        interaction = HTTPClient.capture_interaction(mock_response)
        
        # Verify sensitive headers are redacted
        self.assertEqual(interaction['headers']['Authorization'], '[REDACTED]',
                        "Authorization header should be redacted")
        self.assertEqual(interaction['headers']['Cookie'], '[REDACTED]',
                        "Cookie header should be redacted")
        self.assertEqual(interaction['headers']['X-API-Key'], '[REDACTED]',
                        "X-API-Key header should be redacted")
        self.assertEqual(interaction['headers']['API-Key'], '[REDACTED]',
                        "API-Key header should be redacted")
        
        # Verify non-sensitive headers are preserved
        self.assertEqual(interaction['headers']['User-Agent'], 'Deep-Eye/1.3.0',
                        "User-Agent should not be redacted")
        self.assertEqual(interaction['headers']['Content-Type'], 'application/json',
                        "Content-Type should not be redacted")
    
    def test_request_body_truncation(self):
        """Test that large request bodies are truncated at 5KB."""
        # Create large payload
        large_payload = 'A' * 6000  # 6KB payload
        
        # Create mock response
        mock_response = Mock()
        mock_response.request = Mock()
        mock_response.request.method = 'POST'
        mock_response.request.url = 'https://example.com/api'
        mock_response.request.headers = {'Content-Type': 'application/json'}
        mock_response.request.body = large_payload.encode('utf-8')
        mock_response.status_code = 200
        mock_response.text = 'OK'
        
        # Capture interaction
        interaction = HTTPClient.capture_interaction(mock_response)
        
        # Verify body is truncated
        self.assertIn('[truncated]', interaction['request_body'],
                     "Large request body should be truncated")
        self.assertLessEqual(len(interaction['request_body']), 5100,  # 5000 + truncation message
                            "Truncated body should be <= 5KB")
    
    def test_response_body_truncation(self):
        """Test that large response bodies are truncated at 5KB."""
        # Create large response
        large_response = 'B' * 6000  # 6KB response
        
        # Create mock response
        mock_response = Mock()
        mock_response.request = Mock()
        mock_response.request.method = 'GET'
        mock_response.request.url = 'https://example.com/api'
        mock_response.request.headers = {}
        mock_response.request.body = None
        mock_response.status_code = 200
        mock_response.text = large_response
        
        # Capture interaction
        interaction = HTTPClient.capture_interaction(mock_response)
        
        # Verify response body is truncated
        self.assertIn('[truncated]', interaction['response_body'],
                     "Large response body should be truncated")
        self.assertLessEqual(len(interaction['response_body']), 5100,  # 5000 + truncation message
                            "Truncated response should be <= 5KB")
    
    def test_latency_calculation(self):
        """Test that latency is correctly calculated."""
        start_time = time.time()
        time.sleep(0.1)  # Simulate 100ms delay
        
        # Create mock response
        mock_response = Mock()
        mock_response.request = Mock()
        mock_response.request.method = 'GET'
        mock_response.request.url = 'https://example.com/api'
        mock_response.request.headers = {}
        mock_response.request.body = None
        mock_response.status_code = 200
        mock_response.text = 'OK'
        
        # Capture interaction
        interaction = HTTPClient.capture_interaction(mock_response, start_time=start_time)
        
        # Verify latency is present and reasonable
        self.assertIsNotNone(interaction['latency'])
        self.assertGreaterEqual(interaction['latency'], 0.1,  # At least 100ms
                               "Latency should be >= 100ms")
        self.assertLess(interaction['latency'], 1.0,  # Less than 1 second
                       "Latency should be < 1s for this test")
    
    def test_none_response_handling(self):
        """Test that None response is handled gracefully."""
        interaction = HTTPClient.capture_interaction(None)
        self.assertIsNone(interaction, "None response should return None interaction")
    
    def test_binary_data_handling(self):
        """Test that binary data is handled correctly."""
        # Create mock response with binary body
        mock_response = Mock()
        mock_response.request = Mock()
        mock_response.request.method = 'POST'
        mock_response.request.url = 'https://example.com/upload'
        mock_response.request.headers = {'Content-Type': 'application/octet-stream'}
        mock_response.request.body = b'\x00\x01\x02\x03'  # Binary data
        mock_response.status_code = 200
        mock_response.text = 'File uploaded'
        
        # Capture interaction
        interaction = HTTPClient.capture_interaction(mock_response)
        
        # Verify binary data is handled
        # The implementation should either decode it or replace with placeholder
        self.assertIsNotNone(interaction['request_body'])
        self.assertIsInstance(interaction['request_body'], str,
                            "Request body should be converted to string")
    
    def test_all_fields_present(self):
        """Test that all expected fields are present in captured interaction."""
        # Create mock response
        mock_response = Mock()
        mock_response.request = Mock()
        mock_response.request.method = 'POST'
        mock_response.request.url = 'https://example.com/api'
        mock_response.request.headers = {'Content-Type': 'application/json'}
        mock_response.request.body = b'{"key": "value"}'
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok"}'
        
        start_time = time.time()
        interaction = HTTPClient.capture_interaction(mock_response, start_time=start_time)
        
        # Verify all required fields are present
        required_fields = ['method', 'url', 'headers', 'request_body', 
                          'status_code', 'response_body', 'latency']
        for field in required_fields:
            self.assertIn(field, interaction,
                         f"Field '{field}' should be present in interaction")


class TestVulnerabilityHelper(unittest.TestCase):
    """Test vulnerability creation helper functions."""
    
    def test_create_vulnerability_with_enhanced_fields(self):
        """Test that create_vulnerability accepts and stores enhanced fields."""
        from core.vulnerability_helper import create_vulnerability
        
        vuln = create_vulnerability(
            vuln_type='Test Vulnerability',
            severity='high',
            url='https://example.com',
            description='Test description',
            evidence='Test evidence',
            remediation='Test remediation',
            payload_info={
                'payload': 'test',
                'origin': {'file': 'test.py', 'line': 123},
                'parameter': 'test_param',
                'context': 'test context'
            },
            interaction={
                'method': 'GET',
                'url': 'https://example.com',
                'status_code': 200
            },
            detector={
                'module': 'test.module',
                'file': 'test.py'
            }
        )
        
        # Verify enhanced fields are stored
        self.assertIn('payload_info', vuln)
        self.assertIn('interaction', vuln)
        self.assertIn('detector', vuln)
        self.assertEqual(vuln['payload_info']['payload'], 'test')
        self.assertEqual(vuln['interaction']['method'], 'GET')
        self.assertEqual(vuln['detector']['module'], 'test.module')
    
    def test_timestamp_auto_added(self):
        """Test that timestamp is automatically added to vulnerabilities."""
        from core.vulnerability_helper import create_vulnerability
        
        vuln = create_vulnerability(
            vuln_type='Test',
            severity='low',
            url='https://example.com',
            description='Test',
            evidence='Test',
            remediation='Test'
        )
        
        self.assertIn('timestamp', vuln)
        self.assertIsNotNone(vuln['timestamp'])
        # Verify format (YYYY-MM-DD HH:MM:SS)
        self.assertRegex(vuln['timestamp'], r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')


def run_tests():
    """Run all security feature tests."""
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromModule(__import__(__name__))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    exit(run_tests())
