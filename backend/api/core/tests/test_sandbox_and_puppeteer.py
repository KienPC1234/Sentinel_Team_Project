import os
import socket
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

from django.conf import settings
from django.test import TestCase

from api.utils.puppeteer_host_client import fetch_with_puppeteer_host
from api.utils.sandbox_analyzer import LocalSandboxAnalyzer
from api.utils.vt_client import VTClient


def _tcp_reachable(url: str, default_port: int, timeout: float = 1.5) -> bool:
    """Return True when a TCP connection to the URL's host:port succeeds.

    Used to skip infrastructure-dependent integration tests (Docker sandbox
    daemon, Node Puppeteer host) on runners where those services are not
    provisioned, e.g. the plain Django CI job.
    """
    if not url:
        return False
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or default_port
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


SANDBOX_DAEMON_URL = getattr(settings, 'SANDBOX_DAEMON_URL', '') or ''
PUPPETEER_HOST_URL = getattr(settings, 'PUPPETEER_HOST_URL', '') or ''

SANDBOX_DAEMON_UP = _tcp_reachable(SANDBOX_DAEMON_URL, 5005)
PUPPETEER_HOST_UP = _tcp_reachable(PUPPETEER_HOST_URL, 3010)


class DockerSandboxAndPuppeteerTests(TestCase):
    """
    Automated test suite verifying Docker Zero-Trust Sandbox file analyzer
    and Puppeteer host rendering client.

    Tests that require the Docker sandbox daemon or the Node Puppeteer host
    are skipped when that infrastructure is not provisioned (e.g. the plain
    Django CI job); the dedicated ``docker-sandbox`` workflow runs them.
    """

    def setUp(self):
        self.analyzer = LocalSandboxAnalyzer()
        self.vt_client = VTClient()

    @unittest.skipUnless(SANDBOX_DAEMON_UP, 'Docker sandbox daemon not reachable')
    def test_sandbox_scan_clean_file(self):
        """Test scanning a benign file produces a SAFE verdict and low risk score."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'This is a completely harmless test text file.\nAll checks should pass.\n')
            temp_path = f.name

        try:
            result = self.analyzer.scan_file(temp_path)
            self.assertIsNotNone(result)
            self.assertEqual(result.get('verdict'), 'SAFE')
            self.assertLessEqual(result.get('risk_score', 100), 20)
            self.assertFalse(result.get('clamav', {}).get('infected', True))

            docker_info = result.get('docker_sandbox', {})
            if docker_info:
                self.assertTrue(docker_info.get('executed_in_container'))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    @unittest.skipUnless(SANDBOX_DAEMON_UP, 'Docker sandbox daemon not reachable')
    def test_sandbox_scan_eicar_malware(self):
        """Test scanning an EICAR test string triggers MALICIOUS detection via ClamAV."""
        eicar_bytes = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        with tempfile.NamedTemporaryFile(suffix='.com', delete=False) as f:
            f.write(eicar_bytes)
            temp_path = f.name

        try:
            result = self.analyzer.scan_file(temp_path)
            self.assertIsNotNone(result)
            self.assertEqual(result.get('verdict'), 'MALICIOUS')
            self.assertGreaterEqual(result.get('risk_score', 0), 80)
            self.assertTrue(result.get('clamav', {}).get('infected'))
            self.assertIn('Eicar', str(result.get('threat_family', '')))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    @unittest.skipUnless(SANDBOX_DAEMON_UP, 'Docker sandbox stack not provisioned')
    def test_sandbox_cli_fallback_when_daemon_unreachable(self):
        """Test ephemeral container CLI mode executes properly when the daemon microservice is down."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'Clean file content to test Docker CLI fallback mode.')
            temp_path = f.name

        try:
            with patch('requests.post', side_effect=Exception('Daemon unavailable')):
                result = self.analyzer.scan_file(temp_path)

            self.assertIsNotNone(result)
            self.assertEqual(result.get('verdict'), 'SAFE')
            docker_info = result.get('docker_sandbox', {})
            if self.analyzer.has_docker:
                self.assertTrue(docker_info.get('executed_in_container'))
                self.assertIn('Docker Ephemeral CLI Fallback', docker_info.get('mode', ''))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_sandbox_custom_configuration_injection(self):
        """Test LocalSandboxAnalyzer constructor overrides take precedence over defaults."""
        custom_analyzer = LocalSandboxAnalyzer(
            daemon_url='http://custom-host:9999',
            docker_image='custom-sandbox:tag',
            docker_memory='2g',
            docker_pids_limit=128,
            docker_bin='/usr/local/bin/docker-custom',
            timeout=60,
            daemon_timeout=15,
        )
        self.assertEqual(custom_analyzer.daemon_url, 'http://custom-host:9999')
        self.assertEqual(custom_analyzer.docker_image, 'custom-sandbox:tag')
        self.assertEqual(custom_analyzer.docker_memory, '2g')
        self.assertEqual(custom_analyzer.docker_pids_limit, 128)
        self.assertEqual(custom_analyzer.docker_bin, '/usr/local/bin/docker-custom')
        self.assertEqual(custom_analyzer.default_timeout, 60)
        self.assertEqual(custom_analyzer.default_daemon_timeout, 15)

    def test_sandbox_dynamic_daemon_url_dispatch(self):
        """Test scan_file posts to the dynamically configured daemon URL endpoint."""
        custom_analyzer = LocalSandboxAnalyzer(daemon_url='http://cluster-sandbox:7000')
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'Payload to test dispatch URL.')
            temp_path = f.name

        try:
            with patch('requests.post') as mock_post:
                mock_post.return_value.status_code = 200
                mock_post.return_value.json.return_value = {
                    'verdict': 'SAFE',
                    'risk_score': 5,
                    'is_malicious': False,
                    'is_suspicious': False,
                }
                res = custom_analyzer.scan_file(temp_path)
                mock_post.assert_called_once()
                called_url = mock_post.call_args[0][0]
                self.assertEqual(called_url, 'http://cluster-sandbox:7000/scan')
                self.assertEqual(res.get('verdict'), 'SAFE')
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


    def test_vt_client_wrapper_compatibility(self):
        """Test VTClient wrapper delegates properly to LocalSandboxAnalyzer."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'VTClient compatibility wrapper test.')
            temp_path = f.name

        try:
            res = self.vt_client.scan_file(temp_path)
            self.assertIsNotNone(res)
            self.assertIn('verdict', res)
            self.assertIn('risk_score', res)
            self.assertIn('engines', res)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    @unittest.skipUnless(PUPPETEER_HOST_UP, 'Node Puppeteer host not reachable')
    def test_puppeteer_live_render(self):
        """Test Puppeteer host renders an external safe URL and extracts title & body."""
        res = fetch_with_puppeteer_host('https://example.com', timeout_ms=15000)
        self.assertTrue(res.get('ok'))
        self.assertEqual(res.get('status_code'), 200)
        self.assertIn('Example Domain', res.get('title', ''))
        self.assertGreater(len(res.get('content', '')), 10)

    def test_puppeteer_ssrf_block(self):
        """Test Puppeteer host SSRF defense rejects loopback address with 400 Bad Request."""
        res = fetch_with_puppeteer_host('http://127.0.0.1:8000', timeout_ms=5000)
        self.assertFalse(res.get('ok'))
        self.assertEqual(res.get('status_code'), 400)
        self.assertEqual(res.get('error'), 'Invalid or blocked internal URL')

    def test_puppeteer_connection_failure_handling(self):
        """Test fetch_with_puppeteer_host fails gracefully when the host is unreachable."""
        with patch('requests.post', side_effect=Exception('Connection refused')):
            res = fetch_with_puppeteer_host('https://example.com')
            self.assertFalse(res.get('ok'))
            self.assertIsNone(res.get('status_code'))
            self.assertIn('Puppeteer host connection failed', res.get('error', ''))

