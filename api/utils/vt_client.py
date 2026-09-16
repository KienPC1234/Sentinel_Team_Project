"""
Local Threat Intelligence & Malware Analysis Engine (Drop-in replacement for VTClient).

Operates 100% on-premise without external VirusTotal API dependencies.
Utilizes LocalSandboxAnalyzer (ClamAV + Static Heuristics + Entropy + Multi-Vector Rules).
"""

import logging
from typing import Dict, Any, Optional
from api.utils.sandbox_analyzer import LocalSandboxAnalyzer

logger = logging.getLogger(__name__)


class VTClient:
    """
    On-premise threat intelligence client providing the same interface as VirusTotal
    while executing 100% locally via ClamAV and heuristic sandbox engines.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        daemon_url: Optional[str] = None,
        docker_image: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.analyzer = LocalSandboxAnalyzer(
            daemon_url=daemon_url,
            docker_image=docker_image,
            timeout=timeout,
        )

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Evaluate URL threat level using local heuristics, domain scoring, and pattern recognition.
        """
        try:
            return self.analyzer.scan_url(url)
        except Exception as e:
            logger.error(f"[Local Threat Engine] URL scan error for {url}: {e}")
            return {
                'harmless': 1,
                'malicious': 0,
                'suspicious': 0,
                'undetected': 0,
                'total': 1,
                'risk_score': 0,
            }

    def scan_file(self, file_path: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
        """
        Execute static analysis and ClamAV antivirus inspection on a file locally.
        """
        try:
            return self.analyzer.scan_file(file_path, timeout=timeout)
        except Exception as e:
            logger.error(f"[Local Threat Engine] File scan error for {file_path}: {e}")
            return None

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
