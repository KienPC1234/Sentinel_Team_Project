import vt
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

VT_API_KEY = getattr(settings, 'VT_API_KEY', '')

class VTClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or VT_API_KEY
        self.client = vt.Client(self.api_key)

    def scan_url(self, url):
        """Scan a URL and return summary of results"""
        try:
            # First, check if already analyzed
            url_id = vt.url_id(url)
            try:
                analysis = self.client.get_object("/urls/{}", url_id)
                stats = analysis.last_analysis_stats
            except vt.APIError:
                # If not found, submit for analysis
                analysis = self.client.scan_url(url, wait_for_completion=True)
                stats = analysis.stats
            
            return {
                'harmless': stats.get('harmless', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total': sum(stats.values())
            }
        except Exception as e:
            logger.error(f"VirusTotal URL Scan Error: {e}")
            return None

    def scan_file(self, file_path):
        """Scan a file and return summary of results"""
        try:
            with open(file_path, "rb") as f:
                analysis = self.client.scan_file(f, wait_for_completion=True)
                stats = analysis.stats
            
            return {
                'harmless': stats.get('harmless', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total': sum(stats.values())
            }
        except Exception as e:
            logger.error(f"VirusTotal File Scan Error: {e}")
            return None

    def close(self):
        self.client.close()

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
