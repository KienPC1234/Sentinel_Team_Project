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

    def scan_file(self, file_path, timeout=300):
        """Scan a file and return summary of results.
        
        Args:
            file_path: Path to the file to scan
            timeout: Max seconds to wait for VT analysis (default 5 min)
        """
        import time
        client = None
        try:
            # Use a dedicated client with timeout to avoid connection leaks
            client = vt.Client(self.api_key)
            
            logger.info(f"[VT FileScan] Uploading file: {file_path}")
            with open(file_path, "rb") as f:
                analysis = client.scan_file(f)
            
            logger.info(f"[VT FileScan] File uploaded. Analysis ID: {analysis.id}. Waiting for completion (timeout={timeout}s)...")
            
            # Poll for completion with timeout instead of blocking indefinitely
            start_time = time.time()
            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.warning(f"[VT FileScan] Timeout after {timeout}s for analysis {analysis.id}")
                    # Try to get partial results
                    try:
                        analysis = client.get_object("/analyses/{}", analysis.id)
                    except Exception:
                        pass
                    break
                
                try:
                    analysis = client.get_object("/analyses/{}", analysis.id)
                    if analysis.status == "completed":
                        logger.info(f"[VT FileScan] Analysis completed after {elapsed:.1f}s")
                        break
                except Exception as poll_err:
                    logger.warning(f"[VT FileScan] Poll error: {poll_err}")
                
                # Log progress every 30s
                if int(elapsed) % 30 == 0 and elapsed > 5:
                    logger.info(f"[VT FileScan] Still waiting... ({elapsed:.0f}s elapsed)")
                
                time.sleep(10)
            
            stats = analysis.stats if hasattr(analysis, 'stats') else {}
            if not stats:
                logger.warning(f"[VT FileScan] No stats in analysis result. Status: {getattr(analysis, 'status', 'unknown')}")
                return None
            
            result = {
                'harmless': stats.get('harmless', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total': sum(stats.values())
            }
            logger.info(f"[VT FileScan] Results: {result}")
            return result
        except Exception as e:
            logger.error(f"[VT FileScan] Error: {e}", exc_info=True)
            return None
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

    def close(self):
        self.client.close()

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
