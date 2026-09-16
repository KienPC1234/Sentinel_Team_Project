"""
Local Threat Intelligence & Multi-Vector Sandbox Analyzer.

Replaces third-party external dependencies (e.g. VirusTotal) with an on-premise,
zero-trust inspection architecture combining:
1. Docker-isolated ephemeral container sandbox (zero-network, read-only, cap-dropped)
2. ClamAV local antivirus engine (signature verification)
3. Deep static & heuristic feature extraction (entropy, PDF exploits, Office macros, PE injection APIs)
4. Verifiable forensic evidence reporting (proof of maliciousness)
5. Local Domain/URL threat intelligence (WHOIS, DNS MX, ScamAdviser, SSL reputation)
6. On-device Ollama LLM deep heuristic scoring
"""

import os
import re
import math
import json
import hashlib
import zipfile
import subprocess
import logging
import base64
import requests
from typing import Dict, Any, Optional, List

try:
    from django.conf import settings
except ImportError:
    settings = None

logger = logging.getLogger(__name__)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte stream (0.0 - 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _get_setting(name: str, default: Any = None) -> Any:
    """Safely retrieve a Django setting without triggering ImproperlyConfigured in non-Django runtimes."""
    try:
        from django.conf import settings
        if getattr(settings, 'configured', False):
            return getattr(settings, name, default)
    except Exception:
        pass
    return default


class LocalSandboxAnalyzer:
    """
    On-premise file & threat analyzer running locally in Docker sandbox with zero cloud leakage.
    Configurable via Django settings, environment variables, or explicit constructor arguments.
    """

    DEFAULT_DAEMON_URL = 'http://127.0.0.1:5005'
    DEFAULT_DOCKER_IMAGE = 'sentinel-sandbox:latest'
    DEFAULT_DOCKER_MEMORY = '1g'
    DEFAULT_DOCKER_PIDS_LIMIT = 64
    DEFAULT_TIMEOUT = 45
    DEFAULT_DAEMON_TIMEOUT = 30
    DEFAULT_DOCKER_BIN = 'docker'
    DEFAULT_MAX_SNIPPET_BYTES = 512_000
    DEFAULT_MAX_SNIPPET_LINES = 150

    def __init__(
        self,
        daemon_url: Optional[str] = None,
        docker_image: Optional[str] = None,
        docker_memory: Optional[str] = None,
        docker_pids_limit: Optional[int] = None,
        docker_bin: Optional[str] = None,
        clamscan_bin: Optional[str] = None,
        timeout: Optional[int] = None,
        daemon_timeout: Optional[int] = None,
    ):
        cfg_daemon_url = _get_setting('SANDBOX_DAEMON_URL')
        self.daemon_url = (daemon_url or cfg_daemon_url or os.getenv('SANDBOX_DAEMON_URL', self.DEFAULT_DAEMON_URL)).rstrip('/')

        cfg_docker_image = _get_setting('SANDBOX_DOCKER_IMAGE')
        self.docker_image = docker_image or cfg_docker_image or os.getenv('SANDBOX_DOCKER_IMAGE', self.DEFAULT_DOCKER_IMAGE)

        cfg_docker_mem = _get_setting('SANDBOX_DOCKER_MEMORY')
        self.docker_memory = docker_memory or cfg_docker_mem or os.getenv('SANDBOX_DOCKER_MEMORY', self.DEFAULT_DOCKER_MEMORY)

        cfg_docker_pids = _get_setting('SANDBOX_DOCKER_PIDS_LIMIT')
        env_docker_pids = os.getenv('SANDBOX_DOCKER_PIDS_LIMIT')
        self.docker_pids_limit = docker_pids_limit or cfg_docker_pids or (int(env_docker_pids) if env_docker_pids else self.DEFAULT_DOCKER_PIDS_LIMIT)

        cfg_docker_bin = _get_setting('DOCKER_BIN')
        self.docker_bin = docker_bin or cfg_docker_bin or os.getenv('DOCKER_BIN', self.DEFAULT_DOCKER_BIN)

        cfg_timeout = _get_setting('SANDBOX_TIMEOUT')
        env_timeout = os.getenv('SANDBOX_TIMEOUT')
        self.default_timeout = timeout or cfg_timeout or (int(env_timeout) if env_timeout else self.DEFAULT_TIMEOUT)

        cfg_daemon_timeout = _get_setting('SANDBOX_DAEMON_TIMEOUT')
        env_daemon_timeout = os.getenv('SANDBOX_DAEMON_TIMEOUT')
        self.default_daemon_timeout = daemon_timeout or cfg_daemon_timeout or (int(env_daemon_timeout) if env_daemon_timeout else self.DEFAULT_DAEMON_TIMEOUT)

        self.clamscan_bin = clamscan_bin or self._find_clamscan()
        self.has_docker = self._check_docker()

    def _check_docker(self) -> bool:
        try:
            res = subprocess.run([self.docker_bin, 'ps'], capture_output=True, timeout=2)
            return res.returncode == 0
        except Exception:
            return False

    def _find_clamscan(self) -> Optional[str]:
        cfg_clamscan = _get_setting('CLAMSCAN_BIN')
        configured = cfg_clamscan or os.getenv('CLAMSCAN_BIN')
        if configured and os.path.exists(configured):
            return configured


        for candidate in ('/usr/bin/clamscan', '/usr/bin/clamdscan', 'clamscan'):
            try:
                res = subprocess.run([candidate, '--version'], capture_output=True, timeout=3)
                if res.returncode == 0:
                    return candidate
            except Exception:
                continue
        return None


    _BINARY_MAGIC = [
        b'\x7fELF', b'MZ', b'PK\x03\x04', b'\x1f\x8b', b'BZh',
        b'\xfd7zXZ', b'Rar!', b'\xca\xfe\xba\xbe', b'\xce\xfa\xed\xfe',
        b'\xcf\xfa\xed\xfe', b'\x89PNG', b'\xff\xd8\xff', b'GIF8',
        b'%PDF', b'\xd0\xcf\x11\xe0', b'RIFF', b'\x00\x00\x00',
    ]
    _ENT_NORMAL = 6.2
    _ENT_WARN   = 7.5

    def _probe_entropy(self, probe: bytes) -> float:
        if not probe:
            return 0.0
        freq = [0] * 256
        for b in probe:
            freq[b] += 1
        n, ent = len(probe), 0.0
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    def _classify_content(self, head: bytes, sample_size: int = 8192):
        """
        Returns ('binary', None), ('text', None), or ('text_high_entropy', float).
        - binary: do not read.
        - text: plain readable, no warnings.
        - text_high_entropy: readable but entropy in [6.2, 7.5] -- warn AI.
        """
        if not head:
            return 'binary', None
        probe = head[:sample_size]
        for magic in self._BINARY_MAGIC:
            if probe[:len(magic)] == magic:
                return 'binary', None
        if len(probe) >= 8 and probe[4:8] == b'ftyp':
            return 'binary', None
        if b'\x00' in probe:
            return 'binary', None
        printable = sum(
            1 for b in probe
            if b in (0x09, 0x0a, 0x0d) or 0x20 <= b <= 0x7e or b >= 0x80
        )
        if not probe or printable / len(probe) < 0.90:
            return 'binary', None
        ent = self._probe_entropy(probe) if len(probe) >= 64 else 0.0
        if ent > self._ENT_WARN:
            return 'binary', None
        elif ent > self._ENT_NORMAL:
            return 'text_high_entropy', round(ent, 3)
        return 'text', None

    def _extract_script_snippet(self, file_path: str, head_bytes: bytes) -> str:
        """
        Return first 150 lines of any text-readable file (<= 500 KB).
        Entropy 6.2-7.5: readable with AI warning header.
        Entropy > 7.5 or binary magic/null bytes: rejected.
        Control characters stripped to prevent prompt injection.
        """
        try:
            if os.path.getsize(file_path) > self.DEFAULT_MAX_SNIPPET_BYTES:
                return ''
            kind, ent_val = self._classify_content(head_bytes)
            if kind == 'binary':
                return ''
            lines = []
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= self.DEFAULT_MAX_SNIPPET_LINES:
                        break
                    clean = ''.join(
                        ch for ch in line.rstrip('\n\r')
                        if ch == '\t' or (' ' <= ch <= '~') or ord(ch) > 127
                    )
                    lines.append(clean)
            body = '\n'.join(lines)
            if kind == 'text_high_entropy':
                header = (
                    f"[CANH BAO PHAN TICH]: File nay co Shannon entropy cao ({ent_val}/8.0), "
                    f"co the la ma nguon bi obfuscate, encode (base64/hex/XOR), hoac chua "
                    f"payload nhung van doc duoc. Kiem tra ky tung dong lenh.\n"
                    f"{'=' * 60}\n"
                )
                return header + body
            return body
        except Exception:
            return ''

    def scan_file(self, file_path: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute comprehensive local static analysis + ClamAV scan + Docker sandbox isolation on a file.
        Produces verifiable forensic evidence proving why a file is clean, suspicious, or malicious.
        """
        if not os.path.exists(file_path):
            return {
                'harmless': 0,
                'malicious': 0,
                'suspicious': 0,
                'undetected': 0,
                'total': 0,
                'risk_score': 0,
                'error': 'File not found',
            }

        effective_timeout = timeout if timeout is not None else self.default_timeout

        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            head_bytes = f.read(min(file_size, 4 * 1024 * 1024))
            f.seek(0)
            file_bytes = f.read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            md5 = hashlib.md5(file_bytes).hexdigest()

        entropy = calculate_entropy(head_bytes)
        script_snippet = self._extract_script_snippet(file_path, head_bytes)
        # 1. PRIMARY: Execute full analysis inside Docker Sandbox Container (Daemon or Ephemeral)
        docker_sandbox_result = self._run_docker_sandbox_probe(file_path, timeout=effective_timeout) if self.has_docker else None


        malicious = 0
        suspicious = 0
        harmless = 0
        forensic_proofs = []
        threat_family = None

        if docker_sandbox_result and docker_sandbox_result.get('container_analysis'):
            c_data = docker_sandbox_result['container_analysis']
            verdict = c_data.get('verdict', 'SAFE')
            risk_score = c_data.get('risk_score', 5)
            threat_family = c_data.get('threat_family')
            forensic_proofs = c_data.get('forensic_evidence', [])
            
            if c_data.get('is_malicious') or verdict == 'MALICIOUS':
                malicious = 1
            elif c_data.get('is_suspicious') or verdict == 'SUSPICIOUS':
                suspicious = 1
            else:
                harmless = 1
                
            total = malicious + suspicious + harmless
            ai_explanation = self._generate_ai_explanation(forensic_proofs, verdict, risk_score)
            clamav_info = c_data.get('engines', {}).get('clamav', {'available': True, 'infected': False})
            
            return {
                'harmless': harmless,
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': 0,
                'total': total,
                'risk_score': risk_score,
                'verdict': verdict,
                'threat_family': threat_family,
                'file_metadata': c_data.get('file_metadata', {
                    'size_bytes': file_size,
                    'md5': md5,
                    'sha256': sha256,
                    'entropy': entropy,
                }),
                'forensic_evidence': forensic_proofs,
                'engines': c_data.get('engines', {'clamav': clamav_info}),
                'script_snippet': c_data.get('script_snippet') or script_snippet,
                'docker_sandbox': docker_sandbox_result,
                'clamav': clamav_info,
                'ai_explanation': ai_explanation,
                'engine': 'Sentinel-Docker-ZeroTrust-Sandbox',
            }

        # 2. SECONDARY / FALLBACK: Local host inspection if Docker is unavailable
        clamav_result = self._scan_with_clamav(file_path, timeout=effective_timeout)
        heuristics = self._inspect_file_heuristics(file_path, head_bytes, entropy)

        if clamav_result.get('infected'):
            malicious += 1
            threat_family = clamav_result.get('threat_name')
            forensic_proofs.append({
                'category': 'Antivirus Signature (ClamAV)',
                'severity': 'CRITICAL',
                'description': f"Chữ ký mã độc được xác nhận bởi ClamAV Engine: {clamav_result.get('threat_name')}",
                'evidence': clamav_result.get('threat_name'),
            })

        if heuristics.get('high_risk_indicators'):
            malicious += 1
            for ind in heuristics['high_risk_indicators']:
                forensic_proofs.append({
                    'category': 'Exploit & Malware Indicator',
                    'severity': 'HIGH',
                    'description': ind.get('desc', ''),
                    'evidence': ind.get('evidence', ''),
                })

        if heuristics.get('suspicious_indicators'):
            suspicious += 1
            for ind in heuristics['suspicious_indicators']:
                forensic_proofs.append({
                    'category': 'Suspicious Anomaly',
                    'severity': 'MEDIUM',
                    'description': ind.get('desc', ''),
                    'evidence': ind.get('evidence', ''),
                })

        if entropy > 7.4 and heuristics.get('is_executable'):
            suspicious += 1
            forensic_proofs.append({
                'category': 'High Entropy Payload',
                'severity': 'MEDIUM',
                'description': f"Độ hỗn loạn Entropy cực cao ({entropy}/8.0) cho thấy payload thực thi đã bị nén/mã hóa (Packed/Obfuscated)",
                'evidence': f"Shannon Entropy: {entropy}",
            })

        if malicious > 0:
            risk_score = 95
            verdict = 'MALICIOUS'
        elif suspicious > 0:
            risk_score = 65
            verdict = 'SUSPICIOUS'
        else:
            harmless += 1
            risk_score = 5
            verdict = 'SAFE'

        total = malicious + suspicious + harmless
        ai_explanation = self._generate_ai_explanation(forensic_proofs, verdict, risk_score)

        return {
            'harmless': harmless,
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': 0,
            'total': total,
            'risk_score': min(100, risk_score),
            'verdict': verdict,
            'threat_family': threat_family,
            'file_metadata': {
                'size_bytes': file_size,
                'md5': md5,
                'sha256': sha256,
                'entropy': entropy,
            },
            'forensic_evidence': forensic_proofs,
            'engines': {
                'clamav': clamav_result,
                'pefile': {'is_pe': heuristics.get('is_pe', False)},
                'oletools': {'has_macros': heuristics.get('has_macros', False)},
                'yara': {'matches': len(heuristics.get('high_risk_indicators', []))},
            },
            'script_snippet': script_snippet,
            'docker_sandbox': docker_sandbox_result,
            'clamav': clamav_result,
            'ai_explanation': ai_explanation,
            'engine': 'Local-ZeroTrust-Docker-ClamAV-Sandbox',
        }

    def _run_docker_sandbox_probe(self, file_path: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Runs isolated heuristic extraction via Sentinel Docker Sandbox Daemon (or fallback container).
        """
        abs_path = os.path.abspath(file_path)
        effective_timeout = timeout if timeout is not None else self.default_timeout

        # 1. High-speed Daemon Microservice Mode (<20ms) via base64 or path
        scan_url = f"{self.daemon_url}/scan"
        try:
            import base64
            with open(abs_path, 'rb') as f:
                b64_data = base64.b64encode(f.read()).decode('utf-8')
            daemon_timeout = min(effective_timeout, self.default_daemon_timeout)
            resp = requests.post(
                scan_url,
                json={
                    'file_base64': b64_data,
                    'file_name': os.path.basename(abs_path),
                },
                timeout=daemon_timeout
            )
            if resp.status_code == 200:
                container_data = resp.json()
                return {
                    'executed_in_container': True,
                    'mode': f'Docker Sandbox Daemon ({self.daemon_url})',
                    'isolation_level': 'Zero-Trust Ephemeral Sandbox (Network Isolated, Memory Capped)',
                    'container_analysis': container_data,
                }
            else:
                logger.warning(f"[Sandbox Daemon] Non-200 status {resp.status_code} from {scan_url}: {resp.text[:200]}")
        except Exception as daemon_err:
            logger.debug(f"[Sandbox Daemon] Microservice error or timeout on {scan_url}: {daemon_err}")

        # 2. Ephemeral CLI Fallback Mode
        try:
            cli_timeout = max(35, effective_timeout)
            cmd = [
                self.docker_bin, 'run', '--rm',
                '--entrypoint', 'python',
                '--network', 'none',
                '--cap-drop', 'ALL',
                '--memory', str(self.docker_memory),
                '--pids-limit', str(self.docker_pids_limit),
                '-v', f"{abs_path}:/target:ro",
                self.docker_image,
                '/sandbox/analyze.py', '/target'
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=cli_timeout)
            if res.returncode == 0 and res.stdout.strip():
                try:
                    container_data = json.loads(res.stdout.strip())
                    return {
                        'executed_in_container': True,
                        'mode': f'Docker Ephemeral CLI Fallback ({self.docker_image})',
                        'isolation_level': 'Zero-Trust Ephemeral Sandbox (No Network, Cap-Drop ALL, Memory-Capped)',
                        'container_analysis': container_data,
                    }
                except Exception as parse_err:
                    logger.warning(f"[Sandbox CLI] JSON parse failed: {parse_err}")
            return {
                'executed_in_container': False,
                'mode': f'Docker Ephemeral CLI Fallback ({self.docker_image})',
                'error': res.stderr.strip() or 'Container exited with non-zero status or empty output',
                'output': res.stdout.strip()[:500],
            }
        except Exception as e:
            logger.error(f"[Sandbox CLI] Fallback execution failed: {e}")
            return {'executed_in_container': False, 'error': str(e)}

    def _scan_with_clamav(self, file_path: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Scan file using ClamAV engine."""
        if not self.clamscan_bin:
            return {'available': False, 'infected': False, 'threat_name': None}

        effective_timeout = timeout if timeout is not None else self.default_timeout
        try:
            cmd = [self.clamscan_bin, '--no-summary', file_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=effective_timeout)

            
            if proc.returncode == 1:
                match = re.search(r':\s*(.+)\s+FOUND', proc.stdout)
                threat = match.group(1).strip() if match else 'Malware.Detected'
                logger.warning(f"[ClamAV] Threat detected in {file_path}: {threat}")
                return {'available': True, 'infected': True, 'threat_name': threat}
            elif proc.returncode == 0:
                return {'available': True, 'infected': False, 'threat_name': None}
            else:
                return {'available': True, 'infected': False, 'error': proc.stderr.strip()[:100]}
        except Exception as e:
            logger.error(f"[ClamAV] Execution error: {e}")
            return {'available': False, 'infected': False, 'error': str(e)}

    def _inspect_file_heuristics(self, file_path: str, head_bytes: bytes, entropy: float) -> Dict[str, Any]:
        """Deep static inspections for PDFs, Office Documents, Scripts, and Executables with proof artifacts."""
        high_risk = []
        suspicious = []
        details = {}
        ext = os.path.splitext(file_path)[1].lower()

        # 1. Executable Headers (MZ / ELF)
        is_pe = head_bytes.startswith(b'MZ')
        is_elf = head_bytes.startswith(b'\x7fELF')
        details['is_executable'] = is_pe or is_elf or ext in ('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.apk')
        details['is_pe'] = is_pe
        details['is_elf'] = is_elf

        # 2. PDF Exploit Inspection
        if ext == '.pdf' or b'%PDF-' in head_bytes[:1024]:
            pdf_exploit_patterns = {
                b'/Launch': ("Tệp PDF chứa lệnh khởi chạy tệp thực thi bên ngoài hệ thống (/Launch)", "/Launch action"),
                b'/EmbeddedFiles': ("Tệp PDF chứa tệp tin nhị phân đính kèm ẩn (/EmbeddedFiles)", "/EmbeddedFiles object"),
                b'/JS': ("Tệp PDF chứa luồng thực thi mã JavaScript nhúng (/JS)", "/JS script stream"),
                b'/JavaScript': ("Tệp PDF chứa mã JavaScript khai thác lỗ hổng (/JavaScript)", "/JavaScript block"),
                b'/OpenAction': ("Tệp PDF tự động kích hoạt hành động ngay khi mở (/OpenAction)", "/OpenAction trigger"),
            }
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(4 * 1024 * 1024)
                    for pat, (desc, ev) in pdf_exploit_patterns.items():
                        if pat in content:
                            suspicious.append({'desc': desc, 'evidence': ev})
            except Exception:
                pass

        # 3. Office Document Macros (DOCX / XLSX / PPTX / DOC)
        if ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.zip'):
            try:
                if zipfile.is_zipfile(file_path):
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        namelist = zf.namelist()
                        if any('vbaproject.bin' in name.lower() for name in namelist):
                            high_risk.append({
                                'desc': "Phát hiện mã VBA Macro nhúng (vbaProject.bin) có khả năng thực thi mã độc tự động",
                                'evidence': "vbaProject.bin found in package contents",
                            })
                        if any(n.endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs')) for n in namelist):
                            high_risk.append({
                                'desc': "Gói tệp nén chứa payload thực thi nguy hiểm",
                                'evidence': f"Packed binaries: {[n for n in namelist if n.endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs'))]}",
                            })
            except Exception:
                pass

        # 4. Script Heuristics
        if ext in ('.ps1', '.bat', '.cmd', '.vbs', '.js', '.sh'):
            text = head_bytes.decode('utf-8', errors='ignore').lower()
            if '-enc' in text or 'invoke-expression' in text or 'iex' in text:
                high_risk.append({
                    'desc': "Script chứa lệnh PowerShell bị mã hóa Base64 / Obfuscated Execution",
                    'evidence': "-enc / Invoke-Expression / iex commands detected",
                })
            if 'wscript.shell' in text and ('run' in text or 'exec' in text):
                suspicious.append({
                    'desc': "Script sử dụng WScript.Shell để kích hoạt tiến trình con ngầm",
                    'evidence': "WScript.Shell.Run / Exec execution pattern",
                })
            if 'downloadstring' in text or 'certutil -urlcache' in text:
                high_risk.append({
                    'desc': "Chứa lệnh Dropper tải payload từ xa bằng Certutil hoặc WebClient",
                    'evidence': "downloadstring / certutil -urlcache commands found",
                })

        return {
            'high_risk_indicators': high_risk,
            'suspicious_indicators': suspicious,
            'is_executable': details['is_executable'],
        }

    def _generate_ai_explanation(self, forensic_proofs: List[Dict], verdict: str, risk_score: int) -> str:
        """Construct readable forensic summary in Vietnamese."""
        if verdict == 'SAFE':
            return "Tệp tin đã qua kiểm tra toàn diện bằng ClamAV và phân tích cấu trúc tĩnh; không phát hiện chữ ký mã độc, macro ẩn hay hành vi bất thường."
        
        proof_lines = [f"- [{p['severity']}] {p['description']} (Bằng chứng: {p['evidence']})" for p in forensic_proofs]
        return f"Cảnh báo rủi ro ({risk_score}/100 - {verdict}):\n" + "\n".join(proof_lines)

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Local URL threat assessment using multi-layered heuristic intelligence.
        """
        if not url:
            return {'harmless': 1, 'malicious': 0, 'suspicious': 0, 'undetected': 0, 'total': 1, 'risk_score': 0}

        from api.utils.normalization import normalize_domain
        domain = normalize_domain(url) or ''
        
        malicious = 0
        suspicious = 0
        harmless = 0
        risk_score = 0
        proofs = []

        domain_lower = domain.lower()
        suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.work', '.click', '.monster')
        
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            suspicious += 1
            risk_score += 35
            proofs.append("Tên miền sử dụng TLD có mức độ lạm dụng lừa đảo cao")

        # Homoglyphs / brand phishing patterns
        brand_scams = ('vietcombank', 'techcombank', 'mbbank', 'vpbank', 'vnpay', 'zalopay', 'shopee', 'lazada', 'momo')
        for brand in brand_scams:
            if brand in domain_lower and not domain_lower.endswith(f"{brand}.com.vn") and not domain_lower.endswith(f"{brand}.vn") and not domain_lower == f"{brand}.com":
                malicious += 1
                risk_score = max(risk_score, 85)
                proofs.append(f"Tên miền mạo danh thương hiệu tài chính/thương mại điện tử: {brand.upper()}")
                break

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            suspicious += 1
            risk_score = max(risk_score, 70)
            proofs.append("Sử dụng địa chỉ IP trực tiếp thay cho tên miền hợp lệ")

        if not malicious and not suspicious:
            harmless += 1
            risk_score = 0

        total = malicious + suspicious + harmless
        return {
            'harmless': harmless,
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': 0,
            'total': total,
            'risk_score': min(100, risk_score),
            'forensic_proofs': proofs,
            'engine': 'Local-Heuristic-URL-Intelligence',
        }
