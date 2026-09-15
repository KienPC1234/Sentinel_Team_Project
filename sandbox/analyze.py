#!/usr/bin/env python3
"""
Enterprise Zero-Trust Malware Analysis Engine (Docker Container).
Multi-Layer Static Analysis Pipeline:
1. Archive & ZIP Inspector (Unpack & Recursive multi-file scan with password cracking & zip-bomb guard)
2. Python-Magic (True file type & extension spoofing check)
3. ExifTool (Forensic metadata, compile time, author extraction)
4. Secret & Reverse-Shell Heuristic Inspector (TruffleHog style token & shell regex)
5. YARA ruleset engine (Neo23x0 Florian Roth Signature-Base community rules)
6. OLETools (VBA macro forensic dissection, IOC extraction, Obfuscation detection)
7. PEFile & Mandiant CAPA (Behavioral capabilities, MITRE ATT&CK mapping, Win32 API imports)
8. PyPDF (JavaScript streams, Launch actions, Embedded objects)
9. Shannon Entropy & Cryptographic Hashing (MD5, SHA1, SHA256)
10. ClamAV Antivirus Scanner (High-speed clamd socket daemon)
"""

import sys
import os
import json
import math
import hashlib
import subprocess
import re
import zipfile
import tarfile
import shutil
import tempfile
from typing import Dict, Any, List, Optional

# YARA Engine
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# OLETools Engine
try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

# PEFile Engine
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# PyPDF Engine
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# Python-Magic Engine
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


MAX_SNIPPET_BYTES = 512_000
MAX_SNIPPET_LINES = 150
CAPA_RULES_DIR = os.getenv('CAPA_RULES_PATH', '/sandbox/capa-rules')

# Archive safety limits (Anti-ZipBomb)
MAX_ARCHIVE_FILES = 50
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
COMMON_ARCHIVE_PASSWORDS = [None, b'infected', b'malware', b'password', b'123456', b'virus', b'clean']


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def inspect_file_magic(file_path: str) -> Dict[str, Any]:
    """Verify true MIME type and check for extension spoofing."""
    result = {
        'mime_type': 'application/octet-stream',
        'file_type_desc': 'Unknown',
        'spoofed_extension': False,
        'spoof_warning': None
    }
    if not MAGIC_AVAILABLE:
        return result

    try:
        mime = magic.Magic(mime=True)
        result['mime_type'] = mime.from_file(file_path)
        
        desc = magic.Magic()
        result['file_type_desc'] = desc.from_file(file_path)

        ext = os.path.splitext(file_path)[1].lower()
        mime_type = result['mime_type']

        is_executable_mime = ('x-dosexec' in mime_type or 'x-executable' in mime_type or 'x-sharedlib' in mime_type)
        is_benign_ext = ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.txt', '.csv')

        if is_executable_mime and is_benign_ext:
            result['spoofed_extension'] = True
            result['spoof_warning'] = f"Kỹ thuật ngụy trang phần mở rộng: File có đuôi '{ext}' nhưng thực chất là mã thực thi nhị phân ({mime_type})"
    except Exception as e:
        sys.stderr.write(f"Magic exception: {e}\n")
    return result


def extract_exiftool_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata using exiftool."""
    result = {'available': False, 'metadata': {}}
    if not os.path.exists('/usr/bin/exiftool') and not os.path.exists('exiftool'):
        return result

    try:
        proc = subprocess.run(['exiftool', '-json', file_path], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            if data and isinstance(data, list):
                result['available'] = True
                meta = data[0]
                clean_meta = {
                    k: v for k, v in meta.items()
                    if k not in ('SourceFile', 'Directory', 'FilePermissions')
                }
                result['metadata'] = clean_meta
    except Exception:
        pass
    return result


def inspect_secrets_and_scripts(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """Scan text/scripts for hardcoded secrets, API tokens, and reverse shells."""
    findings = []
    try:
        if os.path.getsize(file_path) > 1024 * 1024:
            return {'findings': findings}

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        secret_patterns = [
            (r'(?i)(aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16})', 'AWS Secret / Access Key'),
            (r'(?i)(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})', 'GitHub Personal Access Token'),
            (r'(?i)(xox[baprs]-[0-9a-zA-Z]{10,48})', 'Slack Bot / User Token'),
            (r'(?i)-----BEGIN\s+(RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----', 'Private Cryptographic Key'),
            (r'(?i)(AIza[0-9A-Za-z\\-_]{35})', 'Google Cloud / Maps API Key'),
            (r'(?i)eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT Token Secret Payload'),
            (r'(?i)(/bin/sh\s+-i\s+>&|/bin/bash\s+-i\s+>&|nc\s+-e\s+/bin/)', 'Interactive Reverse Shell Payload'),
        ]

        for pattern, label in secret_patterns:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    'type': label,
                    'count': len(matches),
                    'sample': str(matches[0])[:30] + '...'
                })
    except Exception:
        pass
    return {'findings': findings}


def extract_script_snippet(file_path: str, head_bytes: bytes) -> str:
    """Return snippet of text-readable file."""
    try:
        size = os.path.getsize(file_path)
        if size > MAX_SNIPPET_BYTES:
            return ''

        lines = []
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= MAX_SNIPPET_LINES:
                    break
                clean = ''.join(
                    ch for ch in line.rstrip('\n\r')
                    if ch == '\t' or (' ' <= ch <= '~') or ord(ch) > 127
                )
                lines.append(clean)

        return '\n'.join(lines)
    except Exception:
        return ''


_YARA_COMPILED_RULES = None

def _get_yara_engine():
    global _YARA_COMPILED_RULES
    if _YARA_COMPILED_RULES is not None:
        return _YARA_COMPILED_RULES
    if not YARA_AVAILABLE:
        return None

    # 1. Prefer pre-compiled binary YARA database (734+ Florian Roth community rulesets)
    compiled_path = '/sandbox/rules/compiled_rules.yarc'
    if os.path.exists(compiled_path):
        try:
            _YARA_COMPILED_RULES = yara.load(filepath=compiled_path)
            return _YARA_COMPILED_RULES
        except Exception as e:
            sys.stderr.write(f"Failed loading compiled community YARA index: {e}\n")

    # 2. Fallback: Dynamic compile from community directory
    community_dir = '/sandbox/rules/signature_base'
    if os.path.isdir(community_dir):
        try:
            import glob
            fps = {}
            for yf in sorted(glob.glob(os.path.join(community_dir, '*.yar'))):
                name = os.path.splitext(os.path.basename(yf))[0]
                try:
                    yara.compile(filepath=yf)
                    fps[name] = yf
                except Exception:
                    pass
            if fps:
                _YARA_COMPILED_RULES = yara.compile(filepaths=fps)
                return _YARA_COMPILED_RULES
        except Exception as e:
            sys.stderr.write(f"Failed compiling community YARA rules: {e}\n")

    return None


def analyze_with_yara(file_path: str) -> List[Dict[str, Any]]:
    """Scan target file against compiled enterprise & community YARA rules."""
    matches_list = []
    rules = _get_yara_engine()
    if rules is None:
        return matches_list

    try:
        matches = rules.match(file_path, timeout=10)
        for match in matches:
            meta = match.meta or {}
            matched_identifiers = []
            for s in match.strings[:5]:
                if hasattr(s, 'identifier'):
                    matched_identifiers.append(s.identifier)
                elif isinstance(s, (tuple, list)) and len(s) > 1:
                    matched_identifiers.append(str(s[1]))
                else:
                    matched_identifiers.append(str(s))

            matches_list.append({
                'rule': match.rule,
                'severity': meta.get('severity', meta.get('level', 'HIGH')),
                'description': meta.get('description', f"Khớp tập luật YARA mã độc: {match.rule}"),
                'author': meta.get('author', 'Community Threat Intel'),
                'strings': matched_identifiers,
            })
    except Exception as e:
        sys.stderr.write(f"YARA Match Exception: {e}\n")
    return matches_list


def analyze_with_oletools(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """Forensic examination of MS Office documents using OLETools."""
    result = {'has_macros': False, 'suspicious_keywords': [], 'macro_code_preview': ''}
    if not OLETOOLS_AVAILABLE:
        return result

    ext = os.path.splitext(file_path)[1].lower()
    is_office_ext = ext in ('.doc', '.docx', '.xls', '.xlsx', '.xlsm', '.docm', '.dotm', '.ppt', '.pptx', '.vba', '.bas', '.cls', '.rtf', '.bin')
    is_ole_magic = head_bytes.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
    is_zip = head_bytes.startswith(b'PK\x03\x04')

    if not (is_office_ext or is_ole_magic or is_zip):
        return result

    try:
        vbaparser = VBA_Parser(file_path)
        if getattr(vbaparser, 'type', None) in ('Text', None) and not is_office_ext:
            vbaparser.close()
            return result

        if vbaparser.detect_vba_macros():
            extracted = list(vbaparser.extract_macros())
            if extracted:
                result['has_macros'] = True
                analysis = vbaparser.analyze_macros()
                for kw_type, keyword, description in analysis:
                    if kw_type in ('AutoExec', 'Suspicious'):
                        result['suspicious_keywords'].append({
                            'type': kw_type,
                            'keyword': keyword,
                            'description': description,
                        })
                
                for (filename, stream_path, vba_filename, vba_code) in extracted:
                    if vba_code and len(vba_code.strip()) > 0:
                        result['macro_code_preview'] = vba_code[:1500]
                        break
        vbaparser.close()
    except Exception:
        pass
    return result


def analyze_with_pefile(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """PE structure and Win32 API import analysis using PEFile."""
    result = {'is_pe': False, 'sections': [], 'imphash': None, 'suspicious_apis': [], 'high_entropy_sections': []}
    if not PEFILE_AVAILABLE or not head_bytes.startswith(b'MZ'):
        return result

    try:
        pe = pefile.PE(file_path, fast_load=True)
        result['is_pe'] = True
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        ])

        try:
            result['imphash'] = pe.get_imphash()
        except Exception:
            pass

        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_entropy = section.get_entropy()
            result['sections'].append({'name': sec_name, 'entropy': round(sec_entropy, 3)})
            if sec_entropy > 7.2:
                result['high_entropy_sections'].append({'name': sec_name, 'entropy': round(sec_entropy, 3)})

        dangerous_imports = {
            'VirtualAlloc': 'Memory allocation for shellcode execution',
            'VirtualAllocEx': 'Remote process memory allocation (Injection)',
            'WriteProcessMemory': 'Writing shellcode to remote process memory (Injection)',
            'CreateRemoteThread': 'Executing injected thread in remote process',
            'QueueUserAPC': 'Early bird / APC injection technique',
            'SetThreadContext': 'Thread hijacking execution pattern',
            'URLDownloadToFileA': 'Direct file downloader routine',
            'URLDownloadToFileW': 'Direct file downloader routine',
            'InternetOpenUrlA': 'C2 beaconing or file downloader',
            'WinExec': 'Legacy direct program execution',
            'ShellExecuteA': 'Shell invocation of external binaries',
        }

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp and imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if func_name in dangerous_imports:
                            result['suspicious_apis'].append({
                                'api': func_name,
                                'description': dangerous_imports[func_name],
                            })
        pe.close()
    except Exception:
        pass
    return result


def analyze_with_pdf(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """Forensic deep inspection of PDF streams, JavaScript, and launch actions."""
    result = {'is_pdf': False, 'has_javascript': False, 'has_launch_action': False, 'suspicious_elements': []}
    
    ext = os.path.splitext(file_path)[1].lower()
    if not (head_bytes.startswith(b'%PDF') or ext == '.pdf'):
        return result

    result['is_pdf'] = True
    try:
        with open(file_path, 'rb') as f:
            content = f.read(16 * 1024 * 1024)

        indicators = [
            (b'/JavaScript', 'Embedded JavaScript engine object (/JavaScript)', 'HIGH'),
            (b'/JS', 'Embedded JavaScript code stream (/JS)', 'HIGH'),
            (b'/Launch', 'Automatic external application execution (/Launch action)', 'CRITICAL'),
            (b'/OpenAction', 'Automatic action trigger on document opening (/OpenAction)', 'HIGH'),
            (b'/AA', 'Additional action trigger on page render or mouse movement (/AA)', 'MEDIUM'),
            (b'/EmbeddedFiles', 'Embedded payload attachment in document (/EmbeddedFiles)', 'HIGH'),
            (b'/RichMedia', 'Embedded Flash or external RichMedia player (/RichMedia)', 'MEDIUM'),
            (b'/XFA', 'XML Forms Architecture (potential memory exploit vector)', 'MEDIUM'),
            (b'eval(', 'Obfuscated JavaScript dynamic code evaluation', 'CRITICAL'),
            (b'unescape(', 'Obfuscated shellcode payload decoding', 'CRITICAL'),
            (b'String.fromCharCode', 'Character code obfuscated payload construction', 'HIGH'),
            (b'app.launchURL', 'Automatic browser beaconing or URL opening', 'HIGH'),
            (b'this.exportDataObject', 'Dropper action exporting embedded files to disk', 'CRITICAL'),
        ]

        for pattern, desc, sev in indicators:
            if pattern in content:
                if pattern in (b'/JavaScript', b'/JS', b'eval(', b'unescape('):
                    result['has_javascript'] = True
                if pattern in (b'/Launch', b'this.exportDataObject'):
                    result['has_launch_action'] = True
                result['suspicious_elements'].append({
                    'element': pattern.decode('utf-8', errors='ignore'),
                    'description': desc,
                    'severity': sev
                })
    except Exception:
        pass
    return result


def analyze_with_capa(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """Extract deep behavioral capabilities and MITRE ATT&CK tactics using Mandiant CAPA."""
    result = {'available': False, 'capabilities': [], 'mitre_attacks': []}
    
    # Run Capa only on PE or ELF binaries under 15MB to prevent memory bloat
    is_binary = head_bytes.startswith(b'MZ') or head_bytes.startswith(b'\x7fELF')
    if not is_binary:
        return result

    if not os.path.isdir(CAPA_RULES_DIR):
        return result

    try:
        if os.path.getsize(file_path) > 15 * 1024 * 1024:
            return result

        cmd = ['capa', '--rules', CAPA_RULES_DIR, '-j', file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if proc.returncode in (0, 1) and proc.stdout:
            data = json.loads(proc.stdout)
            result['available'] = True
            
            rules = data.get('rules', {})
            for rule_name, rule_meta in rules.items():
                meta = rule_meta.get('meta', {})
                desc = meta.get('description') or rule_name
                namespace = meta.get('namespace', '')
                attacks = meta.get('att&ck', [])
                
                result['capabilities'].append({
                    'rule': rule_name,
                    'namespace': namespace,
                    'description': desc,
                })
                for att in attacks:
                    if att not in result['mitre_attacks']:
                        result['mitre_attacks'].append(att)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Capa analysis timed out on {file_path}\n")
    except Exception:
        pass
    return result


def analyze_with_clamav(file_path: str) -> Dict[str, Any]:
    """Scan file with ClamAV daemon socket (instantaneous) or CLI fallback."""
    result = {'available': False, 'infected': False, 'threat_name': None}
    
    # 1. Ultra-fast native ClamD UNIX socket communication (<5ms)
    socket_path = '/var/run/clamav/clamd.ctl'
    if os.path.exists(socket_path):
        try:
            import socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(socket_path)
            abs_target = os.path.abspath(file_path)
            sock.sendall(f"zSCAN {abs_target}\0".encode('utf-8'))
            resp = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            result['available'] = True
            if 'FOUND' in resp:
                result['infected'] = True
                match = re.search(r':\s*(.+)\s+FOUND', resp)
                result['threat_name'] = match.group(1).strip() if match else 'Malware.Detected'
            return result
        except Exception as e:
            sys.stderr.write(f"ClamD socket error: {e}\n")

    # 2. CLI fallback
    for bin_path in ('/usr/bin/clamdscan', '/usr/bin/clamscan', 'clamscan'):
        if os.path.exists(bin_path):
            try:
                proc = subprocess.run([bin_path, '--no-summary', file_path], capture_output=True, text=True, timeout=15)
                result['available'] = True
                if proc.returncode == 1:
                    result['infected'] = True
                    match = re.search(r':\s*(.+)\s+FOUND', proc.stdout)
                    result['threat_name'] = match.group(1).strip() if match else 'Malware.Detected'
                return result
            except Exception:
                pass
    return result


def inspect_and_unpack_archive(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """
    Detects ZIP/TAR archives, unpacks safely with anti-ZipBomb guards & password cracking,
    and returns list of extracted child files for recursive threat scanning.
    """
    archive_result = {
        'is_archive': False,
        'format': None,
        'password_protected': False,
        'unpacked_successfully': False,
        'child_files': [],
        'archive_dir': None
    }

    is_zip = head_bytes.startswith(b'PK\x03\x04')
    is_tar_gz = head_bytes.startswith(b'\x1f\x8b')
    is_7z = head_bytes.startswith(b'7z\xbc\xaf\x27\x1c')
    is_rar = head_bytes.startswith(b'Rar!\x1a\x07')

    ext = os.path.splitext(file_path)[1].lower()
    if not (is_zip or is_tar_gz or is_7z or is_rar or ext in ('.zip', '.tar', '.gz', '.tgz', '.7z', '.rar')):
        return archive_result

    archive_result['is_archive'] = True
    temp_dir = tempfile.mkdtemp(prefix='sandbox_archive_')
    archive_result['archive_dir'] = temp_dir

    total_extracted_size = 0
    extracted_count = 0

    # Handle ZIP archives
    if is_zip or ext == '.zip':
        archive_result['format'] = 'ZIP'
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Test password if encrypted
                pwd_found = None
                for candidate in COMMON_ARCHIVE_PASSWORDS:
                    try:
                        zf.setpassword(candidate)
                        # Test reading first file to verify password
                        for inf in zf.infolist()[:1]:
                            zf.read(inf)
                        pwd_found = candidate
                        break
                    except Exception:
                        continue

                if pwd_found is not None or not zf.infolist():
                    archive_result['unpacked_successfully'] = True
                    if pwd_found is not None and pwd_found != None:
                        archive_result['password_protected'] = True

                    for member in zf.infolist():
                        if member.is_dir() or member.filename.startswith('/') or '..' in member.filename:
                            continue
                        
                        # Anti-ZipBomb guard
                        if member.file_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES or (total_extracted_size + member.file_size) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                            break
                        if extracted_count >= MAX_ARCHIVE_FILES:
                            break

                        target_out = os.path.join(temp_dir, os.path.basename(member.filename))
                        with open(target_out, 'wb') as out_f:
                            out_f.write(zf.read(member, pwd=pwd_found))
                        
                        archive_result['child_files'].append(target_out)
                        total_extracted_size += member.file_size
                        extracted_count += 1
        except Exception:
            pass

    # Handle TAR / TAR.GZ archives
    elif is_tar_gz or ext in ('.tar', '.gz', '.tgz'):
        archive_result['format'] = 'TAR/GZ'
        try:
            with tarfile.open(file_path, 'r:*') as tf:
                archive_result['unpacked_successfully'] = True
                for member in tf.getmembers():
                    if member.isdir() or member.name.startswith('/') or '..' in member.name:
                        continue
                    if member.size > MAX_ARCHIVE_UNCOMPRESSED_BYTES or (total_extracted_size + member.size) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        break
                    if extracted_count >= MAX_ARCHIVE_FILES:
                        break

                    f_obj = tf.extractfile(member)
                    if f_obj:
                        target_out = os.path.join(temp_dir, os.path.basename(member.name))
                        with open(target_out, 'wb') as out_f:
                            out_f.write(f_obj.read())
                        archive_result['child_files'].append(target_out)
                        total_extracted_size += member.size
                        extracted_count += 1
        except Exception:
            pass

    # Fallback to 7z CLI for 7z/RAR/complex zips if available
    if not archive_result['child_files'] and (os.path.exists('/usr/bin/7z') or os.path.exists('7z')):
        for pwd in ('', '-pinfected', '-pmalware', '-ppassword', '-p123456'):
            cmd = ['7z', 'e', f'-o{temp_dir}', '-y']
            if pwd:
                cmd.append(pwd)
            cmd.append(file_path)
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=10)
                if proc.returncode == 0:
                    archive_result['unpacked_successfully'] = True
                    for root, _, files in os.walk(temp_dir):
                        for f in files:
                            archive_result['child_files'].append(os.path.join(root, f))
                    if archive_result['child_files']:
                        break
            except Exception:
                pass

    return archive_result


def run_full_sandbox_analysis_dict(file_path: str) -> dict:
    if not os.path.exists(file_path):
        return {'error': 'Target file not found inside container'}

    size = os.path.getsize(file_path)
    with open(file_path, 'rb') as f:
        head = f.read(min(size, 4 * 1024 * 1024))
        f.seek(0)
        full_content = f.read()
        sha256 = hashlib.sha256(full_content).hexdigest()
        md5 = hashlib.md5(full_content).hexdigest()
        sha1 = hashlib.sha1(full_content).hexdigest()

    file_entropy = calculate_entropy(head)

    # 1. Multi-Engine Pipeline for Target File
    magic_info = inspect_file_magic(file_path)
    exif_info = extract_exiftool_metadata(file_path)
    secret_info = inspect_secrets_and_scripts(file_path, head)
    yara_matches = analyze_with_yara(file_path)
    ole_results = analyze_with_oletools(file_path, head)
    pe_results = analyze_with_pefile(file_path, head)
    pdf_results = analyze_with_pdf(file_path, head)
    capa_results = analyze_with_capa(file_path, head)
    clamav_results = analyze_with_clamav(file_path)
    archive_info = inspect_and_unpack_archive(file_path, head)
    script_snippet = extract_script_snippet(file_path, head)

    forensic_evidence = []
    is_malicious = False
    is_suspicious = False
    threat_names = []

    # 2. Archive Recursive Dissection
    nested_threats = []
    if archive_info['is_archive'] and archive_info['child_files']:
        try:
            for child in archive_info['child_files']:
                c_name = os.path.basename(child)
                c_yara = analyze_with_yara(child)
                c_clam = analyze_with_clamav(child)
                
                if c_clam.get('infected'):
                    is_malicious = True
                    threat_names.append(c_clam.get('threat_name'))
                    forensic_evidence.append({
                        'category': f"Archive Child ({c_name}) - ClamAV",
                        'severity': 'CRITICAL',
                        'description': f"Tập tin nén chứa mã độc được phát hiện bởi ClamAV: {c_clam.get('threat_name')}",
                        'evidence': f"File: {c_name}, Signature: {c_clam.get('threat_name')}"
                    })
                    nested_threats.append({'file': c_name, 'engine': 'ClamAV', 'threat': c_clam.get('threat_name')})

                for ym in c_yara:
                    if ym.get('severity') == 'CRITICAL':
                        is_malicious = True
                    else:
                        is_suspicious = True
                    threat_names.append(ym.get('rule'))
                    forensic_evidence.append({
                        'category': f"Archive Child ({c_name}) - YARA",
                        'severity': ym.get('severity', 'HIGH'),
                        'description': ym.get('description', ''),
                        'evidence': f"File: {c_name}, Rule: {ym.get('rule')}"
                    })
                    nested_threats.append({'file': c_name, 'engine': 'YARA', 'rule': ym.get('rule')})
        finally:
            # Guarantee cleanup of unpacked temporary directory
            if archive_info.get('archive_dir') and os.path.exists(archive_info['archive_dir']):
                try:
                    shutil.rmtree(archive_info['archive_dir'])
                except Exception:
                    pass

    # Process Extension Spoofing
    if magic_info.get('spoofed_extension'):
        is_malicious = True
        threat_names.append('Trojan.ExtensionCloaking')
        forensic_evidence.append({
            'category': 'File Extension Spoofing (Magic)',
            'severity': 'CRITICAL',
            'description': magic_info['spoof_warning'],
            'evidence': f"MIME: {magic_info['mime_type']}, Detected: {magic_info['file_type_desc']}"
        })

    # Process ClamAV
    if clamav_results.get('infected'):
        is_malicious = True
        threat_names.append(clamav_results.get('threat_name'))
        forensic_evidence.append({
            'category': 'Antivirus Signature (ClamAV)',
            'severity': 'CRITICAL',
            'description': f"Chữ ký mã độc được xác nhận bởi ClamAV Engine: {clamav_results.get('threat_name')}",
            'evidence': clamav_results.get('threat_name'),
        })

    # Process YARA Matches
    for ym in yara_matches:
        if ym.get('severity') == 'CRITICAL':
            is_malicious = True
        else:
            is_suspicious = True
        threat_names.append(ym.get('rule'))
        forensic_evidence.append({
            'category': 'YARA Rule Signature',
            'severity': ym.get('severity', 'HIGH'),
            'description': ym.get('description', ''),
            'evidence': f"Rule: {ym.get('rule')}, Patterns: {ym.get('strings', [])}",
        })

    # Process Capa Behaviors & MITRE ATT&CK
    if capa_results.get('available') and capa_results.get('capabilities'):
        is_suspicious = True
        for cap in capa_results['capabilities'][:5]:
            forensic_evidence.append({
                'category': 'Malware Capability (Mandiant CAPA)',
                'severity': 'HIGH' if 'anti-analysis' in cap['namespace'] or 'injection' in cap['namespace'] else 'MEDIUM',
                'description': f"Hành vi nhị phân ({cap['namespace']}): {cap['description']}",
                'evidence': f"Rule: {cap['rule']}"
            })
        if capa_results.get('mitre_attacks'):
            forensic_evidence.append({
                'category': 'MITRE ATT&CK Tactics (CAPA)',
                'severity': 'HIGH',
                'description': f"Chiến thuật tấn công được nhận diện: {', '.join(capa_results['mitre_attacks'][:6])}",
                'evidence': f"Tactics: {capa_results['mitre_attacks']}"
            })

    # Process Secrets & Reverse Shells
    for sf in secret_info.get('findings', []):
        if 'Shell' in sf['type']:
            is_malicious = True
            sev = 'CRITICAL'
        else:
            is_suspicious = True
            sev = 'HIGH'
        forensic_evidence.append({
            'category': 'Secret / Reverse Shell Extraction',
            'severity': sev,
            'description': f"Phát hiện dấu hiệu mã độc / rò rỉ bảo mật: {sf['type']}",
            'evidence': f"Mẫu: {sf['sample']}"
        })

    # Process OLETools / Macros
    if ole_results.get('has_macros'):
        if ole_results.get('suspicious_keywords'):
            is_malicious = True
            for kw in ole_results['suspicious_keywords']:
                forensic_evidence.append({
                    'category': 'VBA Macro Malware (OLETools)',
                    'severity': 'CRITICAL' if kw['type'] in ('AutoExec', 'Suspicious') else 'HIGH',
                    'description': f"Phát hiện macro độc hại ({kw['type']}): {kw['description']}",
                    'evidence': f"Keyword: {kw['keyword']}",
                })

    # Process PDF Exploit Elements
    if pdf_results.get('is_pdf') and pdf_results.get('suspicious_elements'):
        for el in pdf_results['suspicious_elements']:
            if el['severity'] == 'CRITICAL':
                is_malicious = True
            else:
                is_suspicious = True
            if not threat_names:
                threat_names.append('Exploit.PDF.MaliciousAction')
            forensic_evidence.append({
                'category': 'PDF Exploit & Action (PyPDF)',
                'severity': el['severity'],
                'description': f"Dấu hiệu khai thác PDF: {el['description']}",
                'evidence': f"Element: {el['element']}"
            })

    # Process PEFile
    if pe_results.get('is_pe'):
        if pe_results.get('suspicious_apis'):
            if len(pe_results['suspicious_apis']) >= 2:
                is_malicious = True
            else:
                is_suspicious = True
            for api in pe_results['suspicious_apis']:
                forensic_evidence.append({
                    'category': 'Win32 Process Injection API (PEFile)',
                    'severity': 'CRITICAL' if 'Injection' in api['description'] else 'HIGH',
                    'description': f"Nhập API nguy hiểm: {api['api']} ({api['description']})",
                    'evidence': f"Import: {api['api']}",
                })
        if pe_results.get('high_entropy_sections'):
            is_suspicious = True
            for sec in pe_results['high_entropy_sections']:
                forensic_evidence.append({
                    'category': 'Packed / Encrypted PE Section',
                    'severity': 'MEDIUM',
                    'description': f"Phần Section '{sec['name']}' có entropy cao ({sec['entropy']}/8.0), dấu hiệu bị Pack/Obfuscate",
                    'evidence': f"Section: {sec['name']}, Entropy: {sec['entropy']}",
                })

    # Overall Risk Score
    if is_malicious:
        risk_score = 95
        verdict = 'MALICIOUS'
    elif is_suspicious:
        risk_score = 65
        verdict = 'SUSPICIOUS'
    else:
        risk_score = 5
        verdict = 'SAFE'

    output = {
        'status': 'success',
        'verdict': verdict,
        'risk_score': risk_score,
        'is_malicious': is_malicious,
        'is_suspicious': is_suspicious,
        'threat_family': threat_names[0] if threat_names else None,
        'file_metadata': {
            'size_bytes': size,
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'entropy': file_entropy,
            'imphash': pe_results.get('imphash'),
            'mime_type': magic_info.get('mime_type'),
            'file_type_desc': magic_info.get('file_type_desc'),
            'is_archive': archive_info.get('is_archive', False),
            'archive_file_count': len(archive_info.get('child_files', [])),
            'exif': exif_info.get('metadata', {}),
        },
        'forensic_evidence': forensic_evidence,
        'archive_analysis': {
            'is_archive': archive_info.get('is_archive', False),
            'format': archive_info.get('format'),
            'password_protected': archive_info.get('password_protected', False),
            'nested_threats': nested_threats,
        },
        'script_snippet': script_snippet,
        'engines': {
            'magic': {'available': MAGIC_AVAILABLE, 'mime': magic_info.get('mime_type')},
            'exiftool': {'available': exif_info.get('available')},
            'yara': {'available': YARA_AVAILABLE, 'matches': len(yara_matches)},
            'capa': {'available': capa_results.get('available'), 'capabilities': len(capa_results.get('capabilities', []))},
            'oletools': {'available': OLETOOLS_AVAILABLE, 'has_macros': ole_results.get('has_macros')},
            'pefile': {'available': PEFILE_AVAILABLE, 'is_pe': pe_results.get('is_pe')},
            'clamav': clamav_results,
            'archive_inspector': {'supported': True},
        },
        'sandbox_runtime': 'Sentinel Enterprise Docker Container (Multi-Layer Static Analysis + Capa + Archive Inspection)',
    }
    return output


def run_full_sandbox_analysis(file_path: str):
    res = run_full_sandbox_analysis_dict(file_path)
    print(json.dumps(res, ensure_ascii=False))


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '/target'
    run_full_sandbox_analysis(target)
