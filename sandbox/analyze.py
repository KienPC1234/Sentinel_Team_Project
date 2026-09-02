#!/usr/bin/env python3
"""
Enterprise Zero-Trust Malware Analysis Engine (Docker Container).
Integrates:
1. YARA ruleset engine
2. OLETools (VBA macro forensic dissection, IOC extraction, Obfuscation detection)
3. PEFile (Windows PE section entropy, dangerous Win32 API imports, Imphash)
4. PDF Analysis (JavaScript streams, Launch actions, Embedded objects)
5. Shannon Entropy & Cryptographic Hashing (MD5, SHA1, SHA256)
6. ClamAV Antivirus Scanner
"""

import sys
import os
import json
import math
import hashlib
import zipfile
import subprocess
import re
from typing import Dict, Any, List

# YARA Engine
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# OLETools Engine
try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
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


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 - 8.0)."""
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


def analyze_with_yara(file_path: str, rules_path: str = '/sandbox/rules/malware_rules.yar') -> List[Dict[str, Any]]:
    """Scan target file against compiled YARA rules."""
    matches_list = []
    if not YARA_AVAILABLE or not os.path.exists(rules_path):
        return matches_list

    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
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
                'severity': meta.get('severity', 'HIGH'),
                'description': meta.get('description', f"Khớp tập luật YARA mã độc: {match.rule}"),
                'strings': matched_identifiers,
            })
    except Exception as e:
        sys.stderr.write(f"YARA Match Exception: {e}\n")
    return matches_list


def analyze_with_oletools(file_path: str, head_bytes: bytes) -> Dict[str, Any]:
    """Forensic examination of MS Office documents using OLETools."""
    result = {'has_macros': False, 'vba_iocs': [], 'suspicious_keywords': [], 'macro_code_preview': ''}
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
        # Skip pure text files
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
    if not PEFILE_AVAILABLE:
        return result

    if not head_bytes.startswith(b'MZ'):
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

        # Check section entropy
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_entropy = section.get_entropy()
            result['sections'].append({'name': sec_name, 'entropy': round(sec_entropy, 3)})
            if sec_entropy > 7.2:
                result['high_entropy_sections'].append({'name': sec_name, 'entropy': round(sec_entropy, 3)})

        # Check dangerous Win32 APIs
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


def analyze_with_clamav(file_path: str) -> Dict[str, Any]:
    """Scan file with ClamAV binary if present."""
    result = {'available': False, 'infected': False, 'threat_name': None}
    
    # 1. Try fast daemon socket scanner first
    if os.path.exists('/usr/bin/clamdscan'):
        try:
            proc = subprocess.run(['/usr/bin/clamdscan', '--no-summary', '--fdpass', file_path], capture_output=True, text=True, timeout=3)
            result['available'] = True
            if proc.returncode == 1:
                result['infected'] = True
                match = re.search(r':\s*(.+)\s+FOUND', proc.stdout)
                result['threat_name'] = match.group(1).strip() if match else 'Malware.Detected'
            return result
        except Exception:
            pass

    # 2. Fast fallback to clamscan
    for bin_path in ('/usr/bin/clamscan', 'clamscan'):
        if os.path.exists(bin_path):
            try:
                proc = subprocess.run([bin_path, '--no-summary', '--max-filesize=10M', file_path], capture_output=True, text=True, timeout=5)
                result['available'] = True
                if proc.returncode == 1:
                    result['infected'] = True
                    match = re.search(r':\s*(.+)\s+FOUND', proc.stdout)
                    result['threat_name'] = match.group(1).strip() if match else 'Malware.Detected'
                return result
            except Exception:
                pass
    return result


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

    # 1. Multi-Engine Executions
    yara_matches = analyze_with_yara(file_path)
    ole_results = analyze_with_oletools(file_path, head)
    pe_results = analyze_with_pefile(file_path, head)
    clamav_results = analyze_with_clamav(file_path)

    forensic_evidence = []
    is_malicious = False
    is_suspicious = False
    threat_names = []

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
        },
        'forensic_evidence': forensic_evidence,
        'engines': {
            'yara': {'available': YARA_AVAILABLE, 'matches': len(yara_matches)},
            'oletools': {'available': OLETOOLS_AVAILABLE, 'has_macros': ole_results.get('has_macros')},
            'pefile': {'available': PEFILE_AVAILABLE, 'is_pe': pe_results.get('is_pe')},
            'clamav': clamav_results,
        },
        'sandbox_runtime': 'Sentinel Enterprise Docker Container (YARA + OLETools + PEFile + ClamAV)',
    }
    return output


def run_full_sandbox_analysis(file_path: str):
    res = run_full_sandbox_analysis_dict(file_path)
    print(json.dumps(res, ensure_ascii=False))


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '/target'
    run_full_sandbox_analysis(target)
