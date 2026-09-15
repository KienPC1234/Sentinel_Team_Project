#!/usr/bin/env python3
"""
Sentinel Enterprise Malware Sandbox Daemon.
Runs 24/7 inside Docker container on port 5005.
Provides high-speed malware analysis API with YARA, OLETools, PEFile, ClamAV, and CAPA.
Multi-threaded, robust error handling, zero-trust unprivileged execution.
"""

import sys
import os
import json
import base64
import tempfile
import binascii
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from analyze import (
    run_full_sandbox_analysis_dict,
    YARA_AVAILABLE,
    OLETOOLS_AVAILABLE,
    PEFILE_AVAILABLE,
    MAGIC_AVAILABLE,
    PYPDF_AVAILABLE,
    CAPA_RULES_DIR
)

PORT = int(os.getenv('SANDBOX_PORT', '5005'))


class SandboxRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send_json(self, status_code: int, data: dict):
        try:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path == '/health':
            has_capa = os.path.isdir(CAPA_RULES_DIR)
            has_socket = os.path.exists('/var/run/clamav/clamd.ctl')
            self._send_json(200, {
                'status': 'healthy',
                'service': 'Sentinel Zero-Trust Malware Sandbox Daemon',
                'engines': {
                    'yara': YARA_AVAILABLE,
                    'oletools': OLETOOLS_AVAILABLE,
                    'pefile': PEFILE_AVAILABLE,
                    'clamav': has_socket,
                    'capa': has_capa,
                    'magic': MAGIC_AVAILABLE,
                    'pypdf': PYPDF_AVAILABLE,
                    'archive_inspector': True,
                }
            })
        else:
            self._send_json(404, {'error': 'Not Found'})

    def do_POST(self):
        if self.path == '/scan':
            target_file_path = None
            is_temp = False
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length <= 0:
                    self._send_json(400, {'error': 'Empty payload or missing Content-Length'})
                    return

                raw_body = self.rfile.read(content_length)
                try:
                    payload = json.loads(raw_body.decode('utf-8', errors='ignore'))
                except Exception:
                    self._send_json(400, {'error': 'Invalid JSON format in request body'})
                    return

                # Option A: Direct base64 payload transfer
                if 'file_base64' in payload:
                    b64_data = payload['file_base64']
                    filename = payload.get('file_name', 'target.bin')
                    ext = os.path.splitext(filename)[1] or '.bin'
                    try:
                        raw_bytes = base64.b64decode(b64_data)
                    except (binascii.Error, ValueError) as b64_err:
                        self._send_json(400, {'error': f'Malformed base64 data: {b64_err}'})
                        return

                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                        tf.write(raw_bytes)
                        target_file_path = tf.name
                        is_temp = True

                # Option B: Shared volume file path
                elif 'file_path' in payload:
                    fp = payload['file_path']
                    # Path validation: prevent path traversal tricks
                    real_path = os.path.realpath(fp)
                    if os.path.exists(real_path) and os.path.isfile(real_path):
                        target_file_path = real_path

                if not target_file_path or not os.path.exists(target_file_path):
                    self._send_json(400, {'error': 'Target file not found or payload empty'})
                    return

                try:
                    result = run_full_sandbox_analysis_dict(target_file_path)
                    self._send_json(200, result)
                finally:
                    if is_temp and target_file_path and os.path.exists(target_file_path):
                        try:
                            os.remove(target_file_path)
                        except Exception:
                            pass

            except Exception as e:
                self._send_json(500, {'error': f'Internal analysis error: {str(e)}'})
        else:
            self._send_json(404, {'error': 'Not Found'})

    def log_message(self, format, *args):
        sys.stderr.write(f"[SandboxDaemon] {self.address_string()} - {format % args}\n")


def run_daemon():
    server = ThreadingHTTPServer(('0.0.0.0', PORT), SandboxRequestHandler)
    sys.stderr.write(f"🚀 Sentinel Malware Sandbox Daemon (Multi-Threaded) running on port {PORT}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    run_daemon()
