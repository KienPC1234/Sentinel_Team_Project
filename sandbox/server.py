#!/usr/bin/env python3
"""
Sentinel Enterprise Malware Sandbox Daemon.
Runs 24/7 inside Docker container on port 5005.
Provides high-speed malware analysis API with YARA, OLETools, PEFile, and ClamAV.
"""

import sys
import os
import json
import base64
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from analyze import (
    run_full_sandbox_analysis_dict,
    YARA_AVAILABLE,
    OLETOOLS_AVAILABLE,
    PEFILE_AVAILABLE
)

PORT = int(os.getenv('SANDBOX_PORT', '5005'))


class SandboxRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            self._send_json(200, {
                'status': 'healthy',
                'service': 'Sentinel Zero-Trust Malware Sandbox Daemon',
                'engines': {
                    'yara': YARA_AVAILABLE,
                    'oletools': OLETOOLS_AVAILABLE,
                    'pefile': PEFILE_AVAILABLE,
                    'clamav': True,
                }
            })
        else:
            self._send_json(404, {'error': 'Not Found'})

    def do_POST(self):
        if self.path == '/scan':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                raw_body = self.rfile.read(content_length)
                payload = json.loads(raw_body.decode('utf-8'))
                
                target_file_path = None
                is_temp = False

                # Option A: Direct base64 payload transfer
                if 'file_base64' in payload:
                    b64_data = payload['file_base64']
                    filename = payload.get('file_name', 'target.bin')
                    ext = os.path.splitext(filename)[1] or '.bin'
                    raw_bytes = base64.b64decode(b64_data)
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                        tf.write(raw_bytes)
                        target_file_path = tf.name
                        is_temp = True
                # Option B: Shared volume file path
                elif 'file_path' in payload:
                    fp = payload['file_path']
                    if os.path.exists(fp):
                        target_file_path = fp

                if not target_file_path or not os.path.exists(target_file_path):
                    self._send_json(400, {'error': 'File not found or payload empty'})
                    return

                try:
                    result = run_full_sandbox_analysis_dict(target_file_path)
                    self._send_json(200, result)
                finally:
                    if is_temp and os.path.exists(target_file_path):
                        try:
                            os.remove(target_file_path)
                        except Exception:
                            pass

            except Exception as e:
                self._send_json(500, {'error': str(e)})
        else:
            self._send_json(404, {'error': 'Not Found'})

    def log_message(self, format, *args):
        sys.stderr.write(f"[SandboxDaemon] {self.address_string()} - {format % args}\n")


def run_daemon():
    server = HTTPServer(('0.0.0.0', PORT), SandboxRequestHandler)
    sys.stderr.write(f"🚀 Sentinel Malware Sandbox Daemon running on port {PORT}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    run_daemon()
