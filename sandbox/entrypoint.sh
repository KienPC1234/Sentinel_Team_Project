#!/bin/bash
set -e

# Start ClamAV daemon in the background to hold 3.6M+ signatures in memory for ultra-fast scans
if command -v clamd >/dev/null 2>&1; then
    echo "[Sandbox] Initializing ClamAV daemon in background..."
    clamd --config-file=/etc/clamav/clamd.conf &
    # Allow background clamd socket initialization
    for i in {1..20}; do
        if [ -S /var/run/clamav/clamd.ctl ]; then
            echo "[Sandbox] ClamAV socket ready (/var/run/clamav/clamd.ctl)."
            break
        fi
        sleep 1
    done
fi

echo "[Sandbox] Launching Sentinel Zero-Trust Daemon..."
exec python /sandbox/server.py

