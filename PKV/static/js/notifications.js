/**
 * ShieldCall VN - Global Notification & Real-time System
 * Handles WebSocket connections for notifications and RAG status.
 */

window.NotificationManager = {
    ws: null,
    ragWs: null,
    isStaff: false,
    _recentHashes: {},  // dedup: hash → timestamp

    init(isStaff = false) {
        this.isStaff = isStaff;
        console.log("[NotificationManager] Initializing (isStaff=" + isStaff + ")...");
        // Connect WebSocket for real-time notifications
        if (window.is_authenticated) {
            this.connectNotifications();
        }
        
        // RAG status is now handled via HTTP polling on the admin page
        this.setupPermissionHandler();
    },

    connectNotifications() {
        if (!window.location.host) return;
        const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        this.ws = new WebSocket(`${proto}://${window.location.host}/ws/notifications/`);

        this.ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'notification') {
                this.handlePush(data);
            }
        };

        this.ws.onclose = () => {
            console.log("[NotificationManager] Socket closed. Reconnecting in 5s...");
            setTimeout(() => this.connectNotifications(), 5000);
        };
    },

    connectRagStatus() {
        // Double check condition before connecting (in case of reconnect)
        if (!this.isStaff || !window.location.pathname.includes('/api/v1/admin/rag/')) {
            return; 
        }

        const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        this.ragWs = new WebSocket(`${proto}://${window.location.host}/ws/rag/`);

        this.ragWs.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'rag_status') {
                this.handleRagUpdate(data);
            }
        };

        this.ragWs.onclose = () => {
             // Only reconnect if still on the correct page
            if (this.isStaff && window.location.pathname.includes('/api/v1/admin/rag/')) {
                setTimeout(() => this.connectRagStatus(), 5000);
            }
        };
    },

    /**
     * Strip markdown syntax for plain-text contexts (toasts, browser notifications).
     */
    stripMd(text) {
        if (!text) return '';
        return text
            .replace(/#{1,6}\s+/g, '')          // headings
            .replace(/\*\*(.+?)\*\*/g, '$1')     // bold
            .replace(/\*(.+?)\*/g, '$1')         // italic
            .replace(/__(.+?)__/g, '$1')          // bold alt
            .replace(/_(.+?)_/g, '$1')            // italic alt
            .replace(/~~(.+?)~~/g, '$1')          // strikethrough
            .replace(/`{1,3}([^`]+)`{1,3}/g, '$1') // code
            .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // links
            .replace(/^\s*[-*+]\s+/gm, '• ')     // unordered list
            .replace(/^\s*\d+\.\s+/gm, '')       // ordered list
            .replace(/^>\s?/gm, '')               // blockquote
            .replace(/---+/g, '')                  // hr
            .trim();
    },

    /**
     * Deduplicate pushes across tabs using a hash + 8s window.
     * Returns true if this message is a duplicate and should be skipped.
     */
    _isDuplicate(data) {
        const raw = (data.title || '') + '|' + (data.message || '') + '|' + (data.notification_type || '');
        let hash = 0;
        for (let i = 0; i < raw.length; i++) {
            hash = ((hash << 5) - hash) + raw.charCodeAt(i);
            hash |= 0;
        }
        const now = Date.now();
        if (this._recentHashes[hash] && now - this._recentHashes[hash] < 8000) {
            return true; // duplicate within 8s window
        }
        this._recentHashes[hash] = now;
        // Cleanup old entries every 50 pushes
        const keys = Object.keys(this._recentHashes);
        if (keys.length > 50) {
            keys.forEach(k => { if (now - this._recentHashes[k] > 10000) delete this._recentHashes[k]; });
        }
        return false;
    },

    handlePush(data) {
        console.log("[Push] Received:", data);

        // Deduplicate across tabs / rapid re-sends
        if (this._isDuplicate(data)) {
            console.log("[Push] Duplicate skipped");
            return;
        }

        const cleanMsg = this.stripMd(data.message);

        // Toast (plain text, no markdown chars)
        if (typeof showToast === 'function') {
            showToast(cleanMsg, data.notification_type || 'info');
        } else {
            console.info("Notification: " + cleanMsg);
        }

        // Dispatch event so the notification bell component can update
        window.dispatchEvent(new CustomEvent('sc:notification', { detail: data }));

        // Browser notification only when tab is NOT visible (avoid double popup)
        if (document.visibilityState !== 'visible' && Notification.permission === "granted") {
            new Notification(data.title || "ShieldCall VN", {
                body: cleanMsg,
                icon: "/static/logo.png"
            });
        }
    },

    handleRagUpdate(data) {
        console.log("[RAG] Update:", data);
        if (typeof showToast !== 'function') return;

        if (data.status === 'RUNNING') {
            showToast(data.message, 'info');
        } else if (data.status === 'SUCCESS') {
            if (typeof showAlert === 'function') {
                showAlert('Thành công', data.message, 'success');
            } else {
                showToast(data.message, 'success');
            }
        } else if (data.status === 'FAILED') {
            if (typeof showAlert === 'function') {
                showAlert('Lỗi RAG', data.message, 'error');
            } else {
                showToast(data.message, 'error');
            }
        }
    },

    async requestPermission() {
        if (!("Notification" in window)) {
            console.log("Browser does not support notifications");
            return;
        }

        if (Notification.permission !== "granted") {
            const permission = await Notification.requestPermission();
            if (permission === "granted") {
                if (typeof showToast === 'function') {
                    showToast("Đã bật thông báo hệ thống", "success");
                }
            }
        }
    },

    setupPermissionHandler() {
        document.addEventListener('mousedown', () => {
            if (Notification.permission === 'default') {
                this.requestPermission();
            }
        }, { once: true });
    }
};

// Global Utility Functions
window.TESTPUSHMESSAGE = async function (msg = "Test push from client") {
    try {
        const csrf = typeof getCSRFToken === 'function' ? getCSRFToken() : '';
        const res = await fetch('/api/v1/notifications/test-push/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
            body: JSON.stringify({ message: msg })
        });
        const data = await res.json();
        console.log("[TestPush] Result:", data);
    } catch (e) {
        console.error("[TestPush] Error:", e);
    }
};

window.REBUILDRAG = async function () {
    if (typeof Swal === 'undefined') {
        if (confirm("Bạn có chắc chắn muốn xóa DB cũ và rebuild index từ đầu không?")) {
            executeRebuildRag();
        }
        return;
    }

    const result = await Swal.fire({
        title: 'Xác nhận xóa?',
        text: "Bạn có chắc chắn muốn xóa DB cũ và rebuild index từ đầu không?",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ff1744',
        cancelButtonColor: '#3085d6',
        confirmButtonText: 'Xóa & Rebuild',
        cancelButtonText: 'Hủy'
    });

    if (result.isConfirmed) {
        executeRebuildRag();
    }
};

async function executeRebuildRag() {
    try {
        const csrf = typeof getCSRFToken === 'function' ? getCSRFToken() : '';
        const res = await fetch('/api/v1/admin/rag/reset/', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrf }
        });
        const data = await res.json();
        if (data.status === 'success') {
            if (typeof showToast === 'function') showToast(data.message, 'info');
        } else {
            if (typeof showAlert === 'function') showAlert('Lỗi', data.message, 'error');
        }
    } catch (e) {
        console.error("[RAGReset] Error:", e);
    }
}
