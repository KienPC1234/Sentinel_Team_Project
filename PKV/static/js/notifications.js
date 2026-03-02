/**
 * ShieldCall VN - Global Notification & Real-time System
 * Handles WebSocket connections for notifications and RAG status.
 */

window.NotificationManager = {
    ws: null,
    ragWs: null,
    isStaff: false,
    _version: '2026-03-02-v3-toast-policy',
    _recentHashes: {},  // dedup: hash → timestamp
    _prefKey: 'sc_notification_pref',
    _snoozeKey: 'sc_notification_snooze_until',

    _log(...args) {
        console.info('[WebPush]', ...args);
    },

    showReliableToast(message, type = 'info') {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type);
            return;
        }
        try {
            const colorMap = {
                success: { bg: 'rgba(16,185,129,0.18)', border: 'rgba(16,185,129,0.45)' },
                error: { bg: 'rgba(239,68,68,0.18)', border: 'rgba(239,68,68,0.45)' },
                warning: { bg: 'rgba(245,158,11,0.18)', border: 'rgba(245,158,11,0.45)' },
                info: { bg: 'rgba(6,182,212,0.18)', border: 'rgba(6,182,212,0.45)' },
            };
            const c = colorMap[type] || colorMap.info;
            const toast = document.createElement('div');
            toast.className = 'sc-ws-toast';
            toast.textContent = message;
            toast.style.position = 'fixed';
            toast.style.right = '16px';
            toast.style.bottom = '92px';
            toast.style.maxWidth = '420px';
            toast.style.padding = '10px 14px';
            toast.style.borderRadius = '12px';
            toast.style.backdropFilter = 'blur(10px)';
            toast.style.border = `1px solid ${c.border}`;
            toast.style.background = c.bg;
            toast.style.color = '#fff';
            toast.style.fontSize = '13px';
            toast.style.fontWeight = '600';
            toast.style.zIndex = '2147483647';
            toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.35)';
            toast.style.transform = 'translateX(20px)';
            toast.style.opacity = '0';
            toast.style.transition = 'all .2s ease';

            const stack = document.querySelectorAll('.sc-ws-toast');
            let offset = 92;
            stack.forEach(el => { offset += (el.offsetHeight || 44) + 8; });
            toast.style.bottom = `${offset}px`;

            document.body.appendChild(toast);
            requestAnimationFrame(() => {
                toast.style.transform = 'translateX(0)';
                toast.style.opacity = '1';
            });

            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(20px)';
                setTimeout(() => toast.remove(), 240);
            }, 3600);
        } catch (e) {
            console.info('Notification:', message);
        }
    },

    init(isStaff = false) {
        this.isStaff = isStaff;
        console.log("[NotificationManager] Initializing (isStaff=" + isStaff + ", version=" + this._version + ")...");
        this._log('permission=', (typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'));
        // Connect WebSocket for real-time notifications
        if (window.is_authenticated) {
            this.connectNotifications();
        }

        this.initNotificationBanner();
        this.setupPermissionHandler();

        if (window.is_authenticated && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
            this.ensureWebPushSubscription();
        }

        if (window.is_authenticated && typeof Notification !== 'undefined' && Notification.permission === 'denied') {
            this.showReliableToast('Bạn đã chặn thông báo. Vào Site settings của trình duyệt để bật lại.', 'warning');
        }
    },

    initNotificationBanner() {
        const banner = document.getElementById('sc-noti-banner');
        if (!banner) return;

        const allowBtn = document.getElementById('sc-noti-allow');
        const laterBtn = document.getElementById('sc-noti-later');
        const denyBtn = document.getElementById('sc-noti-deny');

        if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window) || !window.is_authenticated) {
            banner.classList.add('hidden');
            return;
        }

        const pref = localStorage.getItem(this._prefKey) || 'later';
        const snoozeUntil = parseInt(localStorage.getItem(this._snoozeKey) || '0', 10);
        const now = Date.now();

        const shouldShow = Notification.permission === 'default' && pref !== 'deny' && (!Number.isFinite(snoozeUntil) || snoozeUntil <= now);
        banner.classList.toggle('hidden', !shouldShow);

        if (allowBtn) {
            allowBtn.onclick = async () => {
                try {
                    const permission = await Notification.requestPermission();
                    if (permission === 'granted') {
                        localStorage.setItem(this._prefKey, 'allow');
                        localStorage.removeItem(this._snoozeKey);
                        banner.classList.add('hidden');
                        await this.ensureWebPushSubscription();
                    } else if (permission === 'denied') {
                        localStorage.setItem(this._prefKey, 'deny');
                        banner.classList.add('hidden');
                        this.showReliableToast('Bạn đã từ chối thông báo. Có thể bật lại trong Site settings.', 'warning');
                    } else {
                        localStorage.setItem(this._prefKey, 'later');
                        localStorage.setItem(this._snoozeKey, String(Date.now() + (2 * 24 * 60 * 60 * 1000)));
                        banner.classList.add('hidden');
                    }
                } catch (e) {
                    console.warn('[WebPush] Permission request failed', e);
                }
            };
        }

        if (laterBtn) {
            laterBtn.onclick = () => {
                localStorage.setItem(this._prefKey, 'later');
                localStorage.setItem(this._snoozeKey, String(Date.now() + (2 * 24 * 60 * 60 * 1000)));
                banner.classList.add('hidden');
            };
        }

        if (denyBtn) {
            denyBtn.onclick = async () => {
                localStorage.setItem(this._prefKey, 'deny');
                banner.classList.add('hidden');
                await this.syncUnsubscribe();
            };
        }
    },

    async syncUnsubscribe() {
        try {
            if (!('serviceWorker' in navigator)) return;
            const registration = await navigator.serviceWorker.getRegistration('/');
            if (!registration) return;
            const subscription = await registration.pushManager.getSubscription();
            if (!subscription) return;

            const resp = await fetch('/api/v1/push/unsubscribe/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': (typeof getCSRFToken === 'function' ? getCSRFToken() : ''),
                },
                body: JSON.stringify({ endpoint: subscription.endpoint }),
            });
            if (!resp.ok) {
                const txt = await resp.text();
                this._log('Unsubscribe API failed', resp.status, txt.slice(0, 220));
            } else {
                this._log('Unsubscribe API success');
            }
            await subscription.unsubscribe();
            this._log('Browser subscription removed');
        } catch (e) {
            console.warn('[WebPush] Unsubscribe sync failed', e);
        }
    },

    urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
        const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    },

    async ensureWebPushSubscription() {
        try {
            if (!window.is_authenticated) {
                this._log('Skip subscribe: user is not authenticated');
                return;
            }
            if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) {
                this._log('Skip subscribe: browser does not support Notification/ServiceWorker/PushManager');
                return;
            }
            if (Notification.permission !== 'granted') {
                this._log('Skip subscribe: Notification.permission =', Notification.permission);
                return;
            }
            const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname);
            if (!window.isSecureContext && !isLocalhost) {
                this._log('Skip subscribe: insecure context. Need HTTPS (or localhost).');
                this.showReliableToast('WebPush cần HTTPS để đăng ký thông báo.', 'warning');
                return;
            }

            if (!window.WEBPUSH_PUBLIC_KEY) {
                const keyResp = await fetch('/api/v1/push/public-key/');
                if (keyResp.ok) {
                    const keyData = await keyResp.json();
                    window.WEBPUSH_PUBLIC_KEY = keyData.public_key || '';
                    this._log('Fetched VAPID public key');
                } else {
                    const txt = await keyResp.text();
                    this._log('Public key API failed', keyResp.status, txt.slice(0, 220));
                }
            }
            if (!window.WEBPUSH_PUBLIC_KEY) {
                console.warn('[WebPush] Missing WEBPUSH_PUBLIC_KEY');
                this.showReliableToast('Thiếu VAPID public key, chưa thể đăng ký thông báo.', 'error');
                return;
            }

            const registration = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
            this._log('Service worker registered', registration.scope);

            navigator.serviceWorker.addEventListener('message', (event) => {
                if (event?.data?.type === 'push_click' && event?.data?.url) {
                    window.location.href = event.data.url;
                }
            });

            let subscription = await registration.pushManager.getSubscription();
            if (!subscription) {
                subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: this.urlBase64ToUint8Array(window.WEBPUSH_PUBLIC_KEY),
                });
                this._log('Created new browser subscription');
            } else {
                this._log('Reusing existing browser subscription');
            }

            const subscribeResp = await fetch('/api/v1/push/subscribe/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': (typeof getCSRFToken === 'function' ? getCSRFToken() : ''),
                },
                body: JSON.stringify(subscription.toJSON()),
            });

            if (!subscribeResp.ok) {
                const txt = await subscribeResp.text();
                this._log('Subscribe API failed', subscribeResp.status, txt.slice(0, 260));
                this.showReliableToast('Đăng ký WebPush thất bại. Mở Console để xem chi tiết.', 'error');
                return;
            }

            this._log('Subscribe API success');
            this.showReliableToast('Đã đăng ký thông báo trình duyệt thành công.', 'success');
        } catch (e) {
            console.warn('[WebPush] Subscription setup failed', e);
            this.showReliableToast('Lỗi khi đăng ký WebPush. Mở Console để kiểm tra.', 'error');
        }
    },

    async debugStatus() {
        const state = {
            version: this._version,
            authenticated: !!window.is_authenticated,
            permission: (typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'),
            isSecureContext: !!window.isSecureContext,
            hasServiceWorker: ('serviceWorker' in navigator),
            hasPushManager: ('PushManager' in window),
            hasPublicKey: !!window.WEBPUSH_PUBLIC_KEY,
            origin: window.location.origin,
        };
        try {
            if ('serviceWorker' in navigator) {
                const reg = await navigator.serviceWorker.getRegistration('/');
                state.swRegistered = !!reg;
                state.swScope = reg ? reg.scope : null;
                if (reg) {
                    const sub = await reg.pushManager.getSubscription();
                    state.hasBrowserSubscription = !!sub;
                    state.endpointPreview = sub?.endpoint ? `${sub.endpoint.slice(0, 48)}...` : null;
                }
            }
        } catch (e) {
            state.debugError = String(e);
        }
        console.table(state);
        return state;
    },

    async forceResubscribe() {
        try {
            if (!('serviceWorker' in navigator)) return;
            const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
            const oldSub = await reg.pushManager.getSubscription();
            if (oldSub) {
                await this.syncUnsubscribe();
            }
            await this.ensureWebPushSubscription();
        } catch (e) {
            console.warn('[WebPush] Force re-subscribe failed', e);
        }
    },

    connectNotifications() {
        if (!window.location.host) return;
        const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        this.ws = new WebSocket(`${proto}://${window.location.host}/ws/notifications/`);

        this.ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'notification') {
                this.handlePush(data);
            } else if (data.type === 'notification_count') {
                this.handleUnreadCount(data);
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

        const permission = (typeof Notification !== 'undefined' ? Notification.permission : 'unsupported');
        if (permission !== 'granted') {
            this.showReliableToast(cleanMsg, data.notification_type || 'info');
            this._log('Toast-only mode for WS push (permission=' + permission + ')');
        } else {
            this.showBrowserNotification(data).then((shown) => {
                if (!shown) {
                    this.showReliableToast(cleanMsg, data.notification_type || 'info');
                    this._log('Browser notify failed -> fallback toast');
                }
            });
        }

        // Dispatch event so the notification bell component can update
        window.dispatchEvent(new CustomEvent('sc:notification', { detail: data }));

        // Delivery policy:
        // - online: WebSocket (toast + bell)
        // - offline/background: native WebPush handled by service worker
    },

    async showBrowserNotification(data) {
        try {
            if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return false;

            const title = data?.title || 'ShieldCall VN';
            const body = this.stripMd(data?.message || 'Bạn có thông báo mới');
            const url = data?.url || '/dashboard/';
            const options = {
                body,
                icon: '/static/logo.png',
                badge: '/static/logo.png',
                data: { url },
                tag: `ws-${data?.notification_type || 'info'}-${Date.now()}`,
                renotify: false,
                requireInteraction: false,
            };

            if ('serviceWorker' in navigator) {
                const registration = await navigator.serviceWorker.getRegistration('/');
                if (registration && typeof registration.showNotification === 'function') {
                    await registration.showNotification(title, options);
                    this._log('Browser notification displayed via service worker');
                    return true;
                }
            }

            const n = new Notification(title, options);
            n.onclick = () => {
                try { window.focus(); } catch (_) {}
                if (url) window.location.href = url;
                n.close();
            };
            this._log('Browser notification displayed via Notification API fallback');
            return true;
        } catch (e) {
            console.warn('[WebPush] Failed to display browser notification', e);
            return false;
        }
    },

    handleUnreadCount(data) {
        const count = Number(data?.unread_count);
        if (!Number.isFinite(count)) return;
        window.dispatchEvent(new CustomEvent('sc:notification-count', {
            detail: { unread_count: count }
        }));
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
                localStorage.setItem(this._prefKey, 'allow');
                localStorage.removeItem(this._snoozeKey);
                this.ensureWebPushSubscription();
                if (typeof showToast === 'function') {
                    showToast("Đã bật thông báo hệ thống", "success");
                }
            }
        }
    },

    setupPermissionHandler() {
        // Intentionally no auto-prompt. Permission requests are controlled by banner choice.
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

window.WEBPUSH_STATUS = async function () {
    if (!window.NotificationManager) return null;
    return window.NotificationManager.debugStatus();
};

window.WEBPUSH_RESUBSCRIBE = async function () {
    if (!window.NotificationManager) return;
    return window.NotificationManager.forceResubscribe();
};

window.WEBPUSH_VERSION = function () {
    if (!window.NotificationManager) return null;
    const v = window.NotificationManager._version || 'unknown';
    console.info('[WebPush] Version:', v);
    return v;
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
