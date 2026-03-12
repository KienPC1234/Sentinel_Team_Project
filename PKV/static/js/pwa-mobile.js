/**
 * ShieldCall VN - PWA Mobile Support Logic
 * Handles PWA installation prompts and mobile-specific behaviors.
 */

window.ShieldCallPWA = (function() {
    let deferredPrompt;
    const PWA_VERSION = '1.0.0';

    function init() {
        console.log('🛡️ ShieldCall PWA Logic Initialized v' + PWA_VERSION);
        
        // Register Service Worker
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                // Use absolute path for Service Worker
                navigator.serviceWorker.register('/sw.js')
                    .then(reg => console.log('✅ Service Worker Registered'))
                    .catch(err => console.warn('❌ Service Worker Registration Failed:', err));
            });
        }

        // Detect if already installed or running in standalone mode
        const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

        // Catch the install prompt
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            console.log('✨ PWA Installable detected');
            
            // Only show prompt automatically on mobile if not standalone
            if (isMobile && !isStandalone) {
                setTimeout(showMobileInstallPrompt, 3000); // 3-second delay for better UX
            }
        });

        window.addEventListener('appinstalled', (evt) => {
            console.log('🚀 ShieldCall đã được cài đặt thành công!');
            if (typeof Swal !== 'undefined') {
                Swal.fire({
                    icon: 'success',
                    title: 'Đã cài đặt!',
                    text: 'ShieldCall đã được thêm vào màn hình chính của bạn.',
                    background: '#0d0d1f',
                    color: '#fff',
                    confirmButtonColor: '#06b6d4'
                });
            }
        });
    }

    async function showMobileInstallPrompt() {
        if (!deferredPrompt || typeof Swal === 'undefined') return;

        const result = await Swal.fire({
            title: 'Trải nghiệm tốt hơn?',
            text: 'Cài đặt ứng dụng ShieldCall ngay để truy cập nhanh chóng và bảo vệ tốt hơn!',
            icon: 'info',
            showCancelButton: true,
            confirmButtonText: 'Cài đặt ngay',
            cancelButtonText: 'Để sau',
            background: '#0d0d1f',
            color: '#fff',
            confirmButtonColor: '#06b6d4',
            cancelButtonColor: 'rgba(255,255,255,0.1)',
            customClass: {
                popup: 'rounded-[1.5rem] border border-white/10'
            },
            position: 'bottom'
        });

        if (result.isConfirmed) {
            deferredPrompt.prompt();
            const { outcome } = await deferredPrompt.userChoice;
            console.log(`User response to install prompt: ${outcome}`);
            deferredPrompt = null;
        }
    }

    return {
        init: init
    };
})();

// Auto-init on script load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => window.ShieldCallPWA.init());
} else {
    window.ShieldCallPWA.init();
}
