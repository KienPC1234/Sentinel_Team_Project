/**
 * ShieldCall VN - PWA Client Helper (TypeScript)
 * Handles Service Worker registration, PWA installation prompts, and update lifecycles.
 */

interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{
    outcome: 'accepted' | 'dismissed';
    platform: string;
  }>;
  prompt(): Promise<void>;
}

declare global {
  interface Window {
    ShieldCallPWA?: typeof ShieldCallPWA;
    Swal?: {
      fire(options: Record<string, unknown>): Promise<{ isConfirmed: boolean }>;
    };
  }
}

declare const process: { env: { NODE_ENV?: string } };

let deferredPrompt: BeforeInstallPromptEvent | null = null;

export const ShieldCallPWA = {
  version: '2026-v2',

  init(): void {
    if (typeof window === 'undefined') return;

    // 1. Register Service Worker (Production Only)
    if ('serviceWorker' in navigator) {
      if (process.env.NODE_ENV !== 'production') {
        void navigator.serviceWorker.getRegistrations().then((registrations) => {
          for (const registration of registrations) {
            void registration.unregister();
          }
        });
        return;
      }

      const registerSW = () => {
        navigator.serviceWorker
          .register('/sw.js', { scope: '/' })
          .then((registration) => {
            // Check if updated service worker is already waiting to activate
            if (registration.waiting && navigator.serviceWorker.controller) {
              this.notifyUpdateAvailable();
            }

            // Check for service worker updates during lifecycle
            registration.addEventListener('updatefound', () => {
              const installingWorker = registration.installing;
              if (installingWorker) {
                installingWorker.addEventListener('statechange', () => {
                  if (
                    installingWorker.state === 'installed' &&
                    navigator.serviceWorker.controller
                  ) {
                    // New version available
                    this.notifyUpdateAvailable();
                  }
                });
              }
            });
          })
          .catch((err) => {
            console.warn('[PWA] Service Worker registration failed:', err);
          });
      };

      if (document.readyState === 'complete') {
        registerSW();
      } else {
        window.addEventListener('load', registerSW);
      }

      // Listen for push notification click routing
      navigator.serviceWorker.addEventListener('message', (event) => {
        const data = event.data as { type?: string; url?: string } | undefined;
        if (data?.type === 'push_click' && data.url) {
          window.location.href = data.url;
        }
      });
    }

    // 2. Capture install prompt
    const isStandalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      ('standalone' in navigator && (navigator as unknown as { standalone: boolean }).standalone === true);
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e as BeforeInstallPromptEvent;

      if (isMobile && !isStandalone) {
        setTimeout(() => {
          void this.promptInstall();
        }, 3000);
      }
    });

    window.addEventListener('appinstalled', () => {
      deferredPrompt = null;
      if (window.Swal) {
        void window.Swal.fire({
          icon: 'success',
          title: 'Đã cài đặt thành công!',
          text: 'ShieldCall VN đã được thêm vào màn hình chính của bạn.',
          background: '#0d111e',
          color: '#fff',
          confirmButtonColor: '#06b6d4',
        });
      }
    });
  },

  async promptInstall(): Promise<boolean> {
    if (!deferredPrompt) return false;

    if (window.Swal) {
      const res = await window.Swal.fire({
        title: 'Cài đặt ShieldCall VN?',
        text: 'Cài đặt ứng dụng để nhận cảnh báo lừa đảo tức thì và trải nghiệm bảo vệ toàn diện.',
        icon: 'info',
        showCancelButton: true,
        confirmButtonText: 'Cài đặt ngay',
        cancelButtonText: 'Để sau',
        background: '#0d111e',
        color: '#fff',
        confirmButtonColor: '#06b6d4',
      });

      if (!res.isConfirmed) return false;
    }

    try {
      await deferredPrompt.prompt();
      const choice = await deferredPrompt.userChoice;
      deferredPrompt = null;
      return choice.outcome === 'accepted';
    } catch {
      return false;
    }
  },

  notifyUpdateAvailable(): void {
    // Graceful notification when a new SW version is waiting
    if (window.Swal) {
      void window.Swal.fire({
        title: 'Cập nhật mới!',
        text: 'Đã có phiên bản ShieldCall VN mới hơn. Tải lại để áp dụng ngay?',
        icon: 'info',
        showCancelButton: true,
        confirmButtonText: 'Tải lại ngay',
        cancelButtonText: 'Bỏ qua',
        background: '#0d111e',
        color: '#fff',
        confirmButtonColor: '#06b6d4',
      }).then((res) => {
        if (res.isConfirmed) {
          window.location.reload();
        }
      });
    }
  },
};

if (typeof window !== 'undefined') {
  window.ShieldCallPWA = ShieldCallPWA;
}
