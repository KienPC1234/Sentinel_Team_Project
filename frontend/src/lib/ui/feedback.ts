'use client';

import { toast } from 'sonner';
import Swal from 'sweetalert2';
import { escapeHtml } from '../chat/markdown';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export function showToast(message: string, type: ToastType = 'info'): void {
  if (typeof window === 'undefined') return;
  const msg = String(message || '');
  if (!msg) return;

  switch (type) {
    case 'success':
      toast.success(msg);
      break;
    case 'error':
      toast.error(msg);
      break;
    case 'warning':
      toast.warning(msg);
      break;
    case 'info':
    default:
      toast.info(msg);
      break;
  }
}

export function showAlert(title: string, text: string, icon: 'info' | 'success' | 'error' | 'warning' | 'question' = 'info'): Promise<void> {
  return Swal.fire({
    title: escapeHtml(title),
    text,
    icon,
    background: 'var(--sc-night-2)',
    color: 'var(--sc-white)',
    confirmButtonColor: 'var(--sc-brand)',
  }).then(() => undefined);
}

export interface DialogOptions {
  title?: string;
  icon?: 'info' | 'success' | 'error' | 'warning' | 'question';
  confirmButtonText?: string;
  cancelButtonText?: string;
  input?: 'text' | 'number' | 'email' | 'textarea';
  inputPlaceholder?: string;
}

export async function scAlert(message: string, options: DialogOptions = {}): Promise<void> {
  await Swal.fire({
    title: options.title || 'Thông báo',
    text: String(message ?? ''),
    icon: options.icon || 'info',
    confirmButtonText: options.confirmButtonText || 'OK',
    background: 'var(--sc-night-2)',
    color: 'var(--sc-white)',
  });
}

export async function scConfirm(message: string, options: DialogOptions = {}): Promise<boolean> {
  const result = await Swal.fire({
    title: options.title || 'Xác nhận',
    text: String(message ?? ''),
    icon: options.icon || 'question',
    showCancelButton: true,
    confirmButtonText: options.confirmButtonText || 'Đồng ý',
    cancelButtonText: options.cancelButtonText || 'Hủy',
    background: 'var(--sc-night-2)',
    color: 'var(--sc-white)',
  });
  return !!result.isConfirmed;
}

export async function scPrompt(
  message: string,
  defaultValue = '',
  options: DialogOptions = {},
): Promise<string | null> {
  const result = await Swal.fire({
    title: options.title || 'Nhập thông tin',
    text: String(message ?? ''),
    input: options.input || 'text',
    inputValue: defaultValue ?? '',
    inputPlaceholder: options.inputPlaceholder || '',
    showCancelButton: true,
    confirmButtonText: options.confirmButtonText || 'Xác nhận',
    cancelButtonText: options.cancelButtonText || 'Hủy',
    background: 'var(--sc-night-2)',
    color: 'var(--sc-white)',
  });
  if (!result.isConfirmed) return null;
  return (result.value ?? '') as string;
}
