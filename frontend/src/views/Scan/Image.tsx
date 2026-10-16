'use client';
/* Trang "Kiểm tra Ảnh / Chứng từ" — tái dùng engine quét ảnh của Qr ở chế độ 'image'
 * (OCR nội dung ảnh chụp màn hình, hoá đơn, tin nhắn... + phân tích rủi ro).
 */
import Qr from './Qr';

export default function ImageScan() {
  return <Qr mode="image" />;
}
