// ESLint flat config cho frontend — Next.js 16 (App Router) + TypeScript + React.
//
// Lưu ý: Next.js 16 đã bỏ `next lint`, ESLint chạy độc lập qua CLI:
//   npm run lint:eslint        → kiểm tra
//   npm run lint:eslint:fix    → tự sửa lỗi có thể sửa
// `npm run lint` vẫn là oxlint (nhanh, dùng trong vòng lặp dev).
//
// Cấu hình này KHÔNG tham gia vào `next build` (Next 16 đã tách lint khỏi build),
// nên thêm/sửa ở đây không ảnh hưởng việc build hay chạy app.
import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,

  {
    rules: {
      // Ảnh trong dự án đều đến từ S3/CDN với kích thước đã tối ưu sẵn và
      // không chỗ nào dùng next/image → tắt để tránh nhiễu vô ích.
      '@next/next/no-img-element': 'off',

      // Dự án là hybrid Next.js + Django: nhiều `<a href>` cố ý trỏ sang route
      // do Django phục vụ (`/admin/` → route handler proxy, `/api/docs/` →
      // Swagger) để buộc tải lại toàn trang. Rule này báo nhầm là dùng <Link>.
      // Để mức cảnh báo chứ không chặn.
      '@next/next/no-html-link-for-pages': 'warn',

      // `&`, `"`, `'` trong text JSX: nhiều tài liệu tiếng Việt dùng dấu nháy.
      // React không hề lỗi với việc này → cảnh báo.
      'react/no-unescaped-entities': 'warn',

      // ── Nhóm rule mới của eslint-plugin-react-hooks (hướng React Compiler) ──
      // Dự án KHÔNG bật React Compiler (next.config.ts không có reactCompiler).
      // Các rule dưới đây báo hàng loạt cho pattern hợp lệ đang dùng
      // (fetch dữ liệu trong useEffect + setState, biến module-scope).
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/immutability': 'off',
      // Đọc `ref.current` trong lúc render thì vẫn nên cảnh báo (đây là lỗi thật).
      'react-hooks/refs': 'warn',

      // `any` còn xuất hiện ở lớp adapter gọi API; để mức cảnh báo, không chặn.
      '@typescript-eslint/no-explicit-any': 'warn',

      // Biến/hàm không dùng: cảnh báo, bỏ qua tên bắt đầu bằng `_`.
      // (Lỗi import thừa từng làm hỏng `tsc` nên vẫn muốn thấy.)
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // React 17+ tự động có JSX runtime, không cần import React.
      'react/react-in-jsx-scope': 'off',
    },
  },

  // File chạy trong Node (script build, file cấu hình).
  {
    files: ['scripts/**/*.{js,mjs,cjs}', '*.config.{js,mjs,cjs,ts}'],
    languageOptions: {
      globals: {
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
      },
    },
  },

  globalIgnores([
    // Mặc định của eslint-config-next
    '.next/**',
    'out/**',
    'build/**',
    'next-env.d.ts',
    // Bundle Service Worker sinh bởi `npm run build:scripts` (src/sw.ts → public/sw.js)
    'public/sw.js',
  ]),
]);

export default eslintConfig;
