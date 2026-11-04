# ShieldCall VN: Phone number structure and reputation, 2026-11-01

Status: source changes applied to backend and frontend in /data/Sentinel_Team_Project; NOT restarted or built in production.

Validation:
- Django system check: exit 0.
- 15/15 backend regression tests pass.
- TypeScript tsc --noEmit: exit 0.
- oxlint Phone.tsx: zero errors and warnings.

Implementation:
- Vietnamese mobile numbers: domestic 10 digits starting 03/05/07/08/09; international +84 plus 9 national digits.
- Fixed line: validate using libphonenumber allocation metadata instead of a brittle hardcoded list of area codes.
- 0084 dialing normalized to +84. +1 849 is not +84.
- International number with a claim of Vietnamese organizational identity triggers a caution, never an automatic fraud accusation.
- Caller ID spoofing is possible even with valid numbering.
- API outputs phone_structure and reputation_provenance. Phone number format is contextual evidence, not proof of fraud or caller identity.
- Community reports already in the system are identified separately from official verified sources. Official phone blacklist and Trang Trang automatic feeds are NOT connected.
- External web lookup of a queried number is disabled by default. It only runs after explicit external_lookup_consent=true. Do not log phone number or external exception content.
- The frontend offers explicit controls for the Vietnamese-organization claim and external lookup consent, a source explanation panel, and manual Trang Trang reference.

Sources:
https://mst.gov.vn/bo-tttt-day-manh-dinh-danh-cuoc-goi-de-ngan-ngua-lua-dao-tren-khong-gian-mang-19724111208351436.htm
https://spdv.mic.gov.vn/chuyen-sim-11-so-ve-10-so-dich-vu-ngan-hang-co-anh-huong-khong-197118192.htm
https://mst.gov.vn/canh-bao-lua-dao-tu-cuoc-goi-dien-thoai-quoc-te-197159134.htm
https://congan.angiang.gov.vn/canh-bao-thu-doan-gia-mao-so-dien-thoai-hien-thi-de-lua-dao-chiem-doat-tai-san
https://www.trangtrang.com/

Files:
backend/api/utils/vn_phone_numbering.py
backend/api/core/views/scan_views.py
backend/api/core/serializers.py
backend/api/utils/trust_guard.py
frontend/src/views/Scan/Phone.tsx
backend/api/core/tests/test_vn_phone_numbering.py
backend/api/core/tests/test_phone_lookup_consent.py

Rollback backups:
C:\Users\admin\Documents\SentinelToolbox\backups\phone_20261101

Release caution:
The git working tree contains unrelated changes. Building/reloading production without review could release those changes as well. No production restart performed.
