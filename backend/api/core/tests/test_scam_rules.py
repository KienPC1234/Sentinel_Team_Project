from django.test import SimpleTestCase

from api.utils.scam_rules import PATTERNS, heuristic_score, match_patterns


class ScamRulesTest(SimpleTestCase):
    def test_patterns_include_vn_dictionary(self):
        # Từ điển VN mở rộng phải được nạp (>= 30 mẫu).
        self.assertGreaterEqual(len(PATTERNS), 30)

    def test_detects_otp_and_impersonation(self):
        labels = match_patterns("Công an yêu cầu cung cấp mã OTP để xác minh")
        self.assertIn("Yêu cầu OTP", labels)
        self.assertTrue(any("cơ quan" in l.lower() for l in labels))

    def test_detects_vneid_and_tax(self):
        labels = match_patterns("Cài app VNeID định danh điện tử, hoàn thuế gấp")
        self.assertTrue(any("VNeID" in l for l in labels))
        self.assertTrue(any("thuế" in l.lower() for l in labels))

    def test_benign_text_no_patterns(self):
        self.assertEqual(match_patterns("Anh ơi chiều nay đi cà phê không?"), [])

    def test_score_counts_and_caps(self):
        self.assertEqual(heuristic_score("không có gì"), 0)
        self.assertGreater(heuristic_score("mã OTP"), 0)
        self.assertLessEqual(heuristic_score(" ".join(["otp công an chuyển khoản trúng thưởng khóa tài khoản"] * 20)), 100)

    def test_score_monotonic_with_hits(self):
        low = heuristic_score("mã OTP")
        high = heuristic_score("công an yêu cầu OTP chuyển khoản trúng thưởng khóa tài khoản")
        self.assertGreater(high, low)
