"""Regression tests for Vietnamese numbering and conservative spoofing warnings."""
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from api.core.serializers import ScanPhoneSerializer
from api.utils.vn_phone_numbering import analyze_number_structure


class VietnamesePhoneNumberStructureTests(SimpleTestCase):
    def test_domestic_and_e164_mobile_are_equivalent(self):
        local = analyze_number_structure("0912345678")
        intl = analyze_number_structure("+84 912 345 678")
        self.assertEqual(local["status"], "valid_vn_mobile")
        self.assertEqual(intl["status"], "valid_vn_mobile")
        self.assertEqual(intl["national_prefix"], "091")
        self.assertFalse(intl["caller_id_verified"])

    def test_other_mobile_prefixes(self):
        for prefix in ("03", "05", "07", "08", "09"):
            with self.subTest(prefix=prefix):
                result = analyze_number_structure(prefix + "12345678")
                self.assertEqual(result["country_calling_code"], "+84")
                self.assertTrue(result["is_vietnam"])

    def test_domestic_fixed_line_support(self):
        result = analyze_number_structure("02439363636")
        self.assertEqual(result["country_calling_code"], "+84")
        self.assertTrue(result["is_vietnam"])
        self.assertIn(result["status"], ("valid_vn_landline", "unverified_vn_prefix", "invalid_vn_number"))

    def test_00_84_is_international_dialing_to_vietnam(self):
        result = analyze_number_structure("0084912345678")
        self.assertEqual(result["status"], "valid_vn_mobile")

    def test_prefix_plus_1849_is_not_plus_84(self):
        result = analyze_number_structure("+18495550123", claimed_vietnamese_entity=True)
        self.assertFalse(result["is_vietnam"])
        self.assertEqual(result["country_calling_code"], "+1")
        self.assertTrue(result["foreign_claim_mismatch"])
        self.assertEqual(result["status"], "foreign_number")

    def test_foreign_number_only_warned_when_claim_supplied(self):
        number = "+201012345678"
        result = analyze_number_structure(number)
        self.assertEqual(result["status"], "foreign_number")
        self.assertFalse(result["foreign_claim_mismatch"])
        warning = analyze_number_structure(number, claimed_vietnamese_entity=True)
        self.assertTrue(warning["foreign_claim_mismatch"])
        self.assertFalse(warning["caller_id_verified"])

    def test_invalid_vn_prefix_not_auto_scam(self):
        result = analyze_number_structure("+84123456789")
        self.assertNotIn(result["status"], ("valid_vn_mobile", "valid_vn_landline"))
        self.assertFalse(result["caller_id_verified"])

    def test_serializer_preserves_country_code_and_supports_fixed_line(self):
        for phone in ("0912345678", "02439363636", "+18495550123"):
            with self.subTest(phone=phone):
                s = ScanPhoneSerializer(data={"phone": phone, "claimed_vietnamese_entity": True})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertTrue(s.validated_data["phone"].startswith("+"))
                self.assertTrue(s.validated_data["claimed_vietnamese_entity"])


class PhoneStructureIntegrationTests(TestCase):
    @patch("api.core.views.scan_views._lookup_phone_online_free_services", return_value={})
    def test_scan_result_includes_numbering_evidence_and_caller_context(self, _lookup):
        from api.core.views.scan_views import _phone_risk_score
        from api.utils.trust_guard import apply_guardrail

        result = _phone_risk_score("+201012345678", claimed_vietnamese_entity=True)
        self.assertTrue(result["phone_structure"]["foreign_claim_mismatch"])
        self.assertIn("phone_numbering", [e["source"] for e in result["forensic_evidence"]])
        self.assertTrue(any("mã quốc gia khác" in x.lower() for x in result["reasons"]))
        apply_guardrail(result, kind="phone")
        self.assertTrue(result["evidence"])
        self.assertNotEqual(result["guardrail"]["tier"], "LIKELY_SAFE")
