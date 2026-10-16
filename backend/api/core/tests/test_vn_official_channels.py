"""Verify official Vietnamese reporting channel descriptions stay accurate."""
from django.test import SimpleTestCase
from api.utils.vn_sources import VN_OFFICIAL_CHANNELS


class VietnamOfficialChannelTests(SimpleTestCase):
    def test_156_is_reporting_number_not_case_verification(self):
        rows = [x for x in VN_OFFICIAL_CHANNELS if x.get("phone") == "156"]
        self.assertEqual(len(rows), 1)
        entry = rows[0]
        self.assertIn("phản ánh", entry["name"].lower())
        self.assertIn("không phải", entry["description"].lower())
        self.assertIn("mic.gov.vn", entry["url"])

    def test_113_is_emergency_not_default_fraud_support(self):
        rows = [x for x in VN_OFFICIAL_CHANNELS if x.get("phone") == "113"]
        self.assertEqual(len(rows), 1)
        self.assertIn("khẩn cấp", rows[0]["description"].lower())

    def test_unverified_contact_not_recommended(self):
        self.assertNotIn("069.2342609", [x.get("phone") for x in VN_OFFICIAL_CHANNELS])
