"""Phone lookup privacy regression: no number disclosure without explicit opt-in."""
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from api.core.serializers import ScanPhoneSerializer
from api.core.views.scan_views import _lookup_phone_online_free_services


class PhoneLookupConsentTests(SimpleTestCase):
    def test_default_does_not_send_to_search_provider(self):
        with patch("api.utils.ollama_client.web_search_query") as lookup:
            result = _lookup_phone_online_free_services("+84912345678")
        lookup.assert_not_called()
        self.assertFalse(result["checked"])
        self.assertFalse(result["suspected_disposable"])
        self.assertEqual(result["risk_boost"], 0)

    def test_explicit_opt_in_may_query_web(self):
        with patch("api.utils.ollama_client.web_search_query", return_value=[] ) as lookup:
            result = _lookup_phone_online_free_services("+84912345679", authorized=True)
        lookup.assert_called_once()
        self.assertFalse(result["suspected_disposable"])

    def test_external_exception_never_logs_number(self):
        phone = "+84912398765"
        with patch("api.utils.ollama_client.web_search_query", side_effect=ValueError("query leaked " + phone)):
            with self.assertLogs("api.core.views.scan_views", level="WARNING") as recorded:
                _lookup_phone_online_free_services(phone, authorized=True)
        self.assertNotIn(phone, "\n".join(recorded.output))

    def test_serializer_default_no_external_consent(self):
        s = ScanPhoneSerializer(data={"phone": "0912345678"})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertFalse(s.validated_data["external_lookup_consent"])
        self.assertFalse(s.validated_data["claimed_vietnamese_entity"])

    def test_serializer_opt_in_explicit(self):
        s = ScanPhoneSerializer(data={"phone": "+201012345678", "external_lookup_consent": True})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertTrue(s.validated_data["external_lookup_consent"])


class RiskProvenanceTests(TestCase):
    @patch("api.core.views.scan_views._lookup_phone_online_free_services")
    def test_default_lookup_is_not_authorized_and_provenance_is_explicit(self, lookup):
        lookup.return_value = {"checked": False, "suspected_disposable": False}
        from api.core.views.scan_views import _phone_risk_score
        result = _phone_risk_score("+84912345678")
        lookup.assert_called_once_with("+84912345678", authorized=False)
        source = result["reputation_provenance"]
        self.assertFalse(source["official_blacklist_connected"])
        self.assertFalse(source["trangtrang_connected"])
        self.assertFalse(source["external_search_performed"])
        self.assertEqual(source["local_approved_reports"], 0)
