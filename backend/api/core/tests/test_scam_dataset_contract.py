"""Regression tests for the first privacy-safe ShieldCall dataset contract."""
from copy import deepcopy
from uuid import uuid4

from django.test import SimpleTestCase

from api.utils.scam_dataset_contract import (
    DatasetContractError, validate_dataset_event,
)


def sample_event():
    return {
        "schema_version": "1.0.0",
        "event_id": str(uuid4()),
        "channel": "voice_call",
        "observed_at": "2026-11-01T10:00:00+07:00",
        "source": {
            "type": "community_report",
            "reference_id": "report_demo_001",
            "permission_status": "approved",
            "license_id": "internal-consent-v1",
            "received_at": "2026-11-01T11:00:00+07:00",
        },
        "number": {
            "e164_token": "hmac:v1:" + "a" * 64,
            "country_calling_code": "+84",
            "format_valid": True,
            "caller_id_verified": False,
        },
        "labels": {
            "assessment": "suspected_scam",
            "tactics": ["otp_request", "urgency_pressure"],
            "evidence_tier": "C",
            "review_status": "pending",
            "verification_status": "unconfirmed",
            "subject_attribution": "not_established",
            "review_id": None,
        },
        "evidence_ids": [],
        "consent_basis": "user_opt_in",
        "consent_scope": ["fraud_analysis"],
    }


class DatasetContractTests(SimpleTestCase):
    def assert_rejected(self, event, code):
        with self.assertRaises(DatasetContractError) as caught:
            validate_dataset_event(event)
        self.assertEqual(caught.exception.code, code)

    def test_unverified_community_report_is_accepted_as_suspicion_only(self):
        original = sample_event()
        validated = validate_dataset_event(original)
        self.assertEqual(validated["labels"]["assessment"], "suspected_scam")
        self.assertEqual(validated["labels"]["verification_status"], "unconfirmed")
        validated["labels"]["tactics"].append("legal_threat")
        self.assertEqual(len(original["labels"]["tactics"]), 2)

    def test_raw_phone_field_rejected(self):
        event = sample_event()
        event["number"]["raw_phone"] = "example-private-value"
        self.assert_rejected(event, "number_shape")

    def test_plain_sha256_without_keyed_hmac_rejected(self):
        event = sample_event()
        event["number"]["e164_token"] = "a" * 64
        self.assert_rejected(event, "number_token")

    def test_unapproved_source_rejected(self):
        event = sample_event()
        event["source"]["permission_status"] = "pending"
        self.assert_rejected(event, "source_permission_not_approved")

    def test_unexpected_raw_transcript_rejected(self):
        event = sample_event()
        event["raw_transcript"] = "private text"
        self.assert_rejected(event, "event_shape")

    def test_report_cannot_claim_verified_scam_without_tier_a(self):
        event = sample_event()
        event["labels"]["assessment"] = "verified_scam_behavior"
        self.assert_rejected(event, "verified_behavior_requires_tier_a")

    def test_report_cannot_claim_legitimate_without_review(self):
        event = sample_event()
        event["labels"]["assessment"] = "legitimate"
        self.assert_rejected(event, "legitimate_requires_review")

    def test_caller_id_cannot_be_marked_verified(self):
        event = sample_event()
        event["number"]["caller_id_verified"] = True
        self.assert_rejected(event, "caller_id_unverified_only")

    def test_tier_a_requires_independent_evidence_and_review(self):
        event = sample_event()
        event["labels"].update({
            "evidence_tier": "A",
            "review_status": "independently_verified",
            "verification_status": "independently_corroborated",
            "review_id": "review_demo_001",
            "assessment": "verified_scam_behavior",
        })
        self.assert_rejected(event, "tier_a_evidence")
        event["evidence_ids"] = ["evidence_demo_001"]
        self.assertEqual(validate_dataset_event(event)["labels"]["evidence_tier"], "A")

    def test_tier_b_requires_human_review_and_evidence(self):
        event = sample_event()
        event["labels"].update({
            "evidence_tier": "B",
            "review_status": "human_reviewed",
            "verification_status": "reviewed_observation",
            "review_id": "review_demo_002",
        })
        event["evidence_ids"] = ["evidence_demo_002"]
        self.assertEqual(validate_dataset_event(event)["labels"]["evidence_tier"], "B")

    def test_synthetic_event_is_separate_and_never_a_real_world_verdict(self):
        event = sample_event()
        event["source"]["type"] = "synthetic"
        event["number"] = None
        event["consent_basis"] = "synthetic"
        event["consent_scope"] = []
        event["evidence_ids"] = []
        event["labels"].update({
            "evidence_tier": "D",
            "assessment": "unknown",
            "verification_status": "synthetic",
        })
        self.assertEqual(validate_dataset_event(event)["labels"]["evidence_tier"], "D")
        event["labels"]["assessment"] = "suspected_scam"
        self.assert_rejected(event, "tier_d_no_real_world_verdict")

    def test_community_report_requires_opt_in(self):
        event = sample_event()
        event["consent_basis"] = "partner_agreement"
        self.assert_rejected(event, "community_opt_in_required")

    def test_timezone_required(self):
        event = sample_event()
        event["observed_at"] = "2026-11-01T10:00:00"
        self.assert_rejected(event, "observed_at")

    def test_event_time_must_not_be_after_receipt(self):
        event = sample_event()
        event["observed_at"] = "2026-11-02T10:00:00+07:00"
        self.assert_rejected(event, "timestamp_order")

    def test_unknown_tactics_and_duplicate_evidence_rejected(self):
        event = sample_event()
        event["labels"]["tactics"].append("invented_tactic")
        self.assert_rejected(event, "tactics")
        event = sample_event()
        event["evidence_ids"] = ["evidence_demo_001", "evidence_demo_001"]
        self.assert_rejected(event, "duplicate_evidence_id")

    def test_errors_do_not_echo_private_values(self):
        event = sample_event()
        secret = "do-not-echo-this-private-input"
        event["number"]["raw_phone"] = secret
        try:
            validate_dataset_event(event)
        except DatasetContractError as error:
            self.assertNotIn(secret, str(error))
        else:
            self.fail("Expected DatasetContractError")
