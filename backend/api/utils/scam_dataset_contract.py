"""Strict v1 contract for privacy-minimized ShieldCall incident observations.

This module validates a proposed dataset row; it does NOT grant permission to
collect personal data, anonymize evidence, or authenticate caller identity.
No database, network, model, or production side effects.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import re
from typing import Any, Mapping
from uuid import UUID

SCHEMA_VERSION = "1.0.0"
CHANNELS = frozenset({"voice_call", "sms"})
SOURCE_TYPES = frozenset({
    "community_report", "official_notice", "partner_feed",
    "research_dataset", "synthetic",
})
ASSESSMENTS = frozenset({
    "unknown", "suspected_scam", "verified_scam_behavior",
    "legitimate", "unwanted_marketing",
})
TACTICS = frozenset({
    "bank_impersonation", "government_impersonation",
    "telecom_impersonation", "delivery_impersonation",
    "family_impersonation", "otp_request", "money_transfer_request",
    "malicious_link", "app_install_request", "urgency_pressure",
    "legal_threat", "investment_lure",
})
REVIEW_STATUSES = frozenset({"pending", "human_reviewed", "independently_verified"})
CONSENT_BASES = frozenset({
    "user_opt_in", "partner_agreement", "public_notice_reviewed", "synthetic",
})
CONSENT_SCOPES = frozenset({"fraud_analysis", "evidence_review", "model_training"})
_TOKEN = re.compile(r"^hmac:v1:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{2,127}$")
_LICENSE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:_-]{1,63}$")
_COUNTRY = re.compile(r"^\+[1-9][0-9]{0,2}$")


class DatasetContractError(ValueError):
    """A machine-readable code; never includes user-supplied values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise DatasetContractError(code)


def _shape(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), code)
    _require(set(value.keys()) == keys, code)
    return value


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID.fullmatch(value))


def _timestamp(value: Any, code: str) -> datetime:
    _require(isinstance(value, str) and len(value) <= 40, code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DatasetContractError(code) from None
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None, code)
    return parsed


def _unique_enum_list(value: Any, allowed: frozenset[str], code: str, limit: int) -> None:
    _require(isinstance(value, list) and len(value) <= limit, code)
    _require(all(isinstance(item, str) and item in allowed for item in value), code)
    _require(len(set(value)) == len(value), code)


def validate_dataset_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed on unexpected fields, weak provenance, or overstated labels.

    Returns a detached validated copy. A passing record is NOT necessarily
    legally usable or factually true; reviewers must verify attestations.
    Error messages deliberately contain no record values or PII.
    """
    event = _shape(event, {
        "schema_version", "event_id", "channel", "observed_at", "source",
        "number", "labels", "evidence_ids", "consent_basis", "consent_scope",
    }, "event_shape")
    _require(event["schema_version"] == SCHEMA_VERSION, "schema_version")
    try:
        UUID(event["event_id"]) if isinstance(event["event_id"], str) else None
        _require(isinstance(event["event_id"], str), "event_id")
    except (ValueError, AttributeError):
        raise DatasetContractError("event_id") from None
    _require(event["channel"] in CHANNELS if isinstance(event["channel"], str) else False, "channel")
    observed_at = _timestamp(event["observed_at"], "observed_at")

    source = _shape(event["source"], {
        "type", "reference_id", "permission_status", "license_id", "received_at",
    }, "source_shape")
    _require(source["type"] in SOURCE_TYPES if isinstance(source["type"], str) else False, "source_type")
    _require(_identifier(source["reference_id"]), "source_reference_id")
    _require(source["permission_status"] == "approved", "source_permission_not_approved")
    _require(isinstance(source["license_id"], str) and bool(_LICENSE.fullmatch(source["license_id"])), "source_license")
    received_at = _timestamp(source["received_at"], "source_received_at")
    _require(observed_at <= received_at, "timestamp_order")

    number = event["number"]
    if number is not None:
        number = _shape(number, {
            "e164_token", "country_calling_code", "format_valid", "caller_id_verified",
        }, "number_shape")
        _require(isinstance(number["e164_token"], str) and bool(_TOKEN.fullmatch(number["e164_token"])), "number_token")
        cc = number["country_calling_code"]
        _require(cc is None or (isinstance(cc, str) and bool(_COUNTRY.fullmatch(cc))), "country_calling_code")
        _require(type(number["format_valid"]) is bool, "number_format_valid")
        _require(number["caller_id_verified"] is False, "caller_id_unverified_only")

    labels = _shape(event["labels"], {
        "assessment", "tactics", "evidence_tier", "review_status",
        "verification_status", "subject_attribution", "review_id",
    }, "labels_shape")
    assessment = labels["assessment"]
    tier = labels["evidence_tier"]
    review = labels["review_status"]
    verification = labels["verification_status"]
    _require(isinstance(assessment, str) and assessment in ASSESSMENTS, "assessment")
    _unique_enum_list(labels["tactics"], TACTICS, "tactics", 12)
    _require(isinstance(tier, str) and tier in {"A", "B", "C", "D"}, "evidence_tier")
    _require(isinstance(review, str) and review in REVIEW_STATUSES, "review_status")
    _require(isinstance(verification, str) and verification in {
        "unconfirmed", "reviewed_observation", "independently_corroborated", "synthetic",
    }, "verification_status")
    _require(labels["subject_attribution"] == "not_established", "identity_attribution_not_supported")
    _require(labels["review_id"] is None or _identifier(labels["review_id"]), "review_id")

    evidence_ids = event["evidence_ids"]
    _require(isinstance(evidence_ids, list) and len(evidence_ids) <= 20, "evidence_ids")
    _require(all(_identifier(v) for v in evidence_ids), "evidence_ids")
    _require(len(set(evidence_ids)) == len(evidence_ids), "duplicate_evidence_id")

    _require(isinstance(event["consent_basis"], str) and event["consent_basis"] in CONSENT_BASES, "consent_basis")
    _unique_enum_list(event["consent_scope"], CONSENT_SCOPES, "consent_scope", 3)
    _require("fraud_analysis" in event["consent_scope"] or source["type"] == "synthetic", "fraud_analysis_scope_required")
    if source["type"] == "community_report":
        _require(event["consent_basis"] == "user_opt_in", "community_opt_in_required")

    if tier == "A":
        _require(review == "independently_verified" and verification == "independently_corroborated", "tier_a_verification")
        _require(bool(evidence_ids) and labels["review_id"] is not None, "tier_a_evidence")
    elif tier == "B":
        _require(review == "human_reviewed" and verification == "reviewed_observation", "tier_b_review")
        _require(bool(evidence_ids) and labels["review_id"] is not None, "tier_b_evidence")
    elif tier == "C":
        _require(review == "pending" and verification == "unconfirmed", "tier_c_unconfirmed")
        _require(labels["review_id"] is None, "tier_c_review_id")
    else:
        _require(source["type"] == "synthetic" and event["consent_basis"] == "synthetic", "tier_d_synthetic_only")
        _require(review == "pending" and verification == "synthetic", "tier_d_verification")
        _require(number is None and not evidence_ids and labels["review_id"] is None, "tier_d_no_real_identifiers")
        _require(assessment == "unknown", "tier_d_no_real_world_verdict")

    _require((source["type"] == "synthetic") == (tier == "D"), "synthetic_tier_consistency")
    _require((event["consent_basis"] == "synthetic") == (tier == "D"), "synthetic_basis_consistency")
    if assessment == "verified_scam_behavior":
        _require(tier == "A", "verified_behavior_requires_tier_a")
    if assessment == "legitimate":
        _require(tier in {"A", "B"}, "legitimate_requires_review")
    return deepcopy(dict(event))
