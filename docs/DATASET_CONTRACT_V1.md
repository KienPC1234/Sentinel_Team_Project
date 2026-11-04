# ShieldCall Dataset Contract v1.0.0 — First implementation slice

Status: **development only**. No ingestion endpoint, database migration, external feed, user-data import, production restart, or model retraining is included.

## Purpose

A dataset row represents an **observed call/SMS event**, not an accusation against the registered owner of a telephone number. The caller ID may be spoofed. A valid Vietnamese prefix cannot establish caller identity; a foreign prefix cannot establish fraud.

Implemented in `backend/api/utils/scam_dataset_contract.py`. Tests: `backend/api/core/tests/test_scam_dataset_contract.py`.

## Required event fields

| Field | Meaning |
| --- | --- |
| `schema_version`, `event_id`, `channel` | Version, UUID, voice_call or sms |
| `observed_at` | Event time with explicit timezone |
| `source` | Type, opaque reference ID, approval attestation, license ID, received timestamp |
| `number` | Null or HMAC v1 token, calling code, format flag; caller ID verification must be false in v1 |
| `labels` | Assessment, tactics, evidence tier, review/verification state, attribution and review ID |
| `evidence_ids` | References to evidence stored **outside** the dataset row |
| `consent_basis`, `consent_scope` | Declared intake basis and permitted purposes; not legal proof by themselves |

All fields are strict: unknown fields (including `raw_phone`, `raw_transcript`) are rejected. The module does not create HMACs, redact screenshots, check a license or verify consent; those must be separate security-reviewed components.

### Label taxonomy

- `unknown`: insufficient evidence, no safety conclusion.
- `suspected_scam`: unconfirmed indicators, never proof of criminal conduct.
- `verified_scam_behavior`: independently corroborated **behavior in the event**, not subscriber or person identity; Tier A only.
- `legitimate`: requires human review and evidence, not merely a clean blacklist lookup.
- `unwanted_marketing`: category of reported nuisance; does not imply fraud.

Tactics are controlled values in code (impersonation, OTP requests, pressure, malicious links, money transfers, etc.). They describe observed or alleged behaviors, not proven ownership.

### Evidence and review tiers

| Tier | Allowed status | Required references | Meaning |
| --- | --- | --- | --- |
| A | independently_verified / independently_corroborated | evidence IDs + review ID | Independent corroboration, still no identity attribution |
| B | human_reviewed / reviewed_observation | evidence IDs + review ID | Human-reviewed observation, not necessarily independent truth |
| C | pending / unconfirmed | no review ID | Raw unverified report |
| D | pending / synthetic | no real number/evidence | Synthetic test case, never a real-world verdict |

A large volume of community reports must **not** automatically upgrade a case from C to A. Source `permission_status=approved` is an intake attestation that must be backed by a separately audited source register. `consent_basis=user_opt_in` likewise requires separate consent records, and does not by itself authorize training or sharing.

## Privacy boundaries

- HMAC tokens are **pseudonymous, not anonymous**; they remain linkable and may still qualify as personal data. Use a key outside the database, preferably KMS/HSM, with key IDs and rotation planning.
- Never send raw numbers, transcripts, names, OTPs, screenshots, or audio through this contract. Store evidence in a separate protected store with access controls, retention, deletion, and audit policies.
- This v1 contract prohibits claiming `caller_id_verified=true`. Caller authentication needs an independently verified mechanism, not numbering metadata.
- No raw input is interpolated into validation error messages.
- A valid record is **not** proof of legality, source truthfulness, valid consent, or model suitability. Review against Vietnam's current personal-data law and contracts before collecting live data.

## Next controlled slices

1. Build a source registry with signed/approved provenance, license evidence, retention policy, and consent records.
2. Build a Privacy Gateway to redact and tokenize at intake; fuzz-test for PII leaks.
3. Add staging tables, immutable audit events, review/appeal lifecycle, and deletion propagation.
4. Add independent labeled test sets, temporal/campaign-separated splits, and calibrated false-positive metrics.
5. Only then expose a user report endpoint, gated by security/legal review.

## How to test (CI settings; no production database)

```bash
cd backend
../.venv/bin/python manage.py test api.core.tests.test_scam_dataset_contract --settings=PKV.settings_ci --noinput
../.venv/bin/python manage.py check --settings=PKV.settings_ci
```

No automatic blocking or public blacklist publication is permitted by this slice.
