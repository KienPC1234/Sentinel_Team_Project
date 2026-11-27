"""R83/R84: source-locked, independent signed-label dataset INTAKE ONLY.

No network, no AI inference, no access to production DB or quarantined SMS.
Signatures show key possession, NOT independent authority accreditation.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from collections import Counter, defaultdict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LABELS = {'observed_scam_action', 'no_observable_scam_action', 'indeterminate'}
CHANNELS = {'sms', 'email', 'messaging', 'web', 'voice_transcript'}
REJECT_SOURCE = {'revealwire', 'rsb', 'rsbplus', 'synthetic', 'generated', 'template'}
PII = [
    ('raw_email', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ('raw_http_link', re.compile(r'(?i)\b(?:https?://|www\.)\S+')),
    ('raw_vn_phone', re.compile(r'(?<!\w)(?:\+?84|0)[- .]?(?:\d[- .]?){9,10}(?!\w)')),
    ('long_number', re.compile(r'(?<!\d)\d{8,}(?!\d)')),
    ('token_query', re.compile(r'(?i)\b(?:password|token|secret|api[_-]?key)\s*[:=]\s*\S{6,}')),
    (
        'leaked_label',
        re.compile(
            r'(?i)(?:\b(?:ground_truth|correct_label)\s*[:=]|\[(?:scam|legitimate|fraud)\]|__SCAM__)'
        ),
    ),
]

# R84 fixed, versioned baseline; an adversarial caller must not replace
# existing known synthetic hashes with an empty/smaller self-provided file.
# Updating the corpus requires an audited new code/version release.
KNOWN_PRIOR_SHA256 = 'c39ba29db75165758ca6b3dea0b87dad238a22c218b57830fae56af621f5a4c2'
KNOWN_PRIOR_COUNT = 3158


class Rejected(ValueError):
    """Raised when candidate dataset records, grants, or signatures fail verification."""


def fail(code: str):
    raise Rejected(code)


def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf8')


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha_file(path: pathlib.Path) -> str:
    return digest(path.read_bytes())


def load_pinned_prior(path: pathlib.Path) -> set[str]:
    if sha_file(path) != KNOWN_PRIOR_SHA256:
        fail('known_prior_fingerprint_sha_mismatch')
    lines = path.read_text(encoding='ascii').splitlines()
    if len(lines) != KNOWN_PRIOR_COUNT or len(set(lines)) != KNOWN_PRIOR_COUNT:
        fail('known_prior_fingerprint_count_mismatch')
    if any(not re.fullmatch(r'[0-9a-f]{64}', x) for x in lines):
        fail('known_prior_fingerprint_schema')
    return set(lines)


def utc(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, AttributeError, ValueError):
        fail('invalid_timestamp')
    if parsed.tzinfo is None:
        fail('timestamp_not_timezone_aware')
    return parsed.astimezone(dt.timezone.utc)


def open_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding='utf8'))
    except (ValueError, UnicodeError):
        fail('bad_json')


def load_lines(path: pathlib.Path) -> list:
    try:
        return [json.loads(line) for line in path.read_text(encoding='utf8').splitlines() if line.strip()]
    except (ValueError, UnicodeError):
        fail('bad_jsonl')


def trusted(keys: dict, key_id: str, role: str) -> Ed25519PublicKey:
    obj = keys.get(key_id)
    if not obj or obj.get('role') != role:
        fail('untrusted_signer')
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(obj['public_key_b64'], validate=True))
    except (ValueError, KeyError):
        fail('invalid_trust_key')


def signed(keys: dict, key_id: str, role: str, payload: dict, signature: str) -> None:
    key = trusted(keys, key_id, role)
    try:
        key.verify(base64.b64decode(signature, validate=True), canonical(payload))
    except Exception:
        fail('signature_invalid')


def label_statement(record: dict, label: str) -> dict:
    # R84 domain-separated, fully bound signed snapshot.
    # Collection date/channel/synthetic origin must be authenticated by
    # BOTH independent reviewers, not mutable after their signatures.
    return {
        'domain': 'ShieldCall/R84/observable-label/v1',
        'sample_id': record['sample_id'],
        'source_id': record['source_id'],
        'campaign_id': record['campaign_id'],
        'collected_at': record['collected_at'],
        'channel': record['channel'],
        'synthetic': record['synthetic'],
        'text_sha256': digest(record['text'].encode('utf8')),
        'label': label,
        'observable_at_collection': True,
    }


def source_bundle_digest(records: list[dict], source_id: str) -> str:
    # Rights-holder signature must authorize an EXACT snapshot of all the
    # source's records. No approval for arbitrary new samples with only
    # new reviewer signatures. Excludes reviewer signatures to avoid cycles.
    items = []
    for record in records:
        if record.get('source_id') != source_id:
            continue
        items.append(
            {
                'sample_id': record['sample_id'],
                'source_id': record['source_id'],
                'campaign_id': record['campaign_id'],
                'collected_at': record['collected_at'],
                'channel': record['channel'],
                'synthetic': record['synthetic'],
                'text_sha256': digest(record['text'].encode('utf8')),
            }
        )
    if not items:
        fail('source_grant_without_records')
    items.sort(key=lambda r: r['sample_id'])
    return digest(
        canonical(
            {
                'domain': 'ShieldCall/R84/source-bundle/v1',
                'source_id': source_id,
                'records': items,
            }
        )
    )


def check_private(path: pathlib.Path) -> None:
    # Never write approved source or labels into world-readable locations.
    if path.is_symlink():
        fail('symlink_input_forbidden')
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o077):
        fail('private_input_required')


def validate(records: list, grants: list, keys: dict, previous: set[str]) -> list[dict]:
    if not isinstance(records, list) or not records:
        fail('no_independent_records')
    if not isinstance(grants, list) or not grants:
        fail('no_signed_rights_grants')
    if not isinstance(keys, dict):
        fail('trusted_public_keys_required')

    today = dt.datetime.now(dt.timezone.utc)
    bysrc = {}
    needed_grant_fields = {
        'source_id',
        'rights_holder',
        'license',
        'grant_digest',
        'allow_evaluation',
        'allow_cloud_evaluation',
        'expires_at',
        'signer_id',
        'signature_b64',
        'source_class',
    }
    for grant in grants:
        if set(grant) != needed_grant_fields:
            fail('source_grant_schema')
        if grant['source_id'] in bysrc:
            fail('duplicate_source_grant')
        if grant['source_class'] != 'independent_human_collected':
            fail('not_independent_source')
        grant_meta = f"{grant['source_id']} {grant['rights_holder']} {grant['license']}".lower()
        if any(bad in grant_meta for bad in REJECT_SOURCE):
            fail('synthetic_source_not_independent')
        if grant['allow_evaluation'] is not True:
            fail('evaluation_rights_not_granted')
        if grant['allow_cloud_evaluation'] is not True:
            fail('cloud_data_use_not_approved')
        if utc(grant['expires_at']) <= today:
            fail('rights_expired')
        unsigned_grant = {k: v for k, v in grant.items() if k != 'signature_b64'}
        signed(keys, grant['signer_id'], 'rights', unsigned_grant, grant['signature_b64'])
        bysrc[grant['source_id']] = grant

    ids = set()
    texts = set()
    accepted = []
    required_record_fields = {
        'sample_id',
        'source_id',
        'campaign_id',
        'collected_at',
        'channel',
        'text',
        'synthetic',
        'reviewers',
        'adjudication',
    }
    for record in records:
        if set(record) != required_record_fields:
            fail('record_schema')
        sid = record['sample_id']
        if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{10,72}', sid):
            fail('bad_sample_id')
        if sid in ids:
            fail('duplicate_sample_id')
        ids.add(sid)
        if record['source_id'] not in bysrc:
            fail('no_signed_source_grant')
        if record['synthetic'] is not False:
            fail('not_real_human_source')
        if record['channel'] not in CHANNELS:
            fail('channel_invalid')
        if not isinstance(record['campaign_id'], str) or not re.fullmatch(
            r'[A-Za-z0-9_-]{8,90}', record['campaign_id']
        ):
            fail('campaign_id_invalid')
        collected = utc(record['collected_at'])
        if collected > today + dt.timedelta(minutes=3):
            fail('future_collection_date')
        if not isinstance(record['text'], str) or not (25 <= len(record['text']) <= 12000):
            fail('sample_text_length')
        if any(rx.search(record['text']) for _, rx in PII):
            fail('pii_or_label_leak_rejected')
        txt_hash = digest(' '.join(record['text'].lower().split()).encode('utf8'))
        if txt_hash in previous:
            fail('overlaps_prior_synthetic_or_training')
        if txt_hash in texts:
            fail('duplicate_content')
        texts.add(txt_hash)

        # Two independently signed reviewers. Disagreement: third independent adjudicator.
        rev = record['reviewers']
        if not isinstance(rev, list) or len(rev) != 2:
            fail('two_reviewers_required')
        if rev[0].get('signer_id') == rev[1].get('signer_id'):
            fail('reviewers_not_independent')
        labels = []
        for entry in rev:
            if set(entry) != {'signer_id', 'label', 'signature_b64'} or entry['label'] not in LABELS:
                fail('reviewer_schema')
            sign_obj = label_statement(record, entry['label'])
            signed(keys, entry['signer_id'], 'reviewer', sign_obj, entry['signature_b64'])
            labels.append(entry['label'])

        if labels[0] == labels[1]:
            if record['adjudication'] is not None:
                fail('spurious_adjudication')
            label = labels[0]
        else:
            adj = record['adjudication']
            if not isinstance(adj, dict) or set(adj) != {'signer_id', 'label', 'signature_b64'}:
                fail('adjudication_required')
            if adj['label'] not in LABELS:
                fail('adjudication_label_invalid')
            if adj['signer_id'] in [x['signer_id'] for x in rev]:
                fail('adjudicator_is_reviewer')
            sign_obj = label_statement(record, adj['label'])
            signed(keys, adj['signer_id'], 'reviewer', sign_obj, adj['signature_b64'])
            label = adj['label']

        accepted.append(
            {
                'record': record,
                'label': label,
                'text_sha256': digest(record['text'].encode('utf8')),
                'normalized_hash': txt_hash,
                'collected': collected,
            }
        )

    # Rights grants may never be reused to authorize unapproved content,
    # changed timestamps, added records, or dropped source records.
    for source_id, grant in bysrc.items():
        approved = grant['grant_digest']
        if not isinstance(approved, str) or not re.fullmatch(r'[0-9a-f]{64}', approved):
            fail('source_bundle_digest_schema')
        actual = source_bundle_digest(records, source_id)
        if approved != actual:
            fail('source_bundle_digest_mismatch')
    return accepted


def freeze(
    accepted: list[dict],
    grants: list[dict],
    keys_path: pathlib.Path,
    records_path: pathlib.Path,
    prior_path: pathlib.Path,
    out: pathlib.Path,
) -> dict:
    if out.exists():
        fail('output_exists_no_overwrite')
    bysrc = defaultdict(list)
    bycamp = defaultdict(set)
    for item in accepted:
        bysrc[item['record']['source_id']].append(item)
        bycamp[item['record']['campaign_id']].add(item['record']['source_id'])
    if len(bysrc) < 2:
        fail('independent_sources_missing')

    # Freeze without using labels: separate entire sources and entire campaigns,
    # and choose latest source group(s) to prevent train/test time leakage.
    ordered = sorted(bysrc, key=lambda s: min(x['collected'] for x in bysrc[s]))
    n_hold = max(1, (len(ordered) + 3) // 4)
    devs = set(ordered[:-n_hold])
    holds = set(ordered[-n_hold:])
    if not devs:
        fail('insufficient_sources')
    for users in bycamp.values():
        if (users & devs) and (users & holds):
            fail('campaign_crosses_frozen_split')

    dev = [x for s in devs for x in bysrc[s]]
    hold = [x for s in holds for x in bysrc[s]]
    if max(x['collected'] for x in dev) > min(x['collected'] for x in hold):
        fail('collection_times_overlap_future_holdout')

    # Do not expose the final labels to a scoring process. A custodian must
    # retain the truth separately until the prediction ledger is immutable.
    out.mkdir(mode=0o700)
    os.chmod(out, 0o700)

    def private_write(name: str, contents: bytes) -> str:
        target_path = out / name
        fd = os.open(target_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(contents)
        return digest(contents)

    def sample(item: dict) -> dict:
        rec = item['record']
        return {
            'sample_id': rec['sample_id'],
            'source_id': rec['source_id'],
            'campaign_id': rec['campaign_id'],
            'collected_at': rec['collected_at'],
            'channel': rec['channel'],
            'text': rec['text'],
            'text_sha256': item['text_sha256'],
        }

    def jsonl(rows: list[dict]) -> bytes:
        return b''.join(canonical(x) + b'\n' for x in rows)

    dev_sorted = sorted(dev, key=lambda x: x['record']['sample_id'])
    hold_sorted = sorted(hold, key=lambda x: x['record']['sample_id'])
    input_dev = jsonl([sample(x) for x in dev_sorted])
    input_hold = jsonl([sample(x) for x in hold_sorted])
    truth = jsonl(
        [
            {
                'sample_id': x['record']['sample_id'],
                'label': x['label'],
                'text_sha256': x['text_sha256'],
            }
            for x in hold_sorted
        ]
    )
    hashes = {
        'development_inputs.jsonl': private_write('development_inputs.jsonl', input_dev),
        'holdout_inputs.jsonl': private_write('holdout_inputs.jsonl', input_hold),
        'custodian_holdout_truth_DO_NOT_SHARE.jsonl': private_write(
            'custodian_holdout_truth_DO_NOT_SHARE.jsonl', truth
        ),
    }

    # Note: truth is NOT cryptographically sealed; only an external independent
    # custodian can guarantee blindness of the final scoring stage.
    counts = Counter(x['label'] for x in hold_sorted)
    manifest = {
        'protocol': 'ShieldCall R83 source-and-campaign-disjoint chronological holdout',
        'research_only': True,
        'real_independent_source_authority_not_attested_by_this_software': True,
        'source_records_sha256': sha_file(records_path),
        'rights_grants_sha256': digest(canonical(grants)),
        'trusted_public_keys_sha256': sha_file(keys_path),
        'prior_synthetic_digest_sha256': sha_file(prior_path),
        'bytes_sha256': hashes,
        'dev_n': len(dev),
        'holdout_n': len(hold),
        'dev_sources': sorted(devs),
        'holdout_sources': sorted(holds),
        'dev_campaign_count': len({x['record']['campaign_id'] for x in dev}),
        'holdout_campaign_count': len({x['record']['campaign_id'] for x in hold}),
        # Observable text mechanism != independently verified real-world fraud.
        # A verified legitimate/confirmed scam outcome authority is separately
        # required before any consumer FPR or scam recall may be published.
        'observational_label_count': sum(counts[k] for k in LABELS if k != 'indeterminate'),
        'real_world_fpr_scoreable': False,
        'confirmed_fraud_or_benign_outcomes_attested': False,
        'acceptance_eligible': False,
        'reason': (
            'External source authority, independent labels and campaign disjointness '
            'require custodian review; candidate is not a validated public-population dataset.'
        ),
        'no_cloud_calls_or_production_changes': True,
    }
    manifest_sha = private_write('FROZEN_MANIFEST.json', canonical(manifest) + b'\n')
    return {
        'manifest_sha256': manifest_sha,
        'dev_n': len(dev),
        'holdout_n': len(hold),
        'candidate_only': True,
        'acceptance_eligible': False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--records', type=pathlib.Path, required=True)
    ap.add_argument('--grants', type=pathlib.Path, required=True)
    ap.add_argument('--trusted-public-keys', type=pathlib.Path, required=True)
    ap.add_argument('--prior-digests', type=pathlib.Path, required=True)
    ap.add_argument('--out', type=pathlib.Path, required=True)
    args = ap.parse_args()

    for input_file in (args.records, args.grants, args.trusted_public_keys, args.prior_digests):
        if not input_file.exists():
            fail('missing_input')
        check_private(input_file)

    roots = open_json(args.trusted_public_keys)
    records = load_lines(args.records)
    grants = load_lines(args.grants)
    previous = load_pinned_prior(args.prior_digests)
    out = freeze(
        validate(records, grants, roots, previous),
        grants,
        args.trusted_public_keys,
        args.records,
        args.prior_digests,
        args.out,
    )
    print(json.dumps(out, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Rejected, PermissionError, OSError, ValueError) as exc:
        # Never print content or network credentials to logs.
        print('R83_REJECTED:' + str(exc).split(':')[0][:65], file=sys.stderr)
        sys.exit(2)
