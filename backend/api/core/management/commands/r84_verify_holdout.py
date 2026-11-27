"""Manual, default-DENY R84 signed dataset intake. NOT a consumer scan endpoint.

No DB queries, model inference, API routes, scheduled jobs, or provider calls.
Only run after operator independently validates data subjects, rights, reviewer
identities and source permissions, with trusted public-key file SHA pinned.
"""
import fcntl
import hashlib
import os
import re
import shutil
import stat
import uuid
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from api.utils import r84_holdout_gate as gate


def _read_once_private_file(path, *, allow_tracked_readonly=False):
    # Open the final pathname atomically; avoid the pre-check -> reopen
    # TOCTOU that previously let the external trusted-root file be
    # substituted between hash approval and Ed25519 signature validation.
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
        ):
            raise CommandError('R86_INPUT_FILE_OWNER_OR_TYPE_INVALID')
        # External candidate files must be owner-only (0600). Version-controlled
        # SHA baseline files (already SHA256-pinned in code) forbid group/world write.
        mask = 0o022 if allow_tracked_readonly else 0o077
        if before.st_mode & mask:
            raise CommandError('R86_INPUT_FILE_NOT_PRIVATE')
        if not (0 <= before.st_size <= 20 * 1024 * 1024):
            raise CommandError('R84_INPUT_SIZE_LIMIT')
        contents = bytearray()
        while True:
            chunk = os.read(fd, min(65536, 20 * 1024 * 1024 + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
            if len(contents) > 20 * 1024 * 1024:
                raise CommandError('R84_INPUT_SIZE_LIMIT')
        after = os.fstat(fd)
        attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(contents) != before.st_size or any(
            getattr(before, key) != getattr(after, key) for key in attributes
        ):
            raise CommandError('R86_INPUT_MODIFIED_DURING_READ')
        return bytes(contents)
    except (OSError, ValueError) as exc:
        raise CommandError('R86_INPUT_OPEN_OR_READ_FAILED') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _private_snapshot(path, contents):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(contents)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError('R86_SHORT_SNAPSHOT_WRITE')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


class Command(BaseCommand):
    help = 'R84 independent holdout source verification (manual, disabled by default)'

    def add_arguments(self, parser):
        parser.add_argument('--records', required=True)
        parser.add_argument('--grants', required=True)
        parser.add_argument('--trusted-public-keys', required=True)
        parser.add_argument('--output-name', required=True)

    def handle(self, *args, **opts):
        # This gate is not enabled for website requests, Celery, or startup.
        if os.environ.get('SHIELDCALL_R84_INTAKE_ENABLED') != '1':
            raise CommandError('R84_INTAKE_DISABLED')
        approved = os.environ.get('SHIELDCALL_R84_APPROVED_TRUST_SHA256', '')
        if not re.fullmatch(r'[0-9a-f]{64}', approved):
            raise CommandError('R84_EXTERNAL_TRUST_ROOT_NOT_APPROVED')
        root_value = os.environ.get('SHIELDCALL_R84_PRIVATE_ROOT', '')
        if not root_value:
            raise CommandError('R84_PRIVATE_ROOT_MISSING')
        private_root = Path(root_value)
        name = opts['output_name']
        if not re.fullmatch(r'[a-zA-Z0-9_-]{8,90}', name):
            raise CommandError('R84_OUTPUT_NAME_INVALID')

        # Never write accepted source, review statements or holdout truth
        # anywhere accessible under Django/Next production code/media.
        public_root = Path(settings.BASE_DIR).resolve().parent
        if not private_root.is_absolute() or private_root.is_symlink():
            raise CommandError('R84_PRIVATE_ROOT_NOT_ABSOLUTE_OR_SYMLINK')
        try:
            real_root = private_root.resolve(strict=True)
            st = real_root.stat()
            if not stat.S_ISDIR(st.st_mode) or (st.st_mode & 0o077):
                raise CommandError('R84_PRIVATE_ROOT_NOT_0700')
            if real_root == public_root or public_root in real_root.parents:
                raise CommandError('R84_PRIVATE_ROOT_INSIDE_PUBLIC_PROJECT')
        except (FileNotFoundError, OSError) as exc:
            raise CommandError('R84_PRIVATE_ROOT_UNAVAILABLE') from exc

        inputs = [Path(opts[x]) for x in ('records', 'grants', 'trusted_public_keys')]
        baseline = Path(__file__).resolve().parents[2] / 'data' / 'r84_known_synthetic_sha256.txt'

        # Read EACH external file exactly once through a verified file
        # descriptor. The same bytes, not re-opened mutable paths, must
        # determine the approval hash, signature validation and manifest.
        blobs = [
            _read_once_private_file(inputs[0]),
            _read_once_private_file(inputs[1]),
            _read_once_private_file(inputs[2]),
            _read_once_private_file(baseline, allow_tracked_readonly=True),
        ]
        if hashlib.sha256(blobs[2]).hexdigest() != approved:
            raise CommandError('R84_TRUST_ROOT_HASH_MISMATCH')
        if hashlib.sha256(blobs[3]).hexdigest() != gate.KNOWN_PRIOR_SHA256:
            raise CommandError('R86_PRIOR_FINGERPRINTS_CHANGED')

        # One private, lock-protected work directory owns immutable logical
        # input snapshots and temporary output. No production DB, Redis,
        # provider call or live user content can be touched by this command.
        destination = real_root / name
        old_umask = os.umask(0o077)
        lock_fd = None
        scratch = None
        try:
            lock_fd = os.open(
                real_root / '.r84_manual.lock',
                os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if destination.exists() or destination.is_symlink():
                raise CommandError('R84_OUTPUT_EXISTS')
            scratch = real_root / ('.r86_snapshot_' + uuid.uuid4().hex)
            scratch.mkdir(mode=0o700)
            names = (
                'records.jsonl',
                'grants.jsonl',
                'trusted_public_keys.json',
                'known_prior_fingerprints.txt',
            )
            paths = [scratch / n for n in names]
            for path, blob in zip(paths, blobs):
                _private_snapshot(path, blob)
            try:
                previous = gate.load_pinned_prior(paths[3])
                roots = gate.open_json(paths[2])
                records = gate.load_lines(paths[0])
                grants = gate.load_lines(paths[1])
                if len(records) > 10000 or len(grants) > 500:
                    raise CommandError('R84_RECORD_COUNT_LIMIT')
                accepted = gate.validate(records, grants, roots, previous)
            except (gate.Rejected, ValueError, UnicodeError) as exc:
                raise CommandError('R84_UNTRUSTED_INPUT_REJECTED') from exc

            # The exact source/rights/keys/corpus read above is reused by
            # freeze. Re-hash after validation and freeze to catch changes
            # to these private snapshots while the command is operating.
            expected = [hashlib.sha256(v).hexdigest() for v in blobs]
            if any(hashlib.sha256(p.read_bytes()).hexdigest() != d for p, d in zip(paths, expected)):
                raise CommandError('R86_SNAPSHOT_TAMPERED')
            result_dir = scratch / 'frozen'
            result = gate.freeze(accepted, grants, paths[2], paths[0], paths[3], result_dir)
            if any(hashlib.sha256(p.read_bytes()).hexdigest() != d for p, d in zip(paths, expected)):
                raise CommandError('R86_SNAPSHOT_TAMPERED')
            if destination.exists() or destination.is_symlink():
                raise CommandError('R84_OUTPUT_EXISTS')
            result_dir.rename(destination)
        except Exception as exc:
            if isinstance(exc, CommandError):
                raise
            raise CommandError('R84_FREEZE_REJECTED') from exc
        finally:
            if scratch is not None and scratch.exists():
                shutil.rmtree(scratch)
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            os.umask(old_umask)

        self.stdout.write('R84_SOURCE_CANDIDATE_FROZEN')
        self.stdout.write(
            'R84_SAMPLE_COUNTS development=%d holdout=%d' % (result['dev_n'], result['holdout_n'])
        )
        self.stdout.write('R84_ACCEPTANCE_ELIGIBLE=false')
        self.stdout.write('R84_EXPLICIT_CUSTODIAN_REVIEW_REQUIRED=true')
