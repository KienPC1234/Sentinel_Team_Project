#!/usr/bin/env python3
"""Generate VAPID keys (base64url) for WebPush and print ENV-ready output.

Usage:
  python scripts/generate_vapid_keys.py --subject mailto:admin@yourdomain.com
"""

import argparse
from py_vapid import Vapid01
from py_vapid.utils import b64urlencode
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main():
    parser = argparse.ArgumentParser(description='Generate VAPID keys for WebPush')
    parser.add_argument('--subject', default='mailto:admin@yourdomain.com', help='VAPID subject claim')
    args = parser.parse_args()

    vapid = Vapid01()
    vapid.generate_keys()

    public_bytes = vapid.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    private_int = vapid.private_key.private_numbers().private_value
    private_bytes = private_int.to_bytes(32, 'big')

    public_key = b64urlencode(public_bytes)
    private_key = b64urlencode(private_bytes)

    print('WEBPUSH_VAPID_PUBLIC_KEY=' + public_key)
    print('WEBPUSH_VAPID_PRIVATE_KEY=' + private_key)
    print('WEBPUSH_VAPID_SUBJECT=' + args.subject)


if __name__ == '__main__':
    main()
