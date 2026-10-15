#!/usr/bin/env python3
"""
Compiles all curated community YARA rules (Florian Roth signature-base)
into an optimized binary index for ultra-fast matching without handcrafted rules.
"""

import os
import glob
import sys
import yara

RULES_DIR = '/sandbox/rules'
COMMUNITY_DIR = os.path.join(RULES_DIR, 'signature_base')
OUTPUT_COMPILED = '/sandbox/rules/compiled_rules.yarc'


def compile_community_rules():
    if not os.path.isdir(COMMUNITY_DIR):
        sys.stderr.write(f"[-] Community rules directory not found at {COMMUNITY_DIR}\n")
        return False

    filepaths = {}
    skipped = 0
    
    for yf in sorted(glob.glob(os.path.join(COMMUNITY_DIR, '*.yar'))):
        name = os.path.splitext(os.path.basename(yf))[0]
        try:
            yara.compile(filepath=yf)
            filepaths[name] = yf
        except Exception:
            skipped += 1

    print(f"[*] Compiling {len(filepaths)} community threat intelligence rulesets (skipped {skipped})...")
    try:
        compiled = yara.compile(filepaths=filepaths)
        compiled.save(OUTPUT_COMPILED)
        print(f"[+] Successfully generated binary YARA index ({len(filepaths)} rulesets) at {OUTPUT_COMPILED}")
        return True
    except Exception as e:
        sys.stderr.write(f"[-] Failed compiling community rulesets: {e}\n")
        return False


if __name__ == '__main__':
    success = compile_community_rules()
    if not success:
        sys.exit(1)
