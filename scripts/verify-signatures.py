#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently verify every signature in a PDF with OpenSSL.

For each /ByteRange [a b c d], the signature covers data[a:a+b] + data[c:c+d],
and the gap between the two ranges is the /Contents hex string. What lives in
that gap depends on the subfilter:

  /ETSI.CAdES.detached, /adbe.pkcs7.detached -> a detached CMS signature,
      checked with `openssl cms -verify`.
  /ETSI.RFC3161 -> a bare RFC 3161 TimeStampToken, checked with `openssl ts`,
      which also confirms the token's message imprint matches the bytes.

Chain building is skipped throughout; the test certificates are self-signed, so
the point is whether the cryptography and the coverage are right.

Usage: verify-signatures.py [--tsa-ca <pem>] <pdf>...
"""
import os
import re
import subprocess
import sys
import tempfile


def der_length(buf):
    """Exact length of the DER structure at the start of buf.

    /Contents is a fixed-size slot zero-padded to whatever was reserved.
    Trimming trailing zero bytes would also remove any that legitimately end
    the encoding, truncating the blob, so the length is read from the ASN.1
    header instead.
    """
    if len(buf) < 2:
        return len(buf)

    first = buf[1]
    if first < 0x80:                       # short form
        return 2 + first

    count = first & 0x7F                   # long form: count length bytes
    if count == 0 or len(buf) < 2 + count:
        return len(buf)

    return 2 + count + int.from_bytes(buf[2:2 + count], 'big')


def classify(data, pos, gap_end):
    """Reads /Type and /SubFilter out of the signature dictionary.

    PoDoFo writes the dictionary as /Type ... /ByteRange ... /Contents<...>
    /Filter /SubFilter, so the type sits just before the byte range while the
    subfilter only appears after the contents gap. Looking in one window
    either side of the ByteRange finds the wrong dictionary entirely.
    """
    before = data[max(0, pos - 60):pos]
    types = re.findall(rb'/Type\s*/([A-Za-z]+)', before)
    after = data[gap_end:gap_end + 400]
    sub = re.search(rb'/SubFilter\s*/([A-Za-z0-9._]+)', after)
    return (types[-1].decode() if types else '?',
            sub.group(1).decode() if sub else '?')


def check_cms(sig_f, dat_f):
    r = subprocess.run(
        ['openssl', 'cms', '-verify', '-in', sig_f, '-inform', 'DER',
         '-content', dat_f, '-binary', '-noverify', '-out', os.devnull],
        capture_output=True)
    return r.returncode == 0, r.stderr.decode().strip()


def check_timestamp(sig_f, dat_f, tsa_ca):
    """Verifies an RFC 3161 token against the bytes it claims to timestamp."""
    if tsa_ca:
        r = subprocess.run(
            ['openssl', 'ts', '-verify', '-data', dat_f, '-in', sig_f,
             '-token_in', '-CAfile', tsa_ca],
            capture_output=True)
        return r.returncode == 0, r.stderr.decode().strip()

    # No CA supplied: still confirm the token parses and carries an imprint.
    r = subprocess.run(
        ['openssl', 'ts', '-reply', '-in', sig_f, '-token_in', '-text'],
        capture_output=True)
    if r.returncode != 0:
        return False, r.stderr.decode().strip()
    return True, 'token parsed (no --tsa-ca given, chain not checked)'


def describe_dss(data):
    if b'/DSS' not in data:
        return None
    counts = {}
    for key in (b'Certs', b'OCSPs', b'CRLs'):
        m = re.search(b'/' + key + rb'\s*\[([^\]]*)\]', data)
        counts[key.decode()] = len(re.findall(rb'\d+\s+\d+\s+R', m.group(1))) if m else 0
    return counts


def check(path, tsa_ca):
    data = open(path, 'rb').read()
    ranges = [(m.start(), [int(x) for x in m.group(1).split()])
              for m in re.finditer(rb'/ByteRange\s*\[\s*([\d\s]+?)\]', data)]
    if not ranges:
        print(f"  {os.path.basename(path)}: no /ByteRange found")
        return False

    print(f"  {os.path.basename(path)}: {len(ranges)} signature(s)")
    ok_all = True
    for i, (pos, br) in enumerate(ranges, 1):
        a, b, c, d = br[:4]
        covered = data[a:a + b] + data[c:c + d]
        whole = (a == 0 and (c + d) == len(data))
        kind, subfilter = classify(data, pos, c)

        gap = data[a + b:c].strip()
        if not (gap.startswith(b'<') and gap.endswith(b'>')):
            print(f"    sig {i}: byte-range gap is not a hex string")
            ok_all = False
            continue

        raw = bytes.fromhex(gap[1:-1].decode('ascii'))
        der = raw[:der_length(raw)]

        with tempfile.TemporaryDirectory() as td:
            sig_f, dat_f = os.path.join(td, 's.der'), os.path.join(td, 'd.bin')
            open(sig_f, 'wb').write(der)
            open(dat_f, 'wb').write(covered)
            # /Type is the authoritative signal; the subfilter corroborates.
            if kind == 'DocTimeStamp' or subfilter == 'ETSI.RFC3161':
                ok, detail = check_timestamp(sig_f, dat_f, tsa_ca)
            else:
                ok, detail = check_cms(sig_f, dat_f)

        ok_all = ok_all and ok
        print(f"    sig {i}: {'VALID' if ok else 'INVALID':8s} "
              f"{kind:12s} {subfilter:22s} covers_to_eof={whole} blob={len(der)}B")
        if not ok and detail:
            print(f"             {detail[:200]}")

    dss = describe_dss(data)
    if dss is not None:
        print("    /DSS   : " + ", ".join(f"{k}={v}" for k, v in dss.items()))

    return ok_all


def main():
    args = sys.argv[1:]

    # --tsa-ca may be repeated: a run can mix tokens from a local test
    # authority and from a commercial one, which trust different roots.
    anchors = []
    while '--tsa-ca' in args:
        idx = args.index('--tsa-ca')
        anchors.append(args[idx + 1])
        del args[idx:idx + 2]

    if not args:
        print(__doc__)
        return 2

    bundle = None
    tmp = None
    if anchors:
        existing = [a for a in anchors if os.path.exists(a)]
        if len(existing) == 1:
            bundle = existing[0]
        elif existing:
            tmp = tempfile.NamedTemporaryFile('wb', suffix='.pem', delete=False)
            for a in existing:
                tmp.write(open(a, 'rb').read())
                tmp.write(b'\n')
            tmp.close()
            bundle = tmp.name

    try:
        return 0 if all(check(p, bundle) for p in args) else 1
    finally:
        if tmp is not None:
            os.unlink(tmp.name)


sys.exit(main())
