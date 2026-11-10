#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# End-to-end run: credentials, then every signing variant the example supports.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/podofo-pdf-sign}"
WORK="$ROOT/out"

if [ ! -x "$BIN" ]; then
    echo "Build it first: cmake -S . -B build && cmake --build build" >&2
    exit 1
fi

mkdir -p "$WORK"

if [ ! -f "$WORK/test-cert.p12" ]; then
    "$ROOT/scripts/make-test-cert.sh" "$WORK"
fi

cd "$WORK"

echo
echo "=== 1. Inspect the credentials ==========================================="
"$BIN" info --pkcs12 test-cert.p12 --password test

echo "=== 2. Invisible signature on a generated sample ========================="
"$BIN" sign --pkcs12 test-cert.p12 --password test --out sample-invisible.pdf

echo
echo "=== 3. Visible signature, PEM cert + key ================================="
"$BIN" sign --cert cert.pem --key key.pem \
    --out sample-visible.pdf \
    --visible --rect 56,80,240,80 \
    --name "PDF Signing Test" \
    --reason "Approved for release" \
    --location "Bucharest, RO"

echo
echo "=== 4. Incremental update: sign an existing PDF ==========================="
# Signs the output of step 3, so the file ends up carrying two signatures and
# the first one must survive.
"$BIN" sign --pkcs12 test-cert.p12 --password test \
    --in sample-visible.pdf --out sample-countersigned.pdf \
    --field Signature2 \
    --reason "Countersigned"

echo
echo "=== 5. External signing service (HSM integration shape) =================="
"$BIN" sign --cert cert.pem --key key.pem \
    --external-key \
    --out sample-external.pdf \
    --reason "Signed via callback"

echo
echo "=== 6. Legacy Adobe profile instead of PAdES ============================="
"$BIN" sign --pkcs12 test-cert.p12 --password test \
    --type pkcs7 --hash sha512 \
    --out sample-pkcs7.pdf

echo
echo "=== 7. PAdES long-term: sign -> OCSP -> document timestamp =============="
# TSA_URL points this at a real authority, e.g.
#   TSA_URL=http://timestamp.digicert.com scripts/demo.sh
# Without it the in-process mock is used so the demo works offline.
if [ -n "${TSA_URL:-}" ]; then
    TSA_ARGS=(--tsa-url "$TSA_URL")
    echo "Using timestamp authority: $TSA_URL"
else
    TSA_ARGS=(--tsa-cert tsa-cert.pem --tsa-key tsa-key.pem)
    echo "No TSA_URL set, using the local mock authority."
fi

"$BIN" lta --pkcs12 test-cert.p12 --password test \
    "${TSA_ARGS[@]}" \
    --out lta.pdf \
    --visible --rect 56,80,240,80 \
    --reason "Approved for release"

echo
echo "=== 8. Mutual-TLS timestamp against a local HTTPS authority ============="
python3 "$ROOT/scripts/mock-tsa-server.py" --port 8443 \
    --tsa-cert tsa-cert.pem --tsa-key tsa-key.pem \
    --server-cert tsa-server-cert.pem --server-key tsa-server-key.pem \
    --client-ca client-cert.pem > tsa-server.log 2>&1 &
TSA_PID=$!
trap 'kill $TSA_PID 2>/dev/null' EXIT
for _ in $(seq 1 20); do grep -q listening tsa-server.log 2>/dev/null && break; sleep 0.5; done

echo "-- without a client certificate (must be refused at the TLS handshake):"
if "$BIN" add-timestamp --tsa-url https://127.0.0.1:8443/tsr \
        --tsa-ca tsa-server-cert.pem \
        --in lta.lt.pdf --out refused.pdf > refused.log 2>&1; then
    echo "   UNEXPECTED: the server accepted an anonymous client"
else
    tail -1 refused.log
fi
rm -f refused.pdf refused.log

echo "-- with mutual TLS:"
"$BIN" add-timestamp --tsa-url https://127.0.0.1:8443/tsr \
    --tsa-ca tsa-server-cert.pem \
    --tsa-client-cert client-cert.pem --tsa-client-key client-key.pem \
    --in lta.lt.pdf --out lta-mtls.pdf

kill $TSA_PID 2>/dev/null || true
trap - EXIT

echo
echo "=== 9. Validation data from a real OCSP responder ======================="
# The lta run above uses the mock responder because its signing certificate is
# self-signed: no real responder has ever heard of it. Exercising a real one
# needs a real chain, supplied here.
#   OCSP_URL=http://ocsp.certsign.ro OCSP_CERT=leaf.pem OCSP_ISSUER=ca.pem \
#       scripts/demo.sh
if [ -n "${OCSP_URL:-}" ] && [ -n "${OCSP_CERT:-}" ] && [ -n "${OCSP_ISSUER:-}" ]; then
    "$BIN" add-validation --ocsp "$OCSP_URL" \
        --cert "$OCSP_CERT" --issuer "$OCSP_ISSUER" \
        --in sample-invisible.pdf --out lt-real-ocsp.pdf
else
    echo "Set OCSP_URL, OCSP_CERT and OCSP_ISSUER to query a real responder."
    echo "Skipped (the self-signed test certificate cannot be used for this)."
fi

echo
echo "=== Results =============================================================="
ls -lh "$WORK"/*.pdf

echo
echo "Independent verification (OpenSSL):"
# Two sets of anchors: the local mock TSA, and the system store for tokens
# fetched from a commercial authority via TSA_URL.
"$ROOT/scripts/verify-signatures.py" \
    --tsa-ca tsa-cert.pem \
    --tsa-ca /etc/ssl/certs/ca-certificates.crt \
    "$WORK"/*.pdf

echo
echo "Signature subfilters actually written into each file:"
for f in "$WORK"/*.pdf; do
    printf '  %-28s ' "$(basename "$f")"
    # The subfilter is plain text in the signature dictionary.
    if grep -ao 'ETSI\.CAdES\.detached\|adbe\.pkcs7\.detached' "$f" | sort -u | paste -sd, -; then
        :
    else
        echo "(none found)"
    fi
done
