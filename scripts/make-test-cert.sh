#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Creates a throwaway self-signed signing certificate.
#
# It is fine for exercising the code and for inspecting the resulting PDF
# structure, but no validator will trust it: a self-signed certificate chains
# to nothing. Acrobat will show "signature validity is unknown" rather than a
# green check, and that is the correct outcome.

set -euo pipefail

OUT_DIR="${1:-$(pwd)}"
PASSWORD="${P12_PASSWORD:-test}"
DAYS="${DAYS:-365}"
SUBJECT="${SUBJECT:-/C=RO/O=PoDoFo Example/OU=Document Signing/CN=PDF Signing Test}"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "==> Generating a self-signed signing certificate in $OUT_DIR"

# keyUsage digitalSignature + nonRepudiation and the id-kp-documentSigning EKU
# (RFC 9336) are what a real document-signing certificate carries.
openssl req -x509 \
    -newkey rsa:3072 \
    -sha256 \
    -days "$DAYS" \
    -nodes \
    -keyout key.pem \
    -out cert.pem \
    -subj "$SUBJECT" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,nonRepudiation" \
    -addext "extendedKeyUsage=1.3.6.1.5.5.7.3.36" \
    2>/dev/null

# A PKCS#12 bundle is the form signing credentials usually arrive in.
openssl pkcs12 -export \
    -out test-cert.p12 \
    -inkey key.pem \
    -in cert.pem \
    -name "PDF Signing Test" \
    -passout "pass:$PASSWORD"

# A timestamp authority needs its own certificate. OpenSSL's TS_RESP_CTX
# checks X509_PURPOSE_TIMESTAMP_SIGN and refuses anything without a *critical*
# id-kp-timeStamping as its only extended key usage, so a document-signing
# certificate cannot be reused here.
openssl req -x509 \
    -newkey rsa:3072 \
    -sha256 \
    -days "$DAYS" \
    -nodes \
    -keyout tsa-key.pem \
    -out tsa-cert.pem \
    -subj "${TSA_SUBJECT:-/C=RO/O=PoDoFo Example/OU=Timestamping/CN=PDF Test TSA}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,nonRepudiation" \
    -addext "extendedKeyUsage=critical,timeStamping" \
    2>/dev/null

# TLS server certificate for scripts/mock-tsa-server.py. Separate from the
# TSA signing certificate: one secures the transport, the other signs tokens.
openssl req -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days "$DAYS" \
    -nodes \
    -keyout tsa-server-key.pem \
    -out tsa-server-cert.pem \
    -subj "/C=RO/O=PoDoFo Example/CN=localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

# Client certificate, for exercising mutual TLS against that server.
openssl req -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days "$DAYS" \
    -nodes \
    -keyout client-key.pem \
    -out client-cert.pem \
    -subj "/C=RO/O=PoDoFo Example/OU=Subscribers/CN=Timestamp Client" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=clientAuth" \
    2>/dev/null

chmod 600 key.pem test-cert.p12 tsa-key.pem tsa-server-key.pem client-key.pem

echo
echo "  cert.pem       certificate (PEM)"
echo "  key.pem        private key (PEM, unencrypted)"
echo "  test-cert.p12  PKCS#12 bundle, password: $PASSWORD"
echo "  tsa-cert.pem   timestamp authority certificate (critical timeStamping EKU)"
echo "  tsa-key.pem    timestamp authority private key"
echo "  tsa-server-*   TLS certificate for scripts/mock-tsa-server.py"
echo "  client-*       client certificate for exercising mutual TLS"
echo
openssl x509 -in cert.pem -noout -subject -enddate
