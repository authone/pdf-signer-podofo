#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A local RFC 3161 timestamp authority over HTTPS, optionally requiring a
client certificate.

Commercial providers that authenticate subscribers by certificate are not
something you can point a test suite at, so this stands in for one. It speaks
the same protocol over the same transport: POST a DER timestamp-query, get a
DER timestamp-reply. Signing is delegated to `openssl ts -reply`.

It is a test fixture, not a TSA: it signs whatever it is asked to, with
whatever key it is given, and its serial numbers restart with the process.

  mock-tsa-server.py --port 8443 \
      --tsa-cert tsa-cert.pem --tsa-key tsa-key.pem \
      --server-cert tsa-server-cert.pem --server-key tsa-server-key.pem \
      --client-ca client-cert.pem        # omit to allow anonymous clients
"""
import argparse
import http.server
import os
import ssl
import subprocess
import sys
import tempfile

TSA_CONFIG = """
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial          = {serial}
crypto_device   = builtin
signer_cert     = {cert}
certs           = {cert}
signer_key      = {key}
signer_digest   = sha256
default_policy  = 1.3.6.1.4.1.13762.3
digests         = sha256, sha384, sha512
accuracy        = secs:1
clock_precision_digits = 0
ordering        = yes
tsa_name        = yes
ess_cert_id_chain = no
"""


class Handler(http.server.BaseHTTPRequestHandler):
    workdir = None
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        peer = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
        who = "anonymous"
        if peer:
            who = ", ".join(f"{k}={v}" for rdn in peer.get("subject", ())
                            for k, v in rdn)
        sys.stderr.write(f"[tsa] {self.address_string()} ({who}) {fmt % a}\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length)

        if self.headers.get("Content-Type") != "application/timestamp-query":
            self.send_error(415, "expected application/timestamp-query")
            return

        qf = os.path.join(self.workdir, "query.der")
        rf = os.path.join(self.workdir, "reply.der")
        with open(qf, "wb") as f:
            f.write(query)

        proc = subprocess.run(
            ["openssl", "ts", "-reply", "-config",
             os.path.join(self.workdir, "tsa.cnf"),
             "-queryfile", qf, "-out", rf],
            capture_output=True, cwd=self.workdir)

        if proc.returncode != 0 or not os.path.exists(rf):
            self.log_message("openssl failed: %s", proc.stderr.decode()[:200])
            self.send_error(500, "timestamping failed")
            return

        with open(rf, "rb") as f:
            reply = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)
        self.log_message("issued %d byte reply", len(reply))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tsa-cert", required=True)
    p.add_argument("--tsa-key", required=True)
    p.add_argument("--server-cert", required=True)
    p.add_argument("--server-key", required=True)
    p.add_argument("--client-ca", help="require a client certificate signed by this")
    args = p.parse_args()

    workdir = tempfile.mkdtemp(prefix="mock-tsa-")
    with open(os.path.join(workdir, "serial"), "w") as f:
        f.write("01\n")
    with open(os.path.join(workdir, "tsa.cnf"), "w") as f:
        f.write(TSA_CONFIG.format(
            serial=os.path.join(workdir, "serial"),
            cert=os.path.abspath(args.tsa_cert),
            key=os.path.abspath(args.tsa_key)))

    Handler.workdir = workdir

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.server_cert, args.server_key)
    if args.client_ca:
        # This is the mutual part: no client certificate, no handshake.
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(args.client_ca)

    server = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    mode = "mutual TLS" if args.client_ca else "server-auth only"
    sys.stderr.write(f"[tsa] listening on https://127.0.0.1:{args.port}/ ({mode})\n")
    sys.stderr.flush()
    server.serve_forever()


main()
