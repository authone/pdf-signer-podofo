// SPDX-License-Identifier: MIT
//
// The two external services a PAdES long-term signature depends on: an OCSP
// responder that says the signing certificate was good, and a timestamp
// authority that says when.
//
// Both are interfaces so the mock implementations used here can be swapped for
// real network clients without anything else changing. That substitution is
// the whole point of the exercise: the PDF-side code never learns where the
// bytes came from.

#pragma once

#include <cstddef>
#include <string>

namespace pdfsign
{
    /** Produces an OCSP response asserting the status of a certificate. */
    class IOcspResponder
    {
    public:
        virtual ~IOcspResponder() = default;

        /** @param certDer   the certificate being asked about, DER.
         *  @param issuerDer its issuer, DER; the CertID is derived from the
         *         issuer's name and public key.
         *  @returns a DER-encoded OCSP response, ready to drop into /DSS. */
        virtual std::string CreateResponse(const std::string& certDer,
            const std::string& issuerDer) const = 0;

        virtual const char* GetDescription() const = 0;
    };

    /** Produces an RFC 3161 timestamp token over a digest. */
    class ITimestampService
    {
    public:
        virtual ~ITimestampService() = default;

        /** @param hash       the message imprint, already digested.
         *  @param digestName OpenSSL name of the digest that produced it.
         *  @returns a DER-encoded TimeStampToken (a CMS ContentInfo), which is
         *           exactly what goes in a /DocTimeStamp's /Contents. */
        virtual std::string CreateToken(const void* hash, std::size_t hashLen,
            const char* digestName) const = 0;

        /** Whether obtaining a token is cheap enough to do speculatively.
         *
         * PoDoFo hashes the document twice: once to size the /Contents
         * placeholder, once for real. A local authority can be asked both
         * times and the placeholder sized exactly. A remote one must not be,
         * because that doubles the requests to a service that may be metered,
         * rate-limited or simply slow, so the caller reserves a fixed size
         * instead and asks only once.
         */
        virtual bool IsLocal() const = 0;

        virtual const char* GetDescription() const = 0;
    };

    /** An OCSP responder running in this process.
     *
     * It signs with a key supplied by the caller and always answers "good",
     * which is enough to populate a DSS and see how a validator reacts. A real
     * responder would be reached over HTTP and would consult a database.
     */
    class MockOcspResponder final : public IOcspResponder
    {
    public:
        /** @param responderCertDer certificate identifying the responder; for
         *         a self-signed test setup this is the signing certificate
         *         itself, which also makes it its own issuer. */
        MockOcspResponder(std::string responderCertDer, std::string responderKeyDer);

        std::string CreateResponse(const std::string& certDer,
            const std::string& issuerDer) const override;

        const char* GetDescription() const override { return "in-process mock responder"; }

    private:
        std::string m_certDer;
        std::string m_keyDer;
    };

    /** A timestamp authority running in this process.
     *
     * OpenSSL's TS_RESP_CTX does the real work, so the tokens are structurally
     * genuine RFC 3161 and parse in any validator. The signing certificate
     * must carry a critical id-kp-timeStamping extended key usage or OpenSSL
     * refuses to use it; scripts/make-test-cert.sh issues a suitable one.
     */
    class MockTimestampAuthority final : public ITimestampService
    {
    public:
        MockTimestampAuthority(std::string tsaCertDer, std::string tsaKeyDer,
            std::string policyOid = "1.3.6.1.4.1.13762.3");

        std::string CreateToken(const void* hash, std::size_t hashLen,
            const char* digestName) const override;

        bool IsLocal() const override { return true; }

        const char* GetDescription() const override { return "in-process mock TSA"; }

    private:
        std::string m_certDer;
        std::string m_keyDer;
        std::string m_policyOid;
    };
}
