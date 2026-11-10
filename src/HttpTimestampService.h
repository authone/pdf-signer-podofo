// SPDX-License-Identifier: MIT
//
// An RFC 3161 client that obtains timestamp tokens from a trust service
// provider over HTTP or HTTPS, optionally authenticating with a client
// certificate.

#pragma once

#include <string>

#include "HttpClient.h"
#include "ValidationServices.h"

namespace pdfsign
{
    /** How to reach a timestamp authority. */
    struct TsaHttpConfig final
    {
        /** Endpoint URL. http:// and https:// are both accepted; RFC 3161
         * over HTTP is normal, because the token is signed and the request
         * carries only a digest. */
        std::string Url;

        /** TLS, mutual authentication and timeout settings. */
        HttpTransport Transport;

        /** Ask the TSA to embed its certificate in the token.
         *
         * Without it the token is smaller but a validator needs the TSA
         * certificate from elsewhere, which defeats the point of archiving.
         */
        bool RequestCertificate = true;
    };

    /** Fetches timestamp tokens from a remote authority.
     *
     * Only a digest leaves the machine: the request carries the hash of the
     * document's byte ranges and nothing else, and the token that comes back
     * is applied to the PDF locally. That is what makes it acceptable to hand
     * timestamping to a third party.
     *
     * The response is checked against the request before it is accepted. The
     * nonce must come back unchanged, which is what stops a replayed or
     * substituted token, and the message imprint must be the digest we asked
     * about.
     */
    class HttpTimestampService final : public ITimestampService
    {
    public:
        explicit HttpTimestampService(TsaHttpConfig config);

        std::string CreateToken(const void* hash, std::size_t hashLen,
            const char* digestName) const override;

        /** Remote: PoDoFo's dry run must not trigger a second request. */
        bool IsLocal() const override { return false; }

        const char* GetDescription() const override { return m_description.c_str(); }

        /** The time the authority asserted, from the last token obtained.
         * Empty before the first successful call. */
        const std::string& GetLastGenTime() const { return m_lastGenTime; }

    private:
        TsaHttpConfig m_config;
        std::string m_description;
        mutable std::string m_lastGenTime;
    };
}
