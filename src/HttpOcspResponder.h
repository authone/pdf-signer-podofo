// SPDX-License-Identifier: MIT
//
// An OCSP client that asks a real responder about the signing certificate,
// over HTTP or HTTPS.

#pragma once

#include <string>

#include "HttpClient.h"
#include "ValidationServices.h"

namespace pdfsign
{
    /** Queries a certificate's revocation status from an OCSP responder.
     *
     * The DER response that comes back is what goes into the document's /DSS
     * verbatim: a validator years from now re-checks that signed response
     * rather than contacting a responder that may no longer exist.
     */
    class HttpOcspResponder final : public IOcspResponder
    {
    public:
        /** @param url responder endpoint. Empty means take the URL from the
         *         certificate's Authority Information Access extension, which
         *         is where a correctly issued certificate publishes it. */
        HttpOcspResponder(std::string url, HttpTransport transport);

        /** Asks the responder about @p certDer and returns the DER response.
         *
         * The reply is checked before being accepted: the responder must
         * answer about the certificate we asked about, and if it echoes a
         * nonce it must be ours.
         *
         * @throws std::runtime_error if the responder refuses, is
         *         unreachable, or answers about something else.
         */
        std::string CreateResponse(const std::string& certDer,
            const std::string& issuerDer) const override;

        const char* GetDescription() const override { return m_description.c_str(); }

        /** "good", "revoked" or "unknown", from the last successful query. */
        const std::string& GetLastStatus() const { return m_lastStatus; }

        /** Whether the responder echoed our nonce, or returned a
         * pre-produced response without one. */
        const std::string& GetLastNonce() const { return m_lastNonce; }

        /** The endpoint actually used, which may have come from the
         * certificate's AIA rather than the command line. */
        const std::string& GetLastUrl() const { return m_lastUrl; }

        /** Reads the OCSP responder URL out of a certificate's AIA extension.
         * Empty if the certificate publishes none. */
        static std::string FindAiaUrl(const std::string& certDer);

    private:
        std::string m_url;
        HttpTransport m_transport;
        std::string m_description;
        mutable std::string m_lastStatus;
        mutable std::string m_lastUrl;
        mutable std::string m_lastNonce;
    };
}
