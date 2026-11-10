// SPDX-License-Identifier: MIT
//
// The HTTP transport shared by the RFC 3161 timestamp client and the OCSP
// client. Both speak the same pattern: POST a DER request with a protocol
// specific media type, read a DER response back.

#pragma once

#include <string>

namespace pdfsign
{
    /** Transport settings for reaching a trust service provider.
     *
     * Providers authenticate subscribers in different ways: some by client
     * certificate, some by account, some not at all. All three are configured
     * here rather than in each protocol client.
     */
    struct HttpTransport final
    {
        /** PEM bundle used to verify the server's TLS certificate. Empty
         * means the system trust store. */
        std::string CaBundlePath;

        // Mutual TLS: the certificate the provider knows us by.
        std::string ClientCertPath;
        std::string ClientKeyPath;
        std::string ClientKeyPassword;

        // HTTP Basic credentials, for providers that gate access by account.
        std::string Username;
        std::string Password;

        long TimeoutSeconds = 30;

        /** Verify the server's certificate and hostname. Turning this off
         * makes TLS meaningless; it exists only so a provider with a private
         * CA can be tried before its root is installed. */
        bool VerifyPeer = true;

        /** Checks the settings are coherent against @p url.
         *
         * @returns a short human-readable summary of how the connection will
         *          be authenticated, for logging.
         * @throws std::runtime_error if the URL scheme is unsupported, or a
         *         client certificate is configured without its key or over
         *         plain HTTP where it could never be used.
         */
        std::string Validate(const std::string& url) const;
    };

    /** POSTs a request body and returns the response body.
     *
     * @param contentType media type of @p body, e.g. "application/ocsp-request".
     * @param accept      media type expected back.
     * @throws std::runtime_error on a transport failure or a non-200 status.
     */
    std::string HttpPost(const std::string& url, const std::string& body,
        const char* contentType, const char* accept, const HttpTransport& transport);
}
