// SPDX-License-Identifier: MIT
//
// Document-level timestamps: the step that takes a long-term signature from
// LT to LTA by proving the validation data existed at a point in time.

#pragma once

#include <memory>
#include <string>

#include <openssl/evp.h>
#include <podofo/podofo.h>

#include "DocumentSource.h"
#include "ValidationServices.h"

namespace pdfsign
{
    /** A PdfSigner that emits an RFC 3161 timestamp token instead of a CMS
     * signature.
     *
     * PoDoFo does not know about document timestamps, but it does not need to:
     * PdfSigner is the extension point. Overriding the filter, subfilter and
     * type is what turns an ordinary signature field into a /DocTimeStamp, and
     * the base class handles the byte ranges and the placeholder exactly as it
     * does for a normal signature.
     */
    class DocumentTimestampSigner final : public PoDoFo::PdfSigner
    {
    public:
        /** @param service must outlive the signer. */
        /** @param reservedSize bytes to reserve for /Contents when the
         *         service is remote and must not be called during the dry
         *         run. Ignored for a local service, which is asked twice and
         *         sized exactly. */
        DocumentTimestampSigner(const ITimestampService& service,
            PoDoFo::PdfHashingAlgorithm hashing = PoDoFo::PdfHashingAlgorithm::SHA256,
            std::size_t reservedSize = 16384);

        ~DocumentTimestampSigner() override;

        void Reset() override;
        void AppendData(const PoDoFo::bufferview& data) override;
        void ComputeSignature(PoDoFo::charbuff& contents, bool dryrun) override;

        std::string GetSignatureFilter() const override { return "Adobe.PPKLite"; }

        /** The subfilter that marks the /Contents as a bare timestamp token
         * rather than a CMS signature. */
        std::string GetSignatureSubFilter() const override { return "ETSI.RFC3161"; }

        /** /Type is DocTimeStamp, not Sig. This is what tells a validator the
         * field timestamps the document rather than signing it. */
        std::string GetSignatureType() const override { return "DocTimeStamp"; }

        /** Size of the last token produced, for reporting. */
        std::size_t GetLastTokenSize() const { return m_lastTokenSize; }

    private:
        void ensureContext();

        const ITimestampService& m_service;
        PoDoFo::PdfHashingAlgorithm m_hashing;
        const char* m_digestName;
        EVP_MD_CTX* m_context = nullptr;
        std::size_t m_configuredReserve;
        std::size_t m_reserved = 0;
        std::size_t m_lastTokenSize = 0;
    };

    /** Adds a document timestamp as a new revision.
     *
     * Structurally the same dance as signing: a field is created and
     * PoDoFo::SignDocument does the rest. Only the signer differs.
     */
    class DocumentTimestamper final
    {
    public:
        /** @param service must outlive the timestamper. */
        explicit DocumentTimestamper(const ITimestampService& service);

        void SetFieldName(std::string fieldName);
        void SetHashing(PoDoFo::PdfHashingAlgorithm hashing) { m_hashing = hashing; }

        /** /Contents reservation used when the authority is remote. */
        void SetReservedTokenSize(std::size_t bytes) { m_reservedSize = bytes; }

        /** @throws PoDoFo::PdfError or std::runtime_error on failure. */
        void Apply(IDocumentSource& source);

        std::size_t GetTokenSize() const { return m_tokenSize; }

    private:
        const ITimestampService& m_service;
        std::string m_fieldName = "Timestamp1";
        PoDoFo::PdfHashingAlgorithm m_hashing = PoDoFo::PdfHashingAlgorithm::SHA256;
        std::size_t m_reservedSize = 16384;
        std::size_t m_tokenSize = 0;
    };
}
