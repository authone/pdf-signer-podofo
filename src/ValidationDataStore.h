// SPDX-License-Identifier: MIT
//
// The Document Security Store: where a PAdES long-term signature keeps the
// certificates and revocation data a validator will need years from now, once
// the OCSP responder is gone.

#pragma once

#include <string>
#include <vector>

#include <podofo/podofo.h>

#include "DocumentSource.h"
#include "ValidationServices.h"

namespace pdfsign
{
    /** Builds and writes the catalog's /DSS dictionary.
     *
     * PoDoFo has no notion of a DSS, so this is assembled directly from the
     * object model: each blob becomes an indirect stream object, and the
     * arrays holding them hang off /DSS in the document catalog.
     *
     * Collected material is merged with whatever a previous revision already
     * put there, so signing, then adding validation data, then doing it again
     * for a second signature accumulates rather than overwrites.
     */
    class ValidationDataStore final
    {
    public:
        explicit ValidationDataStore(PoDoFo::PdfMemDocument& doc);

        /** DER-encoded X.509 certificate needed to build the chain. */
        void AddCertificate(std::string der);

        /** DER-encoded OCSP response. */
        void AddOcspResponse(std::string der);

        /** DER-encoded CRL. */
        void AddCrl(std::string der);

        bool IsEmpty() const;

        std::size_t GetCertificateCount() const { return m_certs.size(); }
        std::size_t GetOcspCount() const { return m_ocsps.size(); }
        std::size_t GetCrlCount() const { return m_crls.size(); }

        /** Writes everything collected into the catalog.
         *
         * Only mutates the in-memory document; the caller decides how the
         * revision reaches disk.
         */
        void Commit();

    private:
        /** Appends the blobs to the named /DSS array, creating it if needed. */
        void appendTo(PoDoFo::PdfDictionary& dss, const PoDoFo::PdfName& key,
            const std::vector<std::string>& blobs);

        PoDoFo::PdfMemDocument& m_doc;
        std::vector<std::string> m_certs;
        std::vector<std::string> m_ocsps;
        std::vector<std::string> m_crls;
    };

    /** Step 2 of a long-term signature: attach validation data to a document
     * that is already signed, as a new revision.
     *
     * The result is a PAdES B-LT document. Nothing is re-signed; the existing
     * signature keeps covering exactly the bytes it always did, and the new
     * revision is appended after it.
     */
    class ValidationDataUpgrade final
    {
    public:
        /** @param responder must outlive the upgrade. */
        explicit ValidationDataUpgrade(const IOcspResponder& responder);

        /** Registers a certificate whose validation data should be embedded.
         *
         * A production tool would pull the signer certificate out of the
         * signature's CMS blob instead of being told; it is supplied here to
         * keep the example's focus on the PDF structure.
         *
         * @param issuerDer may equal @p certDer for a self-signed certificate.
         */
        void AddSubject(std::string certDer, std::string issuerDer);

        /** @throws PoDoFo::PdfError or std::runtime_error on failure. */
        void Apply(IDocumentSource& source);

        std::size_t GetCertificateCount() const { return m_certCount; }
        std::size_t GetOcspCount() const { return m_ocspCount; }

    private:
        struct Subject final
        {
            std::string CertDer;
            std::string IssuerDer;
        };

        const IOcspResponder& m_responder;
        std::vector<Subject> m_subjects;
        std::size_t m_certCount = 0;
        std::size_t m_ocspCount = 0;
    };
}
