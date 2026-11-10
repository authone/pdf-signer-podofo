// SPDX-License-Identifier: MIT

#pragma once

#include <string>

#include <podofo/podofo.h>

#include "DocumentSource.h"
#include "SignatureAppearance.h"
#include "SigningIdentity.h"

namespace pdfsign
{
    /** What gets recorded in the signature dictionary. */
    struct SignatureMetadata final
    {
        /** Field name; must be unique within the document's AcroForm. */
        std::string FieldName = "Signature1";

        std::string SignerName;
        std::string Reason;
        std::string Location;

        PoDoFo::PdfHashingAlgorithm Hashing = PoDoFo::PdfHashingAlgorithm::SHA256;

        /** PAdES_B yields the ETSI profile (/ETSI.CAdES.detached), Pkcs7 the
         * legacy Adobe one (/adbe.pkcs7.detached). */
        PoDoFo::PdfSignatureType SignatureType = PoDoFo::PdfSignatureType::PAdES_B;
    };

    /** Signs a document, given an identity, a source and an appearance.
     *
     * The signer holds no opinion about where the document came from, whether
     * the signature is visible, or whether the private key is reachable. Each
     * of those is the collaborating object's business.
     */
    class DocumentSigner final
    {
    public:
        /** @param identity must outlive the signer. */
        explicit DocumentSigner(const ISigningIdentity& identity);

        void SetMetadata(SignatureMetadata metadata);
        const SignatureMetadata& GetMetadata() const { return m_metadata; }

        /** Signs @p source, placing the field as @p appearance dictates.
         *
         * Both must outlive the call.
         *
         * @throws PoDoFo::PdfError or std::runtime_error on failure.
         */
        void Sign(IDocumentSource& source, ISignatureAppearance& appearance);

        /** True when the identity handed its key over, false when signing went
         * through the callback. Only meaningful after Sign. */
        bool UsedDirectKey() const { return m_usedDirectKey; }

    private:
        void applyMetadata(PoDoFo::PdfSignature& signature) const;

        const ISigningIdentity& m_identity;
        SignatureMetadata m_metadata;
        bool m_usedDirectKey = false;
    };
}
