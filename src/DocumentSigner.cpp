// SPDX-License-Identifier: MIT

#include "DocumentSigner.h"

#include "SignatureField.h"

#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>

using namespace std;
using namespace PoDoFo;
using namespace pdfsign;

namespace
{
    /** OpenSSL digest name for a PoDoFo hashing algorithm. */
    const char* digestName(PdfHashingAlgorithm hashing)
    {
        switch (hashing)
        {
            case PdfHashingAlgorithm::SHA256:
                return "SHA256";
            case PdfHashingAlgorithm::SHA384:
                return "SHA384";
            case PdfHashingAlgorithm::SHA512:
                return "SHA512";
            default:
                throw runtime_error("Unsupported hashing algorithm");
        }
    }
}

DocumentSigner::DocumentSigner(const ISigningIdentity& identity) :
    m_identity(identity)
{
}

void DocumentSigner::SetMetadata(SignatureMetadata metadata)
{
    if (metadata.FieldName.empty())
        throw runtime_error("The signature field needs a name");

    m_metadata = std::move(metadata);
}

void DocumentSigner::applyMetadata(PdfSignature& signature) const
{
    signature.SetSignatureDate(PdfDate::LocalNow());

    PdfName application("podofo-pdf-sign");
    signature.SetCreatingApplication(application);

    if (!m_metadata.SignerName.empty())
    {
        PdfString value(m_metadata.SignerName);
        signature.SetSignerName(value);
    }

    if (!m_metadata.Reason.empty())
    {
        PdfString value(m_metadata.Reason);
        signature.SetSignatureReason(value);
    }

    if (!m_metadata.Location.empty())
    {
        PdfString value(m_metadata.Location);
        signature.SetSignatureLocation(value);
    }
}

void DocumentSigner::Sign(IDocumentSource& source, ISignatureAppearance& appearance)
{
    source.Open();

    auto& signature = CreateSignatureField(source, appearance, m_metadata.FieldName);
    applyMetadata(signature);
    appearance.Apply(source.GetDocument(), signature);

    PdfSignerCmsParams params;
    params.Hashing = m_metadata.Hashing;
    params.SignatureType = m_metadata.SignatureType;

    auto privateKey = m_identity.TryGetPrivateKeyDer();
    m_usedDirectKey = privateKey != nullptr;

    unique_ptr<PdfSignerCms> signer;
    if (privateKey != nullptr)
    {
        signer = make_unique<PdfSignerCms>(m_identity.GetCertificateDer(),
            *privateKey, params);
    }
    else
    {
        // The identity will not part with its key, so PoDoFo hashes the
        // document and asks it to sign that hash instead. Only the digest
        // crosses the boundary, which is what lets an HSM or a remote service
        // stand in here unchanged.
        auto digest = digestName(m_metadata.Hashing);
        auto& identity = m_identity;
        params.SigningService = [&identity, digest](bufferview hashToSign,
            bool /* dryrun */, charbuff& signedHash)
        {
            auto result = identity.SignHash(hashToSign.data(), hashToSign.size(), digest);

            signedHash.resize(result.size());
            if (!result.empty())
                std::memcpy(signedHash.data(), result.data(), result.size());
        };

        signer = make_unique<PdfSignerCms>(m_identity.GetCertificateDer(), params);
    }

    PoDoFo::SignDocument(source.GetDocument(), source.GetDevice(), *signer,
        signature, source.GetSaveOptions());
}
