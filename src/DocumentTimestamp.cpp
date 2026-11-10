// SPDX-License-Identifier: MIT

#include "DocumentTimestamp.h"

#include <cstring>
#include <stdexcept>
#include <utility>

#include "OpenSslSupport.h"
#include "SignatureAppearance.h"
#include "SignatureField.h"

using namespace std;
using namespace PoDoFo;
using namespace pdfsign;

namespace ssl = pdfsign::ssl;

namespace
{
    /** Spare room reserved in /Contents during the dry run.
     *
     * PoDoFo fixes the placeholder size from the dry run, but the real token
     * is produced over a different digest and can differ by a few bytes: DER
     * integer lengths vary, and so does the encoded time. Reserving slack and
     * zero-padding the real token into it is the standard way out. The cost is
     * a couple of kilobytes of hex in the file.
     */
    constexpr size_t TokenSlack = 2048;

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

DocumentTimestampSigner::DocumentTimestampSigner(const ITimestampService& service,
        PdfHashingAlgorithm hashing, size_t reservedSize) :
    m_service(service),
    m_hashing(hashing),
    m_digestName(digestName(hashing)),
    m_configuredReserve(reservedSize)
{
    ensureContext();
}

DocumentTimestampSigner::~DocumentTimestampSigner()
{
    if (m_context != nullptr)
        EVP_MD_CTX_free(m_context);
}

void DocumentTimestampSigner::ensureContext()
{
    if (m_context == nullptr)
    {
        m_context = EVP_MD_CTX_new();
        if (m_context == nullptr)
            ssl::Fail("Cannot allocate the timestamp digest context");
    }

    auto md = EVP_get_digestbyname(m_digestName);
    if (md == nullptr)
        throw runtime_error(string("Unknown digest '") + m_digestName + "'");

    if (EVP_DigestInit_ex(m_context, md, nullptr) != 1)
        ssl::Fail("Cannot initialise the timestamp digest");
}

void DocumentTimestampSigner::Reset()
{
    // PoDoFo hashes the document more than once: the dry run sizes the
    // placeholder, then the real pass runs over the final byte ranges.
    ensureContext();
}

void DocumentTimestampSigner::AppendData(const bufferview& data)
{
    if (EVP_DigestUpdate(m_context, data.data(), data.size()) != 1)
        ssl::Fail("Cannot hash the document for timestamping");
}

void DocumentTimestampSigner::ComputeSignature(charbuff& contents, bool dryrun)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned digestLen = 0;
    if (EVP_DigestFinal_ex(m_context, digest, &digestLen) != 1)
        ssl::Fail("Cannot finalise the document digest");

    if (dryrun && !m_service.IsLocal())
    {
        // A remote authority is asked exactly once. The dry run only needs to
        // know how much room to leave, and the digest it produces is not the
        // one the final token will cover anyway, so asking now would both
        // waste a request and timestamp the wrong bytes.
        m_reserved = m_configuredReserve;
        contents.clear();
        contents.resize(m_reserved);
        std::memset(contents.data(), 0, m_reserved);
        return;
    }

    // The digest of the byte ranges is the message imprint. Nothing else about
    // the document leaves this process, which is why timestamping can safely
    // be handed to a third party.
    auto token = m_service.CreateToken(digest, digestLen, m_digestName);
    if (token.empty())
        throw runtime_error("The timestamp service returned an empty token");

    m_lastTokenSize = token.size();

    size_t reserved;
    if (dryrun)
    {
        // Local service: size the placeholder from a real token plus slack,
        // since the final one may differ by a few bytes.
        reserved = token.size() + TokenSlack;
        m_reserved = reserved;
    }
    else
    {
        if (m_reserved != 0 && token.size() > m_reserved)
        {
            throw runtime_error("The timestamp token is " + to_string(token.size())
                + " bytes but only " + to_string(m_reserved)
                + " were reserved; raise the reservation with --ts-reserve");
        }

        reserved = token.size();
    }

    contents.clear();
    contents.resize(reserved);
    std::memset(contents.data(), 0, reserved);
    std::memcpy(contents.data(), token.data(), token.size());
}

DocumentTimestamper::DocumentTimestamper(const ITimestampService& service) :
    m_service(service)
{
}

void DocumentTimestamper::SetFieldName(string fieldName)
{
    if (fieldName.empty())
        throw runtime_error("The timestamp field needs a name");

    m_fieldName = std::move(fieldName);
}

void DocumentTimestamper::Apply(IDocumentSource& source)
{
    source.Open();

    // A document timestamp is never visible, and carries none of the signer
    // metadata an ordinary signature does: per ETSI its dictionary holds only
    // the type, filter, subfilter, byte range and contents.
    InvisibleAppearance appearance;
    auto& signature = CreateSignatureField(source, appearance, m_fieldName);

    DocumentTimestampSigner signer(m_service, m_hashing, m_reservedSize);
    PoDoFo::SignDocument(source.GetDocument(), source.GetDevice(), signer,
        signature, source.GetSaveOptions());

    m_tokenSize = signer.GetLastTokenSize();
}
