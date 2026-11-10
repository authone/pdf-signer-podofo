// SPDX-License-Identifier: MIT

#include "HttpOcspResponder.h"
#include "OpenSslSupport.h"

#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

using namespace std;
using namespace pdfsign;

namespace ssl = pdfsign::ssl;

namespace
{
    // RFC 6960 media types. A responder will reject anything else.
    constexpr const char* RequestContentType = "application/ocsp-request";
    constexpr const char* ResponseAccept = "application/ocsp-response";

    /** How much clock skew to tolerate between us and the responder. */
    constexpr long AllowedSkewSeconds = 300;

    struct OcspReqDelete final { void operator()(OCSP_REQUEST* p) const { OCSP_REQUEST_free(p); } };
    struct OcspRespDelete final { void operator()(OCSP_RESPONSE* p) const { OCSP_RESPONSE_free(p); } };
    struct BasicRespDelete final { void operator()(OCSP_BASICRESP* p) const { OCSP_BASICRESP_free(p); } };
    struct CertIdDelete final { void operator()(OCSP_CERTID* p) const { OCSP_CERTID_free(p); } };
    struct AiaDelete final
    {
        void operator()(AUTHORITY_INFO_ACCESS* p) const { AUTHORITY_INFO_ACCESS_free(p); }
    };

    using OcspReqPtr = unique_ptr<OCSP_REQUEST, OcspReqDelete>;
    using OcspRespPtr = unique_ptr<OCSP_RESPONSE, OcspRespDelete>;
    using BasicRespPtr = unique_ptr<OCSP_BASICRESP, BasicRespDelete>;
    using CertIdPtr = unique_ptr<OCSP_CERTID, CertIdDelete>;
    using AiaPtr = unique_ptr<AUTHORITY_INFO_ACCESS, AiaDelete>;

    ssl::X509Ptr derToCert(const string& der, const char* what)
    {
        auto bio = ssl::MemBio(der);
        ssl::X509Ptr cert(d2i_X509_bio(bio.get(), nullptr));
        if (cert == nullptr)
            ssl::Fail(string("Cannot decode the ") + what + " certificate");

        return cert;
    }

    /** Outcome of comparing the response's nonce with the one we sent. */
    enum class NonceResult { Matched, Absent, Mismatched };

    /** Compares the nonces directly rather than via OCSP_check_nonce.
     *
     * That function's return codes are documented inconsistently across
     * versions -- "nonce in request only" comes back as -1 here, which is
     * also the code for a genuine mismatch -- and conflating the two would
     * reject every responder that pre-produces responses.
     */
    NonceResult checkNonce(OCSP_REQUEST* request, OCSP_BASICRESP* basic)
    {
        auto responseIdx = OCSP_BASICRESP_get_ext_by_NID(basic,
            NID_id_pkix_OCSP_Nonce, -1);
        if (responseIdx < 0)
            return NonceResult::Absent;

        auto requestIdx = OCSP_REQUEST_get_ext_by_NID(request,
            NID_id_pkix_OCSP_Nonce, -1);
        if (requestIdx < 0)
            return NonceResult::Absent;

        auto sent = X509_EXTENSION_get_data(OCSP_REQUEST_get_ext(request, requestIdx));
        auto echoed = X509_EXTENSION_get_data(OCSP_BASICRESP_get_ext(basic, responseIdx));
        if (sent == nullptr || echoed == nullptr)
            return NonceResult::Absent;

        return ASN1_OCTET_STRING_cmp(sent, echoed) == 0
            ? NonceResult::Matched
            : NonceResult::Mismatched;
    }

    const char* statusName(int status)
    {
        switch (status)
        {
            case V_OCSP_CERTSTATUS_GOOD:
                return "good";
            case V_OCSP_CERTSTATUS_REVOKED:
                return "revoked";
            default:
                return "unknown";
        }
    }
}

string HttpOcspResponder::FindAiaUrl(const string& certDer)
{
    auto cert = derToCert(certDer, "subject");

    AiaPtr aia(static_cast<AUTHORITY_INFO_ACCESS*>(
        X509_get_ext_d2i(cert.get(), NID_info_access, nullptr, nullptr)));
    if (aia == nullptr)
        return {};

    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia.get()); i++)
    {
        auto entry = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
        if (OBJ_obj2nid(entry->method) != NID_ad_OCSP)
            continue;

        if (entry->location->type != GEN_URI)
            continue;

        auto uri = entry->location->d.uniformResourceIdentifier;
        return string((const char*)ASN1_STRING_get0_data(uri),
            (size_t)ASN1_STRING_length(uri));
    }

    return {};
}

HttpOcspResponder::HttpOcspResponder(string url, HttpTransport transport) :
    m_url(std::move(url)),
    m_transport(std::move(transport))
{
    if (m_url.empty())
    {
        // Resolved per certificate from its AIA extension.
        m_description = "responder named by each certificate (AIA)";
        return;
    }

    auto auth = m_transport.Validate(m_url);
    m_description = m_url;
    if (!auth.empty())
        m_description += " (" + auth + ")";
}

string HttpOcspResponder::CreateResponse(const string& certDer,
    const string& issuerDer) const
{
    auto subject = derToCert(certDer, "subject");
    auto issuer = derToCert(issuerDer, "issuer");

    auto url = m_url;
    if (url.empty())
    {
        url = FindAiaUrl(certDer);
        if (url.empty())
        {
            throw runtime_error("No OCSP responder given and the certificate "
                "publishes none in its Authority Information Access extension; "
                "pass --ocsp with the responder URL");
        }

        // Settings were not validated against this URL at construction.
        m_transport.Validate(url);
    }

    m_lastUrl = url;

    // --- build the request ---------------------------------------------
    // RFC 6960 defines CertID over SHA-1 of the issuer name and key. That is
    // the protocol's choice, not a security decision made here.
    CertIdPtr certId(OCSP_cert_to_id(EVP_sha1(), subject.get(), issuer.get()));
    if (certId == nullptr)
        ssl::Fail("Cannot build the OCSP CertID");

    OcspReqPtr request(OCSP_REQUEST_new());
    if (request == nullptr)
        ssl::Fail("Cannot allocate the OCSP request");

    // OCSP_request_add0_id takes ownership of the CertID on success, but we
    // still need it afterwards to find our answer in the response, so a copy
    // is handed over.
    CertIdPtr owned(OCSP_CERTID_dup(certId.get()));
    if (owned == nullptr)
        ssl::Fail("Cannot duplicate the OCSP CertID");

    if (OCSP_request_add0_id(request.get(), owned.get()) == nullptr)
        ssl::Fail("Cannot add the certificate to the OCSP request");

    owned.release();

    if (OCSP_request_add1_nonce(request.get(), nullptr, -1) != 1)
        ssl::Fail("Cannot add a nonce to the OCSP request");

    unsigned char* requestDer = nullptr;
    auto requestLen = i2d_OCSP_REQUEST(request.get(), &requestDer);
    if (requestLen <= 0)
        ssl::Fail("Cannot encode the OCSP request");

    ssl::SslBufPtr<unsigned char> requestGuard(requestDer);
    string requestBytes((const char*)requestDer, (size_t)requestLen);

    // --- exchange --------------------------------------------------------
    auto responseBytes = HttpPost(url, requestBytes,
        RequestContentType, ResponseAccept, m_transport);

    auto responseBio = ssl::MemBio(responseBytes);
    OcspRespPtr response(d2i_OCSP_RESPONSE_bio(responseBio.get(), nullptr));
    if (response == nullptr)
        ssl::Fail("The responder's reply is not a valid OCSP response");

    auto responseStatus = OCSP_response_status(response.get());
    if (responseStatus != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
        throw runtime_error(string("The OCSP responder refused the request: ")
            + OCSP_response_status_str(responseStatus)
            + " (a responder answers 'unauthorized' for a certificate it does "
              "not issue status for)");
    }

    BasicRespPtr basic(OCSP_response_get1_basic(response.get()));
    if (basic == nullptr)
        ssl::Fail("The OCSP response carries no basic response");

    // --- check the reply answers our request ------------------------------
    // Responders that pre-produce and cache responses legitimately return no
    // nonce at all, so only one that is present and different is a failure.
    switch (checkNonce(request.get(), basic.get()))
    {
        case NonceResult::Mismatched:
            throw runtime_error("The OCSP responder echoed a different nonce; "
                "the reply is not an answer to our request");
        case NonceResult::Absent:
            m_lastNonce = "absent (pre-produced response)";
            break;
        default:
            m_lastNonce = "echoed";
            break;
    }

    int status = 0;
    int reason = 0;
    ASN1_GENERALIZEDTIME* revokedAt = nullptr;
    ASN1_GENERALIZEDTIME* thisUpdate = nullptr;
    ASN1_GENERALIZEDTIME* nextUpdate = nullptr;

    if (OCSP_resp_find_status(basic.get(), certId.get(), &status, &reason,
        &revokedAt, &thisUpdate, &nextUpdate) != 1)
    {
        throw runtime_error("The OCSP response says nothing about the certificate "
            "we asked about");
    }

    if (OCSP_check_validity(thisUpdate, nextUpdate, AllowedSkewSeconds, -1) != 1)
    {
        ERR_clear_error();
        throw runtime_error("The OCSP response is outside its validity window; "
            "check the clock on this machine and on the responder");
    }

    m_lastStatus = statusName(status);

    if (status == V_OCSP_CERTSTATUS_REVOKED)
    {
        // Embedded rather than refused: the DSS is a record of what the
        // responder said, and the caller is told plainly.
        m_lastStatus += reason >= 0
            ? string(" (") + OCSP_crl_reason_str(reason) + ")"
            : string();
    }

    // The DSS stores the whole signed response, not just the status.
    return responseBytes;
}
