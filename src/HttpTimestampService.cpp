// SPDX-License-Identifier: MIT

#include "HttpTimestampService.h"

#include "HttpClient.h"
#include "OpenSslSupport.h"

#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

using namespace std;
using namespace pdfsign;

namespace ssl = pdfsign::ssl;

namespace
{
    // RFC 3161 media types. Providers reject a request sent as anything else.
    constexpr const char* RequestContentType = "application/timestamp-query";
    constexpr const char* ResponseAccept = "application/timestamp-reply";

    struct TsReqDelete final { void operator()(TS_REQ* p) const { TS_REQ_free(p); } };
    struct TsRespDelete final { void operator()(TS_RESP* p) const { TS_RESP_free(p); } };
    struct MsgImprintDelete final { void operator()(TS_MSG_IMPRINT* p) const { TS_MSG_IMPRINT_free(p); } };
    struct X509AlgorDelete final { void operator()(X509_ALGOR* p) const { X509_ALGOR_free(p); } };
    struct Asn1IntDelete final { void operator()(ASN1_INTEGER* p) const { ASN1_INTEGER_free(p); } };

    using TsReqPtr = unique_ptr<TS_REQ, TsReqDelete>;
    using TsRespPtr = unique_ptr<TS_RESP, TsRespDelete>;
    using MsgImprintPtr = unique_ptr<TS_MSG_IMPRINT, MsgImprintDelete>;
    using X509AlgorPtr = unique_ptr<X509_ALGOR, X509AlgorDelete>;
    using Asn1IntPtr = unique_ptr<ASN1_INTEGER, Asn1IntDelete>;

    /** A fresh 64-bit nonce.
     *
     * The authority must echo this back. Without it there is nothing tying
     * the token we receive to the request we sent, so a token captured
     * earlier could be replayed at us.
     */
    Asn1IntPtr makeNonce()
    {
        unsigned char bytes[8];
        if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1)
            ssl::Fail("Cannot generate a timestamp nonce");

        // Clear the top bit so the value stays a positive INTEGER.
        bytes[0] &= 0x7F;

        ssl::BnPtr bn(BN_bin2bn(bytes, (int)sizeof(bytes), nullptr));
        if (bn == nullptr)
            ssl::Fail("Cannot convert the nonce");

        Asn1IntPtr nonce(BN_to_ASN1_INTEGER(bn.get(), nullptr));
        if (nonce == nullptr)
            ssl::Fail("Cannot encode the nonce");

        return nonce;
    }

    string describeFailure(TS_RESP* response)
    {
        auto status = TS_RESP_get_status_info(response);
        auto code = ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(status));

        string text;
        auto reasons = TS_STATUS_INFO_get0_text(status);
        if (reasons != nullptr)
        {
            for (int i = 0; i < sk_ASN1_UTF8STRING_num(reasons); i++)
            {
                auto entry = sk_ASN1_UTF8STRING_value(reasons, i);
                if (!text.empty())
                    text.append("; ");

                text.append((const char*)ASN1_STRING_get0_data(entry),
                    (size_t)ASN1_STRING_length(entry));
            }
        }

        auto result = "the authority returned status " + to_string(code);
        if (!text.empty())
            result += " (" + text + ")";

        return result;
    }

    string asn1TimeToString(const ASN1_GENERALIZEDTIME* time)
    {
        if (time == nullptr)
            return {};

        return string((const char*)ASN1_STRING_get0_data(time),
            (size_t)ASN1_STRING_length(time));
    }
}

HttpTimestampService::HttpTimestampService(TsaHttpConfig config) :
    m_config(std::move(config))
{
    if (m_config.Url.empty())
        throw runtime_error("A timestamp authority URL is required");

    auto auth = m_config.Transport.Validate(m_config.Url);
    m_description = m_config.Url;
    if (!auth.empty())
        m_description += " (" + auth + ")";
}

string HttpTimestampService::CreateToken(const void* hash, size_t hashLen,
    const char* digestName) const
{
    auto md = EVP_get_digestbyname(digestName);
    if (md == nullptr)
        throw runtime_error(string("Unknown digest '") + digestName + "'");

    if (hashLen != (size_t)EVP_MD_get_size(md))
        throw runtime_error("The message imprint length does not match the digest");

    // --- build the request -------------------------------------------
    TsReqPtr request(TS_REQ_new());
    if (request == nullptr)
        ssl::Fail("Cannot allocate the timestamp request");

    if (TS_REQ_set_version(request.get(), 1) != 1)
        ssl::Fail("Cannot set the request version");

    MsgImprintPtr imprint(TS_MSG_IMPRINT_new());
    if (imprint == nullptr)
        ssl::Fail("Cannot allocate the message imprint");

    X509AlgorPtr algorithm(X509_ALGOR_new());
    if (algorithm == nullptr)
        ssl::Fail("Cannot allocate the imprint algorithm");

    if (X509_ALGOR_set0(algorithm.get(), OBJ_nid2obj(EVP_MD_get_type(md)),
        V_ASN1_NULL, nullptr) != 1)
    {
        ssl::Fail("Cannot set the imprint algorithm");
    }

    if (TS_MSG_IMPRINT_set_algo(imprint.get(), algorithm.get()) != 1)
        ssl::Fail("Cannot attach the imprint algorithm");

    if (TS_MSG_IMPRINT_set_msg(imprint.get(),
        (unsigned char*)const_cast<void*>(hash), (int)hashLen) != 1)
    {
        ssl::Fail("Cannot attach the message imprint");
    }

    if (TS_REQ_set_msg_imprint(request.get(), imprint.get()) != 1)
        ssl::Fail("Cannot set the message imprint");

    auto nonce = makeNonce();
    if (TS_REQ_set_nonce(request.get(), nonce.get()) != 1)
        ssl::Fail("Cannot set the request nonce");

    if (TS_REQ_set_cert_req(request.get(),
        m_config.RequestCertificate ? 1 : 0) != 1)
    {
        ssl::Fail("Cannot set the certificate request flag");
    }

    unsigned char* requestDer = nullptr;
    auto requestLen = i2d_TS_REQ(request.get(), &requestDer);
    if (requestLen <= 0)
        ssl::Fail("Cannot encode the timestamp request");

    ssl::SslBufPtr<unsigned char> requestGuard(requestDer);
    string requestBytes((const char*)requestDer, (size_t)requestLen);

    // --- exchange ------------------------------------------------------
    auto responseBytes = HttpPost(m_config.Url, requestBytes,
        RequestContentType, ResponseAccept, m_config.Transport);

    auto responseBio = ssl::MemBio(responseBytes);
    TsRespPtr response(d2i_TS_RESP_bio(responseBio.get(), nullptr));
    if (response == nullptr)
        ssl::Fail("The authority's reply is not a valid timestamp response");

    auto statusInfo = TS_RESP_get_status_info(response.get());
    auto statusCode = ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(statusInfo));

    // 0 granted, 1 grantedWithMods. Anything else is a refusal.
    if (statusCode != 0 && statusCode != 1)
        throw runtime_error("Timestamping was refused: " + describeFailure(response.get()));

    auto info = TS_RESP_get_tst_info(response.get());
    if (info == nullptr)
        throw runtime_error("The timestamp response carries no TSTInfo");

    // --- check the reply actually answers our request -------------------
    auto echoed = TS_TST_INFO_get_nonce(info);
    if (echoed == nullptr)
        throw runtime_error("The authority did not echo the nonce");

    if (ASN1_INTEGER_cmp(echoed, nonce.get()) != 0)
        throw runtime_error("The authority echoed a different nonce; the reply is not ours");

    auto returnedImprint = TS_TST_INFO_get_msg_imprint(info);
    if (returnedImprint == nullptr)
        throw runtime_error("The timestamp response carries no message imprint");

    auto returnedMsg = TS_MSG_IMPRINT_get_msg(returnedImprint);
    if (returnedMsg == nullptr
        || (size_t)ASN1_STRING_length(returnedMsg) != hashLen
        || std::memcmp(ASN1_STRING_get0_data(returnedMsg), hash, hashLen) != 0)
    {
        throw runtime_error("The authority timestamped a different digest");
    }

    m_lastGenTime = asn1TimeToString(TS_TST_INFO_get_time(info));

    // --- take the token -------------------------------------------------
    auto token = TS_RESP_get_token(response.get());
    if (token == nullptr)
        throw runtime_error("The timestamp response carries no token");

    unsigned char* tokenDer = nullptr;
    auto tokenLen = i2d_PKCS7(token, &tokenDer);
    if (tokenLen <= 0)
        ssl::Fail("Cannot encode the timestamp token");

    ssl::SslBufPtr<unsigned char> tokenGuard(tokenDer);
    return string((const char*)tokenDer, (size_t)tokenLen);
}
