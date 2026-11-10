// SPDX-License-Identifier: MIT

#include "ValidationServices.h"
#include "OpenSslSupport.h"

#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>

using namespace std;
using namespace pdfsign;

namespace ssl = pdfsign::ssl;

namespace
{
    // Deleters for the OCSP and timestamp types. Kept local rather than in
    // OpenSslSupport.h, which stays about certificates and keys.
    struct CertIdDelete final { void operator()(OCSP_CERTID* p) const { OCSP_CERTID_free(p); } };
    struct BasicRespDelete final { void operator()(OCSP_BASICRESP* p) const { OCSP_BASICRESP_free(p); } };
    struct OcspRespDelete final { void operator()(OCSP_RESPONSE* p) const { OCSP_RESPONSE_free(p); } };
    struct Asn1TimeDelete final { void operator()(ASN1_TIME* p) const { ASN1_TIME_free(p); } };
    struct Asn1ObjDelete final { void operator()(ASN1_OBJECT* p) const { ASN1_OBJECT_free(p); } };
    struct TsRespCtxDelete final { void operator()(TS_RESP_CTX* p) const { TS_RESP_CTX_free(p); } };
    struct TsReqDelete final { void operator()(TS_REQ* p) const { TS_REQ_free(p); } };
    struct TsRespDelete final { void operator()(TS_RESP* p) const { TS_RESP_free(p); } };
    struct MsgImprintDelete final { void operator()(TS_MSG_IMPRINT* p) const { TS_MSG_IMPRINT_free(p); } };
    struct X509AlgorDelete final { void operator()(X509_ALGOR* p) const { X509_ALGOR_free(p); } };

    using CertIdPtr = unique_ptr<OCSP_CERTID, CertIdDelete>;
    using BasicRespPtr = unique_ptr<OCSP_BASICRESP, BasicRespDelete>;
    using OcspRespPtr = unique_ptr<OCSP_RESPONSE, OcspRespDelete>;
    using Asn1TimePtr = unique_ptr<ASN1_TIME, Asn1TimeDelete>;
    using Asn1ObjPtr = unique_ptr<ASN1_OBJECT, Asn1ObjDelete>;
    using TsRespCtxPtr = unique_ptr<TS_RESP_CTX, TsRespCtxDelete>;
    using TsReqPtr = unique_ptr<TS_REQ, TsReqDelete>;
    using TsRespPtr = unique_ptr<TS_RESP, TsRespDelete>;
    using MsgImprintPtr = unique_ptr<TS_MSG_IMPRINT, MsgImprintDelete>;
    using X509AlgorPtr = unique_ptr<X509_ALGOR, X509AlgorDelete>;

    ssl::X509Ptr derToCert(const string& der, const char* what)
    {
        auto bio = ssl::MemBio(der);
        ssl::X509Ptr cert(d2i_X509_bio(bio.get(), nullptr));
        if (cert == nullptr)
            ssl::Fail(string("Cannot decode the ") + what + " certificate");

        return cert;
    }

    /** The timestamp response context needs a serial number source.
     *
     * A real TSA would allocate a unique, monotonic serial per token and
     * persist it. A constant is fine here and makes output reproducible.
     */
    ASN1_INTEGER* constantSerial(struct TS_resp_ctx*, void*)
    {
        auto serial = ASN1_INTEGER_new();
        if (serial != nullptr)
            ASN1_INTEGER_set(serial, 1);

        return serial;
    }
}

MockOcspResponder::MockOcspResponder(string responderCertDer, string responderKeyDer) :
    m_certDer(std::move(responderCertDer)),
    m_keyDer(std::move(responderKeyDer))
{
    if (m_certDer.empty() || m_keyDer.empty())
        throw runtime_error("The mock OCSP responder needs a certificate and a key");
}

string MockOcspResponder::CreateResponse(const string& certDer, const string& issuerDer) const
{
    auto subject = derToCert(certDer, "subject");
    auto issuer = derToCert(issuerDer, "issuer");
    auto responder = derToCert(m_certDer, "responder");

    auto responderKey = ssl::ParseDerKey(m_keyDer);
    if (responderKey == nullptr)
        ssl::Fail("Cannot read the OCSP responder key");

    // RFC 6960 defines CertID over SHA-1 of the issuer name and key. That is
    // the protocol's choice, not a security decision made here.
    CertIdPtr certId(OCSP_cert_to_id(EVP_sha1(), subject.get(), issuer.get()));
    if (certId == nullptr)
        ssl::Fail("Cannot build the OCSP CertID");

    BasicRespPtr basic(OCSP_BASICRESP_new());
    if (basic == nullptr)
        ssl::Fail("Cannot allocate the OCSP response");

    Asn1TimePtr thisUpdate(X509_gmtime_adj(nullptr, 0));
    Asn1TimePtr nextUpdate(X509_gmtime_adj(nullptr, 60 * 60 * 24 * 7));
    if (thisUpdate == nullptr || nextUpdate == nullptr)
        ssl::Fail("Cannot build the OCSP validity times");

    // Always "good": this responder exists to exercise the PDF plumbing, not
    // to make revocation decisions.
    if (OCSP_basic_add1_status(basic.get(), certId.get(), V_OCSP_CERTSTATUS_GOOD,
        0, nullptr, thisUpdate.get(), nextUpdate.get()) == nullptr)
    {
        ssl::Fail("Cannot add the OCSP single response");
    }

    // flags 0 embeds the responder certificate in the response, which is what
    // lets a validator check the signature without a separate fetch.
    if (OCSP_basic_sign(basic.get(), responder.get(), responderKey.get(),
        EVP_sha256(), nullptr, 0) != 1)
    {
        ssl::Fail("Cannot sign the OCSP response");
    }

    OcspRespPtr response(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get()));
    if (response == nullptr)
        ssl::Fail("Cannot assemble the OCSP response");

    unsigned char* der = nullptr;
    auto len = i2d_OCSP_RESPONSE(response.get(), &der);
    if (len <= 0)
        ssl::Fail("Cannot DER-encode the OCSP response");

    ssl::SslBufPtr<unsigned char> guard(der);
    return string((const char*)der, (size_t)len);
}

MockTimestampAuthority::MockTimestampAuthority(string tsaCertDer, string tsaKeyDer,
        string policyOid) :
    m_certDer(std::move(tsaCertDer)),
    m_keyDer(std::move(tsaKeyDer)),
    m_policyOid(std::move(policyOid))
{
    if (m_certDer.empty() || m_keyDer.empty())
        throw runtime_error("The mock TSA needs a certificate and a key");
}

string MockTimestampAuthority::CreateToken(const void* hash, size_t hashLen,
    const char* digestName) const
{
    auto md = EVP_get_digestbyname(digestName);
    if (md == nullptr)
        throw runtime_error(string("Unknown digest '") + digestName + "'");

    if (hashLen != (size_t)EVP_MD_get_size(md))
        throw runtime_error("The message imprint length does not match the digest");

    auto tsaCert = derToCert(m_certDer, "TSA");
    auto tsaKey = ssl::ParseDerKey(m_keyDer);
    if (tsaKey == nullptr)
        ssl::Fail("Cannot read the TSA key");

    TsRespCtxPtr ctx(TS_RESP_CTX_new());
    if (ctx == nullptr)
        ssl::Fail("Cannot allocate the timestamp response context");

    // OpenSSL enforces that a TSA certificate carries a critical
    // id-kp-timeStamping extended key usage, and refuses the certificate
    // outright if it does not. A document-signing certificate will not do.
    if (TS_RESP_CTX_set_signer_cert(ctx.get(), tsaCert.get()) != 1)
    {
        ssl::Fail("The TSA certificate is not usable for timestamping "
            "(it needs a critical timeStamping extended key usage)");
    }

    if (TS_RESP_CTX_set_signer_key(ctx.get(), tsaKey.get()) != 1)
        ssl::Fail("Cannot set the TSA signing key");

    if (TS_RESP_CTX_set_signer_digest(ctx.get(), md) != 1)
        ssl::Fail("Cannot set the TSA signing digest");

    Asn1ObjPtr policy(OBJ_txt2obj(m_policyOid.c_str(), 1));
    if (policy == nullptr)
        ssl::Fail("Cannot parse the TSA policy OID '" + m_policyOid + "'");

    if (TS_RESP_CTX_set_def_policy(ctx.get(), policy.get()) != 1)
        ssl::Fail("Cannot set the TSA default policy");

    if (TS_RESP_CTX_add_md(ctx.get(), md) != 1)
        ssl::Fail("Cannot register the accepted digest with the TSA");

    TS_RESP_CTX_set_serial_cb(ctx.get(), &constantSerial, nullptr);

    // TS_RESP_create_response consumes a serialised request, so the request a
    // real client would send over HTTP is built here and fed straight in.
    TsReqPtr request(TS_REQ_new());
    if (request == nullptr)
        ssl::Fail("Cannot allocate the timestamp request");

    if (TS_REQ_set_version(request.get(), 1) != 1)
        ssl::Fail("Cannot set the timestamp request version");

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
        ssl::Fail("Cannot set the message imprint on the request");

    // Ask for the TSA certificate to be embedded, so the token validates
    // without a separate certificate fetch.
    if (TS_REQ_set_cert_req(request.get(), 1) != 1)
        ssl::Fail("Cannot set the certificate request flag");

    ssl::BioPtr requestBio(BIO_new(BIO_s_mem()));
    if (requestBio == nullptr)
        ssl::Fail("Cannot allocate the request BIO");

    if (i2d_TS_REQ_bio(requestBio.get(), request.get()) != 1)
        ssl::Fail("Cannot encode the timestamp request");

    TsRespPtr response(TS_RESP_create_response(ctx.get(), requestBio.get()));
    if (response == nullptr)
        ssl::Fail("The TSA refused to produce a response");

    auto status = TS_RESP_get_status_info(response.get());
    auto statusValue = ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(status));
    if (statusValue != 0 && statusValue != 1)
        throw runtime_error("The TSA returned status " + to_string(statusValue));

    // The token is the CMS ContentInfo that goes into /Contents; it is owned
    // by the response, so it is encoded rather than taken.
    auto token = TS_RESP_get_token(response.get());
    if (token == nullptr)
        throw runtime_error("The timestamp response carries no token");

    unsigned char* der = nullptr;
    auto len = i2d_PKCS7(token, &der);
    if (len <= 0)
        ssl::Fail("Cannot DER-encode the timestamp token");

    ssl::SslBufPtr<unsigned char> guard(der);
    return string((const char*)der, (size_t)len);
}
