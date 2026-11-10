// SPDX-License-Identifier: MIT

#include "SigningIdentity.h"
#include "OpenSslSupport.h"

#include <stdexcept>
#include <utility>

#include <openssl/err.h>
#include <openssl/rsa.h>

using namespace std;
using namespace pdfsign;

namespace ssl = pdfsign::ssl;

string CertificateInfo::GetCommonName() const
{
    for (size_t pos = 0; pos != string::npos; )
    {
        auto found = Subject.find("CN=", pos);
        if (found == string::npos)
            break;

        // Skip a match inside another attribute's value.
        if (found != 0 && Subject[found - 1] != ',' && Subject[found - 1] != '/')
        {
            pos = found + 3;
            continue;
        }

        auto start = found + 3;
        auto end = start;
        while (end < Subject.size() && !(Subject[end] == ',' && Subject[end - 1] != '\\'))
            end++;

        return Subject.substr(start, end - start);
    }

    return Subject;
}

LocalSigningIdentity::LocalSigningIdentity(string certDer, string keyDer,
        vector<string> chainDer) :
    m_certDer(std::move(certDer)),
    m_keyDer(std::move(keyDer)),
    m_chainDer(std::move(chainDer))
{
    if (m_certDer.empty())
        throw runtime_error("A signing identity needs a certificate");

    describeCertificate();
    verifyKeyMatchesCertificate();
}

const string* LocalSigningIdentity::TryGetPrivateKeyDer() const
{
    return m_keyDer.empty() ? nullptr : &m_keyDer;
}

void LocalSigningIdentity::describeCertificate()
{
    auto bio = ssl::MemBio(m_certDer);
    ssl::X509Ptr cert(d2i_X509_bio(bio.get(), nullptr));
    if (cert == nullptr)
        ssl::Fail("Cannot decode the DER certificate");

    m_info.Subject = ssl::NameToString(X509_get_subject_name(cert.get()));
    m_info.Issuer = ssl::NameToString(X509_get_issuer_name(cert.get()));
    m_info.Serial = ssl::SerialToString(cert.get());
    m_info.NotBefore = ssl::TimeToString(X509_get0_notBefore(cert.get()));
    m_info.NotAfter = ssl::TimeToString(X509_get0_notAfter(cert.get()));

    auto pubkey = X509_get0_pubkey(cert.get());
    if (pubkey != nullptr)
    {
        auto name = EVP_PKEY_get0_type_name(pubkey);
        m_info.KeyAlgorithm = name == nullptr ? "unknown" : name;
        m_info.KeyBits = (unsigned)EVP_PKEY_get_bits(pubkey);
    }
}

void LocalSigningIdentity::verifyKeyMatchesCertificate() const
{
    if (m_keyDer.empty())
        return;

    auto certBio = ssl::MemBio(m_certDer);
    ssl::X509Ptr cert(d2i_X509_bio(certBio.get(), nullptr));
    if (cert == nullptr)
        ssl::Fail("Cannot re-read the DER certificate");

    auto key = ssl::ParseDerKey(m_keyDer);
    if (key == nullptr)
        ssl::Fail("Cannot re-read the DER private key");

    if (X509_check_private_key(cert.get(), key.get()) != 1)
    {
        ERR_clear_error();
        throw runtime_error("The private key does not match the certificate; "
            "any signature made with them would be rejected");
    }
}

string LocalSigningIdentity::SignHash(const void* hash, size_t hashLen,
    const char* digestName) const
{
    if (m_keyDer.empty())
        throw runtime_error("This identity has no private key to sign with");

    auto md = EVP_get_digestbyname(digestName);
    if (md == nullptr)
        throw runtime_error(string("Unknown digest '") + digestName + "'");

    if (hashLen != (size_t)EVP_MD_get_size(md))
    {
        throw runtime_error(string("Digest length does not match ") + digestName
            + "; the signing callback was handed " + to_string(hashLen) + " bytes");
    }

    auto key = ssl::ParseDerKey(m_keyDer);
    if (key == nullptr)
        ssl::Fail("Cannot read the private key for hash signing");

    ssl::PKeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
    if (ctx == nullptr)
        ssl::Fail("Cannot create a signing context");

    if (EVP_PKEY_sign_init(ctx.get()) <= 0)
        ssl::Fail("Cannot initialise the signing context");

    // RSA needs the padding set explicitly; with the signature digest it makes
    // OpenSSL emit the DigestInfo-wrapped PKCS#1 v1.5 signature PoDoFo expects.
    if (EVP_PKEY_get_base_id(key.get()) == EVP_PKEY_RSA
        && EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0)
    {
        ssl::Fail("Cannot select RSA PKCS#1 v1.5 padding");
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx.get(), md) <= 0)
        ssl::Fail("Cannot select the signature digest");

    auto digest = static_cast<const unsigned char*>(hash);

    size_t len = 0;
    if (EVP_PKEY_sign(ctx.get(), nullptr, &len, digest, hashLen) <= 0)
        ssl::Fail("Cannot determine the signature size");

    string result(len, '\0');
    if (EVP_PKEY_sign(ctx.get(), (unsigned char*)result.data(), &len, digest, hashLen) <= 0)
        ssl::Fail("Signing the hash failed");

    result.resize(len);
    return result;
}

OpaqueKeyIdentity::OpaqueKeyIdentity(unique_ptr<ISigningIdentity> inner) :
    m_inner(std::move(inner))
{
    if (m_inner == nullptr)
        throw runtime_error("OpaqueKeyIdentity needs an identity to wrap");
}

const string& OpaqueKeyIdentity::GetCertificateDer() const
{
    return m_inner->GetCertificateDer();
}

const CertificateInfo& OpaqueKeyIdentity::GetInfo() const
{
    return m_inner->GetInfo();
}

const vector<string>& OpaqueKeyIdentity::GetChainDer() const
{
    return m_inner->GetChainDer();
}

string OpaqueKeyIdentity::SignHash(const void* hash, size_t hashLen,
    const char* digestName) const
{
    return m_inner->SignHash(hash, hashLen, digestName);
}

unique_ptr<ISigningIdentity> IdentityLoader::FromPkcs12(const string& path,
    const string& password)
{
    auto data = ssl::ReadFile(path);
    auto bio = ssl::MemBio(data);

    ssl::P12Ptr p12(d2i_PKCS12_bio(bio.get(), nullptr));
    if (p12 == nullptr)
        ssl::Fail("'" + path + "' is not a PKCS#12 bundle");

    EVP_PKEY* rawKey = nullptr;
    X509* rawCert = nullptr;
    STACK_OF(X509)* rawChain = nullptr;

    // PKCS12_parse distinguishes nullptr ("no password") from "" (an empty
    // one), and bundles exist in both flavours.
    if (PKCS12_parse(p12.get(), password.c_str(), &rawKey, &rawCert, &rawChain) != 1)
    {
        ERR_clear_error();
        if (!password.empty() || PKCS12_parse(p12.get(), nullptr,
            &rawKey, &rawCert, &rawChain) != 1)
        {
            ssl::Fail("Cannot decrypt '" + path + "' (wrong password?)");
        }
    }

    ssl::PKeyPtr key(rawKey);
    ssl::X509Ptr cert(rawCert);
    ssl::StackPtr chain(rawChain);

    if (cert == nullptr)
        throw runtime_error("'" + path + "' contains no certificate");

    if (key == nullptr)
        throw runtime_error("'" + path + "' contains no private key");

    vector<string> chainDer;
    if (chain != nullptr)
    {
        for (int i = 0; i < sk_X509_num(chain.get()); i++)
            chainDer.push_back(ssl::ToDer(*sk_X509_value(chain.get(), i)));
    }

    return make_unique<LocalSigningIdentity>(ssl::ToDer(*cert),
        ssl::ToPkcs8Der(*key), std::move(chainDer));
}

unique_ptr<ISigningIdentity> IdentityLoader::FromCertAndKey(const string& certPath,
    const string& keyPath, const string& password)
{
    auto certData = ssl::ReadFile(certPath);
    auto cert = ssl::ParseCertificate(certData, certPath);

    string keyDer;
    if (!keyPath.empty())
    {
        auto keyData = ssl::ReadFile(keyPath);
        auto key = ssl::ParseKey(keyData, password, keyPath);
        keyDer = ssl::ToPkcs8Der(*key);
    }

    return make_unique<LocalSigningIdentity>(ssl::ToDer(*cert), std::move(keyDer));
}
