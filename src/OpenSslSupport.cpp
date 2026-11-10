// SPDX-License-Identifier: MIT

#include "OpenSslSupport.h"

#include <cstring>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/pem.h>

using namespace std;

namespace
{
    /** OpenSSL password callback backed by a std::string.
     *
     * Returning 0 for an empty password makes OpenSSL report "bad decrypt"
     * instead of prompting on the terminal, which would hang any
     * non-interactive use.
     */
    int passwordCallback(char* buf, int size, int /* rwflag */, void* userdata)
    {
        auto password = static_cast<const string*>(userdata);
        if (password == nullptr || password->empty())
            return 0;

        auto len = (int)password->size();
        if (len > size)
            len = size;

        std::memcpy(buf, password->data(), (size_t)len);
        return len;
    }
}

string pdfsign::ssl::TakeError()
{
    string result;
    unsigned long code;
    while ((code = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(code, buf, sizeof(buf));
        if (!result.empty())
            result.append("; ");

        result.append(buf);
    }

    return result;
}

void pdfsign::ssl::Fail(const string& what)
{
    auto detail = TakeError();
    if (detail.empty())
        throw runtime_error(what);

    throw runtime_error(what + ": " + detail);
}

string pdfsign::ssl::ReadFile(const string& path)
{
    BioPtr bio(BIO_new_file(path.c_str(), "rb"));
    if (bio == nullptr)
        Fail("Cannot open '" + path + "'");

    string result;
    char buf[8192];
    int read;
    while ((read = BIO_read(bio.get(), buf, (int)sizeof(buf))) > 0)
        result.append(buf, (size_t)read);

    if (result.empty())
        throw runtime_error("File '" + path + "' is empty");

    return result;
}

pdfsign::ssl::BioPtr pdfsign::ssl::MemBio(const string& data)
{
    BioPtr bio(BIO_new_mem_buf(data.data(), (int)data.size()));
    if (bio == nullptr)
        Fail("Cannot allocate memory BIO");

    return bio;
}

pdfsign::ssl::X509Ptr pdfsign::ssl::ParseCertificate(const string& data, const string& source)
{
    {
        auto bio = MemBio(data);
        X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (cert != nullptr)
            return cert;
    }

    ERR_clear_error();
    auto bio = MemBio(data);
    X509Ptr cert(d2i_X509_bio(bio.get(), nullptr));
    if (cert == nullptr)
        Fail("'" + source + "' is not a PEM or DER X.509 certificate");

    return cert;
}

pdfsign::ssl::PKeyPtr pdfsign::ssl::ParseDerKey(const string& der)
{
    auto pos = reinterpret_cast<const unsigned char*>(der.data());
    return PKeyPtr(d2i_AutoPrivateKey(nullptr, &pos, (long)der.size()));
}

pdfsign::ssl::PKeyPtr pdfsign::ssl::ParseKey(const string& data,
    const string& password, const string& source)
{
    {
        auto bio = MemBio(data);
        PKeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr,
            &passwordCallback, const_cast<string*>(&password)));
        if (key != nullptr)
            return key;
    }

    ERR_clear_error();
    {
        auto key = ParseDerKey(data);
        if (key != nullptr)
            return key;
    }

    ERR_clear_error();
    {
        auto bio = MemBio(data);
        P12Ptr p12(d2i_PKCS12_bio(bio.get(), nullptr));
        if (p12 != nullptr)
        {
            throw runtime_error("'" + source + "' looks like a PKCS#12 bundle; "
                "pass it with --pkcs12 instead of --key");
        }
    }

    ERR_clear_error();
    Fail("'" + source + "' is not a private key we can read "
        "(wrong password, or an unsupported format)");
}

string pdfsign::ssl::ToDer(const X509& cert)
{
    unsigned char* der = nullptr;
    auto len = i2d_X509(const_cast<X509*>(&cert), &der);
    if (len <= 0)
        Fail("Cannot DER-encode the certificate");

    SslBufPtr<unsigned char> guard(der);
    return string((const char*)der, (size_t)len);
}

string pdfsign::ssl::ToPkcs8Der(EVP_PKEY& key)
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr)
        Fail("Cannot allocate memory BIO");

    if (i2d_PKCS8PrivateKey_bio(bio.get(), &key,
        nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        Fail("Cannot DER-encode the private key as PKCS#8");
    }

    char* data = nullptr;
    auto len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0)
        Fail("PKCS#8 encoding produced no data");

    return string(data, (size_t)len);
}

string pdfsign::ssl::NameToString(X509_NAME* name)
{
    if (name == nullptr)
        return {};

    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr)
        return {};

    // RFC 2253 without the escaping that makes console output noisy.
    if (X509_NAME_print_ex(bio.get(), name, 0,
        XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB) < 0)
    {
        return {};
    }

    char* data = nullptr;
    auto len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0)
        return {};

    return string(data, (size_t)len);
}

string pdfsign::ssl::TimeToString(const ASN1_TIME* time)
{
    if (time == nullptr)
        return {};

    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr)
        return {};

    if (ASN1_TIME_print(bio.get(), time) <= 0)
        return {};

    char* data = nullptr;
    auto len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0)
        return {};

    return string(data, (size_t)len);
}

string pdfsign::ssl::SerialToString(X509* cert)
{
    auto serial = X509_get_serialNumber(cert);
    if (serial == nullptr)
        return {};

    BnPtr bn(ASN1_INTEGER_to_BN(serial, nullptr));
    if (bn == nullptr)
        return {};

    SslBufPtr<char> hex(BN_bn2hex(bn.get()));
    if (hex == nullptr)
        return {};

    return string(hex.get());
}
