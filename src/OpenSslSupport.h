// SPDX-License-Identifier: MIT
//
// Shared OpenSSL plumbing: owning pointers and error reporting.
// Internal to the credential classes; nothing else should need it.

#pragma once

#include <memory>
#include <string>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

namespace pdfsign::ssl
{
    // Several OpenSSL "free" functions (OPENSSL_free, sk_X509_pop_free) are
    // macros whose address cannot be taken, so each deleter is a small struct
    // rather than a function pointer.
    struct BioDelete final { void operator()(BIO* ptr) const { BIO_free_all(ptr); } };
    struct X509Delete final { void operator()(X509* ptr) const { X509_free(ptr); } };
    struct PKeyDelete final { void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); } };
    struct PKeyCtxDelete final { void operator()(EVP_PKEY_CTX* ptr) const { EVP_PKEY_CTX_free(ptr); } };
    struct P12Delete final { void operator()(PKCS12* ptr) const { PKCS12_free(ptr); } };
    struct BnDelete final { void operator()(BIGNUM* ptr) const { BN_free(ptr); } };
    struct SslBufDelete final { void operator()(void* ptr) const { OPENSSL_free(ptr); } };
    struct StackDelete final
    {
        void operator()(STACK_OF(X509)* ptr) const { sk_X509_pop_free(ptr, X509_free); }
    };

    using BioPtr = std::unique_ptr<BIO, BioDelete>;
    using X509Ptr = std::unique_ptr<X509, X509Delete>;
    using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDelete>;
    using PKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PKeyCtxDelete>;
    using P12Ptr = std::unique_ptr<PKCS12, P12Delete>;
    using BnPtr = std::unique_ptr<BIGNUM, BnDelete>;
    using StackPtr = std::unique_ptr<STACK_OF(X509), StackDelete>;

    template <typename T>
    using SslBufPtr = std::unique_ptr<T, SslBufDelete>;

    /** Drains the OpenSSL error queue into a readable message. */
    std::string TakeError();

    /** Throws std::runtime_error with @p what plus the OpenSSL error queue.
     *
     * Without the queue the failures read as a bare "load failed", which does
     * not say whether the file was the wrong format or the password wrong.
     */
    [[noreturn]] void Fail(const std::string& what);

    /** Reads a whole file, throwing if it is missing or empty. */
    std::string ReadFile(const std::string& path);

    /** Wraps a buffer in a read-only memory BIO. The buffer must outlive it. */
    BioPtr MemBio(const std::string& data);

    /** Reads an X.509 certificate, trying PEM then DER.
     *
     * Content is sniffed rather than trusting the file extension, which is
     * unreliable in practice.
     */
    X509Ptr ParseCertificate(const std::string& data, const std::string& source);

    /** Decodes a DER private key, auto-detecting PKCS#8 versus the traditional
     * PKCS#1 / SEC1 encodings. OpenSSL has no BIO form of this call. */
    PKeyPtr ParseDerKey(const std::string& der);

    /** Reads a private key as PEM (optionally encrypted), or DER. */
    PKeyPtr ParseKey(const std::string& data, const std::string& password,
        const std::string& source);

    std::string ToDer(const X509& cert);

    /** Re-encodes a key as unencrypted DER PKCS#8.
     *
     * PdfSignerCms accepts PKCS#1 too, but only PKCS#8 carries the algorithm
     * identifier, so it is the single encoding that works for RSA and EC alike.
     */
    std::string ToPkcs8Der(EVP_PKEY& key);

    std::string NameToString(X509_NAME* name);
    std::string TimeToString(const ASN1_TIME* time);
    std::string SerialToString(X509* cert);
}
