// SPDX-License-Identifier: MIT
//
// Who is signing, and how the private-key operation is performed.

#pragma once

#include <memory>
#include <string>
#include <vector>

namespace pdfsign
{
    /** Human-readable description of a certificate, for display only. */
    struct CertificateInfo final
    {
        std::string Subject;
        std::string Issuer;
        std::string Serial;
        std::string NotBefore;
        std::string NotAfter;
        std::string KeyAlgorithm;
        unsigned KeyBits = 0;

        /** The subject's common name, or the whole DN if it has none. */
        std::string GetCommonName() const;
    };

    /** A signing identity: a certificate, plus the ability to sign with the
     * matching private key.
     *
     * The key may or may not be extractable. A key in a file can be handed to
     * PoDoFo directly; one in an HSM or on a smartcard cannot, and is usable
     * only through SignHash. Callers ask via TryGetPrivateKeyDer rather than
     * being told which kind they have.
     */
    class ISigningIdentity
    {
    public:
        virtual ~ISigningIdentity() = default;

        /** DER-encoded X.509 signer certificate. */
        virtual const std::string& GetCertificateDer() const = 0;

        virtual const CertificateInfo& GetInfo() const = 0;

        /** Any additional certificates the credential source carried.
         *
         * Reported but not embedded; see the README on chain support. */
        virtual const std::vector<std::string>& GetChainDer() const = 0;

        /** The DER PKCS#8 private key, or nullptr when it cannot leave its
         * holder. A nullptr forces callers onto SignHash. */
        virtual const std::string* TryGetPrivateKeyDer() const = 0;

        /** Signs an already-computed digest.
         *
         * @param digestName OpenSSL digest name, e.g. "SHA256". For RSA the
         *        result must be the PKCS#1 v1.5 signature over the
         *        DigestInfo-wrapped digest.
         */
        virtual std::string SignHash(const void* hash, std::size_t hashLen,
            const char* digestName) const = 0;
    };

    /** An identity whose private key is held in this process.
     *
     * The common case: a key file or a PKCS#12 bundle.
     */
    class LocalSigningIdentity final : public ISigningIdentity
    {
    public:
        /** @param certDer DER X.509 certificate.
         *  @param keyDer  DER PKCS#8 private key; may be empty for an identity
         *         used only to inspect the certificate.
         *  @throws std::runtime_error if the key does not match the
         *          certificate, because such a pair produces a well-formed
         *          signature that every validator rejects. */
        LocalSigningIdentity(std::string certDer, std::string keyDer,
            std::vector<std::string> chainDer = {});

        const std::string& GetCertificateDer() const override { return m_certDer; }
        const CertificateInfo& GetInfo() const override { return m_info; }
        const std::vector<std::string>& GetChainDer() const override { return m_chainDer; }
        const std::string* TryGetPrivateKeyDer() const override;
        std::string SignHash(const void* hash, std::size_t hashLen,
            const char* digestName) const override;

    private:
        void describeCertificate();
        void verifyKeyMatchesCertificate() const;

        std::string m_certDer;
        std::string m_keyDer;
        std::vector<std::string> m_chainDer;
        CertificateInfo m_info;
    };

    /** Hides the private key of the identity it wraps.
     *
     * Everything is delegated except TryGetPrivateKeyDer, which reports the key
     * as unavailable. That forces signing through the SignHash callback, which
     * is exactly how a real HSM or remote signing service behaves. It lets the
     * callback path be exercised against an ordinary key file.
     */
    class OpaqueKeyIdentity final : public ISigningIdentity
    {
    public:
        explicit OpaqueKeyIdentity(std::unique_ptr<ISigningIdentity> inner);

        const std::string& GetCertificateDer() const override;
        const CertificateInfo& GetInfo() const override;
        const std::vector<std::string>& GetChainDer() const override;

        /** Always nullptr: the point of this decorator. */
        const std::string* TryGetPrivateKeyDer() const override { return nullptr; }

        std::string SignHash(const void* hash, std::size_t hashLen,
            const char* digestName) const override;

    private:
        std::unique_ptr<ISigningIdentity> m_inner;
    };

    /** Builds identities from the credential formats found on disk. */
    class IdentityLoader final
    {
    public:
        /** Reads a PKCS#12 / PFX bundle: certificate, key and chain in one
         * password-protected file. */
        static std::unique_ptr<ISigningIdentity> FromPkcs12(
            const std::string& path, const std::string& password);

        /** Reads a separate certificate and key. Both PEM and DER are
         * accepted and detected by content.
         *
         * @param keyPath may be empty to load the certificate alone. */
        static std::unique_ptr<ISigningIdentity> FromCertAndKey(
            const std::string& certPath, const std::string& keyPath,
            const std::string& password);
    };
}
