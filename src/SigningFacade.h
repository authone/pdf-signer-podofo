// SPDX-License-Identifier: MIT
//
// The boundary between the signing engine and whatever drives it.
//
// Everything above this line is a user interface; everything below is PoDoFo,
// OpenSSL and libcurl. The types here are deliberately plain -- std::string,
// enums and PODs -- so that no library header has to be visible to a UI, and
// so the engine can be driven from a command line, a dialog, or a test with
// equal ease.

#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace pdfsign
{
    enum class SignatureProfile
    {
        /** /ETSI.CAdES.detached, the ETSI profile. */
        PAdES,

        /** /adbe.pkcs7.detached, the legacy Adobe one. */
        Pkcs7,
    };

    enum class HashAlgorithm { Sha256, Sha384, Sha512 };

    /** Where the signing credentials come from. */
    enum class CredentialKind
    {
        /** A PKCS#12 / PFX bundle: certificate, key and chain in one file. */
        Pkcs12,

        /** Separate certificate and key files, PEM or DER. */
        CertificateAndKey,
    };

    /** How the private key is used. */
    enum class KeyUsageMode
    {
        /** Hand the key to the engine. The normal case. */
        Direct,

        /** Keep the key out of the engine and sign hashes through a callback,
         * which is how an HSM or a remote signing service behaves. */
        ExternalHashSigning,
    };

    enum class TimestampSource
    {
        None,

        /** An RFC 3161 service reached over HTTP or HTTPS. */
        RemoteService,

        /** The in-process mock, for working offline. */
        LocalMock,
    };

    enum class RevocationSource
    {
        None,

        /** An OCSP responder at an explicit URL. */
        RemoteResponder,

        /** The responder each certificate names in its AIA extension. */
        CertificateAia,

        /** The in-process mock, for working offline. */
        LocalMock,
    };

    /** TLS and authentication settings for reaching a trust service provider.
     *
     * Mirrors HttpTransport, repeated here so that a UI need not include the
     * networking headers.
     */
    struct TransportSettings final
    {
        std::string CaBundlePath;
        std::string ClientCertificatePath;
        std::string ClientKeyPath;
        std::string ClientKeyPassword;
        std::string Username;
        std::string Password;
        long TimeoutSeconds = 30;
        bool VerifyPeer = true;
    };

    struct CredentialSettings final
    {
        CredentialKind Kind = CredentialKind::Pkcs12;
        std::string Pkcs12Path;
        std::string CertificatePath;
        std::string KeyPath;
        std::string Password;
        KeyUsageMode KeyUsage = KeyUsageMode::Direct;
    };

    /** The visible appearance, if the signature has one. */
    struct AppearanceSettings final
    {
        bool Visible = false;

        /** One-based, as shown to a user. */
        unsigned PageNumber = 1;

        // PDF points, origin at the page's bottom-left.
        double X = 40;
        double Y = 40;
        double Width = 220;
        double Height = 70;
    };

    struct TimestampSettings final
    {
        TimestampSource Source = TimestampSource::None;
        std::string Url;
        TransportSettings Transport;

        /** Mock only: the authority's own signing credentials. */
        std::string MockCertificatePath;
        std::string MockKeyPath;

        /** /Contents reservation for a remote token, which cannot be sized
         * from a trial request. */
        std::size_t ReserveBytes = 16384;

        std::string FieldName = "Timestamp1";
    };

    struct RevocationSettings final
    {
        RevocationSource Source = RevocationSource::None;
        std::string Url;
        TransportSettings Transport;

        /** Issuer certificate. Required unless the signing certificate is
         * self-signed, because the OCSP CertID is built from the issuer's
         * name and public key. */
        std::string IssuerPath;
    };

    /** A complete job: sign, add validation data, add a document timestamp,
     * or any combination.
     *
     * Running all three in order produces a PAdES B-LTA document. Running one
     * at a time is how an already-signed file is upgraded later.
     */
    struct SignRequest final
    {
        /** Input PDF. Empty, with Sign enabled, generates a sample page. */
        std::string InputPath;
        std::string OutputPath;

        // Which steps to perform.
        bool Sign = true;
        bool AddRevocationData = false;
        bool AddTimestamp = false;

        /** Keep the per-step files when more than one step runs, so each
         * level can be inspected. */
        bool KeepIntermediates = false;

        std::string FieldName = "Signature1";
        std::string SignerName;
        std::string Reason;
        std::string Location;

        SignatureProfile Profile = SignatureProfile::PAdES;
        HashAlgorithm Hash = HashAlgorithm::Sha256;

        CredentialSettings Credential;
        AppearanceSettings Appearance;
        RevocationSettings Revocation;
        TimestampSettings Timestamp;
    };

    /** What a certificate says about itself, for display. */
    struct CertificateSummary final
    {
        bool Loaded = false;

        /** Populated instead of the rest when the credential cannot be read. */
        std::string Error;

        std::string CommonName;
        std::string Subject;
        std::string Issuer;
        std::string Serial;
        std::string NotBefore;
        std::string NotAfter;
        std::string KeyAlgorithm;
        unsigned KeyBits = 0;
        bool HasPrivateKey = false;
        bool SelfSigned = false;
        std::size_t ChainLength = 0;
    };

    /** Coarse stages, for a progress indicator. */
    enum class SignStage
    {
        LoadingCredentials,
        Signing,
        ContactingResponder,
        WritingValidationData,
        ContactingTimestampAuthority,
        ApplyingTimestamp,
        Finished,
    };

    /** Called as the job proceeds. Invoked on the calling thread, so a UI
     * should marshal to its own thread before touching controls. */
    using ProgressHandler = std::function<void(SignStage stage, const std::string& message)>;

    struct SignResult final
    {
        bool Succeeded = false;

        /** A sentence suitable for showing to a user. On failure this is the
         * reason; on success, a short summary. */
        std::string Message;

        std::string OutputPath;
        std::size_t OutputBytes = 0;

        /** "PAdES B-B", "PAdES B-LT" or "PAdES B-LTA". */
        std::string Level;

        std::string SubFilter;
        bool UsedDirectKey = true;

        // Populated when the corresponding step ran.
        std::string RevocationResponder;
        std::string RevocationStatus;
        std::string TimestampAuthority;
        std::string TimestampTime;
        std::size_t TimestampTokenBytes = 0;

        /** Files written for each level when KeepIntermediates is set. */
        std::vector<std::string> Intermediates;

        /** Non-fatal problems worth putting in front of the user, such as a
         * certificate the responder reports as revoked or unknown. */
        std::vector<std::string> Warnings;
    };

    /** Drives the signing engine on behalf of a user interface.
     *
     * Both entry points are non-throwing. A UI has no good way to handle an
     * exception crossing from a worker thread, so failures come back as data:
     * CertificateSummary::Error and SignResult::Message.
     */
    class SigningFacade final
    {
    public:
        /** Reads a credential and describes it, without signing anything.
         *
         * Lets a dialog fill in a "Certificate" field the moment a file is
         * chosen, and report a wrong password immediately rather than at the
         * end of a signing run.
         */
        static CertificateSummary InspectCredential(const CredentialSettings& credential);

        /** Runs the requested steps. */
        static SignResult Execute(const SignRequest& request,
            const ProgressHandler& onProgress = {});

        /** Checks a request without touching the filesystem or the network.
         *
         * Returns an empty string when the request is coherent, otherwise the
         * first problem found, so a dialog can keep its Sign button disabled
         * and say why.
         */
        static std::string Validate(const SignRequest& request);
    };
}
