// SPDX-License-Identifier: MIT

#include "SigningFacade.h"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <utility>

#include <podofo/podofo.h>

#include "DocumentSigner.h"
#include "DocumentSource.h"
#include "DocumentTimestamp.h"
#include "HttpOcspResponder.h"
#include "HttpTimestampService.h"
#include "SampleDoc.h"
#include "SignatureAppearance.h"
#include "SigningIdentity.h"
#include "ValidationDataStore.h"
#include "ValidationServices.h"

using namespace std;
using namespace pdfsign;

namespace fs = std::filesystem;

namespace
{
    PoDoFo::PdfHashingAlgorithm toPodofo(HashAlgorithm hash)
    {
        switch (hash)
        {
            case HashAlgorithm::Sha384:
                return PoDoFo::PdfHashingAlgorithm::SHA384;
            case HashAlgorithm::Sha512:
                return PoDoFo::PdfHashingAlgorithm::SHA512;
            default:
                return PoDoFo::PdfHashingAlgorithm::SHA256;
        }
    }

    PoDoFo::PdfSignatureType toPodofo(SignatureProfile profile)
    {
        return profile == SignatureProfile::Pkcs7
            ? PoDoFo::PdfSignatureType::Pkcs7
            : PoDoFo::PdfSignatureType::PAdES_B;
    }

    HttpTransport toTransport(const TransportSettings& settings)
    {
        HttpTransport transport;
        transport.CaBundlePath = settings.CaBundlePath;
        transport.ClientCertPath = settings.ClientCertificatePath;
        transport.ClientKeyPath = settings.ClientKeyPath;
        transport.ClientKeyPassword = settings.ClientKeyPassword;
        transport.Username = settings.Username;
        transport.Password = settings.Password;
        transport.TimeoutSeconds = settings.TimeoutSeconds;
        transport.VerifyPeer = settings.VerifyPeer;
        return transport;
    }

    unique_ptr<ISigningIdentity> loadIdentity(const CredentialSettings& credential)
    {
        unique_ptr<ISigningIdentity> identity;
        if (credential.Kind == CredentialKind::Pkcs12)
        {
            identity = IdentityLoader::FromPkcs12(credential.Pkcs12Path, credential.Password);
        }
        else
        {
            identity = IdentityLoader::FromCertAndKey(credential.CertificatePath,
                credential.KeyPath, credential.Password);
        }

        // Hiding the key is a property of the identity, so it is expressed by
        // wrapping rather than by a flag the signer would have to consult.
        if (credential.KeyUsage == KeyUsageMode::ExternalHashSigning)
            identity = make_unique<OpaqueKeyIdentity>(std::move(identity));

        return identity;
    }

    /** Inserts a suffix before the extension: out.pdf + "b" -> out.b.pdf. */
    string withSuffix(const string& path, const string& suffix)
    {
        auto full = fs::u8path(path);
        auto stem = full.stem().u8string();
        auto extension = full.extension().u8string();
        auto name = string(stem.begin(), stem.end()) + "." + suffix
            + string(extension.begin(), extension.end());
        return (full.parent_path() / fs::u8path(name)).u8string();
    }

    void report(const ProgressHandler& onProgress, SignStage stage, const string& message)
    {
        if (onProgress)
            onProgress(stage, message);
    }

    size_t fileSize(const string& path)
    {
        error_code ec;
        auto size = fs::file_size(fs::u8path(path), ec);
        return ec ? 0 : (size_t)size;
    }
}

string SigningFacade::Validate(const SignRequest& request)
{
    if (!request.Sign && !request.AddRevocationData && !request.AddTimestamp)
        return "Nothing to do: choose at least one step.";

    if (request.OutputPath.empty())
        return "Choose an output file.";

    // Only the signing step can invent a document; the other two upgrade one.
    if (!request.Sign && request.InputPath.empty())
        return "Choose an input file.";

    if (!request.InputPath.empty() && request.InputPath == request.OutputPath)
        return "The input and output files must be different.";

    auto& credential = request.Credential;
    auto needsCredential = request.Sign
        || request.Revocation.Source == RevocationSource::LocalMock
        || request.Revocation.Source == RevocationSource::RemoteResponder
        || request.Revocation.Source == RevocationSource::CertificateAia;

    if (needsCredential)
    {
        if (credential.Kind == CredentialKind::Pkcs12)
        {
            if (credential.Pkcs12Path.empty())
                return "Choose a PKCS#12 file.";
        }
        else
        {
            if (credential.CertificatePath.empty())
                return "Choose a certificate file.";

            if (request.Sign && credential.KeyPath.empty())
                return "Choose a private key file.";
        }
    }

    if (request.AddTimestamp)
    {
        if (request.Timestamp.Source == TimestampSource::None)
            return "Choose a timestamp authority.";

        if (request.Timestamp.Source == TimestampSource::RemoteService
            && request.Timestamp.Url.empty())
        {
            return "Enter the timestamp authority address.";
        }

        if (request.Timestamp.Source == TimestampSource::LocalMock
            && (request.Timestamp.MockCertificatePath.empty()
                || request.Timestamp.MockKeyPath.empty()))
        {
            return "Choose the local timestamp authority certificate and key.";
        }
    }

    if (request.AddRevocationData)
    {
        if (request.Revocation.Source == RevocationSource::None)
            return "Choose a revocation data source.";

        if (request.Revocation.Source == RevocationSource::RemoteResponder
            && request.Revocation.Url.empty())
        {
            return "Enter the OCSP responder address.";
        }
    }

    if (request.Appearance.Visible && request.Appearance.PageNumber < 1)
        return "Pages are numbered from 1.";

    return {};
}

CertificateSummary SigningFacade::InspectCredential(const CredentialSettings& credential)
{
    CertificateSummary summary;
    try
    {
        auto identity = loadIdentity(credential);
        auto& info = identity->GetInfo();

        summary.Loaded = true;
        summary.CommonName = info.GetCommonName();
        summary.Subject = info.Subject;
        summary.Issuer = info.Issuer;
        summary.Serial = info.Serial;
        summary.NotBefore = info.NotBefore;
        summary.NotAfter = info.NotAfter;
        summary.KeyAlgorithm = info.KeyAlgorithm;
        summary.KeyBits = info.KeyBits;
        summary.HasPrivateKey = identity->TryGetPrivateKeyDer() != nullptr;
        summary.SelfSigned = info.Subject == info.Issuer;
        summary.ChainLength = identity->GetChainDer().size();
    }
    catch (const exception& ex)
    {
        // PdfError derives from std::exception, so this covers the engine's
        // failures and ours alike.
        summary.Loaded = false;
        summary.Error = ex.what();
    }

    return summary;
}

SignResult SigningFacade::Execute(const SignRequest& request,
    const ProgressHandler& onProgress)
{
    SignResult result;

    auto problem = Validate(request);
    if (!problem.empty())
    {
        result.Message = problem;
        return result;
    }

    // Intermediate files are needed whenever more than one step runs, because
    // each step appends a revision to the output of the last.
    vector<string> temporaries;

    try
    {
        report(onProgress, SignStage::LoadingCredentials, "Reading credentials");
        auto identity = loadIdentity(request.Credential);

        auto stepCount = (request.Sign ? 1 : 0)
            + (request.AddRevocationData ? 1 : 0)
            + (request.AddTimestamp ? 1 : 0);
        auto multiStep = stepCount > 1;

        // What each step reads, threaded through the pipeline.
        string current = request.InputPath;

        // ---- step 1: the signature itself ----------------------------
        if (request.Sign)
        {
            auto target = multiStep && (request.AddRevocationData || request.AddTimestamp)
                ? withSuffix(request.OutputPath, "b")
                : request.OutputPath;

            unique_ptr<IDocumentSource> source;
            if (current.empty())
                source = make_unique<NewDocumentSource>(target, &BuildSampleDocument);
            else
                source = make_unique<ExistingDocumentSource>(current, target);

            unique_ptr<ISignatureAppearance> appearance;
            if (request.Appearance.Visible)
            {
                TextBoxAppearance::Text text;
                text.SignerName = request.SignerName.empty()
                    ? identity->GetInfo().GetCommonName()
                    : request.SignerName;
                text.Reason = request.Reason;
                text.Location = request.Location;

                appearance = make_unique<TextBoxAppearance>(
                    request.Appearance.PageNumber - 1,
                    PoDoFo::Rect(request.Appearance.X, request.Appearance.Y,
                        request.Appearance.Width, request.Appearance.Height),
                    std::move(text));
            }
            else
            {
                appearance = make_unique<InvisibleAppearance>(
                    request.Appearance.PageNumber - 1);
            }

            SignatureMetadata metadata;
            metadata.FieldName = request.FieldName;
            metadata.SignerName = request.SignerName;
            metadata.Reason = request.Reason;
            metadata.Location = request.Location;
            metadata.Hashing = toPodofo(request.Hash);
            metadata.SignatureType = toPodofo(request.Profile);

            report(onProgress, SignStage::Signing, "Signing the document");

            DocumentSigner signer(*identity);
            signer.SetMetadata(metadata);
            signer.Sign(*source, *appearance);

            result.UsedDirectKey = signer.UsedDirectKey();
            result.Level = "PAdES B-B";
            result.SubFilter = request.Profile == SignatureProfile::PAdES
                ? "/ETSI.CAdES.detached"
                : "/adbe.pkcs7.detached";

            if (target != request.OutputPath)
            {
                temporaries.push_back(target);
                result.Intermediates.push_back(target);
            }

            current = target;
        }

        // ---- step 2: validation data ---------------------------------
        if (request.AddRevocationData)
        {
            auto target = request.AddTimestamp
                ? withSuffix(request.OutputPath, "lt")
                : request.OutputPath;

            unique_ptr<IOcspResponder> responder;
            switch (request.Revocation.Source)
            {
                case RevocationSource::RemoteResponder:
                    responder = make_unique<HttpOcspResponder>(request.Revocation.Url,
                        toTransport(request.Revocation.Transport));
                    break;

                case RevocationSource::CertificateAia:
                    responder = make_unique<HttpOcspResponder>(string(),
                        toTransport(request.Revocation.Transport));
                    break;

                default:
                {
                    auto key = identity->TryGetPrivateKeyDer();
                    if (key == nullptr)
                    {
                        throw runtime_error("The local responder needs the private key; "
                            "use a real OCSP responder instead.");
                    }

                    responder = make_unique<MockOcspResponder>(
                        identity->GetCertificateDer(), *key);
                    break;
                }
            }

            string issuerDer;
            if (!request.Revocation.IssuerPath.empty())
            {
                auto issuer = IdentityLoader::FromCertAndKey(
                    request.Revocation.IssuerPath, {}, {});
                issuerDer = issuer->GetCertificateDer();
            }
            else
            {
                auto& info = identity->GetInfo();
                if (info.Subject != info.Issuer)
                {
                    throw runtime_error("This certificate was issued by '" + info.Issuer
                        + "', so the issuer certificate is required: the OCSP request "
                          "is built from the issuer's name and public key.");
                }

                issuerDer = identity->GetCertificateDer();
            }

            report(onProgress, SignStage::ContactingResponder,
                string("Querying ") + responder->GetDescription());

            ValidationDataUpgrade upgrade(*responder);
            upgrade.AddSubject(identity->GetCertificateDer(), issuerDer);

            ExistingDocumentSource source(current, target);

            report(onProgress, SignStage::WritingValidationData, "Writing validation data");
            upgrade.Apply(source);

            auto http = dynamic_cast<const HttpOcspResponder*>(responder.get());
            if (http != nullptr)
            {
                result.RevocationResponder = http->GetLastUrl();
                result.RevocationStatus = http->GetLastStatus();

                if (result.RevocationStatus.rfind("revoked", 0) == 0)
                {
                    result.Warnings.push_back("The responder reports this certificate "
                        "as REVOKED. The response was embedded as a record of what it said.");
                }
                else if (result.RevocationStatus == "unknown")
                {
                    result.Warnings.push_back("The responder does not know this "
                        "certificate. The usual cause is the wrong issuer certificate.");
                }
            }
            else
            {
                result.RevocationResponder = responder->GetDescription();
                result.RevocationStatus = "good";
            }

            result.Level = "PAdES B-LT";

            if (target != request.OutputPath)
            {
                temporaries.push_back(target);
                result.Intermediates.push_back(target);
            }

            current = target;
        }

        // ---- step 3: document timestamp ------------------------------
        if (request.AddTimestamp)
        {
            unique_ptr<ITimestampService> service;
            if (request.Timestamp.Source == TimestampSource::RemoteService)
            {
                TsaHttpConfig config;
                config.Url = request.Timestamp.Url;
                config.Transport = toTransport(request.Timestamp.Transport);
                service = make_unique<HttpTimestampService>(std::move(config));
            }
            else
            {
                auto tsa = IdentityLoader::FromCertAndKey(
                    request.Timestamp.MockCertificatePath,
                    request.Timestamp.MockKeyPath, {});
                auto key = tsa->TryGetPrivateKeyDer();
                if (key == nullptr)
                    throw runtime_error("The local timestamp authority needs its private key.");

                service = make_unique<MockTimestampAuthority>(
                    tsa->GetCertificateDer(), *key);
            }

            report(onProgress, SignStage::ContactingTimestampAuthority,
                string("Requesting a timestamp from ") + service->GetDescription());

            DocumentTimestamper timestamper(*service);
            timestamper.SetFieldName(request.Timestamp.FieldName);
            timestamper.SetHashing(toPodofo(request.Hash));
            timestamper.SetReservedTokenSize(request.Timestamp.ReserveBytes);

            ExistingDocumentSource source(current, request.OutputPath);

            report(onProgress, SignStage::ApplyingTimestamp, "Applying the timestamp");
            timestamper.Apply(source);

            result.TimestampAuthority = service->GetDescription();
            result.TimestampTokenBytes = timestamper.GetTokenSize();

            auto http = dynamic_cast<const HttpTimestampService*>(service.get());
            if (http != nullptr)
                result.TimestampTime = http->GetLastGenTime();

            result.Level = request.AddRevocationData ? "PAdES B-LTA" : "PAdES B-T (document)";
            current = request.OutputPath;
        }

        result.Succeeded = true;
        result.OutputPath = request.OutputPath;
        result.OutputBytes = fileSize(request.OutputPath);
        result.Message = "Signed " + fs::u8path(request.OutputPath).filename().u8string()
            + " (" + result.Level + ").";
    }
    catch (const exception& ex)
    {
        result.Succeeded = false;
        result.Message = ex.what();
    }

    if (!request.KeepIntermediates)
    {
        error_code ec;
        for (auto& path : temporaries)
            fs::remove(fs::u8path(path), ec);

        result.Intermediates.clear();
    }

    report(onProgress, SignStage::Finished, result.Message);
    return result;
}
