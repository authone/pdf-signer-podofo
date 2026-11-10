// SPDX-License-Identifier: MIT
//
// podofo-pdf-sign: a worked example of signing a PDF with PoDoFo 1.1.x.
//
// This file is the composition root: it reads the command line and assembles
// the identity, document source and appearance that the signer collaborates
// with. All the branching on user options happens here, once, by choosing
// which objects to build.

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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

namespace
{
    void printUsage()
    {
        cout <<
R"(podofo-pdf-sign - sign a PDF with PoDoFo

USAGE
  podofo-pdf-sign sign            [options]   step 1: sign (PAdES B-B)
  podofo-pdf-sign add-validation  [options]   step 2: embed OCSP  (-> B-LT)
  podofo-pdf-sign add-timestamp   [options]   step 3: document TS (-> B-LTA)
  podofo-pdf-sign lta             [options]   all three in sequence
  podofo-pdf-sign info            [credential options]

CREDENTIALS (pick one)
  --pkcs12 <file>      PKCS#12 / PFX bundle holding certificate, key and chain
  --cert <file>        X.509 certificate, PEM or DER
  --key <file>         private key, PEM or DER (PKCS#8 or PKCS#1)
  --password <pw>      password for the bundle or the encrypted key

INPUT / OUTPUT
  --in <file>          PDF to sign; omit to generate and sign a sample page
  --out <file>         where to write the signed PDF (required for 'sign')

SIGNATURE
  --field <name>       signature field name (default: Signature1)
  --name <text>        signer name recorded in the signature dictionary
  --reason <text>      reason for signing
  --location <text>    place of signing
  --hash <alg>         sha256 (default), sha384 or sha512
  --type <profile>     pades (default, /ETSI.CAdES.detached) or pkcs7
                       (/adbe.pkcs7.detached)

APPEARANCE
  --visible            give the signature a visible appearance on the page
  --page <n>           1-based page for the appearance (default: 1)
  --rect <x,y,w,h>     appearance box in PDF points, origin bottom-left
                       (default: 40,40,220,70)

SIGNING MODE
  --external-key       treat the key as if it could not leave its holder, so
                       PoDoFo hashes the document and calls back to have the
                       hash signed. This is the integration shape an HSM or a
                       remote signing service needs.

TIMESTAMP AUTHORITY (add-timestamp / lta; pick one)
  --tsa-url <url>      RFC 3161 service to fetch the token from, http or
                       https. The token is obtained over the network and
                       applied to the PDF locally; only a digest is sent.
  --tsa-cert <file>    run a local mock TSA instead, for offline testing.
  --tsa-key <file>     mock TSA private key. The certificate must carry a
                       critical timeStamping extended key usage;
                       scripts/make-test-cert.sh issues a suitable one.

TSA TRANSPORT (with --tsa-url)
  --tsa-ca <file>      PEM bundle used to verify the TSA's TLS certificate
  --tsa-client-cert <file>  client certificate for mutual TLS
  --tsa-client-key <file>   client private key for mutual TLS
  --tsa-client-key-pass <pw>  passphrase for the client key
  --tsa-user <name>    HTTP basic auth user
  --tsa-pass <pw>      HTTP basic auth password
  --tsa-timeout <sec>  network timeout, default 30
  --tsa-insecure       skip TLS verification (for a provider whose private
                       CA is not installed yet; do not use in production)
  --tsa-no-cert-req    do not ask the TSA to embed its certificate

OCSP RESPONDER (add-validation / lta)
  --ocsp <url>         responder to query, e.g. http://ocsp.certsign.ro.
                       Sends application/ocsp-request and expects
                       application/ocsp-response. Without this the
                       in-process mock responder is used instead.
  --ocsp-aia           take the responder URL from each certificate's
                       Authority Information Access extension
  --issuer <file>      issuer certificate, PEM or DER. Required with --ocsp
                       unless the signing certificate is self-signed, because
                       the OCSP CertID is built from the issuer's name and key.

OCSP TRANSPORT (with --ocsp)
  --ocsp-ca <file>     PEM bundle used to verify the responder's TLS cert
  --ocsp-client-cert <file>  client certificate for mutual TLS
  --ocsp-client-key <file>   client private key for mutual TLS
  --ocsp-client-key-pass <pw>  passphrase for the client key
  --ocsp-user <name>   HTTP basic auth user
  --ocsp-pass <pw>     HTTP basic auth password
  --ocsp-timeout <sec> network timeout, default 30
  --ocsp-insecure      skip TLS verification

TIMESTAMP PLACEMENT
  --ts-field <name>    document timestamp field name (default: Timestamp1)
  --ts-reserve <bytes> /Contents reservation for a remote token, default
                       16384. A remote authority is contacted once, so the
                       placeholder cannot be sized from a trial token.

EXAMPLES
  # Validation data from a real OCSP responder
  podofo-pdf-sign add-validation --ocsp http://ocsp.certsign.ro \
      --cert signer.pem --issuer ca.pem --in s.pdf --out lt.pdf

  # Timestamp from a public authority over HTTP
  podofo-pdf-sign add-timestamp --tsa-url http://timestamp.digicert.com \
      --in lt.pdf --out lta.pdf

  # ... or from a provider that authenticates subscribers by certificate
  podofo-pdf-sign add-timestamp --tsa-url https://tsa.example.com/tsr \
      --tsa-client-cert client.pem --tsa-client-key client.key \
      --tsa-ca provider-ca.pem --in lt.pdf --out lta.pdf

  # The three steps separately
  podofo-pdf-sign sign           --pkcs12 test-cert.p12 --password test --out s.pdf
  podofo-pdf-sign add-validation --pkcs12 test-cert.p12 --password test \
      --in s.pdf --out lt.pdf
  podofo-pdf-sign add-timestamp  --tsa-url http://timestamp.digicert.com \
      --in lt.pdf --out lta.pdf

  # Sign a generated sample page with a PKCS#12 bundle
  podofo-pdf-sign sign --pkcs12 test-cert.p12 --password test \
      --out signed.pdf --visible --reason "Approved"

  # Sign an existing document as an incremental update
  podofo-pdf-sign sign --cert cert.pem --key key.pem \
      --in contract.pdf --out contract-signed.pdf
)";
    }

    /** Minimal option reader.
     *
     * Deliberately dependency-free: the point of the example is the signing,
     * and an argument-parsing library would only get in the way of reading it.
     */
    class Args final
    {
    public:
        Args(int argc, char* argv[])
        {
            for (int i = 1; i < argc; i++)
                m_items.emplace_back(argv[i]);
        }

        /** Consumes a flag if present. */
        bool Flag(const string& name)
        {
            for (size_t i = 0; i < m_items.size(); i++)
            {
                if (m_items[i] == name)
                {
                    m_items.erase(m_items.begin() + (ptrdiff_t)i);
                    return true;
                }
            }

            return false;
        }

        /** Consumes an option and its value if present. */
        string Value(const string& name, const string& fallback = {})
        {
            for (size_t i = 0; i < m_items.size(); i++)
            {
                if (m_items[i] != name)
                    continue;

                if (i + 1 >= m_items.size())
                    throw runtime_error(name + " needs a value");

                auto value = m_items[i + 1];
                m_items.erase(m_items.begin() + (ptrdiff_t)i,
                    m_items.begin() + (ptrdiff_t)i + 2);
                return value;
            }

            return fallback;
        }

        /** Takes the first non-option argument, which is the command. */
        string TakeCommand()
        {
            if (m_items.empty() || m_items[0].rfind("--", 0) == 0)
                return {};

            auto value = m_items[0];
            m_items.erase(m_items.begin());
            return value;
        }

        /** Anything left over is a typo and should not be ignored. */
        void RejectLeftovers() const
        {
            if (!m_items.empty())
                throw runtime_error("Unrecognised argument '" + m_items[0] + "'");
        }

    private:
        vector<string> m_items;
    };

    PoDoFo::PdfHashingAlgorithm parseHashing(const string& value)
    {
        if (value == "sha256")
            return PoDoFo::PdfHashingAlgorithm::SHA256;

        if (value == "sha384")
            return PoDoFo::PdfHashingAlgorithm::SHA384;

        if (value == "sha512")
            return PoDoFo::PdfHashingAlgorithm::SHA512;

        throw runtime_error("Unknown --hash '" + value + "'; use sha256, sha384 or sha512");
    }

    PoDoFo::PdfSignatureType parseSignatureType(const string& value)
    {
        if (value == "pades")
            return PoDoFo::PdfSignatureType::PAdES_B;

        if (value == "pkcs7")
            return PoDoFo::PdfSignatureType::Pkcs7;

        throw runtime_error("Unknown --type '" + value + "'; use pades or pkcs7");
    }

    PoDoFo::Rect parseRect(const string& value)
    {
        double numbers[4];
        size_t pos = 0;
        for (int i = 0; i < 4; i++)
        {
            if (pos > value.size())
                throw runtime_error("--rect needs four numbers: x,y,w,h");

            size_t consumed = 0;
            numbers[i] = stod(value.substr(pos), &consumed);
            pos += consumed;

            if (i < 3)
            {
                if (pos >= value.size() || value[pos] != ',')
                    throw runtime_error("--rect needs four comma-separated numbers: x,y,w,h");

                pos++;
            }
        }

        if (pos != value.size())
            throw runtime_error("--rect has trailing characters after x,y,w,h");

        if (numbers[2] <= 0 || numbers[3] <= 0)
            throw runtime_error("--rect width and height must be positive");

        return PoDoFo::Rect(numbers[0], numbers[1], numbers[2], numbers[3]);
    }

    size_t parseReserve(const string& value)
    {
        if (value.empty())
            return 16384;

        auto bytes = stol(value);
        if (bytes < 512)
            throw runtime_error("--ts-reserve is too small to hold a timestamp token");

        return (size_t)bytes;
    }

    unsigned parsePageIndex(const string& value)
    {
        if (value.empty())
            return 0;

        auto page = stol(value);
        if (page < 1)
            throw runtime_error("--page is 1-based and must be at least 1");

        return (unsigned)(page - 1);
    }

    /** Builds the identity from whichever mutually exclusive credential source
     * the user supplied. */
    unique_ptr<ISigningIdentity> loadIdentity(Args& args, bool keyRequired)
    {
        auto pkcs12 = args.Value("--pkcs12");
        auto cert = args.Value("--cert");
        auto key = args.Value("--key");
        auto password = args.Value("--password");

        if (!pkcs12.empty() && (!cert.empty() || !key.empty()))
            throw runtime_error("Use either --pkcs12 or --cert/--key, not both");

        if (!pkcs12.empty())
            return IdentityLoader::FromPkcs12(pkcs12, password);

        if (!cert.empty())
        {
            if (key.empty() && keyRequired)
                throw runtime_error("--cert needs a matching --key");

            return IdentityLoader::FromCertAndKey(cert, key, password);
        }

        throw runtime_error("No credentials given; pass --pkcs12, or --cert and --key "
            "(run scripts/make-test-cert.sh to create a throwaway pair)");
    }

    /** The issuer certificate the OCSP CertID is built from.
     *
     * A self-signed certificate is its own issuer. Anything else needs
     * --issuer, because the CertID hashes the issuer's name and public key
     * and a responder cannot match a request built from the wrong one.
     */
    string loadIssuer(const string& issuerPath, const ISigningIdentity& identity)
    {
        if (!issuerPath.empty())
        {
            auto issuer = IdentityLoader::FromCertAndKey(issuerPath, {}, {});
            return issuer->GetCertificateDer();
        }

        auto& info = identity.GetInfo();
        if (info.Subject != info.Issuer)
        {
            throw runtime_error("The signing certificate was issued by '" + info.Issuer
                + "', so --issuer is required: the OCSP CertID is built from the "
                  "issuer's name and public key");
        }

        return identity.GetCertificateDer();
    }

    void printIdentity(const ISigningIdentity& identity)
    {
        auto& info = identity.GetInfo();
        cout << "Signing certificate\n"
             << "  subject    " << info.Subject << "\n"
             << "  issuer     " << info.Issuer << "\n"
             << "  serial     " << info.Serial << "\n"
             << "  valid      " << info.NotBefore << "  ->  " << info.NotAfter << "\n"
             << "  key        " << info.KeyAlgorithm << " " << info.KeyBits << " bits"
             << (identity.TryGetPrivateKeyDer() == nullptr ? " (not available here)" : "")
             << "\n";

        if (!identity.GetChainDer().empty())
        {
            cout << "  chain      " << identity.GetChainDer().size()
                 << " additional certificate(s) present but not embedded\n";
        }

        cout << endl;
    }


    /** Reads the --<prefix>-* transport options.
     *
     * The timestamp and OCSP clients take the same settings, so they are
     * parsed once against a prefix rather than twice by hand.
     */
    HttpTransport parseTransport(Args& args, const string& prefix)
    {
        HttpTransport transport;
        transport.CaBundlePath = args.Value("--" + prefix + "-ca");
        transport.ClientCertPath = args.Value("--" + prefix + "-client-cert");
        transport.ClientKeyPath = args.Value("--" + prefix + "-client-key");
        transport.ClientKeyPassword = args.Value("--" + prefix + "-client-key-pass");
        transport.Username = args.Value("--" + prefix + "-user");
        transport.Password = args.Value("--" + prefix + "-pass");
        transport.VerifyPeer = !args.Flag("--" + prefix + "-insecure");

        auto timeout = args.Value("--" + prefix + "-timeout");
        if (!timeout.empty())
        {
            transport.TimeoutSeconds = stol(timeout);
            if (transport.TimeoutSeconds <= 0)
                throw runtime_error("--" + prefix + "-timeout must be positive");
        }

        return transport;
    }

    /** Builds the timestamp authority client.
     *
     * Either a real RFC 3161 service over the network, or the in-process mock
     * for offline testing. Everything downstream sees only ITimestampService
     * and cannot tell which it got.
     */
    unique_ptr<ITimestampService> loadTimestampService(Args& args)
    {
        auto url = args.Value("--tsa-url");
        auto certPath = args.Value("--tsa-cert");
        auto keyPath = args.Value("--tsa-key");
        auto certPassword = args.Value("--tsa-password");

        // Transport options are consumed either way so a stray one is
        // reported as unrecognised rather than silently ignored.
        TsaHttpConfig http;
        http.Transport = parseTransport(args, "tsa");
        http.RequestCertificate = !args.Flag("--tsa-no-cert-req");

        if (!url.empty())
        {
            if (!certPath.empty() || !keyPath.empty())
                throw runtime_error("Use either --tsa-url or --tsa-cert/--tsa-key, not both");

            http.Url = std::move(url);
            return make_unique<HttpTimestampService>(std::move(http));
        }

        if (certPath.empty() || keyPath.empty())
        {
            throw runtime_error("A document timestamp needs --tsa-url for a real "
                "authority, or --tsa-cert and --tsa-key to run the local mock "
                "(scripts/make-test-cert.sh creates a throwaway pair)");
        }

        auto identity = IdentityLoader::FromCertAndKey(certPath, keyPath, certPassword);
        auto key = identity->TryGetPrivateKeyDer();
        if (key == nullptr)
            throw runtime_error("The mock timestamp authority needs a private key");

        return make_unique<MockTimestampAuthority>(identity->GetCertificateDer(), *key);
    }

    /** Builds the OCSP responder client.
     *
     * Either a real responder over the network, or the in-process mock that
     * signs its own answers. ValidationDataUpgrade only ever sees
     * IOcspResponder and cannot tell which it got.
     *
     * @param identity the signing credentials, used by the mock to sign
     *        responses and as the default subject.
     */
    unique_ptr<IOcspResponder> loadOcspResponder(Args& args,
        const ISigningIdentity& identity)
    {
        auto url = args.Value("--ocsp");
        auto useAia = args.Flag("--ocsp-aia");
        auto transport = parseTransport(args, "ocsp");

        if (!url.empty() || useAia)
        {
            if (!url.empty() && useAia)
                throw runtime_error("Use either --ocsp or --ocsp-aia, not both");

            return make_unique<HttpOcspResponder>(std::move(url), std::move(transport));
        }

        // The mock signs its answers, so it needs the private key.
        auto keyDer = identity.TryGetPrivateKeyDer();
        if (keyDer == nullptr)
        {
            throw runtime_error("The mock OCSP responder needs a private key to "
                "sign with; pass --ocsp to query a real responder instead");
        }

        return make_unique<MockOcspResponder>(identity.GetCertificateDer(), *keyDer);
    }

    /** Step 2: embed an OCSP response, producing a B-LT document. */
    void applyValidationData(const IOcspResponder& responder,
        const string& certDer, const string& issuerDer,
        const string& inputPath, const string& outputPath)
    {
        cout << "Querying " << responder.GetDescription() << endl;

        ValidationDataUpgrade upgrade(responder);
        upgrade.AddSubject(certDer, issuerDer);

        ExistingDocumentSource source(inputPath, outputPath);
        upgrade.Apply(source);

        auto http = dynamic_cast<const HttpOcspResponder*>(&responder);

        auto size = filesystem::file_size(filesystem::u8path(outputPath));
        cout << "Added validation data to " << outputPath << " (" << size << " bytes)\n"
             << "  responder  "
             << (http != nullptr && !http->GetLastUrl().empty()
                    ? http->GetLastUrl()
                    : string(responder.GetDescription()))
             << "\n";

        if (http != nullptr && !http->GetLastStatus().empty())
        {
            cout << "  status     " << http->GetLastStatus() << "\n"
                 << "  nonce      " << http->GetLastNonce() << "\n";
        }

        cout << "  /DSS       " << upgrade.GetCertificateCount() << " certificate(s), "
             << upgrade.GetOcspCount() << " OCSP response(s)\n"
             << "  level      PAdES B-LT" << endl;

        // The response is embedded either way: the DSS records what the
        // responder said. But neither of these is useful validation data, and
        // silently writing one would hide a problem.
        if (http != nullptr && http->GetLastStatus().rfind("revoked", 0) == 0)
        {
            cerr << "warning: the responder reports this certificate as REVOKED; "
                    "the response was embedded as a record of what it said" << endl;
        }
        else if (http != nullptr && http->GetLastStatus() == "unknown")
        {
            cerr << "warning: the responder does not know this certificate. "
                    "The usual cause is a wrong --issuer, since the OCSP CertID "
                    "is built from the issuer's name and public key." << endl;
        }
    }

    /** Step 3: add a document timestamp, producing a B-LTA document. */
    void applyDocumentTimestamp(const ITimestampService& service,
        const string& inputPath, const string& outputPath,
        const string& fieldName, PoDoFo::PdfHashingAlgorithm hashing,
        size_t reserveBytes)
    {
        cout << "Requesting a timestamp from " << service.GetDescription() << endl;

        DocumentTimestamper timestamper(service);
        timestamper.SetFieldName(fieldName);
        timestamper.SetHashing(hashing);
        timestamper.SetReservedTokenSize(reserveBytes);

        ExistingDocumentSource source(inputPath, outputPath);
        timestamper.Apply(source);

        auto size = filesystem::file_size(filesystem::u8path(outputPath));
        cout << "Timestamped " << outputPath << " (" << size << " bytes)\n"
             << "  authority  " << service.GetDescription() << "\n"
             << "  subfilter  /ETSI.RFC3161, /Type /DocTimeStamp\n"
             << "  field      " << fieldName << "\n"
             << "  token      " << timestamper.GetTokenSize() << " bytes";

        auto http = dynamic_cast<const HttpTimestampService*>(&service);
        if (http != nullptr && !http->GetLastGenTime().empty())
            cout << "\n  TSA time   " << http->GetLastGenTime();

        cout << "\n  level      PAdES B-LTA" << endl;
    }

    int runAddValidation(Args& args)
    {
        auto inputPath = args.Value("--in");
        auto outputPath = args.Value("--out");
        auto issuerPath = args.Value("--issuer");

        // A real responder only needs the certificate; the mock needs the key
        // as well, which loadOcspResponder reports if it is missing.
        auto identity = loadIdentity(args, false);
        auto responder = loadOcspResponder(args, *identity);
        args.RejectLeftovers();

        if (inputPath.empty())
            throw runtime_error("--in is required; validation data is added to a signed PDF");

        if (outputPath.empty())
            throw runtime_error("--out is required");

        auto issuerDer = loadIssuer(issuerPath, *identity);

        printIdentity(*identity);
        applyValidationData(*responder, identity->GetCertificateDer(),
            issuerDer, inputPath, outputPath);
        return EXIT_SUCCESS;
    }

    int runAddTimestamp(Args& args)
    {
        auto inputPath = args.Value("--in");
        auto outputPath = args.Value("--out");
        auto fieldName = args.Value("--ts-field", "Timestamp1");
        auto hashing = parseHashing(args.Value("--hash", "sha256"));
        auto reserve = parseReserve(args.Value("--ts-reserve"));
        auto service = loadTimestampService(args);
        args.RejectLeftovers();

        if (inputPath.empty())
            throw runtime_error("--in is required; a document timestamp covers an existing PDF");

        if (outputPath.empty())
            throw runtime_error("--out is required");

        applyDocumentTimestamp(*service, inputPath, outputPath, fieldName,
            hashing, reserve);
        return EXIT_SUCCESS;
    }

    /** Everything the sign step needs, read off the command line. */
    struct SignPlan final
    {
        SignatureMetadata Metadata;
        std::string InputPath;
        std::string OutputPath;
        bool Visible = false;
        bool OpaqueKey = false;
        unsigned PageIndex = 0;
        std::string RectValue;
    };

    /** Consumes the sign-related options. Credentials are read separately so
     * the caller controls the order of error reporting. */
    SignPlan parseSignPlan(Args& args)
    {
        SignPlan plan;
        plan.Metadata.FieldName = args.Value("--field", "Signature1");
        plan.Metadata.SignerName = args.Value("--name");
        plan.Metadata.Reason = args.Value("--reason");
        plan.Metadata.Location = args.Value("--location");
        plan.Metadata.Hashing = parseHashing(args.Value("--hash", "sha256"));
        plan.Metadata.SignatureType = parseSignatureType(args.Value("--type", "pades"));

        plan.InputPath = args.Value("--in");
        plan.OutputPath = args.Value("--out");
        plan.Visible = args.Flag("--visible");
        plan.OpaqueKey = args.Flag("--external-key");
        plan.PageIndex = parsePageIndex(args.Value("--page"));
        plan.RectValue = args.Value("--rect");
        return plan;
    }

    /** Step 1: produce the signature itself. */
    void performSign(const SignPlan& plan, const ISigningIdentity& identity)
    {
        // Where the bytes come from.
        unique_ptr<IDocumentSource> source;
        if (plan.InputPath.empty())
        {
            cout << "No --in given, generating a sample document to sign." << endl;
            source = make_unique<NewDocumentSource>(plan.OutputPath, &BuildSampleDocument);
        }
        else
        {
            source = make_unique<ExistingDocumentSource>(plan.InputPath, plan.OutputPath);
        }

        // What it looks like.
        unique_ptr<ISignatureAppearance> appearance;
        if (plan.Visible)
        {
            auto box = plan.RectValue.empty()
                ? PoDoFo::Rect(40, 40, 220, 70)
                : parseRect(plan.RectValue);

            TextBoxAppearance::Text text;
            text.SignerName = plan.Metadata.SignerName.empty()
                ? identity.GetInfo().GetCommonName()
                : plan.Metadata.SignerName;
            text.Reason = plan.Metadata.Reason;
            text.Location = plan.Metadata.Location;

            appearance = make_unique<TextBoxAppearance>(plan.PageIndex, box, std::move(text));
        }
        else
        {
            appearance = make_unique<InvisibleAppearance>(plan.PageIndex);
        }

        DocumentSigner signer(identity);
        signer.SetMetadata(plan.Metadata);
        signer.Sign(*source, *appearance);

        auto size = filesystem::file_size(filesystem::u8path(source->GetOutputPath()));
        cout << "Signed " << source->GetOutputPath() << " (" << size << " bytes)\n"
             << "  profile    "
             << (plan.Metadata.SignatureType == PoDoFo::PdfSignatureType::PAdES_B
                    ? "PAdES-B (/ETSI.CAdES.detached)"
                    : "legacy (/adbe.pkcs7.detached)")
             << "\n"
             << "  field      " << plan.Metadata.FieldName << "\n"
             << "  appearance " << appearance->GetDescription() << "\n"
             << "  key use    "
             << (signer.UsedDirectKey()
                    ? "key passed to PoDoFo"
                    : "external signing callback")
             << endl;
    }

    int runSign(Args& args)
    {
        auto plan = parseSignPlan(args);
        auto identity = loadIdentity(args, true);
        args.RejectLeftovers();

        if (plan.OutputPath.empty())
            throw runtime_error("--out is required");

        // Pretending the key is unreachable is a property of the identity, so
        // it is expressed by wrapping it rather than by a flag the signer
        // would have to consult.
        if (plan.OpaqueKey)
            identity = make_unique<OpaqueKeyIdentity>(std::move(identity));

        printIdentity(*identity);
        performSign(plan, *identity);
        return EXIT_SUCCESS;
    }

    /** Inserts a suffix before the extension: out.pdf + "b" -> out.b.pdf. */
    string withSuffix(const string& path, const string& suffix)
    {
        auto full = filesystem::u8path(path);
        auto stem = full.stem().u8string();
        auto extension = full.extension().u8string();
        auto name = string(stem.begin(), stem.end()) + "." + suffix
            + string(extension.begin(), extension.end());
        return (full.parent_path() / filesystem::u8path(name)).u8string();
    }

    /** All three steps, keeping each intermediate so the levels can be
     * compared side by side. */
    int runLta(Args& args)
    {
        auto plan = parseSignPlan(args);
        auto timestampField = args.Value("--ts-field", "Timestamp1");
        auto reserve = parseReserve(args.Value("--ts-reserve"));
        auto issuerPath = args.Value("--issuer");
        auto identity = loadIdentity(args, true);
        auto responder = loadOcspResponder(args, *identity);
        auto timestampService = loadTimestampService(args);
        args.RejectLeftovers();

        if (plan.OutputPath.empty())
            throw runtime_error("--out is required");

        if (plan.OpaqueKey)
            identity = make_unique<OpaqueKeyIdentity>(std::move(identity));

        auto bLevel = withSuffix(plan.OutputPath, "b");
        auto ltLevel = withSuffix(plan.OutputPath, "lt");

        printIdentity(*identity);

        cout << "=== step 1: sign =========================================" << endl;
        auto signPlan = plan;
        signPlan.OutputPath = bLevel;
        performSign(signPlan, *identity);

        cout << "\n=== step 2: embed validation data ========================" << endl;
        applyValidationData(*responder, identity->GetCertificateDer(),
            loadIssuer(issuerPath, *identity), bLevel, ltLevel);

        cout << "\n=== step 3: document timestamp ===========================" << endl;
        applyDocumentTimestamp(*timestampService, ltLevel, plan.OutputPath,
            timestampField, plan.Metadata.Hashing, reserve);

        cout << "\nLevels written:\n"
             << "  " << bLevel << "  (B-B)\n"
             << "  " << ltLevel << "  (B-LT)\n"
             << "  " << plan.OutputPath << "  (B-LTA)" << endl;

        return EXIT_SUCCESS;
    }

    int runInfo(Args& args)
    {
        auto identity = loadIdentity(args, false);
        args.RejectLeftovers();
        printIdentity(*identity);
        return EXIT_SUCCESS;
    }
}

int main(int argc, char* argv[])
{
    try
    {
        Args args(argc, argv);
        if (args.Flag("--help") || args.Flag("-h") || argc == 1)
        {
            printUsage();
            return EXIT_SUCCESS;
        }

        auto command = args.TakeCommand();
        if (command.empty())
            command = "sign";

        if (command == "sign")
            return runSign(args);

        if (command == "add-validation")
            return runAddValidation(args);

        if (command == "add-timestamp")
            return runAddTimestamp(args);

        if (command == "lta")
            return runLta(args);

        if (command == "info")
            return runInfo(args);

        throw runtime_error("Unknown command '" + command + "'; expected one of "
            "sign, add-validation, add-timestamp, lta, info");
    }
    catch (const exception& ex)
    {
        // PdfError derives from std::exception, so this covers PoDoFo's
        // failures and ours alike.
        cerr << "error: " << ex.what() << endl;
        return EXIT_FAILURE;
    }
}
