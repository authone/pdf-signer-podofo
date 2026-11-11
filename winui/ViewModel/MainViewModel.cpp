// SPDX-License-Identifier: MIT

#include "MainViewModel.h"

#include <filesystem>
#include <utility>

using namespace std;
using namespace pdfsign;
using namespace pdfsign::ui;

namespace fs = std::filesystem;

namespace
{
    // The window is Romanian, matching the original. Wording lives here
    // rather than in the XAML so that what is shown stays a decision of the
    // presentation layer, not of the markup.
    constexpr const char* NoCertificate = "Fara certificat.";
    constexpr const char* NoTimestamp = "Fara marca temporala.";

    string fileName(const string& path)
    {
        return path.empty() ? string() : fs::u8path(path).filename().u8string();
    }
}

MainViewModel::MainViewModel()
{
    m_credential.Kind = CredentialKind::Pkcs12;
}

void MainViewModel::SetInputPath(string path)
{
    m_inputPath = std::move(path);

    // Keep the output in step with the input until the user names one, which
    // is the behaviour people expect from this kind of dialog.
    if (!m_outputPathIsManual)
        m_outputPath = SuggestedOutputPath();
}

void MainViewModel::SetOutputPath(string path)
{
    m_outputPath = std::move(path);
    m_outputPathIsManual = !m_outputPath.empty();
}

void MainViewModel::SetPkcs12Path(string path)
{
    m_credential.Kind = CredentialKind::Pkcs12;
    m_credential.Pkcs12Path = std::move(path);
    m_credential.CertificatePath.clear();
    m_credential.KeyPath.clear();
    RefreshCertificate();
}

void MainViewModel::SetCertificatePath(string certificate, string key)
{
    m_credential.Kind = CredentialKind::CertificateAndKey;
    m_credential.CertificatePath = std::move(certificate);
    m_credential.KeyPath = std::move(key);
    m_credential.Pkcs12Path.clear();
    RefreshCertificate();
}

void MainViewModel::SetPassword(string password)
{
    m_credential.Password = std::move(password);
    RefreshCertificate();
}

const string& MainViewModel::CredentialPath() const
{
    return m_credential.Kind == CredentialKind::Pkcs12
        ? m_credential.Pkcs12Path
        : m_credential.CertificatePath;
}

void MainViewModel::RefreshCertificate()
{
    if (CredentialPath().empty())
    {
        m_certificate = CertificateSummary();
        return;
    }

    m_certificate = SigningFacade::InspectCredential(m_credential);
}

bool MainViewModel::CertificateIsError() const
{
    return !CredentialPath().empty() && !m_certificate.Loaded;
}

string MainViewModel::CertificateText() const
{
    if (CredentialPath().empty())
        return NoCertificate;

    if (!m_certificate.Loaded)
    {
        // Almost always a wrong password, so say so rather than echoing an
        // OpenSSL error at someone choosing a file.
        return "Certificatul nu a putut fi citit. Verificati parola.";
    }

    auto text = m_certificate.CommonName;
    if (!m_certificate.NotAfter.empty())
        text += "  -  valabil pana la " + m_certificate.NotAfter;

    if (!m_certificate.HasPrivateKey)
        text += "  (fara cheie privata)";

    return text;
}

string MainViewModel::TimestampText() const
{
    if (!m_services.UseTimestamp)
        return NoTimestamp;

    if (m_services.TimestampFrom == TimestampSource::LocalMock)
        return "Marca temporala locala (test).";

    return m_services.TimestampUrl.empty()
        ? "Marca temporala: adresa serviciului nu este completata."
        : "Marca temporala: " + m_services.TimestampUrl;
}

SignRequest MainViewModel::BuildRequest() const
{
    SignRequest request;
    request.InputPath = m_inputPath;
    request.OutputPath = m_outputPath;

    request.Sign = true;
    request.AddRevocationData = m_services.UseRevocation;
    request.AddTimestamp = m_services.UseTimestamp;

    request.Reason = m_reason;
    request.Location = m_location;
    request.Credential = m_credential;
    request.Appearance = m_appearance;

    if (m_services.UseRevocation)
    {
        request.Revocation.Source = m_services.RevocationFrom;
        request.Revocation.Url = m_services.RevocationUrl;
        request.Revocation.IssuerPath = m_services.IssuerPath;
        request.Revocation.Transport = m_services.Transport;
    }

    if (m_services.UseTimestamp)
    {
        request.Timestamp.Source = m_services.TimestampFrom;
        request.Timestamp.Url = m_services.TimestampUrl;
        request.Timestamp.Transport = m_services.Transport;
        request.Timestamp.MockCertificatePath = m_services.MockTsaCertificatePath;
        request.Timestamp.MockKeyPath = m_services.MockTsaKeyPath;
    }

    return request;
}

string MainViewModel::BlockingReason() const
{
    if (m_busy)
        return "Semnarea este in curs.";

    if (m_inputPath.empty())
        return "Selectati fisierul de intrare.";

    if (m_outputPath.empty())
        return "Selectati fisierul de iesire.";

    if (CredentialPath().empty())
        return "Selectati certificatul.";

    if (!m_certificate.Loaded)
        return "Certificatul nu a putut fi citit.";

    if (!m_certificate.HasPrivateKey)
        return "Certificatul nu contine o cheie privata.";

    // Everything else -- paths, service addresses, page numbers -- is the
    // engine's own precondition, so ask it rather than repeating the rules.
    return SigningFacade::Validate(BuildRequest());
}

string MainViewModel::SuggestedOutputPath() const
{
    if (m_inputPath.empty())
        return {};

    auto input = fs::u8path(m_inputPath);
    auto stem = input.stem().u8string();
    auto name = string(stem.begin(), stem.end()) + "-semnat.pdf";
    return (input.parent_path() / fs::u8path(name)).u8string();
}

SignResult MainViewModel::Sign(const ProgressHandler& onProgress)
{
    m_busy = true;
    auto result = SigningFacade::Execute(BuildRequest(), onProgress);
    m_busy = false;
    return result;
}

string MainViewModel::DescribeResult(const SignResult& result)
{
    if (!result.Succeeded)
        return "Semnarea a esuat: " + result.Message;

    auto text = "Document semnat: " + fileName(result.OutputPath)
        + " (" + result.Level + ").";

    if (!result.TimestampAuthority.empty())
        text += " Marca temporala de la " + result.TimestampAuthority + ".";

    if (!result.RevocationStatus.empty())
        text += " Stare certificat: " + result.RevocationStatus + ".";

    return text;
}
