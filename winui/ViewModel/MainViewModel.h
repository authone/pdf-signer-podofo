// SPDX-License-Identifier: MIT
//
// Presentation state for the signing window.
//
// Deliberately plain C++: no WinRT, no XAML, no Windows headers. The window's
// code-behind is a thin adapter that copies text between controls and this
// object, which keeps every decision about what is enabled, what is shown and
// what a button does out of the UI layer and under test.

#pragma once

#include <string>
#include <vector>

#include "SigningFacade.h"

namespace pdfsign::ui
{
    /** Which trust services the job should use. */
    struct ServiceOptions final
    {
        bool UseTimestamp = false;
        TimestampSource TimestampFrom = TimestampSource::RemoteService;
        std::string TimestampUrl;

        bool UseRevocation = false;
        RevocationSource RevocationFrom = RevocationSource::CertificateAia;
        std::string RevocationUrl;
        std::string IssuerPath;

        /** Shared by both clients; a provider usually authenticates the same
         * way for each. */
        TransportSettings Transport;

        // Local mock authority, for working offline.
        std::string MockTsaCertificatePath;
        std::string MockTsaKeyPath;
    };

    /** Everything the main window displays and decides.
     *
     * Strings returned here are already localised for display, because the
     * window should not be choosing wording either.
     */
    class MainViewModel final
    {
    public:
        MainViewModel();

        // --- inputs the window writes -------------------------------------
        void SetInputPath(std::string path);
        void SetOutputPath(std::string path);
        void SetPkcs12Path(std::string path);
        void SetCertificatePath(std::string certificate, std::string key);
        void SetPassword(std::string password);

        void SetVisibleSignature(bool visible) { m_appearance.Visible = visible; }
        void SetReason(std::string reason) { m_reason = std::move(reason); }
        void SetLocation(std::string location) { m_location = std::move(location); }

        ServiceOptions& Services() { return m_services; }
        const ServiceOptions& Services() const { return m_services; }

        // --- state the window reads ---------------------------------------
        const std::string& InputPath() const { return m_inputPath; }
        const std::string& OutputPath() const { return m_outputPath; }
        const std::string& CredentialPath() const;

        /** One line for the "Certificat:" field. */
        std::string CertificateText() const;

        /** True when the credential failed to load, so the window can colour
         * the certificate line as an error. */
        bool CertificateIsError() const;

        /** One line for the timestamp status, mirroring the original's
         * "Fara marca temporala." when none is configured. */
        std::string TimestampText() const;

        /** Empty when the job can run; otherwise why it cannot, ready to show
         * next to a disabled Sign button. */
        std::string BlockingReason() const;
        bool CanSign() const { return BlockingReason().empty(); }

        bool IsBusy() const { return m_busy; }

        // --- actions --------------------------------------------------------
        /** Reads the credential and refreshes the certificate line. Cheap
         * enough to call whenever the file or password changes. */
        void RefreshCertificate();

        /** A sensible output path derived from the input, so the user does
         * not have to invent one: contract.pdf -> contract-signed.pdf. */
        std::string SuggestedOutputPath() const;

        /** Builds the request the facade will run. Exposed so the window can
         * show a summary, and so it can be tested without signing. */
        SignRequest BuildRequest() const;

        /** Runs the job. Blocking: the window must call this off the UI
         * thread and marshal progress back. */
        SignResult Sign(const ProgressHandler& onProgress);

        /** Localised one-line summary of a finished job. */
        static std::string DescribeResult(const SignResult& result);

    private:
        std::string m_inputPath;
        std::string m_outputPath;
        bool m_outputPathIsManual = false;

        CredentialSettings m_credential;
        CertificateSummary m_certificate;

        AppearanceSettings m_appearance;
        std::string m_reason;
        std::string m_location;

        ServiceOptions m_services;
        bool m_busy = false;
    };
}
