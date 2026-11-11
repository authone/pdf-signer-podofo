// SPDX-License-Identifier: MIT

#include "pch.h"
#include "MainWindow.xaml.h"
#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

#include <string>

#include <microsoft.ui.xaml.window.h>
#include <shobjidl.h>

using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;
using namespace Windows::Foundation;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;

using pdfsign::SignResult;
using pdfsign::SignStage;

namespace
{
    /** The engine speaks UTF-8 std::string; WinRT speaks UTF-16 hstring. */
    std::string toUtf8(winrt::hstring const& value)
    {
        return winrt::to_string(value);
    }

    winrt::hstring toHstring(std::string const& value)
    {
        return winrt::to_hstring(value);
    }
}

namespace winrt::ClickSignPdf::implementation
{
    MainWindow::MainWindow() :
        m_model(std::make_unique<pdfsign::ui::MainViewModel>())
    {
        InitializeComponent();
        Title(L"clickSIGN PDF Ultimate");
        Refresh();
    }

    void MainWindow::InitialiseWithWindow(IInspectable const& picker)
    {
        // An unpackaged WinUI 3 app has no implicit window for a picker to
        // parent itself to, and the picker throws without an owner HWND.
        // The handle comes from the window's IWindowNative facet.
        auto native = this->m_inner.as<::IWindowNative>();
        HWND handle{ nullptr };
        check_hresult(native->get_WindowHandle(&handle));

        auto initialiser = picker.as<::IInitializeWithWindow>();
        check_hresult(initialiser->Initialize(handle));
    }

    void MainWindow::Refresh()
    {
        // Guard against the TextChanged handlers firing while we write to the
        // boxes ourselves, which would otherwise mark the output path manual.
        m_updating = true;

        if (OutputPathBox().Text() != toHstring(m_model->OutputPath()))
            OutputPathBox().Text(toHstring(m_model->OutputPath()));

        CertificateText().Text(toHstring(m_model->CertificateText()));
        // Theme resources rather than literal colours, so the window stays
        // legible in dark mode.
        auto brushKey = m_model->CertificateIsError()
            ? L"SystemFillColorCriticalBrush"
            : L"TextFillColorPrimaryBrush";
        CertificateText().Foreground(
            Application::Current().Resources().Lookup(box_value(brushKey))
                .as<Media::Brush>());

        TimestampText().Text(toHstring(m_model->TimestampText()));

        auto reason = m_model->BlockingReason();
        SignButton().IsEnabled(reason.empty() && !m_model->IsBusy());
        StatusText().Text(toHstring(reason));

        m_updating = false;
    }

    void MainWindow::SetBusy(bool busy)
    {
        BusyBar().Visibility(busy ? Visibility::Visible : Visibility::Collapsed);
        SignButton().IsEnabled(!busy && m_model->CanSign());
        BrowseInputButton().IsEnabled(!busy);
        BrowseOutputButton().IsEnabled(!busy);
        BrowseCertificateButton().IsEnabled(!busy);
        SettingsButton().IsEnabled(!busy);
    }

    void MainWindow::OnInputPathChanged(IInspectable const&, TextChangedEventArgs const&)
    {
        if (m_updating)
            return;

        m_model->SetInputPath(toUtf8(InputPathBox().Text()));
        Refresh();
    }

    void MainWindow::OnOutputPathChanged(IInspectable const&, TextChangedEventArgs const&)
    {
        if (m_updating)
            return;

        m_model->SetOutputPath(toUtf8(OutputPathBox().Text()));
        Refresh();
    }

    IAsyncAction MainWindow::OnBrowseInput(IInspectable const&, RoutedEventArgs const&)
    {
        FileOpenPicker picker;
        InitialiseWithWindow(picker);
        picker.FileTypeFilter().Append(L".pdf");

        auto file = co_await picker.PickSingleFileAsync();
        if (file == nullptr)
            co_return;

        m_updating = true;
        InputPathBox().Text(file.Path());
        m_updating = false;

        m_model->SetInputPath(toUtf8(file.Path()));
        Refresh();
    }

    IAsyncAction MainWindow::OnBrowseOutput(IInspectable const&, RoutedEventArgs const&)
    {
        FileSavePicker picker;
        InitialiseWithWindow(picker);
        picker.FileTypeChoices().Insert(L"Document PDF",
            single_threaded_vector<hstring>({ L".pdf" }));
        picker.SuggestedFileName(L"document-semnat");

        auto file = co_await picker.PickSaveFileAsync();
        if (file == nullptr)
            co_return;

        m_model->SetOutputPath(toUtf8(file.Path()));
        Refresh();
    }

    IAsyncAction MainWindow::OnBrowseCertificate(IInspectable const&, RoutedEventArgs const&)
    {
        FileOpenPicker picker;
        InitialiseWithWindow(picker);
        for (auto extension : { L".p12", L".pfx", L".pem", L".crt", L".cer", L".der" })
            picker.FileTypeFilter().Append(extension);

        auto file = co_await picker.PickSingleFileAsync();
        if (file == nullptr)
            co_return;

        auto path = toUtf8(file.Path());
        m_model->SetPkcs12Path(path);

        // A PKCS#12 is normally protected, so ask once and retry rather than
        // leaving the user with "could not be read".
        if (m_model->CertificateIsError())
        {
            auto password = co_await PromptForPassword();
            m_model->SetPassword(toUtf8(password));
        }

        Refresh();
    }

    IAsyncOperation<hstring> MainWindow::PromptForPassword()
    {
        PasswordBox box;
        box.PlaceholderText(L"Parola certificatului");

        ContentDialog dialog;
        dialog.XamlRoot(RootGrid().XamlRoot());
        dialog.Title(box_value(L"Parolă"));
        dialog.Content(box);
        dialog.PrimaryButtonText(L"OK");
        dialog.CloseButtonText(L"Renunță");
        dialog.DefaultButton(ContentDialogButton::Primary);

        auto choice = co_await dialog.ShowAsync();
        co_return choice == ContentDialogResult::Primary ? box.Password() : hstring{};
    }

    IAsyncAction MainWindow::OnPreviewInput(IInspectable const&, RoutedEventArgs const&)
    {
        auto path = InputPathBox().Text();
        if (path.empty())
            co_return;

        auto file = co_await StorageFile::GetFileFromPathAsync(path);
        co_await Windows::System::Launcher::LaunchFileAsync(file);
    }

    IAsyncAction MainWindow::OnOpenSettings(IInspectable const&, RoutedEventArgs const&)
    {
        auto& services = m_model->Services();

        CheckBox useTimestamp;
        useTimestamp.Content(box_value(L"Adaugă marcă temporală"));
        useTimestamp.IsChecked(services.UseTimestamp);

        TextBox timestampUrl;
        timestampUrl.Header(box_value(L"Adresa serviciului de marcare temporală"));
        timestampUrl.PlaceholderText(L"http://timestamp.example.com");
        timestampUrl.Text(toHstring(services.TimestampUrl));

        CheckBox useRevocation;
        useRevocation.Content(box_value(L"Adaugă informații de revocare (OCSP)"));
        useRevocation.IsChecked(services.UseRevocation);

        TextBox revocationUrl;
        revocationUrl.Header(box_value(L"Adresa serviciului OCSP (gol = din certificat)"));
        revocationUrl.PlaceholderText(L"http://ocsp.example.com");
        revocationUrl.Text(toHstring(services.RevocationUrl));

        CheckBox visibleSignature;
        visibleSignature.Content(box_value(L"Semnătură vizibilă pe pagină"));

        StackPanel panel;
        panel.Spacing(12);
        panel.Children().Append(useTimestamp);
        panel.Children().Append(timestampUrl);
        panel.Children().Append(useRevocation);
        panel.Children().Append(revocationUrl);
        panel.Children().Append(visibleSignature);

        ContentDialog dialog;
        dialog.XamlRoot(RootGrid().XamlRoot());
        dialog.Title(box_value(L"Setări"));
        dialog.Content(panel);
        dialog.PrimaryButtonText(L"Salvează");
        dialog.CloseButtonText(L"Renunță");
        dialog.DefaultButton(ContentDialogButton::Primary);

        if (co_await dialog.ShowAsync() != ContentDialogResult::Primary)
            co_return;

        services.UseTimestamp = useTimestamp.IsChecked().GetBoolean();
        services.TimestampUrl = toUtf8(timestampUrl.Text());
        services.TimestampFrom = pdfsign::TimestampSource::RemoteService;

        services.UseRevocation = useRevocation.IsChecked().GetBoolean();
        services.RevocationUrl = toUtf8(revocationUrl.Text());
        services.RevocationFrom = services.RevocationUrl.empty()
            ? pdfsign::RevocationSource::CertificateAia
            : pdfsign::RevocationSource::RemoteResponder;

        m_model->SetVisibleSignature(visibleSignature.IsChecked().GetBoolean());
        Refresh();
    }

    IAsyncAction MainWindow::OnSign(IInspectable const&, RoutedEventArgs const&)
    {
        SetBusy(true);
        ResultBar().IsOpen(false);
        StatusText().Text(L"Se semnează...");

        auto queue = DispatcherQueue();
        auto lifetime = get_strong();

        // Signing hashes the whole document and may wait on a timestamp
        // authority over the network, so it must not run on the UI thread.
        co_await winrt::resume_background();

        auto result = m_model->Sign([this, queue, lifetime](SignStage, std::string const& message)
        {
            // Progress arrives on the worker thread, and only the dispatcher
            // may touch controls, so each step is posted back.
            auto text = toHstring(message);
            queue.TryEnqueue([this, lifetime, text]()
            {
                StatusText().Text(text);
            });
        });

        co_await winrt::resume_foreground(queue);

        SetBusy(false);
        StatusText().Text(L"");

        ResultBar().Title(toHstring(result.Succeeded ? "Succes" : "Eroare"));
        ResultBar().Message(toHstring(pdfsign::ui::MainViewModel::DescribeResult(result)));
        ResultBar().Severity(result.Succeeded
            ? InfoBarSeverity::Success
            : InfoBarSeverity::Error);
        ResultBar().IsOpen(true);

        for (auto const& warning : result.Warnings)
        {
            ResultBar().Severity(InfoBarSeverity::Warning);
            ResultBar().Message(ResultBar().Message() + L"\n" + toHstring(warning));
        }

        Refresh();
    }

    void MainWindow::OnClose(IInspectable const&, RoutedEventArgs const&)
    {
        Close();
    }
}
