// SPDX-License-Identifier: MIT
//
// Code-behind for the signing window.
//
// This file is an adapter and nothing more: it copies text between controls
// and MainViewModel, puts the blocking work on a background thread, and
// marshals the answers back. Every decision about what is valid, what is
// enabled and what is displayed belongs to the view model.

#pragma once

#include "MainWindow.g.h"

#include <memory>

#include "MainViewModel.h"

namespace winrt::ClickSignPdf::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        // Text boxes
        void OnInputPathChanged(Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::Controls::TextChangedEventArgs const& args);
        void OnOutputPathChanged(Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::Controls::TextChangedEventArgs const& args);

        // Buttons
        Windows::Foundation::IAsyncAction OnBrowseInput(
            Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction OnBrowseOutput(
            Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction OnBrowseCertificate(
            Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction OnPreviewInput(
            Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction OnOpenSettings(
            Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction OnSign(
            Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnClose(Windows::Foundation::IInspectable const& sender,
            Microsoft::UI::Xaml::RoutedEventArgs const& args);

    private:
        /** Pushes the view model's state onto the controls. Called after
         * anything that could change it. */
        void Refresh();

        void SetBusy(bool busy);

        /** Asks the user for a password when the credential needs one. */
        Windows::Foundation::IAsyncOperation<hstring> PromptForPassword();

        /** A file picker has to be told which window owns it, or it throws in
         * an unpackaged WinUI 3 app. */
        void InitialiseWithWindow(Windows::Foundation::IInspectable const& picker);

        std::unique_ptr<pdfsign::ui::MainViewModel> m_model;
        bool m_updating = false;
    };
}

namespace winrt::ClickSignPdf::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
