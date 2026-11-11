// SPDX-License-Identifier: MIT
#pragma once

#include "App.xaml.g.h"

namespace winrt::ClickSignPdf::implementation
{
    struct App : AppT<App>
    {
        App();

        void OnLaunched(Microsoft::UI::Xaml::LaunchActivatedEventArgs const& args);

    private:
        Microsoft::UI::Xaml::Window m_window{ nullptr };
    };
}
