# clickSIGN PDF — WinUI 3 front end

A Windows 10/11 desktop window over the same signing engine the CLI uses,
laid out after the original clickSIGN PDF dialog.

> **Not built or run by the author.** This project was developed on Linux. The
> engine, the facade and the view model are compiled and tested there; the XAML
> and its code-behind in `ClickSignPdf/` have **never been through MSVC**.
> Treat them as a working draft: the structure and the API calls are right, but
> expect to fix compile errors on the first build.

## Why WinUI 3 and not "the WinUI in the Windows SDK"

The WinUI that ships inside the Windows SDK is **WinUI 2**, which is UWP XAML
(`Windows.UI.Xaml`). It is the wrong tool here: a UWP app is sandboxed, so it
cannot open arbitrary paths the user types, link PoDoFo, OpenSSL and libcurl
directly, or reach a smartcard or the machine certificate store without
brokered workarounds.

**WinUI 3** is the same XAML dialect for unsandboxed Win32 desktop apps. It
ships in the **Windows App SDK**, a NuGet package, not in the Windows SDK. The
project is configured unpackaged (`WindowsPackageType=None`) for exactly the
reason above; switch `AppxPackage` to `true` and add a `Package.appxmanifest`
if you want MSIX deployment.

## Prerequisites

- Visual Studio 2022 with **Desktop development with C++** and the
  **Windows App SDK C++ templates** component
- Windows SDK 10.0.22621.0 or later
- PoDoFo 1.1.2, OpenSSL 3 and libcurl built for Windows

Point the project at them before building:

```
setx PODOFO_PREFIX  C:\deps\podofo
setx OPENSSL_PREFIX C:\deps\openssl
setx CURL_PREFIX    C:\deps\curl
```

vcpkg is the least painful way to get all three:
`vcpkg install podofo:x64-windows openssl:x64-windows curl:x64-windows`.

Then open `ClickSignPdf/ClickSignPdf.vcxproj` and build x64.

## Where the line between UI and logic is

```
  MainWindow.xaml          layout only
  MainWindow.xaml.cpp      adapter: controls <-> view model, threading
  ---------------------------------------------------------------- Windows
  ViewModel/MainViewModel  plain C++: what is valid, enabled, displayed
  ---------------------------------------------------------------- portable
  src/SigningFacade        plain C++: request -> result, never throws
  ---------------------------------------------------------------- engine
  src/*                    PoDoFo, OpenSSL, libcurl
```

Three properties make the separation real rather than nominal:

**The view model has no Windows dependency at all.** No WinRT, no XAML, no
`windows.h`. It is built by the top-level `CMakeLists.txt` as
`pdfsign_viewmodel` on Linux, so presentation logic that drifts into something
only Windows can compile breaks that build immediately instead of at the next
Visual Studio run. It is also directly unit-testable.

**The facade never throws and exposes no library types.** `SigningFacade.h`
includes nothing but `<string>`, `<vector>` and `<functional>`. A UI has no
sensible way to handle an exception crossing from a worker thread, so failures
come back as data — `SignResult::Message`, `CertificateSummary::Error`.

**The code-behind decides nothing.** Whether the Sign button is enabled is
`MainViewModel::BlockingReason()`. What the certificate line says is
`CertificateText()`. Even the Romanian wording lives in the view model, not the
markup, so the window cannot quietly acquire a rule of its own.

## Threading

`MainViewModel::Sign` blocks: it hashes the whole document and may wait on a
timestamp authority over the network. `OnSign` therefore does
`co_await winrt::resume_background()` first, and posts progress back through
the `DispatcherQueue` before touching any control. Doing this on the UI thread
would freeze the window for as long as the TSA takes to answer.

## Mapping to the original dialog

| Original | Here |
|---|---|
| `Fișier intrare:` + `Selectează` | `InputPathBox`, `BrowseInputButton` |
| PDF button | `PreviewButton`, opens the document in the default viewer |
| `Fișier ieșire:` + `Selectează` | `OutputPathBox`, auto-filled as `<name>-semnat.pdf` |
| wrench button | `SettingsButton`, opens timestamp/OCSP/appearance settings |
| `Certificat:` | `CertificateText`, filled as soon as a file is chosen |
| `Fără marcă temporală.` | `TimestampText`, reflects the configured TSA |
| `Semnează` / `Închide` | `SignButton` / `CloseButton` |

## Known gaps

- **The banner is drawn in XAML**, not an image, so the project builds with no
  binary assets. Drop a logo into `Assets/banner.png` and swap the `Border` in
  `MainWindow.xaml` for an `Image`.
- **No Windows certificate store or smartcard support.** Credentials come from
  a PKCS#12 or PEM file. Signing from a CNG/CAPI key is the natural next step
  and fits the existing `ISigningIdentity` abstraction: implement it over
  `NCryptSignHash` and nothing above it changes.
- **Settings are not persisted** between runs.
- **`Package.appxmanifest` is absent**, matching the unpackaged configuration.
