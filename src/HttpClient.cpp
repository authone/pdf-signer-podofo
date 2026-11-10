// SPDX-License-Identifier: MIT

#include "HttpClient.h"

#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

#include <curl/curl.h>

using namespace std;
using namespace pdfsign;

namespace
{
    struct CurlDelete final { void operator()(CURL* p) const { curl_easy_cleanup(p); } };
    struct SlistDelete final { void operator()(curl_slist* p) const { curl_slist_free_all(p); } };

    using CurlPtr = unique_ptr<CURL, CurlDelete>;
    using SlistPtr = unique_ptr<curl_slist, SlistDelete>;

    /** libcurl wants one global initialisation per process. */
    void ensureCurlInitialised()
    {
        static once_flag once;
        static CURLcode result = CURLE_OK;
        call_once(once, [] { result = curl_global_init(CURL_GLOBAL_DEFAULT); });
        if (result != CURLE_OK)
            throw runtime_error("Cannot initialise libcurl");
    }

    size_t collectBody(char* data, size_t size, size_t count, void* userdata)
    {
        auto total = size * count;
        static_cast<string*>(userdata)->append(data, total);
        return total;
    }

    bool startsWith(const string& value, const char* prefix)
    {
        return value.rfind(prefix, 0) == 0;
    }
}

string HttpTransport::Validate(const string& url) const
{
    auto isHttps = startsWith(url, "https://");
    if (!isHttps && !startsWith(url, "http://"))
        throw runtime_error("The URL must start with http:// or https://");

    auto hasClientCert = !ClientCertPath.empty();
    if (hasClientCert != !ClientKeyPath.empty())
        throw runtime_error("Mutual TLS needs both a client certificate and its key");

    // A client certificate only means anything inside a TLS handshake.
    if (hasClientCert && !isHttps)
        throw runtime_error("Mutual TLS requires an https:// URL");

    if (TimeoutSeconds <= 0)
        throw runtime_error("The timeout must be positive");

    string summary;
    if (hasClientCert)
        summary = "mutual TLS";
    else if (!Username.empty())
        summary = "HTTP basic auth";

    if (isHttps && !VerifyPeer)
        summary += summary.empty() ? "TLS verification disabled" : ", TLS verification disabled";

    return summary;
}

string pdfsign::HttpPost(const string& url, const string& body,
    const char* contentType, const char* accept, const HttpTransport& transport)
{
    ensureCurlInitialised();

    CurlPtr curl(curl_easy_init());
    if (curl == nullptr)
        throw runtime_error("Cannot create a libcurl handle");

    string contentHeader = string("Content-Type: ") + contentType;
    string acceptHeader = string("Accept: ") + accept;

    SlistPtr headers(curl_slist_append(nullptr, contentHeader.c_str()));
    headers.reset(curl_slist_append(headers.release(), acceptHeader.c_str()));
    // Some providers stall when curl announces "Expect: 100-continue".
    headers.reset(curl_slist_append(headers.release(), "Expect:"));
    if (headers == nullptr)
        throw runtime_error("Cannot build the request headers");

    string response;
    char error[CURL_ERROR_SIZE] = { 0 };

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, &collectBody);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, transport.TimeoutSeconds);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, "podofo-pdf-sign/1.0");
    curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error);

    if (!transport.ClientCertPath.empty())
    {
        curl_easy_setopt(curl.get(), CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl.get(), CURLOPT_SSLCERT, transport.ClientCertPath.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(curl.get(), CURLOPT_SSLKEY, transport.ClientKeyPath.c_str());

        if (!transport.ClientKeyPassword.empty())
        {
            curl_easy_setopt(curl.get(), CURLOPT_KEYPASSWD,
                transport.ClientKeyPassword.c_str());
        }
    }

    if (!transport.CaBundlePath.empty())
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, transport.CaBundlePath.c_str());

    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, transport.VerifyPeer ? 1L : 0L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, transport.VerifyPeer ? 2L : 0L);

    if (!transport.Username.empty())
    {
        curl_easy_setopt(curl.get(), CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
        curl_easy_setopt(curl.get(), CURLOPT_USERNAME, transport.Username.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_PASSWORD, transport.Password.c_str());
    }

    auto result = curl_easy_perform(curl.get());
    if (result != CURLE_OK)
    {
        string detail = error[0] != 0 ? error : curl_easy_strerror(result);
        throw runtime_error("Cannot reach " + url + ": " + detail);
    }

    long status = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    if (status != 200)
        throw runtime_error(url + " returned HTTP " + to_string(status));

    if (response.empty())
        throw runtime_error(url + " returned an empty response");

    return response;
}
