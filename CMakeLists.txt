# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.23)

project(podofo-pdf-sign
    VERSION 1.0.0
    DESCRIPTION "Worked example of signing a PDF with PoDoFo"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# scripts/build-podofo.sh installs PoDoFo here. A system-wide or Conan/vcpkg
# install is found without this; it is only a convenience default.
if(NOT DEFINED PODOFO_PREFIX)
    set(PODOFO_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/third_party/prefix")
endif()

if(EXISTS "${PODOFO_PREFIX}")
    list(APPEND CMAKE_PREFIX_PATH "${PODOFO_PREFIX}")
endif()

# No version is requested on purpose. PoDoFo's package version file uses
# SameMinorVersion compatibility, so find_package(PoDoFo 1.0.0) is rejected by
# 1.1.2 even though it is newer. The version is checked after the fact instead.
find_package(PoDoFo REQUIRED)

if(DEFINED PoDoFo_VERSION)
    if(PoDoFo_VERSION VERSION_LESS 0.10.0)
        message(FATAL_ERROR
            "Found PoDoFo ${PoDoFo_VERSION}, which predates the PdfSignerCms "
            "signing API this example uses. Run scripts/build-podofo.sh.")
    endif()
    message(STATUS "Using PoDoFo ${PoDoFo_VERSION}")
endif()

# Used directly for credential loading (PKCS#12, format sniffing, signing a
# bare hash). PoDoFo already depends on OpenSSL, so this adds no new build
# requirement.
find_package(OpenSSL REQUIRED)

# Used by the RFC 3161 client to reach a timestamp authority over HTTP(S).
# libcurl carries the TLS, mutual-authentication, proxy and timeout handling
# that would otherwise have to be written by hand against OpenSSL BIOs.
find_package(CURL REQUIRED)

add_executable(podofo-pdf-sign
    src/main.cpp
    src/OpenSslSupport.cpp
    src/SigningIdentity.cpp
    src/DocumentSource.cpp
    src/SignatureAppearance.cpp
    src/DocumentSigner.cpp
    src/SignatureField.cpp
    src/ValidationServices.cpp
    src/ValidationDataStore.cpp
    src/DocumentTimestamp.cpp
    src/HttpClient.cpp
    src/HttpTimestampService.cpp
    src/HttpOcspResponder.cpp
    src/SampleDoc.cpp)

target_link_libraries(podofo-pdf-sign
    PRIVATE
        podofo::podofo
        OpenSSL::Crypto
        CURL::libcurl)

if(MSVC)
    target_compile_options(podofo-pdf-sign PRIVATE /W4)
else()
    target_compile_options(podofo-pdf-sign PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Let the binary find a locally built PoDoFo without LD_LIBRARY_PATH.
set_target_properties(podofo-pdf-sign PROPERTIES
    BUILD_RPATH "${PODOFO_PREFIX}/lib"
    INSTALL_RPATH "${PODOFO_PREFIX}/lib")

install(TARGETS podofo-pdf-sign RUNTIME DESTINATION bin)
