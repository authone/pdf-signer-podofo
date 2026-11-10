// SPDX-License-Identifier: MIT

#include "DocumentSource.h"

#include <filesystem>
#include <stdexcept>
#include <utility>

using namespace std;
using namespace PoDoFo;
using namespace pdfsign;

namespace fs = std::filesystem;

DocumentSourceBase::DocumentSourceBase(string outputPath) :
    m_outputPath(std::move(outputPath))
{
    if (m_outputPath.empty())
        throw runtime_error("No output path given");
}

PdfMemDocument& DocumentSourceBase::GetDocument()
{
    if (m_document == nullptr)
        throw runtime_error("The document source has not been opened");

    return *m_document;
}

StreamDevice& DocumentSourceBase::GetDevice()
{
    if (m_device == nullptr)
        throw runtime_error("The document source has not been opened");

    return *m_device;
}

NewDocumentSource::NewDocumentSource(string outputPath, ContentBuilder buildContent) :
    DocumentSourceBase(std::move(outputPath)),
    m_buildContent(std::move(buildContent))
{
}

void NewDocumentSource::Open()
{
    m_document = make_unique<PdfMemDocument>();
    if (m_buildContent)
        m_buildContent(*m_document);

    m_device = make_shared<FileStreamDevice>(m_outputPath, FileMode::Create);
}

ExistingDocumentSource::ExistingDocumentSource(string inputPath, string outputPath) :
    DocumentSourceBase(std::move(outputPath)),
    m_inputPath(std::move(inputPath))
{
    if (m_inputPath.empty())
        throw runtime_error("No input path given");
}

void ExistingDocumentSource::Open()
{
    auto input = fs::u8path(m_inputPath);
    auto output = fs::u8path(m_outputPath);

    if (!fs::exists(input))
        throw runtime_error("Input file '" + m_inputPath + "' does not exist");

    // Signing in place would truncate the only copy of the input if anything
    // failed midway, so a distinct output is required.
    if (fs::exists(output) && fs::equivalent(input, output))
    {
        throw runtime_error("Input and output are the same file; signing writes "
            "a new revision, so give --out a different path");
    }

    auto parent = output.parent_path();
    if (!parent.empty() && !fs::exists(parent))
        fs::create_directories(parent);

    fs::copy_file(input, output, fs::copy_options::overwrite_existing);

    // FileMode::Open gives a read-write device over the copy, which is what
    // lets PoDoFo append a revision.
    m_device = make_shared<FileStreamDevice>(m_outputPath, FileMode::Open);
    m_document = make_unique<PdfMemDocument>(m_device);
}
