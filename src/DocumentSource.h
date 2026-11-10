// SPDX-License-Identifier: MIT
//
// Where the document being signed comes from, and how its bytes are written.

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <podofo/podofo.h>

namespace pdfsign
{
    /** Supplies a document together with the stream its signed bytes go to.
     *
     * These travel together because they are not independent: signing an
     * existing file appends a revision to the very bytes the document was
     * parsed from, so the document and the device must be the same file, open
     * for both reading and writing.
     */
    class IDocumentSource
    {
    public:
        virtual ~IDocumentSource() = default;

        /** Prepares the document and the output device. Call once, before the
         * other accessors. */
        virtual void Open() = 0;

        virtual PoDoFo::PdfMemDocument& GetDocument() = 0;
        virtual PoDoFo::StreamDevice& GetDevice() = 0;

        /** Save options that match how this source was opened. */
        virtual PoDoFo::PdfSaveOptions GetSaveOptions() const = 0;

        /** What to call the result in console output. */
        virtual const std::string& GetOutputPath() const = 0;
    };

    /** Common storage for the concrete sources. */
    class DocumentSourceBase : public IDocumentSource
    {
    public:
        PoDoFo::PdfMemDocument& GetDocument() override;
        PoDoFo::StreamDevice& GetDevice() override;
        const std::string& GetOutputPath() const override { return m_outputPath; }

    protected:
        explicit DocumentSourceBase(std::string outputPath);

        std::string m_outputPath;
        std::shared_ptr<PoDoFo::FileStreamDevice> m_device;
        std::unique_ptr<PoDoFo::PdfMemDocument> m_document;
    };

    /** A document created in memory and written out for the first time.
     *
     * Nothing exists on disk yet, so the document is written and signed in a
     * single pass.
     */
    class NewDocumentSource final : public DocumentSourceBase
    {
    public:
        using ContentBuilder = std::function<void(PoDoFo::PdfMemDocument&)>;

        /** @param buildContent fills the empty document with pages. */
        NewDocumentSource(std::string outputPath, ContentBuilder buildContent);

        void Open() override;

        PoDoFo::PdfSaveOptions GetSaveOptions() const override
        {
            return PoDoFo::PdfSaveOptions::SaveOnSigning;
        }

    private:
        ContentBuilder m_buildContent;
    };

    /** An existing PDF, signed as an incremental update.
     *
     * The input is copied to the output and the copy is opened read-write, so
     * PoDoFo appends a revision instead of rewriting the file. That is what
     * keeps any signature already on the document valid.
     */
    class ExistingDocumentSource final : public DocumentSourceBase
    {
    public:
        ExistingDocumentSource(std::string inputPath, std::string outputPath);

        void Open() override;

        /** Refreshing /ModDate would rewrite bytes covered by an earlier
         * signature's byte range and break it. */
        PoDoFo::PdfSaveOptions GetSaveOptions() const override
        {
            return PoDoFo::PdfSaveOptions::NoMetadataUpdate;
        }

    private:
        std::string m_inputPath;
    };
}
