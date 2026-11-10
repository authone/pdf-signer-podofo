// SPDX-License-Identifier: MIT
//
// What the signature looks like on the page, if anything.

#pragma once

#include <memory>
#include <string>

#include <podofo/podofo.h>

namespace pdfsign
{
    /** Decides where the signature widget sits and what it draws.
     *
     * A signature need not be visible at all, and an invisible one protects the
     * document just as fully, so "no appearance" is a first-class case here
     * rather than a flag the signer has to test.
     */
    class ISignatureAppearance
    {
    public:
        virtual ~ISignatureAppearance() = default;

        /** Zero-based page carrying the signature widget. */
        virtual unsigned GetPageIndex() const = 0;

        /** Widget rectangle in PDF points, origin at the page's bottom-left. */
        virtual PoDoFo::Rect GetRect() const = 0;

        /** Attaches the appearance stream, if there is one.
         *
         * Called after the field exists. Implementations that create document
         * objects must keep owning them: the objects have to outlive the call
         * to SignDocument.
         */
        virtual void Apply(PoDoFo::PdfMemDocument& doc,
            PoDoFo::PdfSignature& signature) = 0;

        virtual const char* GetDescription() const = 0;
    };

    /** A signature with no visible representation.
     *
     * A zero-sized rectangle is how PDF expresses this.
     */
    class InvisibleAppearance final : public ISignatureAppearance
    {
    public:
        explicit InvisibleAppearance(unsigned pageIndex = 0) :
            m_pageIndex(pageIndex) { }

        unsigned GetPageIndex() const override { return m_pageIndex; }
        PoDoFo::Rect GetRect() const override { return PoDoFo::Rect(0, 0, 0, 0); }
        void Apply(PoDoFo::PdfMemDocument&, PoDoFo::PdfSignature&) override { }
        const char* GetDescription() const override { return "invisible"; }

    private:
        unsigned m_pageIndex;
    };

    /** A bordered box naming the signer, with the date and any reason given. */
    class TextBoxAppearance final : public ISignatureAppearance
    {
    public:
        /** Lines drawn in the box. Kept separate from the signature dictionary
         * metadata: what is shown and what is recorded need not match. */
        struct Text final
        {
            std::string SignerName;
            std::string Reason;
            std::string Location;
        };

        TextBoxAppearance(unsigned pageIndex, const PoDoFo::Rect& box, Text text);

        unsigned GetPageIndex() const override { return m_pageIndex; }
        PoDoFo::Rect GetRect() const override { return m_box; }
        void Apply(PoDoFo::PdfMemDocument& doc, PoDoFo::PdfSignature& signature) override;
        const char* GetDescription() const override { return "visible"; }

    private:
        unsigned m_pageIndex;
        PoDoFo::Rect m_box;
        Text m_text;

        // Owned here because the widget references it and it must still exist
        // when the document is written.
        std::unique_ptr<PoDoFo::PdfXObjectForm> m_form;
    };
}
