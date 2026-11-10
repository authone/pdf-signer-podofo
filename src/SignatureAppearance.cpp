// SPDX-License-Identifier: MIT

#include "SignatureAppearance.h"

#include <ctime>
#include <utility>

using namespace std;
using namespace PoDoFo;
using namespace pdfsign;

namespace
{
    /** Local time for the drawn text.
     *
     * Only cosmetic: the authoritative time goes into the signature dictionary
     * as a PdfDate.
     */
    string nowAsText()
    {
        auto now = std::time(nullptr);
        std::tm parts{};
#ifdef _WIN32
        localtime_s(&parts, &now);
#else
        localtime_r(&now, &parts);
#endif
        char buf[64];
        if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", &parts) == 0)
            return {};

        return string(buf);
    }
}

TextBoxAppearance::TextBoxAppearance(unsigned pageIndex, const Rect& box, Text text) :
    m_pageIndex(pageIndex),
    m_box(box),
    m_text(std::move(text))
{
}

void TextBoxAppearance::Apply(PdfMemDocument& doc, PdfSignature& signature)
{
    auto width = m_box.Width;
    auto height = m_box.Height;

    m_form = doc.CreateXObjectForm(Rect(0, 0, width, height));

    auto& regular = doc.GetFonts().GetStandard14Font(PdfStandard14FontType::Helvetica);
    auto& bold = doc.GetFonts().GetStandard14Font(PdfStandard14FontType::HelveticaBold);

    PdfPainter painter;
    painter.SetCanvas(*m_form);

    painter.GraphicsState.SetStrokingColor(PdfColor(0.15, 0.25, 0.55));
    painter.DrawRectangle(0.5, 0.5, width - 1.0, height - 1.0);

    painter.GraphicsState.SetNonStrokingColor(PdfColor(0.15, 0.25, 0.55));
    painter.TextState.SetFont(bold, 7.5);
    painter.DrawText("Digitally signed by", 6.0, height - 13.0);

    painter.GraphicsState.SetNonStrokingColor(PdfColor(0.1));
    painter.TextState.SetFont(bold, 9.0);
    painter.DrawText(m_text.SignerName, 6.0, height - 26.0);

    painter.TextState.SetFont(regular, 7.0);
    auto line = height - 38.0;
    painter.DrawText("Date: " + nowAsText(), 6.0, line);

    if (!m_text.Reason.empty())
    {
        line -= 10.0;
        painter.DrawText("Reason: " + m_text.Reason, 6.0, line);
    }

    if (!m_text.Location.empty())
    {
        line -= 10.0;
        painter.DrawText("Location: " + m_text.Location, 6.0, line);
    }

    painter.FinishDrawing();

    signature.MustGetWidget().SetAppearanceStream(*m_form);
}
