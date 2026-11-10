// SPDX-License-Identifier: MIT

#include "SignatureField.h"

#include <stdexcept>

using namespace std;
using namespace PoDoFo;

PdfSignature& pdfsign::CreateSignatureField(IDocumentSource& source,
    ISignatureAppearance& appearance, const string& fieldName)
{
    if (fieldName.empty())
        throw runtime_error("The signature field needs a name");

    auto& pages = source.GetDocument().GetPages();
    if (pages.GetCount() == 0)
        throw runtime_error("The document has no pages");

    auto index = appearance.GetPageIndex();
    if (index >= pages.GetCount())
    {
        throw runtime_error("Page " + to_string(index + 1) + " is out of range; "
            "the document has " + to_string(pages.GetCount()) + " page(s)");
    }

    auto& page = pages.GetPageAt(index);
    return page.CreateField<PdfSignature>(fieldName, appearance.GetRect());
}
