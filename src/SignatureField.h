// SPDX-License-Identifier: MIT

#pragma once

#include <string>

#include <podofo/podofo.h>

#include "DocumentSource.h"
#include "SignatureAppearance.h"

namespace pdfsign
{
    /** Adds a signature field to the page the appearance names.
     *
     * Shared by the ordinary signer and the document-timestamp writer: a
     * timestamp is carried by a signature field like any other signature, it
     * just holds a different kind of blob.
     *
     * @throws std::runtime_error if the document has no pages or the page is
     *         out of range.
     */
    PoDoFo::PdfSignature& CreateSignatureField(IDocumentSource& source,
        ISignatureAppearance& appearance, const std::string& fieldName);
}
