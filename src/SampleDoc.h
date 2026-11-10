// SPDX-License-Identifier: MIT

#pragma once

#include <podofo/podofo.h>

namespace pdfsign
{
    /** Draws a one-page placeholder document into @p doc.
     *
     * Only here so the example has something to sign when the user has no PDF
     * to hand; it is not part of the signing story.
     */
    void BuildSampleDocument(PoDoFo::PdfMemDocument& doc);
}
