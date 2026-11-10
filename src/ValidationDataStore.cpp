// SPDX-License-Identifier: MIT

#include "ValidationDataStore.h"

#include <stdexcept>
#include <utility>

using namespace std;
using namespace PoDoFo;
using namespace pdfsign;

ValidationDataStore::ValidationDataStore(PdfMemDocument& doc) :
    m_doc(doc)
{
}

void ValidationDataStore::AddCertificate(string der)
{
    if (!der.empty())
        m_certs.push_back(std::move(der));
}

void ValidationDataStore::AddOcspResponse(string der)
{
    if (!der.empty())
        m_ocsps.push_back(std::move(der));
}

void ValidationDataStore::AddCrl(string der)
{
    if (!der.empty())
        m_crls.push_back(std::move(der));
}

bool ValidationDataStore::IsEmpty() const
{
    return m_certs.empty() && m_ocsps.empty() && m_crls.empty();
}

void ValidationDataStore::appendTo(PdfDictionary& dss, const PdfName& key,
    const vector<string>& blobs)
{
    if (blobs.empty())
        return;

    // The array has to be attached to the document *before* indirect
    // references go into it. PoDoFo checks that the container has an owner so
    // it can confirm both sides belong to the same document, so building a
    // detached PdfArray and inserting it afterwards fails. Any array left by
    // an earlier revision is reused, which is what makes repeated upgrades
    // accumulate.
    auto entry = dss.FindKey(key.GetString());
    if (entry == nullptr || !entry->IsArray())
        entry = &dss.AddKey(key, PdfObject(PdfArray()));

    auto& array = entry->GetArray();

    for (auto& blob : blobs)
    {
        // Each entry is an indirect stream object holding the raw DER.
        auto& streamObject = m_doc.GetObjects().CreateDictionaryObject();
        streamObject.GetOrCreateStream().SetData(bufferview(blob.data(), blob.size()));
        array.AddIndirect(streamObject);
    }
}

void ValidationDataStore::Commit()
{
    if (IsEmpty())
        return;

    auto& catalog = m_doc.GetCatalog().GetDictionary();

    // Reuse an existing DSS so repeated upgrades accumulate.
    PdfObject* dssObject = catalog.FindKey("DSS");
    if (dssObject == nullptr)
    {
        auto& created = m_doc.GetObjects().CreateDictionaryObject();
        catalog.AddKeyIndirect("DSS", created);
        dssObject = &created;
    }

    auto& dss = dssObject->GetDictionary();

    appendTo(dss, "Certs", m_certs);
    appendTo(dss, "OCSPs", m_ocsps);
    appendTo(dss, "CRLs", m_crls);

    // /VRI is deliberately not written. PDF 2.0 deprecates it, ETSI EN 319
    // 142-1 makes it optional, and the specifications disagree over whether
    // its key digests the signature's /Contents with or without the zero
    // padding PoDoFo reserves. Validators consume the DSS-level arrays above.
}

ValidationDataUpgrade::ValidationDataUpgrade(const IOcspResponder& responder) :
    m_responder(responder)
{
}

void ValidationDataUpgrade::AddSubject(string certDer, string issuerDer)
{
    if (certDer.empty())
        throw runtime_error("A validation-data subject needs a certificate");

    if (issuerDer.empty())
        issuerDer = certDer;

    m_subjects.push_back({ std::move(certDer), std::move(issuerDer) });
}

void ValidationDataUpgrade::Apply(IDocumentSource& source)
{
    if (m_subjects.empty())
        throw runtime_error("No certificates given to collect validation data for");

    source.Open();

    ValidationDataStore store(source.GetDocument());

    for (auto& subject : m_subjects)
    {
        store.AddCertificate(subject.CertDer);

        // A self-signed certificate is its own issuer, so avoid storing it
        // twice.
        if (subject.IssuerDer != subject.CertDer)
            store.AddCertificate(subject.IssuerDer);

        store.AddOcspResponse(m_responder.CreateResponse(subject.CertDer, subject.IssuerDer));
    }

    m_certCount = store.GetCertificateCount();
    m_ocspCount = store.GetOcspCount();

    store.Commit();

    // An incremental update, not a save: the bytes the existing signature
    // covers must not move. The source supplies NoMetadataUpdate for the same
    // reason, since rewriting /ModDate would fall inside that byte range.
    source.GetDocument().SaveUpdate(source.GetDevice(), source.GetSaveOptions());
}
