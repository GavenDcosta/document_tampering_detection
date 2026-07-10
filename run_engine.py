"""Drive the engine on the 4 test PDFs exactly like the app does, and dump findings."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import forensics_engine as fe

ROOT = r"c:\Users\Gaven Dcosta\Desktop\Document_Tampering"
pdfs = [
    "Akesis RSG DA - final.pdf",
    "RSG AKESIS 11 Systems Deal Summary FINAL signed stamped.pdf",
    "RSG Akesis Firm_Commitment_Term_Sheet FINAL signed stamped.pdf",
    "Google.pdf",
]

results = {}
for name in pdfs:
    path = os.path.join(ROOT, name)
    results[name] = fe.analyze_document(path, name)

cross = fe.correlate_documents(results)

print("=" * 90)
print("PER-FILE FINDINGS")
print("=" * 90)
for fn, r in results.items():
    s = r["summary"]
    print(f"\n### {fn}")
    print(f"    pages={s['pages']} producer={s['producer']!r} author={s['author']!r}")
    print(f"    title={s['title']!r}")
    print(f"    {len(r['findings'])} findings:")
    for f in r["findings"]:
        print(f"      [{f['severity']}/{f['status']}] ({f['layer']}) {f['title']}"
              + (f"  p{f['page']}" if f.get('page') else ""))
        print(f"          detail: {f['detail']}")
        if f.get('evidence'):
            print(f"          evidence: {f['evidence']}")

print("\n" + "=" * 90)
print("CROSS-DOCUMENT FINDINGS")
print("=" * 90)
for f in cross:
    print(f"  [{f['severity']}/{f['status']}] {f['title']}")
    print(f"      detail: {f['detail']}")
    print(f"      evidence: {f['evidence']}")

# totals
tot = sum(len(r["findings"]) for r in results.values()) + len(cross)
print(f"\nTOTAL findings across everything: {tot}")
