"""Smoke-test the plain-language layer against the 4 test PDFs."""
import os, forensics_engine as fe

ROOT = r"c:\Users\Gaven Dcosta\Desktop\Document_Tampering"
pdfs = ["Akesis RSG DA - final.pdf",
        "RSG AKESIS 11 Systems Deal Summary FINAL signed stamped.pdf",
        "RSG Akesis Firm_Commitment_Term_Sheet FINAL signed stamped.pdf",
        "Google.pdf"]

results = {n: fe.analyze_document(os.path.join(ROOT, n), n) for n in pdfs}
cross = fe.correlate_documents(results)

summ = fe.build_executive_summary(results, cross)
print("HEADLINE:", summ["headline"])
print(f"counts: files={summ['n_files']} findings={summ['n_findings']} "
      f"high={summ['n_high']} confirmed={summ['n_confirmed']}")
print("\nWHAT WE FOUND:")
for t in summ["themes"]:
    print("  -", t)
print("\nWHAT TO DO NEXT:")
for a in summ["actions"]:
    print("  -", a)

print("\n" + "=" * 80)
print("DOCUMENT VERDICTS")
for fn, r in results.items():
    print(f"  {fn}\n     -> {fe.document_verdict(fn, r, cross)}")

print("\n" + "=" * 80)
print("SAMPLE HUMANIZED FINDING (overlaid text):")
for r in results.values():
    for f in r["findings"]:
        if f["title"] == "Overlaid / inserted text":
            h = fe.humanize(f)
            print(f"  [{h['severity_label']} | {h['status_label']}] {h['headline']}")
            print(f"  What it means: {h['means']}")
            print(f"  What to do:    {h['action']}")
            print(f"  Technical:     {f['detail']}")
            print(f"  Evidence:      {f['evidence']}")
            break
    else:
        continue
    break
