"""Import app.py with Streamlit stubbed, then exercise the real export builders."""
import os, sys, importlib.util
import unittest.mock as mock

# Stub streamlit so importing app.py doesn't need a running server.
st_stub = mock.MagicMock()
st_stub.file_uploader.return_value = []      # -> app hits `if not uploaded: st.stop()`
st_stub.stop.side_effect = SystemExit         # stop the UI cleanly
sys.modules["streamlit"] = st_stub

import forensics_engine as fe

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("app", os.path.join(HERE, "app.py"))
app = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(app)
except SystemExit:
    pass  # expected: UI stopped, but builder functions are now defined on `app`

# ---- analyse the 4 test PDFs ----
ROOT = r"c:\Users\Gaven Dcosta\Desktop\Document_Tampering"
pdfs = ["Akesis RSG DA - final.pdf",
        "RSG AKESIS 11 Systems Deal Summary FINAL signed stamped.pdf",
        "RSG Akesis Firm_Commitment_Term_Sheet FINAL signed stamped.pdf",
        "Google.pdf"]
paths = {n: os.path.join(ROOT, n) for n in pdfs}
results = {n: fe.analyze_document(paths[n], n) for n in pdfs}
cross = fe.correlate_documents(results)

# ---- Markdown ----
md = app.build_markdown(results, cross)
open(os.path.join(HERE, "sample_report.md"), "w", encoding="utf-8").write(md)
print(f"MARKDOWN ok: {len(md)} chars -> sample_report.md")
assert "In plain English" in md and "What to do next" in md

# ---- PDF ----
pdf_bytes = app.build_pdf_report(results, cross, paths=paths)
open(os.path.join(HERE, "sample_report.pdf"), "wb").write(pdf_bytes)
print(f"PDF ok: {len(pdf_bytes)} bytes -> sample_report.pdf")
assert pdf_bytes[:4] == b"%PDF"

# ---- signature crops actually collected? ----
crops = app._collect_signature_crops(results, cross, paths)
print(f"Signature crops collected: {len(crops)} -> {[c[0] for c in crops]}")

print("\nALL EXPORT BUILDERS RAN CLEANLY")
