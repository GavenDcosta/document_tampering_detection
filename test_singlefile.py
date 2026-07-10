"""Reproduce the user's single-file run (DA only) and confirm image evidence renders."""
import os, sys, importlib.util
import unittest.mock as mock

st = mock.MagicMock()
st.cache_data = lambda *a, **k: (lambda f: f)
st.file_uploader.return_value = []
st.stop.side_effect = SystemExit
sys.modules["streamlit"] = st

import forensics_engine as fe
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("app", os.path.join(HERE, "app.py"))
app = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(app)
except SystemExit:
    pass

ROOT = r"c:\Users\Gaven Dcosta\Desktop\Document_Tampering"
name = "Akesis RSG DA - final.pdf"
paths = {name: os.path.join(ROOT, name)}
results = {name: fe.analyze_document(paths[name], name)}
cross = fe.correlate_documents(results)

# confirm the EXIF finding now carries an image_ref
for f in results[name]["findings"]:
    if f["title"] == "Image-editing software tag inside an embedded image":
        print("EXIF finding image_ref:", f["image_ref"])
        assert f["image_ref"][1] is not None

pdf_bytes = app.build_pdf_report(results, cross, paths=paths)
out = os.path.join(HERE, "sample_singlefile.pdf")
open(out, "wb").write(pdf_bytes)
print(f"single-file PDF: {len(pdf_bytes)} bytes -> {out}")

# render the pages so we can eyeball the embedded image
import fitz
d = fitz.open(out)
print("pages:", d.page_count)
for i in range(d.page_count):
    d[i].get_pixmap(dpi=110).save(os.path.join(HERE, f"_sf_{i+1}.png"))
print("rendered", d.page_count, "pages")
