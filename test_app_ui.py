"""Run app.py end-to-end with a mock Streamlit + the 4 real PDFs, to exercise
every UI code path (exec summary, gallery, cards, verdicts, checklist, exports)."""
import os, sys, importlib.util
import unittest.mock as mock

ROOT = r"c:\Users\Gaven Dcosta\Desktop\Document_Tampering"
pdfs = ["Akesis RSG DA - final.pdf",
        "RSG AKESIS 11 Systems Deal Summary FINAL signed stamped.pdf",
        "RSG Akesis Firm_Commitment_Term_Sheet FINAL signed stamped.pdf",
        "Google.pdf"]


class FakeUpload:
    def __init__(self, path):
        self.name = os.path.basename(path)
        self._data = open(path, "rb").read()
    def getvalue(self):
        return self._data


st = mock.MagicMock()
# cache_data must be a pass-through decorator, not a mock
st.cache_data = lambda *a, **k: (lambda f: f)
# columns(n) / columns([..]) must yield an unpackable list of mocks
st.columns.side_effect = lambda spec: [mock.MagicMock() for _ in
                                       range(spec if isinstance(spec, int) else len(spec))]
# multiselect returns its default so DataFrame filtering works
st.multiselect.side_effect = lambda label, options, default=None, **k: (
    default if default is not None else options)
# feed the uploader the 4 real PDFs
st.file_uploader.return_value = [FakeUpload(os.path.join(ROOT, n)) for n in pdfs]
sys.modules["streamlit"] = st

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("app", os.path.join(HERE, "app.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)   # should run to completion with no exception

# sanity: the app analysed all 4 files and built its summary without error
assert hasattr(app, "results") and len(app.results) == 4, "results not populated"
assert hasattr(app, "summary") and app.summary["n_files"] == 4
assert app.pdf_bytes[:4] == b"%PDF" and len(app.md) > 1000

# the image findings must have actually driven st.image(...) with real PNG bytes
img_calls = st.image.call_args_list
assert len(img_calls) > 0, "st.image was never called - no image evidence rendered"
first_arg = img_calls[0].args[0]
assert isinstance(first_arg, (bytes, bytearray)) and first_arg[:4] in (b"\x89PNG",), \
    f"st.image did not receive PNG bytes: {type(first_arg)}"
print(f"App analysed {len(app.results)} files; st.image called {len(img_calls)} times with real PNG bytes")
print(f"summary headline: {app.summary['headline']!r}")
print("APP RAN END-TO-END WITH NO EXCEPTIONS")
