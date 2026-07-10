# Document Forensics — Tampering & Fraud Triage (offline MVP)

An offline tool that analyses uploaded PDFs across nine forensic layers and returns a
findings report — severity-graded, with page and nearest-section references, and a separate
checklist of what still needs external verification.

> **It surfaces anomalies for a human examiner. It does not prove fraud or intent.**
> Confirmed items are reproducible byte/metadata facts; Review/Verify items need judgment or
> the source files.

## What it detects (all offline)

| Layer | Examples of what it flags |
|-------|---------------------------|
| File / byte | integrity hash, data hidden after `%%EOF` |
| Structure | incremental updates (edits appended after saving), digital-signature objects |
| Metadata | author/tool/timestamps, print-to-PDF flattening, internal-title provenance leaks, modified-before-created |
| Fonts | late-added font (possible overlay), mixed base fonts (multi-source assembly) |
| Text | leftover template placeholders, overlaid/inserted fields (rare colour + odd font), fake redactions (dark box over dark text), near-white hidden text, multiple template vintages (footer dates) |
| Image | reused/pasted signatures & stamps (perceptual hash), full-page rasters inside a text PDF, image-editing-software (EXIF) tags inside embedded signatures/stamps/logos |
| Cross-document | identical or reused graphics across files, files re-exported in one session from different sources |
| Verify checklist | source files, registration, signatory authority, cryptographic-signature validation, etc. |

Upload a **whole pack** to unlock the cross-document checks — that's where the strongest
signals (reused signatures, export-session clustering) come from.

## Plain-language reports

Every output (screen, PDF, Markdown) leads with a **plain-English summary** written for a
non-technical reader: a one-line risk verdict, a "what we found / what to do next" section, and
a one-line verdict per document. Each finding is phrased as **What it means** and **What to do**,
with the raw technical detail (object ids, hashes, RGB values, perceptual distances) demoted to a
footnote / expander. The PDF report also embeds the actual reused-signature crops as visual
evidence and a risk gauge.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud (free)

1. Put these files in a GitHub repo (root):
   `app.py`, `forensics_engine.py`, `requirements.txt`, `README.md`.
2. Go to https://share.streamlit.io → **New app** → pick the repo/branch → main file `app.py`.
3. Deploy. No `packages.txt` needed — every dependency installs from pip wheels
   (PyMuPDF, pikepdf ship their own binaries), so there are no system-package requirements.

## Files

- `app.py` — Streamlit UI (upload, findings table, reused-graphic gallery, per-file detail,
  verification checklist, JSON/Markdown export).
- `forensics_engine.py` — the analysis engine and rule set (importable/testable on its own:
  `analyze_document(path)`, `correlate_documents(results)`).

## Scope & honesty (say this to clients)

- **Print-to-PDF flattening** (macOS Quartz, Chrome, Ghostscript) erases revision history, so
  "no incremental updates" is not proof a file was never edited — get the source `.docx`/`.xlsx`.
- **Timestamps and unsigned metadata are forgeable** — corroborate, don't rely.
- **ELA / noise analysis** is for scanned/photographed images, not born-digital text; this MVP
  flags full-page rasters for that follow-up rather than pretending to do it on vector text.
- Strong authentication ultimately comes from **cryptographic signatures** and **external
  authoritative sources**, which are outside this offline tool by design.
